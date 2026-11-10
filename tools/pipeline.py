"""Build once, qualify, and promote the same RabbitMQ OCI candidate."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import time
import urllib.request

from .build_inputs import ROOT, fingerprint, image_digest, needs_rebuild, next_version, resolve
from .registry import package_tags
from .render_recipe import render
from .oci_evidence import export_evidence

IMAGE = "ghcr.io/carvvf/rabbitmq-docker"
SKOPEO = "quay.io/skopeo/stable:v1.22.3"
LOCAL_IMAGE = "rabbitmq-docker:candidate"


def run(*args, capture=False, **kwargs):
    return subprocess.run(list(args), check=True, text=True, stdout=subprocess.PIPE if capture else None, **kwargs)


def summary(message):
    print(message, flush=True)
    path = os.environ.get("GITHUB_STEP_SUMMARY")
    if path:
        with open(path, "a") as stream:
            stream.write(message + "\n")


def verify_checksum(data, expected):
    if not re.fullmatch(r"[0-9a-f]{64}", expected) or hashlib.sha256(data).hexdigest() != expected:
        raise ValueError("Downloaded content does not match its published SHA-256")


def download(url):
    if not url.startswith("https://"):
        raise ValueError("HTTPS is required for build inputs")
    with urllib.request.urlopen(url, timeout=90) as response:
        return response.read()


def prepare(inputs, directory):
    if (ROOT / "Dockerfile").read_text() != render():
        raise ValueError("Dockerfile differs from the reviewed upstream rendering")
    directory.mkdir(parents=True, exist_ok=True)
    (directory / "inputs.json").write_text(json.dumps(inputs, indent=2) + "\n")
    licenses = directory / "licenses"
    licenses.mkdir(exist_ok=True)
    for component in ["openssl", "rabbitmq"]:
        signature = inputs[component]["signature"]
        verify_checksum(download(signature["url"]), signature["sha256"])
    revision = inputs["rabbitmq"]["revision"]
    for name in ["LICENSE", "LICENSE-APACHE2", "LICENSE-MPL-RabbitMQ"]:
        (licenses / name).write_bytes(download(f"https://raw.githubusercontent.com/rabbitmq/rabbitmq-server/{revision}/{name}"))
    admin_revision = inputs["rabbitmqadmin"]["revision"]
    for name in ["LICENSE-MIT", "LICENSE-APACHE"]:
        (licenses / ("rabbitmqadmin-" + name)).write_bytes(download(f"https://raw.githubusercontent.com/rabbitmq/rabbitmqadmin-ng/{admin_revision}/{name}"))


def build_arguments(inputs, version, revision, cachebust):
    arguments = {
        "UBUNTU_BASE_IMAGE": "ubuntu@" + inputs["ubuntu_digest"],
        "CACHEBUST": cachebust,
        "OPENSSL_VERSION": inputs["openssl"]["version"],
        "OPENSSL_SOURCE_SHA256": inputs["openssl"]["sha256"],
        "OTP_VERSION": inputs["otp"]["version"],
        "OTP_SOURCE_SHA256": inputs["otp"]["sha256"],
        "RABBITMQ_VERSION": inputs["rabbitmq"]["version"],
        "RABBITMQ_SOURCE_SHA256": inputs["rabbitmq"]["sha256"],
        "OPENSSL_SIGNATURE_SHA256": inputs["openssl"]["signature"]["sha256"],
        "RABBITMQ_SIGNATURE_SHA256": inputs["rabbitmq"]["signature"]["sha256"],
    }
    labels = {
        "org.opencontainers.image.source": "https://github.com/carvvf/rabbitmq-docker",
        "org.opencontainers.image.version": version,
        "org.opencontainers.image.revision": revision,
        "io.github.carvvf.rabbitmq-docker.rabbitmq.version": inputs["rabbitmq"]["version"],
        "io.github.carvvf.rabbitmq-docker.inputs.sha256": fingerprint(inputs),
        "io.github.carvvf.rabbitmq-docker.recipe.revision": inputs["recipe_revision"],
        "io.github.carvvf.rabbitmq-docker.official.digest": inputs["official_digest"],
        "io.github.carvvf.rabbitmq-docker.ubuntu.digest": inputs["ubuntu_digest"],
    }
    for component in ["rabbitmq", "openssl", "otp"]:
        labels[f"io.github.carvvf.rabbitmq-docker.{component}.revision"] = inputs[component]["revision"]
        labels[f"io.github.carvvf.rabbitmq-docker.{component}.version"] = inputs[component]["version"]
    return [item for key, value in arguments.items() for item in ["--build-arg", f"{key}={value}"]] + [
        item for key, value in labels.items() for item in ["--label", f"{key}={value}"]]


def scan(image, report, trivy, archive=False):
    """Keep reports even when vulnerabilities block publication."""
    command = ["docker", "run", "--rm", "-e", "TRIVY_DISABLE_TELEMETRY=true",
               "-e", "TRIVY_SKIP_VERSION_CHECK=true", "-e", "TRIVY_USERNAME", "-e", "TRIVY_PASSWORD",
               "-v", f"{ROOT / '.cache/trivy'}:/root/.cache/trivy"]
    if archive:
        command += ["-v", f"{image}:/candidate.tar:ro"]
    command += [trivy, "image", "--format", "json", "--scanners", "vuln", "--pkg-types", "os,library",
                "--severity", "HIGH,CRITICAL", "--timeout", "60m", "--platform", "linux/amd64",
                "--db-repository", "ghcr.io/aquasecurity/trivy-db:2",
                "--db-repository", "mirror.gcr.io/aquasec/trivy-db:2"]
    command += ["--input", "/candidate.tar"] if archive else ["--image-src", "remote", image]
    with report.open("w") as output:
        subprocess.run(command, stdout=output, check=True)
    return scan_findings(json.loads(report.read_text()))


def scan_findings(result):
    if (result.get("SchemaVersion") != 2
            or result.get("Metadata", {}).get("OS", {}).get("Family") != "ubuntu"
            or not isinstance(result.get("Results"), list)
            or not any(row.get("Class") == "os-pkgs" and row.get("Type") == "ubuntu" for row in result["Results"])):
        raise ValueError("Expected a Trivy schema 2 image report with a detected Ubuntu package inventory")
    return any(v["Severity"] in {"HIGH", "CRITICAL"} for row in result["Results"] for v in row.get("Vulnerabilities", []) or [])


def reject_findings(found):
    if found:
        raise ValueError("HIGH/CRITICAL vulnerabilities block publication, including findings without a fix")


def copy_image(source, target, directory):
    command = ["docker", "run", "--rm", "-v", f"{directory}:/work", "-e", "REGISTRY_AUTH_FILE=/work/auth.json", SKOPEO,
               "copy", "--all", "--preserve-digests", "--retry-times", "5", source, target]
    run(*command)


def export_docker_archive(directory):
    """Create a fresh Docker archive; never expose an old or partial candidate."""
    target = directory / "candidate.tar"
    target.unlink(missing_ok=True)
    # The writable parent permits cleanup even when Skopeo creates root-owned files.
    with tempfile.TemporaryDirectory(prefix=".docker-archive-", dir=directory) as temporary:
        partial = Path(temporary) / "candidate.tar"
        destination = "/work/" + partial.relative_to(directory).as_posix()
        run("docker", "run", "--rm", "-v", f"{directory}:/work", SKOPEO, "copy",
            "--override-os", "linux", "--override-arch", "amd64", "--retry-times", "5",
            "oci-archive:/work/candidate.oci.tar", f"docker-archive:{destination}:{LOCAL_IMAGE}")
        partial.replace(target)


def verify_platform(reference, digest=None):
    if digest is not None and image_digest(reference) != digest:
        raise ValueError("Published index digest differs from the validated release")
    manifest = json.loads(run("docker", "buildx", "imagetools", "inspect", "--raw", reference, capture=True).stdout)
    platforms = [m["platform"] for m in manifest["manifests"] if m.get("platform", {}).get("os") != "unknown"]
    if len(platforms) != 1 or platforms[0].get("os") != "linux" or platforms[0].get("architecture") != "amd64":
        raise ValueError("The published image must contain exactly linux/amd64, excluding attestations")


def pipeline(mode, force=False):
    if mode != "check" and (
        os.environ.get("GITHUB_ACTIONS") != "true"
        or os.environ.get("GITHUB_REPOSITORY") != "carvvf/rabbitmq-docker"
        or os.environ.get("GITHUB_REF") != "refs/heads/master"
        or os.environ.get("GITHUB_EVENT_NAME") not in {"push", "schedule", "workflow_dispatch"}
    ):
        raise ValueError("Publication is restricted to trusted master workflows in carvvf/rabbitmq-docker")
    os.chdir(ROOT)
    directory = ROOT / "build"
    directory.mkdir(exist_ok=True)
    (ROOT / ".cache/trivy").mkdir(parents=True, exist_ok=True)
    inputs = resolve()
    prepare(inputs, directory)
    revision = run("git", "rev-parse", "HEAD", capture=True).stdout.strip()
    trivy_version = run("bash", "scripts/trivy/resolve-version.sh", capture=True).stdout.strip()
    trivy = f"aquasec/trivy:{trivy_version}"
    summary(f"Trivy: {trivy}; inputs: {fingerprint(inputs)}")
    run("docker", "pull", trivy)
    if mode == "auto":
        tags = package_tags()
        labels = None
        findings = False
        if "latest" in tags:
            active = IMAGE + "@" + image_digest(IMAGE + ":latest")
            run("docker", "pull", "--platform", "linux/amd64", active)
            labels = json.loads(run("docker", "image", "inspect", active, "--format", "{{json .Config.Labels}}", capture=True).stdout)
            findings = scan(active, directory / "trivy-active.json", trivy)
        if not needs_rebuild(inputs, labels, revision, findings=findings, force=force):
            summary("No rebuild required: active inputs, revision, and vulnerability scan are current.")
            return
    tags = package_tags() if mode != "check" else []
    version = next_version(inputs["rabbitmq"]["version"], tags) if mode != "check" else inputs["rabbitmq"]["version"] + "-check"
    cachebust = f"{os.environ.get('GITHUB_RUN_ID', time.time_ns())}-{os.environ.get('GITHUB_RUN_ATTEMPT', '1')}"
    command = ["docker", "buildx", "build", "--platform", "linux/amd64", "--pull", "--provenance=mode=max", "--sbom=true",
               "--tag", LOCAL_IMAGE, "--metadata-file", str(directory / "metadata.json"),
               "--output", f"type=oci,dest={directory / 'candidate.oci.tar'}"]
    if os.environ.get("GITHUB_ACTIONS") == "true":
        command += ["--cache-from", "type=gha,scope=rabbitmq-amd64", "--cache-to", "type=gha,mode=max,scope=rabbitmq-amd64"]
    run(*(command + build_arguments(inputs, version, revision, cachebust) + ["."]))
    export_evidence(directory / "candidate.oci.tar", directory)
    run("docker", "pull", SKOPEO)
    export_docker_archive(directory)
    reject_findings(scan(directory / "candidate.tar", directory / "trivy-candidate.json", trivy, archive=True))
    run("docker", "load", "--input", str(directory / "candidate.tar"))
    run("bash", "tests/test-image.sh", LOCAL_IMAGE, str(directory / "inputs.json"))
    run("docker", "run", "--rm", "-v", f"{directory}:/work", SKOPEO, "inspect", "oci-archive:/work/candidate.oci.tar", capture=True)
    if mode == "check":
        summary("Candidate passed scan and runtime tests; publication is disabled for this run.")
        return
    if version in package_tags():
        raise ValueError(f"Immutable release tag already exists: {version}")
    token = os.environ["GH_TOKEN"]
    auth = directory / "auth.json"
    try:
        run("docker", "run", "--rm", "-i", "-v", f"{directory}:/work", "-e", "REGISTRY_AUTH_FILE=/work/auth.json",
            SKOPEO, "login", "--username", os.environ.get("GITHUB_ACTOR", "carvvf"), "--password-stdin", "ghcr.io", input=token + "\n")
        release = IMAGE + ":" + version
        copy_image("oci-archive:/work/candidate.oci.tar", "docker://" + release, directory)
        verify_platform(release)
        metadata = json.loads((directory / "metadata.json").read_text())
        digest = metadata["containerimage.digest"]
        verify_platform(release, digest)
        immutable = IMAGE + "@" + digest
        reject_findings(scan(immutable, directory / "trivy-published.json", trivy))
        # Digest selection prevents a mutable tag race during promotion.
        copy_image("docker://" + immutable, "docker://" + IMAGE + ":latest", directory)
        verify_platform(IMAGE + ":latest", digest)
        summary(f"Published {release}@{digest}; latest points to the same validated OCI index.")
    finally:
        # Skopeo's container writes a root-owned credentials file. Remove it before artifacts upload.
        if auth.exists():
            run("docker", "run", "--rm", "-v", f"{directory}:/work", "--entrypoint", "rm", SKOPEO, "-f", "/work/auth.json")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=["check", "auto"])
    parser.add_argument("--force-rebuild", action="store_true")
    args = parser.parse_args()
    pipeline(args.mode, args.force_rebuild)


if __name__ == "__main__":
    try:
        main()
    except (ValueError, OSError, subprocess.CalledProcessError) as error:
        print(f"Pipeline failed: {error}", file=sys.stderr)
        raise SystemExit(1) from error
