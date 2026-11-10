"""Resolve verified release inputs shared by local builds and CI."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
from functools import lru_cache
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import urllib.error
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
PRODUCER_VERSION = "0.1.0"
LINES = {
    "rabbitmq": ("rabbitmq/rabbitmq-server", "v", (4, 4), (4, 4, 0)),
    "openssl": ("openssl/openssl", "openssl-", (3, 5), (3, 5, 9)),
    "otp": ("erlang/otp", "OTP-", (29, 1), (29, 1, 2)),
}


@lru_cache(maxsize=1)
def cli_github_token():
    """Read existing CLI credentials once, without exposing them in logs or files."""
    try:
        result = subprocess.run(
            ["gh", "auth", "token", "--hostname", "github.com"],
            capture_output=True, text=True, check=False, timeout=15,
        )
    except FileNotFoundError:
        return None
    if result.returncode != 0:
        return None
    return result.stdout.strip() or None


def github_authentication():
    for name in ["GH_TOKEN", "GITHUB_TOKEN"]:
        if token := os.environ.get(name):
            return token, name
    token = cli_github_token()
    return token, "GitHub CLI" if token else "anonymous"


def request_json(url):
    headers = {"Accept": "application/vnd.github+json", "User-Agent": "rabbitmq-docker"}
    source = "anonymous"
    if url.startswith("https://api.github.com/"):
        token, source = github_authentication()
        if token:
            headers["Authorization"] = f"Bearer {token}"
    try:
        with urllib.request.urlopen(urllib.request.Request(url, headers=headers), timeout=60) as response:
            return json.load(response), response.headers.get("Link", "")
    except urllib.error.HTTPError as error:
        if error.code in {403, 429}:
            body = error.read().decode("utf-8", errors="replace")
            if (error.headers.get("X-RateLimit-Remaining") == "0"
                    or error.headers.get("Retry-After")
                    or "rate limit" in body.lower()):
                reset = error.headers.get("X-RateLimit-Reset", "")
                reset_time = datetime.fromtimestamp(int(reset), timezone.utc).isoformat() if reset.isdigit() else "not provided"
                retry = error.headers.get("Retry-After", "not provided")
                guidance = ("Set GH_TOKEN/GITHUB_TOKEN or authenticate with gh auth login --hostname github.com."
                            if source == "anonymous" else "Wait for the indicated reset before retrying.")
                raise ValueError(
                    f"GitHub API rate limit exceeded (authentication: {source}; "
                    f"reset UTC: {reset_time}; retry-after seconds: {retry}). {guidance}"
                ) from error
        raise


def github_pages(url, request=request_json):
    """Read every page; errors must propagate rather than returning partial results."""
    while url:
        if not url.startswith("https://api.github.com/"):
            raise ValueError("Unexpected GitHub pagination URL")
        page, links = request(url)
        yield from page
        match = re.search(r'<([^>]+)>; rel="next"', links)
        url = match[1] if match else ""


def release_version(release, prefix, series, floor):
    if release.get("draft") or release.get("prerelease"):
        return None
    match = re.fullmatch(re.escape(prefix) + r"([0-9]+\.[0-9]+\.[0-9]+(?:\.[0-9]+)?)", release["tag_name"])
    if not match:
        return None
    parts = tuple(map(int, match[1].split(".")))
    if len(parts) != 3 and prefix != "OTP-":
        return None
    return parts if parts[:2] == series and parts >= floor else None


def select_release(releases, prefix, series, floor):
    candidates = [(v, item) for item in releases if (v := release_version(item, prefix, series, floor))]
    if not candidates:
        raise ValueError(f"No stable release at or above {floor} in series {series}")
    return max(candidates, key=lambda pair: pair[0])[1]


def asset(release, name):
    matches = [a for a in release["assets"] if a["name"] == name]
    if len(matches) != 1 or not re.fullmatch(r"sha256:[0-9a-f]{64}", matches[0].get("digest") or ""):
        raise ValueError(f"A published SHA-256 digest is required for {name}")
    result = matches[0]
    url = result["browser_download_url"]
    if not url.startswith("https://github.com/"):
        raise ValueError("Unexpected release asset URL")
    return {"url": url, "sha256": result["digest"].removeprefix("sha256:")}


def image_digest(reference):
    output = subprocess.check_output(["docker", "buildx", "imagetools", "inspect", reference], text=True)
    match = re.search(r"^Digest:\s+(sha256:[0-9a-f]{64})\s*$", output, re.M)
    if not match:
        raise ValueError(f"Cannot resolve image digest: {reference}")
    return match[1]


def verify_recipe():
    lock = json.loads((ROOT / "upstream.json").read_text())
    if lock.get("schema_version") != 1:
        raise ValueError("Unsupported recipe schema; supported schema versions: 1")
    for name, digest in lock["files"].items():
        actual = hashlib.sha256((ROOT / "vendor/docker-library-rabbitmq" / name).read_bytes()).hexdigest()
        if actual != digest:
            raise ValueError(f"Vendored recipe checksum mismatch: {name}")
    return lock


def resolve():
    lock = verify_recipe()
    result = {"schema_version": 1, "producer_version": PRODUCER_VERSION, "recipe_revision": lock["revision"], "platform": "linux/amd64"}
    for component, (repo, prefix, series, floor) in LINES.items():
        releases = github_pages(f"https://api.github.com/repos/{repo}/releases?per_page=100")
        release = select_release(releases, prefix, series, floor)
        version = release["tag_name"].removeprefix(prefix)
        filename = {
            "rabbitmq": f"rabbitmq-server-generic-unix-latest-toolchain-{version}.tar.xz",
            "openssl": f"openssl-{version}.tar.gz",
            "otp": f"otp_src_{version}.tar.gz",
        }[component]
        data = asset(release, filename)
        expected_url = f"https://github.com/{repo}/releases/download/{release['tag_name']}/{filename}"
        if data["url"] != expected_url:
            raise ValueError("Release archive URL differs from the reviewed recipe's URL")
        if component != "otp":
            data["signature"] = asset(release, filename + ".asc")
        commit, _ = request_json(f"https://api.github.com/repos/{repo}/commits/{release['tag_name']}")
        if not re.fullmatch(r"[0-9a-f]{40}", commit["sha"]):
            raise ValueError("Invalid source revision")
        result[component] = dict(data, version=version, tag=release["tag_name"], revision=commit["sha"])
    result["ubuntu_digest"] = image_digest("ubuntu:26.04")
    result["official_digest"] = image_digest("rabbitmq:4.4-management")
    recipe_versions = json.loads((ROOT / "vendor/docker-library-rabbitmq/versions.json").read_text())["4.4"]
    admin_version = recipe_versions["rabbitmqadmin"]["version"]
    admin_commit, _ = request_json(f"https://api.github.com/repos/rabbitmq/rabbitmqadmin-ng/commits/v{admin_version}")
    if not re.fullmatch(r"[0-9a-f]{40}", admin_commit["sha"]):
        raise ValueError("Invalid rabbitmqadmin source revision")
    result["rabbitmqadmin"] = {
        "version": admin_version,
        "revision": admin_commit["sha"],
        **recipe_versions["rabbitmqadmin"]["arches"]["amd64"],
    }
    return result


def fingerprint(inputs):
    return hashlib.sha256(json.dumps(inputs, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def next_version(version, tags):
    pattern = re.compile(re.escape(version) + r"-custom\.([1-9][0-9]*)")
    numbers = [int(m[1]) for tag in tags if (m := pattern.fullmatch(tag))]
    return f"{version}-custom.{max(numbers, default=0) + 1}"


def needs_rebuild(inputs, active_labels, revision, findings=False, force=False):
    return (force or findings or active_labels is None
            or active_labels.get("io.github.carvvf.rabbitmq-docker.inputs.sha256") != fingerprint(inputs)
            or active_labels.get("org.opencontainers.image.revision") != revision)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    inputs = resolve()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(inputs, indent=2) + "\n")


if __name__ == "__main__":
    main()
