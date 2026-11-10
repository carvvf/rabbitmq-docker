"""Retain original BuildKit SBOM and provenance statements from the OCI candidate."""

import hashlib
import json
import tarfile


def export_evidence(archive, destination):
    statements = []
    with tarfile.open(archive, "r") as bundle:
        def read(name):
            source = bundle.extractfile(name)
            if source is None:
                raise ValueError(f"Missing OCI evidence entry: {name}")
            return source.read()

        visited = set()

        def visit(descriptor):
            digest = descriptor["digest"]
            algorithm, value = digest.split(":", 1)
            if algorithm != "sha256":
                raise ValueError("SHA-256 OCI descriptors are required")
            if digest in visited:
                return
            visited.add(digest)
            media = descriptor["mediaType"]
            if media.startswith(("application/vnd.oci.image.layer.", "application/vnd.docker.image.rootfs.")):
                return
            data = read(f"blobs/sha256/{value}")
            if hashlib.sha256(data).hexdigest() != value:
                raise ValueError("OCI evidence checksum mismatch")
            document = json.loads(data)
            if "predicateType" in document:
                statements.append(document)
            for key in ["manifests", "layers"]:
                for child in document.get(key, []):
                    visit(child)

        for descriptor in json.loads(read("index.json"))["manifests"]:
            visit(descriptor)
    sbom = [s for s in statements if "spdx.dev/Document" in s["predicateType"]]
    provenance = [s for s in statements if "slsa.dev/provenance" in s["predicateType"]]
    if not sbom or not provenance:
        raise ValueError("The OCI candidate must contain both SBOM and provenance attestations")
    for name, documents in [("sbom", sbom), ("provenance", provenance)]:
        (destination / f"{name}.json").write_text(json.dumps(documents, indent=2) + "\n")
