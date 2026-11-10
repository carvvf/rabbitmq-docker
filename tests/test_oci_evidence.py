"""Exercise attestation retention and checksum validation without Docker."""

import hashlib
import io
import json
from pathlib import Path
import tarfile
import tempfile
import unittest

from tools.oci_evidence import export_evidence


class EvidenceTests(unittest.TestCase):
    def make_archive(self, root, corrupted=False, include_sbom=True):
        entries = {}

        def blob(document, media):
            data = json.dumps(document).encode()
            digest = hashlib.sha256(data).hexdigest()
            entries[f"blobs/sha256/{digest}"] = data
            return dict(digest="sha256:" + digest, size=len(data), mediaType=media)

        layers = [blob(dict(predicateType="https://slsa.dev/provenance/v1", predicate={"buildDefinition": {}}), "application/vnd.in-toto+json")]
        if include_sbom:
            layers.append(blob(dict(predicateType="https://spdx.dev/Document", predicate={"spdxVersion": "SPDX-2.3"}), "application/vnd.in-toto+json"))
        manifest = blob(dict(layers=layers), "application/vnd.oci.image.manifest.v1+json")
        entries["index.json"] = json.dumps(dict(manifests=[manifest])).encode()
        if corrupted:
            entries["blobs/sha256/" + layers[0]["digest"].split(":")[1]] = b"corrupted"
        archive = root / "candidate.tar"
        with tarfile.open(archive, "w") as target:
            for name, data in entries.items():
                info = tarfile.TarInfo(name)
                info.size = len(data)
                target.addfile(info, io.BytesIO(data))
        return archive

    def test_original_attestation_statements_are_retained(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            export_evidence(self.make_archive(root), root)
            sbom = json.loads((root / "sbom.json").read_text())
            self.assertEqual(sbom[0]["predicate"]["spdxVersion"], "SPDX-2.3")
            self.assertTrue((root / "provenance.json").exists())

    def test_corrupted_attestation_stops_the_pipeline(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            with self.assertRaisesRegex(ValueError, "checksum"):
                export_evidence(self.make_archive(root, corrupted=True), root)

    def test_missing_sbom_cannot_be_claimed_as_evidence(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            with self.assertRaisesRegex(ValueError, "both SBOM and provenance"):
                export_evidence(self.make_archive(root, include_sbom=False), root)
