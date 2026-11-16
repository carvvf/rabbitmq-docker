"""Offline regression cases for CI publication decisions and GitHub annotations."""

import json
import os
import unittest
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from tools import report_policy


def finding(fixed="", severity="HIGH"):
    return {
        "VulnerabilityID": "CVE-2026-12345",
        "PkgName": "example",
        "InstalledVersion": "1.0",
        "Severity": severity,
        "FixedVersion": fixed,
    }


def report(*findings):
    return {
        "SchemaVersion": 2,
        "Results": [{"Target": "image (ubuntu)", "Vulnerabilities": list(findings)}],
    }


class ReportPolicyTests(unittest.TestCase):
    def run_policy(self, reports, *, observe=False):
        with TemporaryDirectory() as directory:
            root = Path(directory)
            paths = []
            for number, data in enumerate(reports):
                path = root / f"report-{number}.json"
                path.write_text(json.dumps(data))
                paths.append(str(path))
            env = {
                "GITHUB_ACTIONS": "true",
                "GITHUB_STEP_SUMMARY": str(root / "summary"),
                "GITHUB_OUTPUT": str(root / "output"),
            }
            stdout = StringIO()
            with patch.dict(os.environ, env, clear=True), redirect_stdout(stdout):
                status = report_policy.main([*paths, *(["--observe"] if observe else [])])
            summary = (root / "summary").read_text() if (root / "summary").exists() else ""
            return status, stdout.getvalue(), summary

    def test_clean_candidate_succeeds_without_warning(self):
        status, output, _ = self.run_policy([report()])
        self.assertEqual(status, 0)
        self.assertNotIn("::warning", output)

    def test_unfixed_candidate_succeeds_with_explanatory_warning_and_summary(self):
        status, output, summary = self.run_policy([report(finding())])
        self.assertEqual(status, 0)
        self.assertIn("::warning", output)
        self.assertIn("CVE-2026-12345", output)
        self.assertIn("no fixed version listed by Trivy", summary)

    def test_fixed_version_blocks_even_when_other_findings_have_no_fix(self):
        status, output, summary = self.run_policy([report(finding(), finding("1.1"))])
        self.assertEqual(status, 1)
        self.assertIn("::error", output)
        self.assertNotIn("::warning", output)
        self.assertIn("fixed in 1.1", summary)

    def test_fixable_finding_on_second_architecture_blocks_publication(self):
        status, _, _ = self.run_policy([report(), report(finding("1.1"))])
        self.assertEqual(status, 1)

    def test_lower_severities_do_not_change_high_critical_gate(self):
        status, output, _ = self.run_policy([report(finding("1.1", "MEDIUM"))])
        self.assertEqual(status, 0)
        self.assertNotIn("::warning", output)

    def test_initial_scan_does_not_warn_before_remediation(self):
        for value in ("", "1.1"):
            with self.subTest(fixed=value):
                status, output, _ = self.run_policy([report(finding(value))], observe=True)
                self.assertEqual(status, 0)
                self.assertNotIn("::warning", output)
                self.assertNotIn("::error", output)

    def test_invalid_scan_evidence_is_an_error_including_in_observe_mode(self):
        contradictory = finding()
        contradictory["Status"] = "fixed"
        for data in (
            {},
            {"SchemaVersion": 2, "Results": []},
            report({"Severity": "HIGH"}),
            report(finding(severity=[])),
            report(finding(fixed=False)),
            report(contradictory),
        ):
            for observe in (False, True):
                with self.subTest(data=data, observe=observe):
                    status, output, _ = self.run_policy([data], observe=observe)
                    self.assertEqual(status, 2)
                    self.assertIn("cannot evaluate scan evidence", output)

    def test_missing_report_is_an_error(self):
        with TemporaryDirectory() as directory, redirect_stdout(StringIO()):
            status = report_policy.main([str(Path(directory) / "missing.json")])
        self.assertEqual(status, 2)

    def test_truncated_scanner_output_is_an_error(self):
        with TemporaryDirectory() as directory, redirect_stdout(StringIO()):
            path = Path(directory) / "truncated.json"
            path.write_text('{"SchemaVersion": 2, "Results":')
            status = report_policy.main([str(path)])
        self.assertEqual(status, 2)

    def test_warning_payload_cannot_inject_another_annotation(self):
        item = finding()
        item["PkgName"] = "example\n::error::injected"
        status, output, _ = self.run_policy([report(item)])
        self.assertEqual(status, 0)
        self.assertNotIn("\n::error", output)
        self.assertIn("%0A::error", output)


if __name__ == "__main__":
    unittest.main()
