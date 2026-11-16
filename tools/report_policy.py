"""Apply the CI publication policy to complete Trivy JSON reports using the stdlib."""

import argparse
import json
import os
import sys
from dataclasses import dataclass
from pathlib import Path


class InvalidReport(ValueError):
    """A scan report cannot establish a valid publication decision."""


@dataclass(frozen=True)
class Finding:
    target: str
    vulnerability: str
    package: str
    installed: str
    severity: str
    fixed: str

    def describe(self):
        resolution = f"fixed in {self.fixed}" if self.fixed else "no fixed version listed by Trivy"
        return (
            f"{self.target}: {self.vulnerability} {self.severity} "
            f"{self.package} {self.installed}; {resolution}"
        )


def read_findings(path):
    """Reject missing, invalid or empty scan results instead of treating them as clean."""
    return parse_findings(json.loads(Path(path).read_text()), path)


def parse_findings(report, path="Trivy report"):
    """Validate a decoded report before making any publication decision."""
    if not isinstance(report, dict) or report.get("SchemaVersion") != 2:
        raise InvalidReport(f"{path}: expected a Trivy schema 2 report")
    results = report.get("Results")
    if not isinstance(results, list) or not results:
        raise InvalidReport(f"{path}: expected at least one analyzed target")
    findings = []
    for result in results:
        if (
            not isinstance(result, dict)
            or not isinstance(result.get("Target"), str)
            or not result["Target"].strip()
        ):
            raise InvalidReport(f"{path}: an analyzed target is missing its name")
        vulnerabilities = result.get("Vulnerabilities")
        if vulnerabilities is None:
            vulnerabilities = []
        if not isinstance(vulnerabilities, list):
            raise InvalidReport(f"{path}: invalid vulnerability list")
        for item in vulnerabilities:
            if not isinstance(item, dict) or not isinstance(item.get("Severity"), str):
                raise InvalidReport(f"{path}: invalid vulnerability severity")
            if item["Severity"] not in {
                "UNKNOWN",
                "LOW",
                "MEDIUM",
                "HIGH",
                "CRITICAL",
            }:
                raise InvalidReport(f"{path}: invalid vulnerability severity")
            if item["Severity"] not in {"HIGH", "CRITICAL"}:
                continue
            for field in ("VulnerabilityID", "PkgName", "InstalledVersion"):
                if not isinstance(item.get(field), str) or not item[field].strip():
                    raise InvalidReport(f"{path}: vulnerability is missing {field}")
            fixed = item.get("FixedVersion")
            if fixed is None:
                fixed = ""
            if not isinstance(fixed, str):
                raise InvalidReport(f"{path}: invalid fixed version")
            if item.get("Status") == "fixed" and not fixed.strip():
                raise InvalidReport(f"{path}: fixed vulnerability is missing its fixed version")
            findings.append(
                Finding(
                    result["Target"],
                    item["VulnerabilityID"],
                    item["PkgName"],
                    item["InstalledVersion"],
                    item["Severity"],
                    fixed.strip(),
                )
            )
    return findings


def annotation(level, message):
    if os.environ.get("GITHUB_ACTIONS") == "true":
        escaped = message.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")
        print(f"::{level} title=Vulnerability publication policy::{escaped}")
    else:
        print(f"{level.upper()}: {message}")


def evaluate(paths, context, observe=False):
    """Inspect every supplied report before deciding whether publication is allowed."""
    findings = [finding for path in paths for finding in read_findings(path)]
    return evaluate_findings(findings, context, observe)


def evaluate_findings(findings, context, observe=False):
    """Render and gate validated findings for CLI and pipeline callers alike."""
    fixable = [finding for finding in findings if finding.fixed]
    unfixed = [finding for finding in findings if not finding.fixed]
    message = (
        f"{context}: {len(fixable)} fixable HIGH/CRITICAL findings; "
        f"{len(unfixed)} without a fixed version listed by Trivy."
    )
    print(message)
    for finding in findings:
        # Indentation prevents report text from being interpreted as a workflow command.
        for line in finding.describe().splitlines():
            print(f"  {line}")
    if summary := os.environ.get("GITHUB_STEP_SUMMARY"):
        with Path(summary).open("a") as stream:
            stream.write("\n" + message.replace("\n", " ").replace("\r", " ") + "\n\n")
            for finding in findings:
                line = finding.describe().replace("\n", " ").replace("\r", " ")
                stream.write(f"    {line}\n")
    if output := os.environ.get("GITHUB_OUTPUT"):
        with Path(output).open("a") as stream:
            stream.write(f"fixable_count={len(fixable)}\nunfixed_count={len(unfixed)}\n")
            stream.write(f"has_findings={str(bool(findings)).lower()}\n")
    if observe:
        # Initial findings trigger remediation; only the candidate/final scan decides the gate.
        return 0
    if fixable:
        annotation(
            "error",
            f"{context}: publication blocked by {len(fixable)} fixable HIGH/CRITICAL findings.",
        )
        return 1
    for finding in unfixed:
        annotation("warning", f"{context}: publication allowed; {finding.describe()}.")
    return 0


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("reports", nargs="+", type=Path)
    parser.add_argument("--context", default="Trivy scan")
    parser.add_argument(
        "--observe",
        action="store_true",
        help="Validate an initial scan without deciding publication",
    )
    args = parser.parse_args(argv)
    try:
        return evaluate(args.reports, args.context, args.observe)
    except (OSError, ValueError) as error:
        annotation("error", f"{args.context}: cannot evaluate scan evidence: {error}")
        return 2


if __name__ == "__main__":
    sys.exit(main())
