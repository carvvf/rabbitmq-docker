"""Rescan an existing local candidate archive using the shared CI security gate."""

import argparse

from .build_inputs import ROOT
from .pipeline import reject_findings, run, scan, summary


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--archive", type=str, default="build/candidate.tar")
    args = parser.parse_args()
    archive = (ROOT / args.archive).resolve()
    if not archive.is_file():
        parser.error("Candidate archive not found; run the local build and qualification first")
    (ROOT / ".cache/trivy").mkdir(parents=True, exist_ok=True)
    report = ROOT / "build/trivy-local.json"
    report.parent.mkdir(parents=True, exist_ok=True)
    version = run("bash", str(ROOT / "scripts/trivy/resolve-version.sh"), capture=True).stdout.strip()
    scanner = f"aquasec/trivy:{version}"
    summary(f"Trivy: {scanner}; candidate: {archive}; report: {report}")
    run("docker", "pull", scanner)
    reject_findings(scan(archive, report, scanner, archive=True))
    summary("Candidate scan passed: no HIGH/CRITICAL findings in the detected inventory.")


if __name__ == "__main__":
    main()
