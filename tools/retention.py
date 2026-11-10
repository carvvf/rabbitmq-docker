"""Retain recent releases, rollback images and their OCI manifests before cleanup."""

from __future__ import annotations

import argparse
from datetime import datetime, timedelta, timezone
import json
import os
import re
import subprocess
import sys
import urllib.error
import urllib.request

from .build_inputs import ROOT, PRODUCER_VERSION, github_authentication, github_pages, request_json
from .pipeline import IMAGE, run, summary
from .registry import package_tags

PACKAGE_URL = "https://api.github.com/users/carvvf/packages/container/rabbitmq-docker/versions"
RUNS_URL = "https://api.github.com/repos/carvvf/rabbitmq-docker/actions/runs"
CUSTOM = re.compile(r"[0-9]+\.[0-9]+\.[0-9]+-custom\.[1-9][0-9]*")
DIGEST = re.compile(r"sha256:[0-9a-f]{64}")
DAYS = 60
KEEP_CUSTOM = 10


def timestamp(value):
    if not isinstance(value, str):
        return None
    try:
        result = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return result if result.tzinfo is not None else None


def activity(item):
    values = [timestamp(item.get(key)) for key in ["created_at", "updated_at"]]
    return max(values) if all(values) else None


def manifest_children(digest):
    raw = run("docker", "buildx", "imagetools", "inspect", "--raw", IMAGE + "@" + digest, capture=True).stdout
    document = json.loads(raw)
    if document.get("schemaVersion") != 2:
        raise ValueError("Unsupported manifest schema during retention planning")
    if "manifests" in document:
        children = document["manifests"]
        if not isinstance(children, list) or any(not DIGEST.fullmatch(child.get("digest", "")) for child in children):
            raise ValueError("Invalid OCI index descriptors during retention planning")
        return [child["digest"] for child in children]
    if not isinstance(document.get("config"), dict) or not isinstance(document.get("layers"), list):
        raise ValueError("Invalid OCI image manifest during retention planning")
    return []


def version_tags(version):
    tags = version.get("metadata", {}).get("container", {}).get("tags")
    if not isinstance(tags, list) or not all(isinstance(tag, str) for tag in tags):
        raise ValueError("Invalid package-version tags")
    return tags


def plan_versions(versions, now, children=manifest_children):
    """Protect roots and their full manifest closure before identifying deletions."""
    by_digest = {}
    seen_ids = set()
    for item in versions:
        if (type(item.get("id")) is not int or item["id"] <= 0 or item["id"] in seen_ids
                or not DIGEST.fullmatch(item.get("name", "")) or item["name"] in by_digest):
            raise ValueError("Invalid or duplicate package version identity")
        version_tags(item)
        by_digest[item["name"]] = item
        seen_ids.add(item["id"])
    minimum = datetime.min.replace(tzinfo=timezone.utc)
    releases = [item for item in versions if any(CUSTOM.fullmatch(tag) for tag in version_tags(item))]
    releases.sort(key=lambda item: (timestamp(item.get("created_at")) or minimum, item["id"]), reverse=True)
    rollback = {item["id"] for item in releases[:KEEP_CUSTOM]}
    cutoff = now - timedelta(days=DAYS)
    reasons = {}
    for digest, item in by_digest.items():
        tags = version_tags(item)
        date = activity(item)
        if "latest" in tags:
            reasons[digest] = "latest"
        elif item["id"] in rollback:
            reasons[digest] = "rollback-release"
        elif date is None:
            reasons[digest] = "unknown-timestamp"
        elif date >= cutoff:
            reasons[digest] = "within-retention"
        elif any(not CUSTOM.fullmatch(tag) for tag in tags):
            reasons[digest] = "other-protected-tag"

    inspected = set()
    pending = list(reasons)
    while pending:
        digest = pending.pop()
        if digest in inspected:
            continue
        inspected.add(digest)
        for child in children(digest):
            if not DIGEST.fullmatch(child):
                raise ValueError("Invalid referenced manifest digest")
            reasons.setdefault(child, "referenced-by-kept-image")
            pending.append(child)
    keep = [dict(item, retention_reason=reasons[item["name"]]) for item in versions if item["name"] in reasons]
    delete = [item for item in versions if item["name"] not in reasons]
    # Remove expired tagged roots before their untagged child manifests.
    delete.sort(key=lambda item: (not bool(version_tags(item)), item["id"]))
    return keep, delete


def list_versions():
    result = []
    try:
        result.extend(github_pages(PACKAGE_URL + "?per_page=100"))
    except urllib.error.HTTPError as error:
        if error.code == 404 and not result and not package_tags():
            return []
        raise
    return result


def list_runs():
    def page(url):
        value, links = request_json(url)
        if not isinstance(value.get("workflow_runs"), list):
            raise ValueError("Invalid workflow-run listing")
        return value["workflow_runs"], links
    return list(github_pages(RUNS_URL + "?per_page=100", request=page))


def plan_runs(runs, now, current_run):
    cutoff = now - timedelta(days=DAYS)
    result = []
    for item in runs:
        if type(item.get("id")) is not int or item["id"] <= 0:
            raise ValueError("Invalid workflow run identity")
        date = activity(item)
        if (item.get("status") == "completed" and str(item["id"]) != current_run
                and date is not None and date < cutoff):
            result.append(item)
    return result


def delete_url(url):
    token, _ = github_authentication()
    if not token:
        raise ValueError("Authenticated GitHub access is required for retention deletion")
    request = urllib.request.Request(url, method="DELETE", headers={
        "Authorization": "Bearer " + token, "Accept": "application/vnd.github+json",
    })
    with urllib.request.urlopen(request, timeout=60) as response:
        if response.status != 204:
            raise ValueError("GitHub did not confirm retention deletion")


def cleanup(dry_run=False):
    if (os.environ.get("GITHUB_ACTIONS") != "true"
            or os.environ.get("GITHUB_REPOSITORY") != "carvvf/rabbitmq-docker"
            or os.environ.get("GITHUB_REF") != "refs/heads/master"
            or os.environ.get("GITHUB_EVENT_NAME") not in {"schedule", "workflow_dispatch"}):
        raise ValueError("Retention is restricted to trusted master workflows in carvvf/rabbitmq-docker")
    now = datetime.now(timezone.utc)
    versions = list_versions()
    keep, remove = plan_versions(versions, now)
    runs = plan_runs(list_runs(), now, os.environ.get("GITHUB_RUN_ID", ""))
    directory = ROOT / "build"
    directory.mkdir(exist_ok=True)
    plan = dict(schema_version=1, producer_version=PRODUCER_VERSION, dry_run=dry_run,
                generated_at=now.isoformat(), retention_days=DAYS, keep_custom_versions=KEEP_CUSTOM,
                kept_versions=keep, delete_versions=remove, delete_runs=runs)
    (directory / "retention-plan.json").write_text(json.dumps(plan, indent=2) + "\n")
    summary(f"Retention: {len(keep)} package versions kept; {len(remove)} expired versions; {len(runs)} completed runs; dry_run={dry_run}.")
    for item in keep:
        summary(f"KEEP package version {item['id']}: {item['retention_reason']}")
    result = dict(schema_version=1, producer_version=PRODUCER_VERSION, dry_run=dry_run,
                  deleted_versions=[], deleted_runs=[], skipped_versions=[], skipped_runs=[])
    try:
        for item in remove:
            summary(f"{'DRY-RUN' if dry_run else 'DELETE'} package version {item['id']} {item['name']}")
            if dry_run:
                continue
            current, _ = request_json(PACKAGE_URL + "/" + str(item["id"]))
            if current != item:
                result["skipped_versions"].append(item["id"])
                raise ValueError(f"Package version {item['id']} changed since planning; stop and replan before deleting dependent manifests")
            delete_url(PACKAGE_URL + "/" + str(item["id"]))
            result["deleted_versions"].append(item["id"])
        for item in runs:
            summary(f"{'DRY-RUN' if dry_run else 'DELETE'} completed workflow run {item['id']}")
            if dry_run:
                continue
            current, _ = request_json(RUNS_URL + "/" + str(item["id"]))
            if (current.get("status") != "completed" or activity(current) != activity(item)):
                result["skipped_runs"].append(item["id"])
                continue
            delete_url(RUNS_URL + "/" + str(item["id"]))
            result["deleted_runs"].append(item["id"])
    finally:
        (directory / "retention-result.json").write_text(json.dumps(result, indent=2) + "\n")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dry-run", action="store_true")
    arguments = parser.parse_args()
    try:
        cleanup(arguments.dry_run)
    except (ValueError, OSError, subprocess.CalledProcessError) as error:
        print(f"Retention failed: {error}", file=sys.stderr)
        raise SystemExit(1) from error
