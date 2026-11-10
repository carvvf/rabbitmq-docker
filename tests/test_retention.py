"""Offline policy regressions for destructive package and workflow retention."""

from datetime import datetime, timedelta, timezone
import io
import json
from pathlib import Path
import tempfile
import unittest
import urllib.error
from unittest.mock import patch

from tools import retention

NOW = datetime(2026, 11, 10, tzinfo=timezone.utc)


def version(number, tags=None, age=90):
    date = (NOW - timedelta(days=age) + timedelta(seconds=number)).isoformat()
    return dict(id=number, name=f"sha256:{number:064x}", created_at=date, updated_at=date,
                metadata={"container": {"tags": [f"4.4.0-custom.{number}"] if tags is None else tags}})


class RetentionPolicyTests(unittest.TestCase):
    def test_latest_and_ten_newest_custom_releases_are_protected(self):
        versions = [version(i) for i in range(1, 15)]
        versions[0]["metadata"]["container"]["tags"].append("latest")
        keep, delete = retention.plan_versions(versions, NOW, children=lambda digest: [])
        self.assertEqual({item["id"] for item in keep}, {1, *range(5, 15)})
        self.assertEqual({item["id"] for item in delete}, {2, 3, 4})

    def test_recent_versions_and_uncertain_timestamps_are_kept(self):
        recent = version(100, [], age=10)
        boundary = version(101, [], age=60)
        unknown = version(102, [])
        unknown["updated_at"] = "invalid"
        keep, delete = retention.plan_versions([recent, boundary, unknown], NOW, children=lambda digest: [])
        self.assertEqual(len(keep), 3)
        self.assertEqual(delete, [])

    def test_manifest_closure_retains_runtime_and_attestations(self):
        versions = [version(i) for i in range(1, 12)]
        runtime, attestation, orphan = version(100, []), version(101, []), version(102, [])
        graph = {versions[-1]["name"]: [runtime["name"], attestation["name"]]}
        keep, delete = retention.plan_versions(versions + [runtime, attestation, orphan], NOW,
                                               children=lambda digest: graph.get(digest, []))
        self.assertTrue({100, 101} <= {item["id"] for item in keep})
        self.assertEqual({item["id"] for item in delete}, {1, 102})
        self.assertEqual(delete[0]["id"], 1)

    def test_unknown_tags_are_protected(self):
        keep, delete = retention.plan_versions([version(1, ["operator-pinned"])], NOW, children=lambda digest: [])
        self.assertEqual(keep[0]["retention_reason"], "other-protected-tag")
        self.assertEqual(delete, [])

    def test_nested_manifest_references_are_protected_transitively(self):
        root, nested, leaf = version(1), version(100, []), version(101, [])
        graph = {root["name"]: [nested["name"]], nested["name"]: [leaf["name"]]}
        keep, delete = retention.plan_versions([root, nested, leaf], NOW,
                                               children=lambda digest: graph.get(digest, []))
        self.assertEqual({item["id"] for item in keep}, {1, 100, 101})
        self.assertEqual(delete, [])

    def test_manifest_inspection_failure_cannot_return_a_deletion_plan(self):
        def unavailable(digest):
            raise OSError("Registry unavailable")
        with self.assertRaises(OSError):
            retention.plan_versions([version(1)], NOW, children=unavailable)

    def test_duplicate_identities_fail_before_deletion(self):
        with self.assertRaisesRegex(ValueError, "duplicate"):
            retention.plan_versions([version(1), version(1)], NOW, children=lambda digest: [])

    def test_runs_must_be_old_completed_and_not_current(self):
        runs = [dict(version(i, []), status="completed") for i in range(1, 5)]
        runs[1]["status"] = "in_progress"
        runs[2]["updated_at"] = NOW.isoformat()
        self.assertEqual([item["id"] for item in retention.plan_runs(runs, NOW, "4")], [1])

    def test_package_listing_does_not_accept_a_later_page_404_as_bootstrap(self):
        def pages(url):
            yield version(1)
            raise urllib.error.HTTPError(url, 404, "Not Found", {}, io.BytesIO(b"{}"))
        with patch.object(retention, "github_pages", side_effect=pages), patch.object(retention, "package_tags") as tags:
            with self.assertRaises(urllib.error.HTTPError):
                retention.list_versions()
            tags.assert_not_called()

    def test_workflow_runs_are_fully_paginated(self):
        pages = [({"workflow_runs": [{"id": 1}]}, '<https://api.github.com/page2>; rel="next"'),
                 ({"workflow_runs": [{"id": 2}]}, "")]
        with patch.object(retention, "request_json", side_effect=pages):
            self.assertEqual(retention.list_runs(), [{"id": 1}, {"id": 2}])


class RetentionExecutionTests(unittest.TestCase):
    def setUp(self):
        folder = tempfile.TemporaryDirectory()
        self.addCleanup(folder.cleanup)
        self.root = Path(folder.name)
        patches = [patch.object(retention, "ROOT", self.root), patch.object(retention, "summary"),
                   patch.dict(retention.os.environ, {"GITHUB_ACTIONS": "true", "GITHUB_REPOSITORY": "carvvf/rabbitmq-docker",
                                                     "GITHUB_REF": "refs/heads/master", "GITHUB_EVENT_NAME": "workflow_dispatch"})]
        for item in patches:
            item.start()
            self.addCleanup(item.stop)

    def test_dry_run_writes_evidence_without_deleting(self):
        with patch.object(retention, "list_versions", return_value=[]), patch.object(retention, "plan_versions", return_value=([], [version(1)])), patch.object(retention, "list_runs", return_value=[]), patch.object(retention, "delete_url") as delete:
            retention.cleanup(dry_run=True)
            delete.assert_not_called()
        plan = json.loads((self.root / "build/retention-plan.json").read_text())
        result = json.loads((self.root / "build/retention-result.json").read_text())
        self.assertTrue(plan["dry_run"])
        self.assertEqual(result["deleted_versions"], [])

    def test_metadata_change_stops_before_deleting_dependent_manifests(self):
        parent, child = version(1), version(2, [])
        changed = version(1, ["latest"])
        with patch.object(retention, "list_versions", return_value=[]), patch.object(retention, "plan_versions", return_value=([], [parent, child])), patch.object(retention, "list_runs", return_value=[]), patch.object(retention, "request_json", return_value=(changed, "")), patch.object(retention, "delete_url") as delete:
            with self.assertRaisesRegex(ValueError, "replan"):
                retention.cleanup()
            delete.assert_not_called()

    def test_api_permission_failure_is_not_a_successful_cleanup(self):
        error = urllib.error.HTTPError(retention.PACKAGE_URL, 403, "Denied", {}, io.BytesIO(b"{}"))
        with patch.object(retention, "list_versions", side_effect=error), patch.object(retention, "delete_url") as delete:
            with self.assertRaises(urllib.error.HTTPError):
                retention.cleanup()
            delete.assert_not_called()

    def test_confirmed_deletions_are_recorded_in_result(self):
        expired = version(1, [])
        run = dict(version(2, []), status="completed")
        with patch.object(retention, "list_versions", return_value=[]), patch.object(retention, "plan_versions", return_value=([], [expired])), patch.object(retention, "list_runs", return_value=[run]), patch.object(retention, "request_json", side_effect=[(expired, ""), (run, "")]), patch.object(retention, "delete_url") as delete:
            retention.cleanup()
            self.assertEqual(delete.call_args_list, [
                unittest.mock.call(retention.PACKAGE_URL + "/1"),
                unittest.mock.call(retention.RUNS_URL + "/2"),
            ])
        result = json.loads((self.root / "build/retention-result.json").read_text())
        self.assertEqual(result["deleted_versions"], [1])
        self.assertEqual(result["deleted_runs"], [2])

    def test_deletion_failure_records_partial_result_and_stops(self):
        first, second = version(1, []), version(2, [])
        error = urllib.error.HTTPError(retention.PACKAGE_URL, 403, "Denied", {}, io.BytesIO(b"{}"))
        with patch.object(retention, "list_versions", return_value=[]), patch.object(retention, "plan_versions", return_value=([], [first, second])), patch.object(retention, "list_runs", return_value=[]), patch.object(retention, "request_json", side_effect=[(first, ""), (second, "")]), patch.object(retention, "delete_url", side_effect=[None, error]):
            with self.assertRaises(urllib.error.HTTPError):
                retention.cleanup()
        result = json.loads((self.root / "build/retention-result.json").read_text())
        self.assertEqual(result["deleted_versions"], [1])

    def test_untrusted_branch_cannot_start_cleanup(self):
        with patch.dict(retention.os.environ, {"GITHUB_REF": "refs/heads/feature"}), patch.object(retention, "list_versions") as listing:
            with self.assertRaisesRegex(ValueError, "trusted master"):
                retention.cleanup()
            listing.assert_not_called()


if __name__ == "__main__":
    unittest.main()
