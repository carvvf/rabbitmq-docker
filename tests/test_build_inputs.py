"""Offline regression tests for release selection and publication safety."""

import hashlib
import io
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
import urllib.error
from unittest.mock import patch

from tools import build_inputs as inputs
from tools import pipeline
from tools import registry


def release(version, **extra):
    return dict(tag_name="v" + version, prerelease=False, draft=False, **extra)


class GitHubAuthenticationTests(unittest.TestCase):
    def setUp(self):
        inputs.cli_github_token.cache_clear()
        self.addCleanup(inputs.cli_github_token.cache_clear)

    def test_explicit_tokens_take_precedence_over_cli_credentials(self):
        with patch.dict(inputs.os.environ, {"GH_TOKEN": "first", "GITHUB_TOKEN": "second"}, clear=True), patch.object(inputs, "cli_github_token") as cli:
            self.assertEqual(inputs.github_authentication(), ("first", "GH_TOKEN"))
            cli.assert_not_called()
        with patch.dict(inputs.os.environ, {"GITHUB_TOKEN": "second"}, clear=True), patch.object(inputs, "cli_github_token") as cli:
            self.assertEqual(inputs.github_authentication(), ("second", "GITHUB_TOKEN"))
            cli.assert_not_called()

    def test_existing_cli_login_is_reused_once_per_process(self):
        result = subprocess.CompletedProcess([], 0, "cli-credential\n", "")
        with patch.dict(inputs.os.environ, {}, clear=True), patch.object(inputs.subprocess, "run", return_value=result) as command:
            self.assertEqual(inputs.github_authentication(), ("cli-credential", "GitHub CLI"))
            self.assertEqual(inputs.github_authentication(), ("cli-credential", "GitHub CLI"))
            self.assertEqual(command.call_count, 1)

    def test_unavailable_cli_allows_anonymous_public_requests(self):
        with patch.dict(inputs.os.environ, {}, clear=True), patch.object(inputs.subprocess, "run", side_effect=FileNotFoundError):
            self.assertEqual(inputs.github_authentication(), (None, "anonymous"))

    def test_credentials_are_sent_only_to_the_github_api(self):
        for url, expected in [("https://api.github.com/repos/example/repo", "Bearer credential"),
                              ("https://example.com/data", None)]:
            with self.subTest(url=url):
                response = io.StringIO('{"ok": true}')
                response.headers = {}
                with patch.object(inputs, "github_authentication", return_value=("credential", "GitHub CLI")), patch.object(inputs.urllib.request, "urlopen", return_value=response) as request:
                    self.assertEqual(inputs.request_json(url)[0], {"ok": True})
                    self.assertEqual(request.call_args.args[0].get_header("Authorization"), expected)

    def test_rate_limit_error_reports_reset_without_exposing_credentials(self):
        error = urllib.error.HTTPError("https://api.github.com/repos/example/repo", 403, "Forbidden",
                                      {"X-RateLimit-Remaining": "0", "X-RateLimit-Reset": "1794246621"},
                                      io.BytesIO(b'{"message":"API rate limit exceeded"}'))
        with patch.object(inputs, "github_authentication", return_value=("secret-credential", "GitHub CLI")), patch.object(inputs.urllib.request, "urlopen", side_effect=error):
            with self.assertRaisesRegex(ValueError, "GitHub CLI.*reset UTC") as failure:
                inputs.request_json("https://api.github.com/repos/example/repo")
            self.assertNotIn("secret-credential", str(failure.exception))


class RegistryTagTests(unittest.TestCase):
    def test_token_exchange_requests_pull_scope_for_this_package(self):
        with patch.object(registry, "github_authentication", return_value=("workflow-credential", "GH_TOKEN")), patch.dict(registry.os.environ, {"GITHUB_ACTOR": "publisher"}), patch.object(registry, "registry_json", return_value=({"token": "registry-token"}, "")) as request:
            self.assertEqual(registry.registry_token(), "registry-token")
            url, authorization = request.call_args.args
            self.assertEqual(registry.urllib.parse.parse_qs(registry.urllib.parse.urlsplit(url).query),
                             {"service": ["ghcr.io"], "scope": ["repository:carvvf/rabbitmq-docker:pull"]})
            self.assertTrue(authorization.startswith("Basic "))

    def test_missing_token_cannot_start_anonymous_bootstrap(self):
        with patch.object(registry, "github_authentication", return_value=(None, "anonymous")), patch.object(registry, "registry_json") as request:
            with self.assertRaisesRegex(ValueError, "Authenticated GHCR access"):
                registry.package_tags()
            request.assert_not_called()

    def test_authenticated_unknown_name_is_bootstrap(self):
        error = urllib.error.HTTPError("https://ghcr.io", 404, "Not Found", {},
                                      io.BytesIO(b'{"errors":[{"code":"NAME_UNKNOWN"}]}'))
        with patch.object(registry, "registry_token", return_value="token"), patch.object(registry, "registry_json", side_effect=error):
            self.assertEqual(registry.package_tags(), [])

    def test_denied_or_generic_not_found_cannot_become_bootstrap(self):
        for status, code in [(401, "UNAUTHORIZED"), (403, "DENIED"), (404, "DENIED"), (404, "UNKNOWN")]:
            error = urllib.error.HTTPError("https://ghcr.io", status, "Denied", {},
                                          io.BytesIO(json.dumps({"errors": [{"code": code}]}).encode()))
            with self.subTest(status=status, code=code), patch.object(registry, "registry_token", return_value="token"), patch.object(registry, "registry_json", side_effect=error):
                with self.assertRaises(urllib.error.HTTPError):
                    registry.package_tags()

    def test_all_tag_pages_are_used_for_custom_numbering(self):
        pages = [({"name": registry.NAME, "tags": ["latest", "4.4.0-custom.2"]},
                  f'<{registry.TAGS_PATH}?n=100&last=4.4.0-custom.2>; rel="next"'),
                 ({"name": registry.NAME, "tags": ["4.4.0-custom.15"]}, "")]
        with patch.object(registry, "registry_token", return_value="token"), patch.object(registry, "registry_json", side_effect=pages) as request:
            tags = registry.package_tags()
            self.assertEqual(inputs.next_version("4.4.0", tags), "4.4.0-custom.16")
            self.assertEqual(request.call_count, 2)

    def test_later_page_failure_cannot_return_partial_tags(self):
        error = urllib.error.HTTPError("https://ghcr.io", 404, "Not Found", {},
                                      io.BytesIO(b'{"errors":[{"code":"NAME_UNKNOWN"}]}'))
        pages = [({"name": registry.NAME, "tags": ["4.4.0-custom.1"]},
                  f'<{registry.TAGS_PATH}?n=100&last=4.4.0-custom.1>; rel="next"'), error]
        with patch.object(registry, "registry_token", return_value="token"), patch.object(registry, "registry_json", side_effect=pages):
            with self.assertRaises(urllib.error.HTTPError):
                registry.package_tags()

    def test_pagination_cannot_send_credentials_to_another_host(self):
        page = ({"name": registry.NAME, "tags": []}, '<https://example.com/tags>; rel="next"')
        with patch.object(registry, "registry_token", return_value="token"), patch.object(registry, "registry_json", return_value=page) as request:
            with self.assertRaisesRegex(ValueError, "pagination URL"):
                registry.package_tags()
            self.assertEqual(request.call_count, 1)

    def test_existing_empty_package_is_not_an_error(self):
        with patch.object(registry, "registry_token", return_value="token"), patch.object(registry, "registry_json", return_value=({"name": registry.NAME, "tags": None}, "")):
            self.assertEqual(registry.package_tags(), [])


class ReleaseSelectionTests(unittest.TestCase):
    def test_numeric_selection_rejects_other_series_and_prereleases(self):
        versions = [release(v) for v in ["4.4.9", "4.4.10", "4.5.0", "4.4.11-rc.1", "4.3.99"]]
        versions += [dict(tag_name="v4.4.12", prerelease=True, draft=False)]
        self.assertEqual(inputs.select_release(versions, "v", (4, 4), (4, 4, 0))["tag_name"], "v4.4.10")

    def test_floor_and_missing_series_fail_closed(self):
        with self.assertRaisesRegex(ValueError, "No stable release"):
            inputs.select_release([release("4.4.0")], "v", (4, 4), (4, 4, 1))

    def test_otp_four_part_patch_versions_are_ordered_numerically(self):
        versions = [dict(tag_name=v) for v in ["OTP-29.1.2", "OTP-29.1.2.1", "OTP-29.2.0"]]
        self.assertEqual(inputs.select_release(versions, "OTP-", (29, 1), (29, 1, 2))["tag_name"], "OTP-29.1.2.1")

    def test_pagination_reads_every_page(self):
        calls = []
        def request(url):
            calls.append(url)
            if len(calls) == 1:
                return ["first"], '<https://api.github.com/page2>; rel="next"'
            return ["second"], ""
        self.assertEqual(list(inputs.github_pages("https://api.github.com/page1", request)), ["first", "second"])
        self.assertEqual(len(calls), 2)

    def test_failure_on_later_page_cannot_return_an_older_release(self):
        def request(url):
            if url.endswith("page1"):
                return [release("4.4.1")], '<https://api.github.com/page2>; rel="next"'
            raise OSError("Registry unavailable")
        with self.assertRaises(OSError):
            inputs.select_release(inputs.github_pages("https://api.github.com/page1", request), "v", (4, 4), (4, 4, 0))

    def test_missing_or_invalid_published_checksum_is_rejected(self):
        for digest in [None, "md5:abc", "sha256:bad"]:
            with self.subTest(digest=digest), self.assertRaises(ValueError):
                inputs.asset({"assets": [{"name": "source", "digest": digest}]}, "source")

    def test_corrupted_download_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "SHA-256"):
            pipeline.verify_checksum(b"corrupted", hashlib.sha256(b"original").hexdigest())

    def test_tag_numbering_uses_all_matching_releases(self):
        self.assertEqual(inputs.next_version("4.4.0", ["latest", "4.4.0-custom.2", "4.4.0-custom.11", "4.4.1-custom.99"]), "4.4.0-custom.12")


class RebuildTests(unittest.TestCase):
    def test_missing_scanner_inventory_cannot_be_treated_as_clean(self):
        with self.assertRaisesRegex(ValueError, "Ubuntu package inventory"):
            pipeline.scan_findings({"SchemaVersion": 2, "Results": []})

    def test_unfixable_high_findings_still_block(self):
        report = {"SchemaVersion": 2, "Metadata": {"OS": {"Family": "ubuntu"}}, "Results": [
            {"Class": "os-pkgs", "Type": "ubuntu", "Vulnerabilities": [{"Severity": "HIGH", "FixedVersion": ""}]}]}
        self.assertTrue(pipeline.scan_findings(report))

    def test_current_clean_image_is_not_rebuilt(self):
        labels = {"io.github.carvvf.rabbitmq-docker.inputs.sha256": inputs.fingerprint({"input": 1}), "org.opencontainers.image.revision": "revision"}
        self.assertFalse(inputs.needs_rebuild({"input": 1}, labels, "revision"))
        for arguments in [dict(findings=True), dict(force=True)]:
            self.assertTrue(inputs.needs_rebuild({"input": 1}, labels, "revision", **arguments))
        self.assertTrue(inputs.needs_rebuild({"input": 2}, labels, "revision"))
        self.assertTrue(inputs.needs_rebuild({"input": 1}, labels, "new-revision"))
        self.assertTrue(inputs.needs_rebuild({"input": 1}, None, "revision"))


class PublicationTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.value = {"rabbitmq": {"version": "4.4.0"}}
        self.commands = []
        def run(*args, **kwargs):
            self.commands.append(args)
            if args[:3] == ("git", "rev-parse", "HEAD"):
                return subprocess.CompletedProcess(args, 0, "revision\n")
            return subprocess.CompletedProcess(args, 0, "0.76.1\n")
        patches = [patch.object(pipeline, "ROOT", self.root), patch.object(pipeline, "resolve", return_value=self.value),
                   patch.dict(pipeline.os.environ, {"GITHUB_ACTIONS": "true", "GITHUB_REPOSITORY": "carvvf/rabbitmq-docker", "GITHUB_REF": "refs/heads/master", "GITHUB_EVENT_NAME": "push"}),
                   patch.object(pipeline, "prepare"), patch.object(pipeline, "build_arguments", return_value=[]),
                   patch.object(pipeline, "export_evidence"), patch.object(pipeline, "export_docker_archive"),
                   patch.object(pipeline, "run", side_effect=run),
                   patch.object(pipeline.os, "chdir"), patch.object(pipeline, "summary")]
        for item in patches:
            item.start()
            self.addCleanup(item.stop)

    def test_failed_candidate_scan_cannot_publish_or_run_runtime(self):
        with patch.object(pipeline, "package_tags", return_value=[]), patch.object(pipeline, "scan", return_value=True), patch.object(pipeline, "copy_image") as promote:
            with self.assertRaisesRegex(ValueError, "HIGH/CRITICAL"):
                pipeline.pipeline("auto", force=True)
            promote.assert_not_called()
        self.assertFalse(any(command[:2] == ("bash", "tests/test-image.sh") for command in self.commands))

    def test_feature_branch_cannot_enter_the_publication_path(self):
        with patch.dict(pipeline.os.environ, {"GITHUB_REF": "refs/heads/feature"}):
            with self.assertRaisesRegex(ValueError, "trusted master"):
                pipeline.pipeline("auto", force=True)
        self.assertEqual(self.commands, [])

    def test_runtime_failure_prevents_publication(self):
        original = pipeline.run.side_effect
        def fail_runtime(*args, **kwargs):
            if args[:2] == ("bash", "tests/test-image.sh"):
                raise subprocess.CalledProcessError(1, args)
            return original(*args, **kwargs)
        with patch.object(pipeline, "package_tags", return_value=[]), patch.object(pipeline, "scan", return_value=False), patch.object(pipeline.run, "side_effect", fail_runtime), patch.object(pipeline, "copy_image") as promote:
            with self.assertRaises(subprocess.CalledProcessError):
                pipeline.pipeline("auto", force=True)
            promote.assert_not_called()

    def test_release_collision_is_detected_before_publication(self):
        with patch.object(pipeline, "package_tags", side_effect=[[], [], ["4.4.0-custom.1"]]), patch.object(pipeline, "scan", return_value=False), patch.object(pipeline, "copy_image") as promote:
            with self.assertRaisesRegex(ValueError, "already exists"):
                pipeline.pipeline("auto", force=True)
            promote.assert_not_called()

    def test_failed_registry_scan_keeps_latest_untouched(self):
        (self.root / "build").mkdir()
        (self.root / "build/metadata.json").write_text(json.dumps({"containerimage.digest": "sha256:" + "a" * 64}))
        with patch.dict(pipeline.os.environ, {"GH_TOKEN": "test-token"}), patch.object(pipeline, "package_tags", return_value=[]), patch.object(pipeline, "scan", side_effect=[False, True]), patch.object(pipeline, "verify_platform"), patch.object(pipeline, "copy_image") as promote:
            with self.assertRaisesRegex(ValueError, "HIGH/CRITICAL"):
                pipeline.pipeline("auto", force=True)
            self.assertEqual(promote.call_count, 1)
            self.assertTrue(promote.call_args.args[1].endswith(":4.4.0-custom.1"))


class ArchiveExportTests(unittest.TestCase):
    def test_repeated_export_replaces_the_previous_archive(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            target = directory / "candidate.tar"
            target.write_bytes(b"previous image")
            destinations = []

            def copy(*args, **kwargs):
                self.assertFalse(target.exists())
                destination = directory / args[-1].split(":", 2)[1].removeprefix("/work/")
                self.assertFalse(destination.exists())
                destinations.append(destination)
                destination.write_bytes(b"new image")

            with patch.object(pipeline, "run", side_effect=copy):
                pipeline.export_docker_archive(directory)
                self.assertEqual(target.read_bytes(), b"new image")
                pipeline.export_docker_archive(directory)
            self.assertEqual(target.read_bytes(), b"new image")
            self.assertNotEqual(destinations[0], destinations[1])
            self.assertEqual(list(directory.iterdir()), [target])

    def test_failed_export_leaves_no_stale_or_partial_candidate(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            (directory / "candidate.tar").write_bytes(b"previous image")

            def fail(*args, **kwargs):
                destination = directory / args[-1].split(":", 2)[1].removeprefix("/work/")
                destination.write_bytes(b"partial image")
                raise subprocess.CalledProcessError(1, args)

            with patch.object(pipeline, "run", side_effect=fail):
                with self.assertRaises(subprocess.CalledProcessError):
                    pipeline.export_docker_archive(directory)
            self.assertEqual(list(directory.iterdir()), [])


if __name__ == "__main__":
    unittest.main()
