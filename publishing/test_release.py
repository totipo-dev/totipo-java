"""Credential-free failure-path tests; all network, signing and Git mutations are mocked."""
import contextlib
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import urllib.error

import release


class ReleaseTests(unittest.TestCase):
    def setUp(self):
        self.env = patch.dict(os.environ, {
            "REQUESTED_VERSION": "0.1.1", "REQUESTED_COMMIT": "a" * 40,
            "DISPATCH_REF": "refs/heads/main", "DISPATCH_SHA": "a" * 40,
            "GITHUB_RUN_ATTEMPT": "1", "GITHUB_RUN_ID": "123",
            "GITHUB_REPOSITORY": "totipo-org/totipo-java",
        }, clear=True)
        self.env.start()
        self.addCleanup(self.env.stop)
        self.output = contextlib.redirect_stdout(io.StringIO())
        self.output.__enter__()
        self.addCleanup(self.output.__exit__, None, None, None)

    def test_exact_inputs(self):
        self.assertEqual(release.inputs(), ("0.1.1", "a" * 40))

    def test_invalid_operator_inputs(self):
        for key, value in [("REQUESTED_VERSION", "0.1.1\n"), ("REQUESTED_VERSION", "$(id)"),
                           ("REQUESTED_VERSION", "0.1.1-SNAPSHOT"), ("REQUESTED_COMMIT", "a" * 39),
                           ("REQUESTED_COMMIT", "A" * 40), ("REQUESTED_COMMIT", "a" * 40 + "\n"),
                           ("DISPATCH_REF", "refs/heads/feature"), ("DISPATCH_SHA", "b" * 40)]:
            with self.subTest(key=key, value=value), patch.dict(os.environ, {key: value}):
                with self.assertRaises(RuntimeError):
                    release.inputs()

    def test_existing_initial_version_never_uploads(self):
        for statuses in [(200, 200), (200, 404), (404, 200)]:
            with self.subTest(statuses=statuses), patch.object(release, "request", side_effect=[(s, b"") for s in statuses]):
                with self.assertRaisesRegex(RuntimeError, "already exists"):
                    release.central_state()

    def test_absence_requires_two_404s(self):
        with patch.object(release, "request", return_value=(404, b"")):
            self.assertEqual(release.central_state(), "publish")
        with patch.object(release, "request", side_effect=RuntimeError("Network failure")):
            with self.assertRaises(RuntimeError):
                release.central_state()

    def test_same_run_partial_success_skips_upload(self):
        with patch.object(release, "prior_upload", return_value=True), patch.object(release, "request", side_effect=[(200, b""), (404, b"")]):
            self.assertEqual(release.central_state(), "verify")

    def test_ambiguous_upload_and_absence_never_reuploads(self):
        with patch.object(release, "prior_upload", return_value=True), patch.object(release, "request", return_value=(404, b"")):
            with self.assertRaisesRegex(RuntimeError, "Do not upload again"):
                release.central_state()

    def test_history_is_bound_to_same_run_and_commit(self):
        os.environ["GITHUB_RUN_ATTEMPT"] = "2"
        job = {"name": "publish-central", "head_sha": "a" * 40,
               "steps": [{"name": release.UPLOAD_STEP, "started_at": "now", "conclusion": "failure"}]}
        with patch.object(release, "request", return_value=(200, json.dumps({"jobs": [job]}).encode())) as request:
            self.assertTrue(release.prior_upload())
            self.assertIn("/runs/123/attempts/1/jobs?", request.call_args.args[0])
        job["steps"][0]["conclusion"] = "skipped"
        with patch.object(release, "request", return_value=(200, json.dumps({"jobs": [job]}).encode())):
            self.assertFalse(release.prior_upload())
        job["head_sha"] = "b" * 40
        with patch.object(release, "request", return_value=(200, json.dumps({"jobs": [job]}).encode())):
            with self.assertRaisesRegex(RuntimeError, "commit differs"):
                release.prior_upload()

    def test_http_only_404_means_absent(self):
        for status in (401, 403, 429, 500, 503):
            error = urllib.error.HTTPError("https://example.com", status, "test", {}, None)
            with self.subTest(status=status), patch.object(release.urllib.request, "urlopen", side_effect=error):
                with self.assertRaises(RuntimeError):
                    release.request("https://example.com")
        error = urllib.error.HTTPError("https://example.com", 404, "test", {}, None)
        with patch.object(release.urllib.request, "urlopen", side_effect=error):
            self.assertEqual(release.request("https://example.com"), (404, b""))
        with patch.object(release.urllib.request, "urlopen", side_effect=urllib.error.URLError("offline")):
            with self.assertRaisesRegex(RuntimeError, "Network failure"):
                release.request("https://example.com")

    def test_identity_changes_fail_before_release(self):
        with patch.object(release, "git", return_value="b" * 40):
            with self.assertRaisesRegex(RuntimeError, "Checkout differs"):
                release.identity()
        with tempfile.TemporaryDirectory() as directory, patch.object(release, "ROOT", Path(directory)):
            Path(directory, "VERSION").write_text("0.1.2\n")
            with patch.object(release, "git", return_value="a" * 40):
                with self.assertRaisesRegex(RuntimeError, "VERSION differs"):
                    release.identity()
            Path(directory, "VERSION").write_text("0.1.1\n")
            with patch.object(release, "git", side_effect=["a" * 40, " M tracked"]):
                with self.assertRaisesRegex(RuntimeError, "clean"):
                    release.identity()

    def test_remote_mismatch_fails_permanently(self):
        with patch.object(release, "compare_inventory"), patch.object(release, "inventory", return_value={"artifact": "0" * 64}), patch.object(release, "request", return_value=(200, b"wrong")):
            with self.assertRaisesRegex(RuntimeError, "PERMANENT artifact hash mismatch"):
                release.verify_remote(1)

    def test_remote_signature_missing_is_bounded(self):
        data = b"reviewed"
        digest = release.hashlib.sha256(data).hexdigest()
        with patch.object(release, "compare_inventory"), patch.object(release, "inventory", return_value={"artifact": digest}), patch.object(release, "request", side_effect=[(200, data), (404, b"")]), patch.object(release.time, "monotonic", side_effect=[0, 2]):
            with self.assertRaisesRegex(RuntimeError, "deadline exceeded"):
                release.verify_remote(1)

    def test_remote_exact_bytes_and_signature(self):
        data = b"reviewed"
        digest = release.hashlib.sha256(data).hexdigest()
        signature = b"-----BEGIN PGP SIGNATURE-----\nexample\n-----END PGP SIGNATURE-----"
        with patch.object(release, "compare_inventory"), patch.object(release, "inventory", return_value={"artifact": digest}), patch.object(release, "request", side_effect=[(200, data), (200, signature)]):
            release.verify_remote(1)

    def test_inventory_mismatch_fails(self):
        with patch.object(release, "inventory", return_value={"artifact": "different"}), patch.dict(os.environ, {"EXPECTED_INVENTORY": '{"artifact":"reviewed"}'}):
            with self.assertRaisesRegex(RuntimeError, "differs from preflight"):
                release.compare_inventory()

    def test_signing_presence_and_encrypted_password(self):
        with self.assertRaisesRegex(RuntimeError, "MAVEN_CENTRAL_USERNAME"):
            release.secrets()
        properties = {"ORG_GRADLE_PROJECT_" + p: "fake" for p in ["mavenCentralUsername", "mavenCentralPassword", "signingInMemoryKey"]}
        with patch.dict(os.environ, properties), patch.object(release.subprocess, "run") as command:
            command.return_value.stdout = ":secret key packet:\nskey[3]: [v4 protected]"
            with self.assertRaisesRegex(RuntimeError, "SIGNING_IN_MEMORY_KEY_PASSWORD"):
                release.secrets()
            command.return_value.stdout = ":secret key packet:\nskey[3]: [2048 bits]"
            release.secrets()

    def test_conflicting_remote_tag_never_moves(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(release, "ROOT", Path(directory)):
            Path(directory, "VERSION").write_text("0.1.1\n")
            Path(directory, "SPEC_PIN.md").write_bytes(b"pin")
            with patch.object(release, "SPEC_PIN_SHA256", release.hashlib.sha256(b"pin").hexdigest()), patch.object(release, "git", side_effect=["a" * 40, "", "", "a" * 40, "b" * 40 + "\trefs/tags/v0.1.1", ""]):
                with self.assertRaisesRegex(RuntimeError, "never move"):
                    release.identity(allow_tag=True)

    def test_existing_inconsistent_release_never_overwrites(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(release, "ROOT", Path(directory)):
            Path(directory, "review").mkdir()
            Path(directory, "review/V0_1_1_RELEASE_NOTES.md").write_text("## v0.1.1\n\nreviewed")
            with patch.object(release, "identity"), patch.object(release, "git", side_effect=["tag", "unsigned annotated tag"]), patch.object(release, "release_record", return_value={"tag_name": "v0.1.2"}), patch.object(release.subprocess, "run") as mutate:
                with self.assertRaisesRegex(RuntimeError, "inconsistent"):
                    release.tag_release()
                mutate.assert_not_called()

    def test_signing_outputs_bind_to_unsigned_inventory(self):
        data = b"reviewed publication"
        digest = release.hashlib.sha256(data).hexdigest()
        with tempfile.TemporaryDirectory() as directory, patch.object(release, "ROOT", Path(directory)), patch.object(release, "inventory", return_value={"org/totipo/totipo-core/0.1.1/totipo-core-0.1.1.pom": digest}):
            publication = Path(directory, "core/build/publications/maven")
            publication.mkdir(parents=True)
            (publication / "pom-default.xml").write_bytes(data)
            with self.assertRaisesRegex(RuntimeError, "exactly one signing output"):
                release.signed()
            (publication / "pom-default.xml.asc").write_bytes(b"-----BEGIN PGP SIGNATURE-----\nfixture\n-----END PGP SIGNATURE-----")
            release.signed()
            (publication / "pom-default.xml").write_bytes(b"changed")
            with self.assertRaisesRegex(RuntimeError, "differs from reviewed"):
                release.signed()

    def test_existing_exact_release_is_idempotent(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(release, "ROOT", Path(directory)):
            Path(directory, "review").mkdir()
            notes = "## v0.1.1\n\nreviewed"
            Path(directory, "review/V0_1_1_RELEASE_NOTES.md").write_text(notes)
            body = notes + f"\n\n### Release provenance\n\n- Java source commit: `{'a' * 40}`\n- Totipo v1/r18 spec commit: `{release.SPEC_COMMIT}`\n- Portable corpus: 90/90 executed, none deferred.\n"
            record = {"tag_name": "v0.1.1", "name": "v0.1.1", "draft": False, "prerelease": False, "body": body}
            with patch.object(release, "identity"), patch.object(release, "git", side_effect=["tag", "unsigned annotated tag", "a" * 40 + " refs/tags/v0.1.1", "tag"]) as commands, patch.object(release, "release_record", return_value=record), patch.object(release.subprocess, "run") as mutate:
                release.tag_release()
                mutate.assert_not_called()
                self.assertFalse(any(call.args[0] in {"push", "config"} for call in commands.call_args_list))

    def test_absent_tag_creates_annotation_at_exact_commit_then_release(self):
        os.environ["GH_TOKEN"] = "fake-token"
        with tempfile.TemporaryDirectory() as directory, patch.object(release, "ROOT", Path(directory)):
            Path(directory, "review").mkdir()
            Path(directory, "review/V0_1_1_RELEASE_NOTES.md").write_text("## v0.1.1\n\nreviewed")
            with patch.object(release, "identity"), patch.object(release, "git", side_effect=["tag", "unsigned annotated tag", "", "", "", "", "tag", ""]) as commands, patch.object(release, "release_record", return_value=None), patch.object(release.subprocess, "run") as create:
                release.tag_release()
                commands.assert_any_call("-c", "tag.gpgSign=false", "tag", "-a", "v0.1.1", "a" * 40, "-m", "totipo-java 0.1.1")
                push = commands.call_args_list[-1]
                self.assertEqual(push.args, ("push", "origin", "refs/tags/v0.1.1"))
                self.assertNotIn("fake-token", " ".join(push.args))
                self.assertEqual(create.call_args.args[0][:4], ["gh", "release", "create", "v0.1.1"])
                self.assertIn("--verify-tag", create.call_args.args[0])


if __name__ == "__main__":
    unittest.main()
