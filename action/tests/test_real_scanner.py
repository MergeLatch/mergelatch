"""Runs the Action's Python steps against the REAL MergeLatch scanner binary.

Real: the scanner binary, its exit codes, its JSON output, and the helper's
prepare, scan, and report steps. Simulated: the GitHub environment (the
workflow context, GITHUB_OUTPUT and GITHUB_STEP_SUMMARY are plain files here).
This is not the composite Action running on GitHub; the smoke-test workflow does
that.

Skipped unless MERGELATCH_TEST_BIN points at a built `mergelatch` binary.
"""

import os
import pathlib
import shutil
import unittest

from helpers import REPO_ROOT, SHA_HEAD, SHA_MERGE, SHA_OTHER, Workspace, mla, read_outputs, read_summary

BINARY = os.environ.get("MERGELATCH_TEST_BIN")
FIXTURES = REPO_ROOT / "fixtures"


@unittest.skipUnless(BINARY and os.access(BINARY, os.X_OK), "MERGELATCH_TEST_BIN is not set")
class RealScanner(unittest.TestCase):
    def setUp(self):
        self.ws = Workspace()
        self.addCleanup(self.ws.cleanup)

    def copy_fixture(self, fixture, name):
        shutil.copytree(FIXTURES / fixture, self.ws.workspace / name)

    def run_steps(self, scan_directory=".", before_scan=None, **env_extra):
        env = self.ws.env(MLA_INPUT_SCAN_DIRECTORY=scan_directory, **env_extra)
        self.assertEqual(mla.main(["x", "prepare"], env), 0)
        out = read_outputs(self.ws.tmp)
        state = pathlib.Path(out["state-dir"])
        if out["ok"] == "true":
            (state / "binary-path.txt").write_text(BINARY + "\n")
            (state / "rustc-version.txt").write_text("rustc (test)\n")
        env["MLA_STATE_DIR"] = str(state)
        if before_scan:
            before_scan()
        self.assertEqual(mla.main(["x", "scan"], env), 0)
        env["MLA_BUILD_OUTCOME"] = "success"
        code = mla.main(["x", "report"], env)
        return code, read_outputs(self.ws.tmp), read_summary(self.ws.tmp)

    def test_clean_fixture(self):
        self.copy_fixture("gha-permissions/safe-read-only", "clean")
        code, out, summary = self.run_steps("clean")
        self.assertEqual((code, out["status"], out["scanner-exit-code"], out["findings-count"]), (0, "clean", "0", "0"))
        self.assertEqual(out["files-inspected"], "1")
        self.assertIn("No findings in the supported checks", summary)

    def test_findings_fixture(self):
        self.copy_fixture("gha-permissions/workflow-write-all", "dir with spaces")
        code, out, summary = self.run_steps("dir with spaces")
        self.assertEqual((code, out["status"], out["scanner-exit-code"], out["findings-count"]), (0, "findings", "1", "1"))
        self.assertIn("Findings require review", summary)
        self.assertIn("ML-GHA-001", summary)

    def test_incomplete_fixture(self):
        self.copy_fixture("gha-permissions/malformed", "bad")
        code, out, summary = self.run_steps("bad")
        self.assertEqual((code, out["status"], out["scanner-exit-code"], out["incomplete-count"]), (0, "incomplete", "2", "1"))
        self.assertIn("this is not a pass", summary)

    def test_all_four_rules_are_reported(self):
        wf = self.ws.workspace / "all" / ".github" / "workflows"
        wf.mkdir(parents=True)
        (wf / "ci.yml").write_text(
            "on: pull_request_target\npermissions: write-all\njobs:\n  b:\n    runs-on: x\n    steps:\n"
            "      - uses: actions/checkout@v4\n        with:\n          ref: ${{ github.event.pull_request.head.sha }}\n"
            "      - run: echo ${{ github.event.pull_request.title }} && npm test\n")
        code, out, summary = self.run_steps("all")
        self.assertEqual((code, out["status"], out["findings-count"]), (0, "findings", "4"))
        for rule in ("ML-GHA-001", "ML-GHA-002", "ML-GHA-003", "ML-GHA-004"):
            self.assertIn(rule, summary)

    def test_a_directory_without_workflows_is_clean_but_says_nothing_was_checked(self):
        (self.ws.workspace / "empty").mkdir()
        code, out, summary = self.run_steps("empty")
        self.assertEqual((code, out["status"], out["files-inspected"]), (0, "clean", "0"))
        self.assertIn("No workflow files were inspected", summary)

    def test_invalid_target_is_an_error_and_fails_the_step(self):
        code, out, summary = self.run_steps("does-not-exist")
        self.assertEqual((code, out["status"]), (1, "error"))
        self.assertIn("Error: results cannot be trusted", summary)

    def test_scanner_exit_3_is_an_error_and_fails_the_step(self):
        # The directory vanishes after validation, so the real scanner reports exit code 3.
        (self.ws.workspace / "vanishing").mkdir()
        code, out, summary = self.run_steps("vanishing", before_scan=lambda: shutil.rmtree(self.ws.workspace / "vanishing"))
        self.assertEqual((code, out["status"], out["scanner-exit-code"]), (1, "error", "3"))
        self.assertIn("The scanner reported an error", summary)

    def test_unusual_workflow_file_names_cannot_break_the_summary(self):
        wf = self.ws.workspace / "odd" / ".github" / "workflows"
        wf.mkdir(parents=True)
        name = "a b<img src=x>\n::error::x [l](http:--e) \u202e.yml"
        (wf / name).write_text("permissions: write-all\n")
        code, out, summary = self.run_steps("odd")
        self.assertEqual((code, out["status"]), (0, "findings"))
        self.assertNotIn("<img", summary)
        self.assertNotIn("](http", summary)
        self.assertNotIn("\u202e", summary)
        for line in summary.splitlines():
            self.assertFalse(line.startswith("::"), line)
            if line.startswith("|"):
                self.assertTrue(line.endswith("|"), line)

    def test_hostile_build_files_in_the_scanned_directory_are_only_read(self):
        self.copy_fixture("action-hostile", "hostile")
        code, out, _ = self.run_steps("hostile")
        self.assertEqual((code, out["status"]), (0, "clean"))
        leftovers = [p.name for p in (self.ws.workspace / "hostile").iterdir() if p.name.startswith("HOSTILE_")]
        self.assertEqual(leftovers, [])

    def test_revision_matches_the_expected_merge_commit(self):
        (self.ws.workspace / ".git" / "HEAD").write_text(SHA_MERGE + "\n")
        wf = self.ws.workspace / ".github" / "workflows"
        wf.mkdir(parents=True)
        (wf / "ci.yml").write_text("on: push\npermissions:\n  contents: read\njobs: {}\n")
        code, out, summary = self.run_steps(".", MLA_SHA=SHA_MERGE, MLA_PR_HEAD_SHA=SHA_HEAD)
        self.assertEqual((code, out["status"], out["revision-check"], out["scanned-revision"]), (0, "clean", "matches-merge", SHA_MERGE))
        self.assertIn("matches the expected merge commit", summary)

    def test_head_checkout_is_labelled_as_head_not_merge(self):
        (self.ws.workspace / ".git" / "HEAD").write_text(SHA_HEAD + "\n")
        code, out, _ = self.run_steps(".", MLA_SHA=SHA_MERGE, MLA_PR_HEAD_SHA=SHA_HEAD)
        self.assertEqual((code, out["revision-check"]), (0, "matches-head"))

    def test_a_stale_checkout_fails_even_though_the_scan_itself_was_clean(self):
        (self.ws.workspace / ".git" / "HEAD").write_text(SHA_OTHER + "\n")
        code, out, summary = self.run_steps(".", MLA_SHA=SHA_MERGE, MLA_PR_HEAD_SHA=SHA_HEAD)
        self.assertEqual((code, out["status"], out["revision-check"]), (1, "error", "mismatch"))
        self.assertIn("neither the expected merge commit", summary)

    def test_a_scanned_subdirectory_has_no_revision_and_says_so(self):
        (self.ws.workspace / "sub").mkdir()
        code, out, _ = self.run_steps("sub", MLA_SHA=SHA_MERGE, MLA_PR_HEAD_SHA=SHA_HEAD)
        self.assertEqual((code, out["revision-check"]), (0, "unavailable"))

    def test_a_secret_like_marker_in_the_scanned_files_does_not_reach_the_summary_or_log(self):
        import contextlib, io
        wf = self.ws.workspace / "s" / ".github" / "workflows"
        wf.mkdir(parents=True)
        (wf / "ci.yml").write_text(
            "on: push\npermissions: write-all # SECRET_COMMENT_MARKER_987\nenv:\n  TOKEN: SECRET_ENV_MARKER_987\njobs: {}\n")
        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer):
            code, out, summary = self.run_steps("s")
        self.assertEqual(out["status"], "findings")
        self.assertNotIn("SECRET_", summary)
        self.assertNotIn("SECRET_", buffer.getvalue())


if __name__ == "__main__":
    unittest.main()
