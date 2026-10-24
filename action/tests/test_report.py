"""Tests for report validation, evaluation, and the job summary (mocked scanner output)."""

import json
import pathlib
import re
import tempfile
import unittest

from helpers import (CLEAN, SHA_ACTION, SHA_HEAD, SHA_MERGE, SHA_OTHER, context, finding, gap,
                     github_env, mla, raw, read_outputs, read_summary, report)


class ParseReport(unittest.TestCase):
    def test_valid_reports_of_each_status_are_accepted(self):
        for data in (report(), report("findings", [finding()]), report("incomplete", gaps=[gap()])):
            self.assertEqual(mla.parse_report(raw(data))["status"], data["status"])

    def test_error_report_is_accepted(self):
        data = {"schema_version": 1, "status": "error", "message": "invalid scan target"}
        self.assertEqual(mla.parse_report(raw(data))["status"], "error")

    def test_empty_truncated_and_malformed_output_is_rejected(self):
        good = raw(report("findings", [finding()]))
        for bad in (b"", b"   ", good[: len(good) // 2], good[:-1], b"not json", b"[]", b"null",
                    b"\xff\xfe", good + b"{}", b'{"a": NaN}'):
            with self.assertRaises(mla.ReportError, msg=bad[:30]):
                mla.parse_report(bad)

    def test_oversized_output_is_rejected(self):
        with self.assertRaises(mla.ReportError):
            mla.parse_report(b" " * (mla.MAX_REPORT_BYTES + 1))

    def test_duplicate_keys_are_rejected(self):
        text = json.dumps(report()).replace('"status": "clean"', '"status": "findings", "status": "clean"')
        with self.assertRaises(mla.ReportError):
            mla.parse_report(text.encode())

    def test_wrong_schema_and_types_are_rejected(self):
        def broken(mutate):
            data = report("findings", [finding()])
            mutate(data)
            return raw(data)
        cases = [
            lambda d: d.update(schema_version=2),
            lambda d: d.update(schema_version=True),
            lambda d: d.update(status="passed"),
            lambda d: d.pop("scanner"),
            lambda d: d["scanner"].update(version="1.0 \n"),
            lambda d: d["ruleset"].update(id="a b"),
            lambda d: d["summary"].update(findings=-1),
            lambda d: d["summary"].update(findings=True),
            lambda d: d["summary"].update(findings=5),
            lambda d: d["findings"][0].update(severity="critical"),
            lambda d: d["findings"][0].update(rule_id="ml gha"),
            lambda d: d["findings"][0].update(line="7"),
            lambda d: d["findings"][0].pop("evidence"),
            lambda d: d["target"].update(revision={"commit": "not-hex", "reference": None}),
            lambda d: d.update(findings={}),
            lambda d: d.update(incomplete=[gap(kind="Bad Kind")]),
        ]
        for mutate in cases:
            with self.assertRaises(mla.ReportError):
                mla.parse_report(broken(mutate))

    def test_status_must_match_the_lists(self):
        with self.assertRaises(mla.ReportError):
            mla.parse_report(raw(report("clean", [finding()])))
        with self.assertRaises(mla.ReportError):
            mla.parse_report(raw(report("findings")))
        with self.assertRaises(mla.ReportError):
            mla.parse_report(raw(report("incomplete")))
        with self.assertRaises(mla.ReportError):
            mla.parse_report(raw(report("findings", [finding()], [gap()])))


class Evaluate(unittest.TestCase):
    def evaluate(self, data, code, **kw):
        return mla.evaluate(raw(data), code, context(), **kw)

    def test_exit_codes_map_to_statuses(self):
        self.assertEqual(self.evaluate(report(), 0)["status"], "clean")
        self.assertEqual(self.evaluate(report("findings", [finding()]), 1)["status"], "findings")
        self.assertEqual(self.evaluate(report("incomplete", gaps=[gap()]), 2)["status"], "incomplete")

    def test_scanner_error_exit_is_an_error(self):
        data = {"schema_version": 1, "status": "error", "message": "invalid scan target: nope"}
        result = mla.evaluate(raw(data), 3, context())
        self.assertEqual(result["status"], "error")
        self.assertEqual(result["exit_code"], 3)
        self.assertIn("scanner reported an error", result["reason"])

    def test_exit_code_inconsistent_with_status_is_an_error(self):
        for data, code in ((report(), 1), (report(), 2), (report("findings", [finding()]), 0),
                           (report("findings", [finding()]), 2), (report("incomplete", gaps=[gap()]), 0),
                           (report("incomplete", gaps=[gap()]), 1), (report(), 3)):
            result = self.evaluate(data, code)
            self.assertEqual(result["status"], "error", (data["status"], code))
            self.assertIsNone(result["report"])

    def test_error_status_with_a_success_exit_code_is_an_error(self):
        data = {"schema_version": 1, "status": "error", "message": "m"}
        self.assertEqual(mla.evaluate(raw(data), 0, context())["status"], "error")

    def test_abnormal_exits_never_look_clean(self):
        for code in (4, 101, 124, 126, 127, 137, 139, 153, 255):
            # Even with a perfectly valid clean report on disk.
            result = self.evaluate(report(), code)
            self.assertEqual(result["status"], "error", code)

    def test_missing_pieces(self):
        self.assertEqual(mla.evaluate(None, 0, context())["status"], "error")
        self.assertEqual(mla.evaluate(b"", 0, context())["status"], "error")
        self.assertEqual(mla.evaluate(raw(report()), None, context())["status"], "error")
        self.assertEqual(self.evaluate(report(), 0, prepare_error="no checkout")["status"], "error")
        self.assertEqual(self.evaluate(report(), 0, build_outcome="failure")["status"], "error")
        self.assertEqual(self.evaluate(report(), 0, build_outcome="skipped")["status"], "error")
        self.assertEqual(self.evaluate(report(), 0, build_outcome="success")["status"], "clean")

    def test_revision_checks(self):
        def check(commit, **ctx):
            data = report(target={"path": "/x", "revision": None if commit is None
                                  else {"commit": commit, "reference": None}})
            return mla.evaluate(raw(data), 0, context(**ctx))
        self.assertEqual(check(SHA_MERGE)["revision_check"], "matches-merge")
        self.assertEqual(check(SHA_HEAD)["revision_check"], "matches-head")
        self.assertEqual(check(None)["revision_check"], "unavailable")
        self.assertEqual(check(None)["status"], "clean")
        stale = check(SHA_OTHER)
        self.assertEqual(stale["revision_check"], "mismatch")
        self.assertEqual(stale["status"], "error")
        self.assertIsNone(stale["report"] and None)  # report kept only for display
        self.assertEqual(check(SHA_OTHER, event="push")["revision_check"], "not-applicable")
        self.assertEqual(check(SHA_OTHER, event="push")["status"], "clean")
        self.assertEqual(check(SHA_OTHER, merge_sha=None, head_sha=None)["revision_check"], "not-applicable")

    def test_findings_with_a_stale_revision_are_still_an_error(self):
        data = report("findings", [finding()], target={"path": "/x", "revision": {"commit": SHA_OTHER, "reference": None}})
        result = mla.evaluate(raw(data), 1, context())
        self.assertEqual(result["status"], "error")

    def test_context_values_are_validated(self):
        ctx = mla.read_context({"MLA_SHA": "xyz", "MLA_PR_HEAD_SHA": SHA_HEAD.upper(),
                                "MLA_REPOSITORY": "a b/c", "MLA_RUN_ID": "12x",
                                "MLA_EVENT_NAME": "pull_request\n::error::x"})
        self.assertIsNone(ctx["merge_sha"])
        self.assertIsNone(ctx["head_sha"])
        self.assertIsNone(ctx["repository"])
        self.assertIsNone(ctx["run_id"])
        self.assertIsNone(ctx["event"])
        ok = mla.read_context({"MLA_ACTION_REF": SHA_ACTION})
        self.assertEqual(ok["action_sha"], SHA_ACTION)
        self.assertIsNone(mla.read_context({"MLA_ACTION_REF": "v1"})["action_sha"])


class Escaping(unittest.TestCase):
    def test_markdown_and_html_are_neutralized(self):
        for text in ("<script>alert(1)</script>", "**bold** _it_ `code` [x](http://evil)",
                     "![img](http://evil/x.png)", "| a | b |", "# heading", "> quote",
                     "https://evil.example/path", "www.evil.example", "@octocat", ":smile:",
                     "$x$ $$y$$", "&lt;already&gt;", "- list", "1. item", "~~strike~~"):
            out = mla.md(text)
            self.assertNotIn("<", out)
            self.assertNotIn(">", out)
            for ch in "*_`[]()|#!@$~:":
                self.assertNotIn(ch, re.sub(r"\\.", "", out), (text, ch))

    def test_control_and_format_characters_are_made_visible(self):
        out = mla.md("a\nb\r\x1b[31m‮​\x00c\t")
        self.assertNotRegex(out, r"[\x00-\x1f‮​  ]")
        self.assertIn("\\u{a}", out)
        self.assertIn("\\u{202e}", out)

    def test_long_text_is_truncated(self):
        out = mla.md("x" * 10000, 50)
        self.assertEqual(out, "x" * 50 + "...")

    def test_plain_log_text_cannot_start_a_workflow_command(self):
        self.assertNotIn("::", mla.plain("::error::pwned\n::set-output name=x::y"))


class Summary(unittest.TestCase):
    def build(self, data, code, max_findings=25, ctx=None, source="action-checkout", **kw):
        result = mla.evaluate(raw(data), code, ctx or context(), **kw)
        return result, mla.build_summary(result, ctx or context(), source, max_findings, "rustc 1.99.1")

    def test_clean_summary_is_advisory_and_not_proof(self):
        _, text = self.build(report(), 0)
        self.assertIn("No findings in the supported checks", text)
        self.assertIn("Advisory only", text)
        self.assertIn("does not mean this pull request is safe", text)
        self.assertIn("not a merge gate", text)
        self.assertIn("matches the expected merge commit", text)

    def test_zero_files_is_called_out(self):
        data = report()
        data["summary"]["files_inspected"] = 0
        _, text = self.build(data, 0)
        self.assertIn("No workflow files were inspected", text)

    def test_findings_summary_is_prominent(self):
        _, text = self.build(report("findings", [finding(), finding(rule_id="ML-GHA-003", severity="high", line=9)]), 1)
        self.assertIn("Findings require review", text.splitlines()[0])
        self.assertIn("ML-GHA-002", text)
        self.assertIn("ML-GHA-003", text)
        self.assertIn("Rules matched", text)

    def test_incomplete_summary_says_not_a_pass(self):
        _, text = self.build(report("incomplete", gaps=[gap()]), 2)
        self.assertIn("Incomplete: this is not a pass", text.splitlines()[0])
        self.assertIn("Incomplete inspections", text)
        self.assertNotIn("No findings in the supported checks", text)

    def test_error_summary_never_says_clean(self):
        for data, code in ((report(), 101), (report(), 1)):
            _, text = self.build(data, code)
            self.assertIn("Error: results cannot be trusted", text)
            self.assertNotIn("No findings in the supported checks", text)

    def test_provenance_is_listed_and_does_not_claim_both_revisions(self):
        _, text = self.build(report(), 0)
        for expected in ("Scanner version", "mergelatch-builtin 1", "Expected merge commit", SHA_MERGE,
                         "Expected PR head commit", SHA_HEAD, "Scanned revision", "pinned at the full commit SHA"):
            self.assertIn(expected, text)
        self.assertNotIn("both", text.lower())

    def test_unpinned_and_local_scanner_sources_are_flagged(self):
        _, text = self.build(report(), 0, ctx=context(action_ref="v1", action_sha=None))
        self.assertIn("NOT a full commit SHA", text)
        _, text = self.build(report(), 0, source="workspace")
        self.assertIn("NOT an independently pinned release", text)

    def test_injection_attempts_in_every_untrusted_field_are_neutralized(self):
        evil = "<img src=x onerror=alert(1)>\n::error::pwned\n**x** [a](http://evil) ‮ ${{ secrets.X }} SECRET_MARKER_123"
        data = report(
            "findings",
            [finding(file="dir with space/" + evil + ".yml", location=evil, evidence=evil, title=evil,
                     rule_id="ML-GHA-002")],
            target={"path": evil, "revision": {"commit": SHA_MERGE, "reference": evil}},
        )
        result, text = self.build(data, 1)
        self.assertEqual(result["status"], "findings")
        self.assertNotIn("<img", text)
        self.assertNotIn("](http", text)
        self.assertNotRegex(text, r"(?m)^::")
        self.assertNotIn("‮", text)
        # Every table row stays on one line.
        for line in text.splitlines():
            if line.startswith("|"):
                self.assertTrue(line.endswith("|"), line)
        # The target path and reference are not displayed at all.
        self.assertNotIn("onerror", text.replace("\\", "").split("Findings")[0])

    def test_incomplete_details_are_neutralized_too(self):
        evil = "<b>x</b>\n# heading\n| col |"
        _, text = self.build(report("incomplete", gaps=[gap(path=evil, detail=evil, kind="invalid_yaml")]), 2)
        self.assertNotIn("<b>", text)
        self.assertNotIn("\n# heading", text)

    def test_large_reports_are_truncated_but_counts_stay_exact(self):
        many = [finding(file="f%d.yml" % i, line=i) for i in range(3000)]
        result, text = self.build(report("findings", many), 1, max_findings=10)
        self.assertEqual(len(result["report"]["findings"]), 3000)
        self.assertIn("2990 more finding(s) are not shown", text)
        self.assertLess(len(text.encode()), mla.MAX_SUMMARY_BYTES)
        self.assertIn("| Findings | 3000 |", text)

    def test_very_long_strings_are_cut(self):
        _, text = self.build(report("findings", [finding(evidence="e" * 100000, location="l" * 100000)]), 1)
        self.assertLess(len(text), 8000)
        self.assertNotIn("e" * 300, text)


class Outputs(unittest.TestCase):
    def run_report(self, tmp, data, code, **ctx_env):
        state = pathlib.Path(tmp, "state")
        state.mkdir(exist_ok=True)
        (state / "state.json").write_text(json.dumps({"error": None, "scan_dir": "/x", "scanner_source": "action-checkout",
                                                       "max_findings": 25}))
        if data is not None:
            (state / "report.json").write_bytes(data if isinstance(data, bytes) else raw(data))
        if code is not None:
            (state / "scan-exit-code.txt").write_text("%d\n" % code)
        env = github_env(tmp, MLA_STATE_DIR=str(state), MLA_EVENT_NAME="pull_request", MLA_SHA=SHA_MERGE,
                         MLA_PR_HEAD_SHA=SHA_HEAD, MLA_ACTION_REF=SHA_ACTION, MLA_REPOSITORY="octo/repo")
        env.update(ctx_env)
        return mla.report_command(env), env

    def test_clean_writes_outputs_and_succeeds(self):
        with tempfile.TemporaryDirectory() as tmp:
            code, _ = self.run_report(tmp, report(), 0)
            out = read_outputs(tmp)
            self.assertEqual(code, 0)
            self.assertEqual(out["status"], "clean")
            self.assertEqual(out["findings-count"], "0")
            self.assertEqual(out["scanner-exit-code"], "0")
            self.assertEqual(out["revision-check"], "matches-merge")
            self.assertEqual(out["scanned-revision"], SHA_MERGE)
            self.assertEqual(out["action-pinned"], "true")
            self.assertEqual(out["ruleset"], "mergelatch-builtin-1")

    def test_findings_and_incomplete_succeed_but_keep_their_exit_codes(self):
        with tempfile.TemporaryDirectory() as tmp:
            code, _ = self.run_report(tmp, report("findings", [finding()] * 3), 1)
            self.assertEqual(code, 0)
            out = read_outputs(tmp)
            self.assertEqual((out["status"], out["findings-count"], out["scanner-exit-code"]), ("findings", "3", "1"))
            self.assertIn("Findings require review", read_summary(tmp))
        with tempfile.TemporaryDirectory() as tmp:
            code, _ = self.run_report(tmp, report("incomplete", gaps=[gap(), gap(path=None)]), 2)
            self.assertEqual(code, 0)
            out = read_outputs(tmp)
            self.assertEqual((out["status"], out["incomplete-count"], out["scanner-exit-code"]), ("incomplete", "2", "2"))

    def test_operational_failures_fail_the_step_and_say_error(self):
        cases = {
            "crash": (b"", 101), "missing binary": (None, 127), "timeout": (None, 124),
            "truncated": (raw(report())[:50], 0), "no exit code": (raw(report()), None),
            "scanner error": (raw({"schema_version": 1, "status": "error", "message": "m"}), 3),
        }
        for name, (data, code) in cases.items():
            with tempfile.TemporaryDirectory() as tmp:
                result, _ = self.run_report(tmp, data, code)
                self.assertEqual(result, 1, name)
                self.assertEqual(read_outputs(tmp)["status"], "error", name)
                self.assertEqual(read_outputs(tmp)["scanner-exit-code"], "" if code is None else str(code), name)
                self.assertIn("Error: results cannot be trusted", read_summary(tmp), name)

    def test_preparation_failure_is_reported(self):
        with tempfile.TemporaryDirectory() as tmp:
            state = pathlib.Path(tmp, "state")
            state.mkdir()
            (state / "state.json").write_text(json.dumps({"error": "no checkout was found", "scan_dir": None}))
            env = github_env(tmp, MLA_STATE_DIR=str(state))
            self.assertEqual(mla.report_command(env), 1)
            self.assertIn("no checkout was found", read_summary(tmp))

    def test_missing_state_directory_fails_safely(self):
        with tempfile.TemporaryDirectory() as tmp:
            env = github_env(tmp, MLA_STATE_DIR=str(pathlib.Path(tmp, "nope")))
            self.assertEqual(mla.report_command(env), 1)
            self.assertEqual(read_outputs(tmp)["status"], "error")

    def test_stale_revision_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            data = report(target={"path": "/x", "revision": {"commit": SHA_OTHER, "reference": None}})
            result, _ = self.run_report(tmp, data, 0)
            self.assertEqual(result, 1)
            self.assertEqual(read_outputs(tmp)["revision-check"], "mismatch")
            self.assertEqual(read_outputs(tmp)["status"], "error")

    def test_failure_to_write_outputs_or_summary_fails_the_step(self):
        with tempfile.TemporaryDirectory() as tmp:
            result, env = self.run_report(tmp, report(), 0, GITHUB_OUTPUT=str(pathlib.Path(tmp, "no-such-dir", "out")))
            self.assertEqual(result, 1)
        with tempfile.TemporaryDirectory() as tmp:
            result, _ = self.run_report(tmp, report(), 0, GITHUB_STEP_SUMMARY=str(pathlib.Path(tmp, "no-such-dir", "s")))
            self.assertEqual(result, 1)
        with tempfile.TemporaryDirectory() as tmp:
            result, _ = self.run_report(tmp, report(), 0, GITHUB_OUTPUT="")
            self.assertEqual(result, 1)

    def test_log_output_never_contains_report_text(self):
        import contextlib, io
        evil = "::error::INJECTED SECRET_MARKER_123"
        data = report("findings", [finding(file=evil, evidence=evil, location=evil, title=evil)])
        buffer = io.StringIO()
        with tempfile.TemporaryDirectory() as tmp, contextlib.redirect_stdout(buffer):
            self.run_report(tmp, data, 1)
        self.assertNotIn("INJECTED", buffer.getvalue())
        self.assertNotIn("SECRET_MARKER", buffer.getvalue())
        for line in buffer.getvalue().splitlines():
            self.assertRegex(line, r"^(::(warning|error) title=MergeLatch advisory scan::[A-Za-z0-9 ().,]+|MergeLatch advisory scan finished.*)$")

    def test_output_values_cannot_inject_extra_outputs(self):
        with tempfile.TemporaryDirectory() as tmp:
            env = github_env(tmp)
            for bad in ("a\nstatus=clean", "a b", "x=y\r", "", "é"):
                if bad == "":
                    mla.write_output(env, "scanned-revision", bad)
                    continue
                with self.assertRaises(mla.ActionError):
                    mla.write_output(env, "scanned-revision", bad)
            with self.assertRaises(mla.ActionError):
                mla.write_output(env, "Bad Name", "x")


class ProvenanceReporting(unittest.TestCase):
    """Regression tests for gaps found by reading the real summaries of a
    SHA-pinned run on GitHub: the pinned SHA was not shown, an early error said
    'no expected revision for this event', and an unknown scanner source was
    described as pinned."""

    def summary(self, data, code, ctx=None, source="action-checkout", **kw):
        ctx = ctx or context()
        result = mla.evaluate(raw(data) if data is not None else None, code, ctx, **kw)
        return result, mla.build_summary(result, ctx, source, 25, "rustc 1.99.1")

    def test_the_pinned_action_revision_is_shown_with_its_repository(self):
        _, text = self.summary(report(), 0)
        self.assertIn("| Action revision | MergeLatch/mergelatch\\@%s |" % SHA_ACTION, text)

    def test_a_tag_or_branch_reference_is_called_out(self):
        _, text = self.summary(report(), 0, ctx=context(action_ref="v1", action_sha=None))
        self.assertIn("NOT a full commit SHA (reference: v1)", text)
        self.assertNotIn(SHA_ACTION, text)

    def test_a_local_action_has_no_reference_and_says_so(self):
        _, text = self.summary(report(), 0, ctx=context(action_ref="", action_sha=None, action_repository=None))
        self.assertIn("not reported (a local Action has no reference)", text)

    def test_errors_before_a_scan_do_not_claim_a_revision_check_was_not_applicable(self):
        for kwargs in ({"prepare_error": "no checkout was found"}, {"build_outcome": "failure"}):
            result, text = self.summary(None, None, **kwargs)
            self.assertEqual(result["status"], "error")
            self.assertEqual(result["revision_check"], "not-checked")
            self.assertIn("not checked (there was no scan result to compare)", text)
            self.assertNotIn("no expected revision for this event", text)

    def test_a_scan_that_fails_after_running_is_also_not_checked(self):
        result, _ = self.summary(report(), 101)
        self.assertEqual(result["revision_check"], "not-checked")

    def test_an_unknown_scanner_source_is_not_described_as_pinned(self):
        _, text = self.summary(None, None, source="unknown", prepare_error="x")
        self.assertIn("not determined (the preparation step did not finish)", text)
        self.assertNotIn("pinned at the full commit SHA", text)

    def test_outputs_carry_the_revision_and_the_unknown_source(self):
        import json, pathlib, tempfile
        with tempfile.TemporaryDirectory() as tmp:
            state = pathlib.Path(tmp, "state")
            state.mkdir()
            (state / "state.json").write_text(json.dumps({"error": "no checkout was found", "scan_dir": None}))
            env = github_env(tmp, MLA_STATE_DIR=str(state), MLA_EVENT_NAME="pull_request", MLA_ACTION_REF=SHA_ACTION,
                             MLA_ACTION_REPOSITORY="MergeLatch/mergelatch", MLA_SHA=SHA_MERGE)
            self.assertEqual(mla.report_command(env), 1)
            out = read_outputs(tmp)
            self.assertEqual(out["revision-check"], "not-checked")
            self.assertEqual(out["scanner-source"], "unknown")
            self.assertEqual(out["action-revision"], SHA_ACTION)
            self.assertEqual(out["action-pinned"], "true")

    def test_an_unpinned_reference_leaves_the_revision_output_empty(self):
        import json, pathlib, tempfile
        with tempfile.TemporaryDirectory() as tmp:
            state = pathlib.Path(tmp, "state")
            state.mkdir()
            (state / "state.json").write_text(json.dumps({"error": None, "scan_dir": "/x", "scanner_source": "action-checkout"}))
            (state / "report.json").write_bytes(raw(report()))
            (state / "scan-exit-code.txt").write_text("0\n")
            env = github_env(tmp, MLA_STATE_DIR=str(state), MLA_ACTION_REF="main")
            mla.report_command(env)
            out = read_outputs(tmp)
            self.assertEqual((out["action-revision"], out["action-pinned"]), ("", "false"))


if __name__ == "__main__":
    unittest.main()