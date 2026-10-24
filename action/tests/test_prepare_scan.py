"""Tests for input validation, scanner invocation, and the build script.

The scanner and the Rust tools are replaced by small fake programs here, so
these tests check how the Action calls them, not what they do. The real
scanner is exercised in test_real_scanner.py and in the GitHub-hosted smoke test.
"""

import json
import os
import pathlib
import shutil
import stat
import subprocess
import tempfile
import unittest

from helpers import ACTION_DIR, Workspace, github_env, mla, raw, read_outputs, read_summary, report, finding

BUILD_SH = ACTION_DIR / "build.sh"


def make_executable(path: pathlib.Path, body: str) -> pathlib.Path:
    path.write_text("#!/bin/sh\n" + body)
    path.chmod(path.stat().st_mode | stat.S_IXUSR)
    return path


class Prepare(unittest.TestCase):
    def setUp(self):
        self.ws = Workspace()
        self.addCleanup(self.ws.cleanup)

    def prepare(self, **extra):
        env = self.ws.env(**extra)
        code = mla.main(["x", "prepare"], env)
        out = read_outputs(self.ws.tmp)
        state = json.loads(pathlib.Path(out["state-dir"], "state.json").read_text())
        return code, out, state

    def test_default_directory_is_the_workspace_root(self):
        code, out, state = self.prepare()
        self.assertEqual(code, 0)
        self.assertEqual(out["ok"], "true")
        self.assertEqual(state["scan_dir"], str(self.ws.workspace))
        self.assertEqual(state["scanner_source"], "action-checkout")
        self.assertEqual(out["action-root"], str(self.ws.action))
        self.assertEqual(state["max_findings"], 25)

    def test_state_directory_is_private_and_inside_runner_temp(self):
        _, out, _ = self.prepare()
        state_dir = pathlib.Path(out["state-dir"])
        self.assertEqual(state_dir.parent, self.ws.tmp / "runner-temp")
        self.assertEqual(stat.S_IMODE(state_dir.stat().st_mode), 0o700)

    def test_unusual_directory_names_are_accepted_and_kept_literal(self):
        for name in ("dir with space", "ünï-çødé", "-dash", "a'b", "$(touch pwned)", "x;y", "`id`", "a&b", "100%", "[x]"):
            sub = self.ws.workspace / name
            sub.mkdir()
            _, out, state = self.prepare(MLA_INPUT_SCAN_DIRECTORY=name)
            self.assertEqual(out["ok"], "true", name)
            self.assertEqual(state["scan_dir"], str(sub), name)
        self.assertFalse((self.ws.workspace / "pwned").exists())

    def test_nested_relative_paths_work(self):
        (self.ws.workspace / "a" / "b").mkdir(parents=True)
        for value in ("a/b", "./a/b", "a//b", "a/b/"):
            _, out, state = self.prepare(MLA_INPUT_SCAN_DIRECTORY=value)
            self.assertEqual(out["ok"], "true", value)
            self.assertEqual(state["scan_dir"], str(self.ws.workspace / "a" / "b"))

    def test_bad_directories_are_rejected_with_an_explanation(self):
        (self.ws.workspace / "file.txt").write_text("x")
        outside = self.ws.root / "outside"
        outside.mkdir()
        (self.ws.workspace / "escape").symlink_to(outside)
        (self.ws.workspace / "inside-link").symlink_to(self.ws.workspace / "file.txt")
        cases = {
            "../outside": "..", "a/../../outside": "..", "..": "..",
            "/etc": "relative", "\\windows": "relative", "C:\\x": "relative",
            "bad\nname": "control", "bad\rname": "control", "bad\0name": "control",
            "missing": "does not exist", "file.txt": "not a directory",
            "escape": "outside the workspace", "inside-link": "not a directory",
        }
        for value, fragment in cases.items():
            _, out, state = self.prepare(MLA_INPUT_SCAN_DIRECTORY=value)
            self.assertEqual(out["ok"], "false", value)
            self.assertIn(fragment, state["error"], value)
            self.assertIsNone(state["scan_dir"])

    def test_symlink_to_a_directory_inside_the_workspace_is_allowed(self):
        (self.ws.workspace / "real").mkdir()
        (self.ws.workspace / "link").symlink_to(self.ws.workspace / "real")
        _, out, state = self.prepare(MLA_INPUT_SCAN_DIRECTORY="link")
        self.assertEqual(out["ok"], "true")
        self.assertEqual(state["scan_dir"], str(self.ws.workspace / "real"))

    def test_a_missing_checkout_is_an_error_not_an_empty_clean_scan(self):
        shutil.rmtree(self.ws.workspace / ".git")
        _, out, state = self.prepare()
        self.assertEqual(out["ok"], "false")
        self.assertIn("no checkout", state["error"])

    def test_git_file_counts_as_a_checkout(self):
        shutil.rmtree(self.ws.workspace / ".git")
        (self.ws.workspace / ".git").write_text("gitdir: elsewhere\n")
        _, out, _ = self.prepare()
        self.assertEqual(out["ok"], "true")

    def test_only_the_pull_request_event_is_accepted(self):
        for event in ("pull_request_target", "workflow_run", "push", "workflow_dispatch", "schedule"):
            _, out, state = self.prepare(MLA_EVENT_NAME=event)
            self.assertEqual(out["ok"], "false", event)
            self.assertIn("only the pull_request event", state["error"])
        _, out, _ = self.prepare(MLA_EVENT_NAME="pull_request")
        self.assertEqual(out["ok"], "true")

    def test_max_findings_must_be_a_small_number(self):
        for value in ("0", "101", "abc", "-1", "1e3", "2.5", " 5", "٣"):
            _, out, _ = self.prepare(MLA_INPUT_MAX_FINDINGS=value)
            self.assertEqual(out["ok"], "false", value)
        for value, expected in (("1", 1), ("100", 100), ("", 25)):
            _, out, state = self.prepare(MLA_INPUT_MAX_FINDINGS=value)
            self.assertEqual(out["ok"], "true", value)
            self.assertEqual(state["max_findings"], expected)

    def test_scanner_source_inside_the_workspace_is_marked(self):
        local = self.ws.workspace
        for name in ("Cargo.toml", "Cargo.lock", "rust-toolchain.toml"):
            (local / name).write_text("")
        _, out, state = self.prepare(MLA_ACTION_PATH=str(local))
        self.assertEqual(state["scanner_source"], "workspace")
        inside = local / "nested-action"
        inside.mkdir()
        for name in ("Cargo.toml", "Cargo.lock", "rust-toolchain.toml"):
            (inside / name).write_text("")
        _, _, state = self.prepare(MLA_ACTION_PATH=str(inside))
        self.assertEqual(state["scanner_source"], "workspace")

    def test_incomplete_action_directory_is_an_error(self):
        (self.ws.action / "Cargo.lock").unlink()
        _, out, state = self.prepare()
        self.assertEqual(out["ok"], "false")
        self.assertIn("scanner source", state["error"])

    def test_missing_workspace_is_an_error(self):
        _, out, state = self.prepare(MLA_WORKSPACE=str(self.ws.root / "nope"))
        self.assertEqual(out["ok"], "false")

    def test_prepare_fails_the_step_if_it_cannot_write_outputs(self):
        env = self.ws.env(GITHUB_OUTPUT=str(self.ws.root / "no-dir" / "out"))
        self.assertEqual(mla.main(["x", "prepare"], env), 1)


class RejectedEvent(unittest.TestCase):
    """An unsupported event, followed through preparation and the report step
    the way action.yml chains them: build and scan are skipped when preparation
    says ok=false, and report always runs."""

    EVENTS = (None, "", " ", "pull_request_target", "workflow_run", "push", "schedule", "workflow_dispatch",
              "repository_dispatch", "issue_comment", "issues", "pull_request_review",
              "pull_request_review_comment", "merge_group", "workflow_call", "release", "fork",
              "Pull_Request", "PULL_REQUEST", "pull_request ", " pull_request", "pull_request\n",
              "pull-request", "pull_request_x", "pull_requests", "unknown_event")

    def follow(self, ws, event):
        extra = {} if event is None else {"MLA_EVENT_NAME": event}
        env = ws.env(**extra)
        if event is None:
            del env["MLA_EVENT_NAME"]
        self.assertEqual(mla.main(["x", "prepare"], env), 0)
        out = read_outputs(ws.tmp)
        state = pathlib.Path(out["state-dir"])
        return env, out, state

    def test_a_rejected_event_stops_before_build_and_scan_and_ends_in_error(self):
        for event in self.EVENTS:
            with self.subTest(event=event):
                ws = Workspace()
                self.addCleanup(ws.cleanup)
                env, out, state = self.follow(ws, event)
                self.assertEqual(out["ok"], "false")
                self.assertNotIn("action-root", out)
                # action.yml skips build and scan here; scan() is also safe if it were called.
                env["MLA_STATE_DIR"] = str(state)
                self.assertEqual(mla.main(["x", "scan"], env), 0)
                self.assertEqual(sorted(p.name for p in state.iterdir()), ["state.json"])
                env["MLA_BUILD_OUTCOME"] = ""
                code = mla.main(["x", "report"], env)
                result = read_outputs(ws.tmp)
                self.assertEqual(code, 1)
                self.assertEqual(result["status"], "error")
                self.assertEqual((result["findings-count"], result["incomplete-count"]), ("0", "0"))
                self.assertEqual(result["revision-check"], "not-checked")
                summary = read_summary(ws.tmp)
                self.assertIn("only the pull\\_request event", summary)
                self.assertIn("The job failed on purpose", summary)
                self.assertNotIn("No findings in the supported checks", summary)

    def test_the_event_value_is_not_stored_in_the_preparation_error(self):
        ws = Workspace()
        self.addCleanup(ws.cleanup)
        _, _, state = self.follow(ws, "SECRET_EVENT_MARKER_42")
        self.assertNotIn("SECRET_EVENT_MARKER_42", (state / "state.json").read_text())

    def test_the_exact_pull_request_event_still_runs(self):
        ws = Workspace()
        self.addCleanup(ws.cleanup)
        _, out, state = self.follow(ws, "pull_request")
        self.assertEqual(out["ok"], "true")
        self.assertIsNone(json.loads((state / "state.json").read_text())["error"])


class Scan(unittest.TestCase):
    def setUp(self):
        self.ws = Workspace()
        self.addCleanup(self.ws.cleanup)
        env = self.ws.env()
        mla.main(["x", "prepare"], env)
        self.out = read_outputs(self.ws.tmp)
        self.state = pathlib.Path(self.out["state-dir"])

    def install(self, body):
        binary = make_executable(self.ws.root / "fake-mergelatch", body)
        (self.state / "binary-path.txt").write_text(str(binary) + "\n")
        return binary

    def run_scan(self, **extra):
        env = self.ws.env(MLA_STATE_DIR=str(self.state), **extra)
        self.assertEqual(mla.main(["x", "scan"], env), 0)
        text = (self.state / "scan-exit-code.txt").read_text()
        return int(text.strip())

    def test_each_scanner_exit_code_is_captured_exactly(self):
        for code in (0, 1, 2, 3, 4, 101, 126):
            self.install("echo '{}'\nexit %d\n" % code)
            self.assertEqual(self.run_scan(), code)
            self.assertEqual((self.state / "report.json").read_text().strip(), "{}")

    def test_the_scanner_is_called_with_a_fixed_argument_list(self):
        sub = self.ws.workspace / "dir with $(touch pwned) and 'quotes'"
        sub.mkdir()
        env = self.ws.env(MLA_INPUT_SCAN_DIRECTORY=sub.name)
        mla.main(["x", "prepare"], env)
        self.state = pathlib.Path(read_outputs(self.ws.tmp)["state-dir"])
        log = self.ws.root / "argv.log"
        self.install('for a in "$@"; do printf "%%s\\0" "$a"; done > %s\necho {}\n' % log)
        self.run_scan()
        args = log.read_bytes().split(b"\0")[:-1]
        self.assertEqual([a.decode() for a in args], ["scan", "--format", "json", str(sub)])
        self.assertFalse((self.ws.workspace / "pwned").exists())
        self.assertFalse(pathlib.Path("pwned").exists())

    def test_the_workflow_environment_and_secrets_are_not_passed_on(self):
        dump = self.ws.root / "env.log"
        self.install("env > %s\necho {}\n" % dump)
        old = dict(os.environ)
        os.environ.update({"GITHUB_TOKEN": "TOKEN_MARKER", "MY_SECRET": "SECRET_MARKER", "ACTIONS_RUNTIME_TOKEN": "RT_MARKER"})
        try:
            self.run_scan()
        finally:
            os.environ.clear()
            os.environ.update(old)
        text = dump.read_text()
        for marker in ("TOKEN_MARKER", "SECRET_MARKER", "RT_MARKER", "GITHUB_"):
            self.assertNotIn(marker, text)

    def test_the_scanner_runs_in_the_state_directory_not_the_scanned_one(self):
        log = self.ws.root / "cwd.log"
        self.install("pwd > %s\necho {}\n" % log)
        self.run_scan()
        self.assertEqual(pathlib.Path(log.read_text().strip()).resolve(), self.state.resolve())

    def test_missing_unusable_or_absent_binaries_are_127(self):
        self.assertEqual(self.run_scan(), 127)  # no binary-path.txt
        (self.state / "binary-path.txt").write_text(str(self.ws.root / "nope") + "\n")
        self.assertEqual(self.run_scan(), 127)
        not_executable = self.ws.root / "plain-file"
        not_executable.write_text("x")
        (self.state / "binary-path.txt").write_text(str(not_executable) + "\n")
        self.assertEqual(self.run_scan(), 127)

    def test_timeout_is_124(self):
        self.install("sleep 30\n")
        self.assertEqual(self.run_scan(MLA_SCAN_TIMEOUT="1"), 124)

    def test_signals_are_reported_as_128_plus_the_signal(self):
        self.install("kill -9 $$\n")
        self.assertEqual(self.run_scan(), 137)

    def test_runaway_output_is_stopped(self):
        self.install("head -c 40000000 /dev/zero\n")
        code = self.run_scan()
        self.assertNotIn(code, (0, 1, 2, 3))
        self.assertLessEqual((self.state / "report.json").stat().st_size, mla.SCANNER_OUTPUT_LIMIT)

    def test_nothing_runs_when_preparation_failed(self):
        shutil.rmtree(self.ws.workspace / ".git")
        mla.main(["x", "prepare"], self.ws.env())
        state = pathlib.Path(read_outputs(self.ws.tmp)["state-dir"])
        marker = self.ws.root / "ran"
        binary = make_executable(self.ws.root / "never", "touch %s\n" % marker)
        (state / "binary-path.txt").write_text(str(binary))
        env = self.ws.env(MLA_STATE_DIR=str(state))
        self.assertEqual(mla.main(["x", "scan"], env), 0)
        self.assertFalse(marker.exists())
        self.assertFalse((state / "scan-exit-code.txt").exists())

    def test_scan_then_report_end_to_end_with_a_fake_scanner(self):
        data = report("findings", [finding()])
        self.install("cat <<'EOF'\n%s\nEOF\nexit 1\n" % json.dumps(data))
        self.run_scan()
        env = self.ws.env(MLA_STATE_DIR=str(self.state))
        self.assertEqual(mla.main(["x", "report"], env), 0)
        self.assertEqual(read_outputs(self.ws.tmp)["status"], "findings")


class BuildScript(unittest.TestCase):
    """Runs the build step with fake rustup, cargo and rustc in a fake home.

    The fake tools record how they were called, including their complete
    environment, so these tests show exactly what the build is given.
    """

    def setUp(self):
        self.ws = Workspace()
        self.addCleanup(self.ws.cleanup)
        self.home = self.ws.root / "home"
        self.cargo_bin = self.home / ".cargo" / "bin"
        self.cargo_bin.mkdir(parents=True)
        self.log = self.ws.root / "calls.log"
        record = (
            'printf "%%s|cwd=%%s|args=%%s\\n" "%s" "$(pwd)" "$*" >> %s\n'
            'env | sort > %s.$$.%s.env\n'
        )
        for tool in ("rustup", "cargo"):
            make_executable(self.cargo_bin / tool, record % (tool, self.log, self.ws.root / "env", tool))
        make_executable(self.cargo_bin / "rustc", 'echo "rustc 1.99.1 (fake)"\n')
        self.state = self.ws.root / "state"
        self.state.mkdir()

    def build_env(self, **extra):
        env = {
            "RUNNER_TEMP": str(self.ws.tmp),
            "MLA_ACTION_ROOT": str(self.ws.action),
            "MLA_STATE_DIR": str(self.state),
        }
        env.update(extra)
        return env

    def run_build(self, **extra):
        return mla.build(self.build_env(**extra), home=str(self.home))

    def recorded_env(self, tool):
        files = sorted(self.ws.root.glob("env.*.%s.env" % tool))
        self.assertEqual(len(files), 1, files)
        return dict(line.split("=", 1) for line in files[0].read_text().splitlines() if "=" in line)

    def test_builds_from_the_action_directory_with_a_locked_release_build(self):
        self.assertEqual(self.run_build(), 0)
        calls = self.log.read_text().splitlines()
        self.assertEqual(len(calls), 2)
        self.assertEqual(calls[0], "rustup|cwd=%s|args=toolchain install --no-self-update" % self.ws.action)
        self.assertEqual(calls[1], "cargo|cwd=%s|args=build --locked --release -p mergelatch-cli" % self.ws.action)
        self.assertEqual((self.state / "binary-path.txt").read_text().strip(),
                         "%s/mergelatch-cargo-target/release/mergelatch" % self.ws.tmp)
        self.assertIn("rustc 1.99.1", (self.state / "rustc-version.txt").read_text())

    def test_the_build_gets_an_environment_built_from_fixed_values(self):
        self.assertEqual(self.run_build(), 0)
        env = self.recorded_env("cargo")
        self.assertEqual(env["HOME"], str(self.home))
        self.assertEqual(env["CARGO_HOME"], str(self.home / ".cargo"))
        self.assertEqual(env["RUSTUP_HOME"], str(self.home / ".rustup"))
        self.assertEqual(env["PATH"].split(":")[0], str(self.cargo_bin))
        self.assertEqual(env["CARGO_TARGET_DIR"], "%s/mergelatch-cargo-target" % self.ws.tmp)
        allowed = {"HOME", "CARGO_HOME", "RUSTUP_HOME", "PATH", "LANG", "RUNNER_TEMP", "MLA_ACTION_ROOT",
                   "MLA_STATE_DIR", "MLA_CONTROLLED_ENV", "CARGO_TARGET_DIR", "PWD", "SHLVL", "_", "OLDPWD"}
        self.assertEqual(set(env) - allowed, set(), "unexpected variables reached cargo")

    def test_hostile_variables_in_the_calling_process_never_reach_the_build(self):
        hostile = {
            "BASH_ENV": "/workspace/evil.sh", "ENV": "/workspace/evil.sh", "CARGO_HOME": "/workspace/evil-cargo",
            "RUSTUP_HOME": "/workspace/evil-rustup", "RUSTUP_DIST_SERVER": "http://evil.invalid",
            "RUSTUP_TOOLCHAIN": "evil", "RUSTC_WRAPPER": "/workspace/evil", "RUSTFLAGS": "-Cevil",
            "CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER": "/workspace/evil-linker",
            "CARGO_BUILD_RUSTC": "/workspace/evil", "CARGO_REGISTRIES_CRATES_IO_PROTOCOL": "evil",
            "CC": "/workspace/evil", "PATH": "/workspace/bin:/usr/bin", "HOME": "/workspace/home",
            "SHELLOPTS": "xtrace", "BASHOPTS": "x", "LD_PRELOAD": "/workspace/evil.so",
        }
        old = dict(os.environ)
        os.environ.update(hostile)
        try:
            self.assertEqual(self.run_build(), 0)
        finally:
            os.environ.clear()
            os.environ.update(old)
        for tool in ("rustup", "cargo"):
            env = self.recorded_env(tool)
            for name, value in hostile.items():
                self.assertNotIn("/workspace", env.get(name, ""), (tool, name))
            self.assertNotIn("evil", " ".join(env.values()))

    def test_the_scanned_directory_is_never_the_working_directory_or_an_argument(self):
        hostile = self.ws.workspace / "hostile"
        (hostile / ".cargo").mkdir(parents=True)
        (hostile / "rust-toolchain.toml").write_text('[toolchain]\nchannel = "0.0.1"\n')
        (hostile / "Cargo.toml").write_text("[package]\nname='x'\n")
        (hostile / ".cargo" / "config.toml").write_text("[build]\nrustc = 'false'\n")
        self.assertEqual(self.run_build(MLA_SCAN_DIRECTORY=str(hostile)), 0)
        text = self.log.read_text()
        self.assertNotIn("hostile", text)
        self.assertNotIn(str(self.ws.workspace), text)

    def test_a_failing_build_fails_and_leaves_no_binary_path(self):
        make_executable(self.cargo_bin / "cargo", "exit 101\n")
        self.assertNotEqual(self.run_build(), 0)
        self.assertFalse((self.state / "binary-path.txt").exists())

    def test_missing_trusted_tools_are_a_clear_operational_error(self):
        (self.cargo_bin / "cargo").unlink()
        with self.assertRaises(mla.ActionError) as caught:
            self.run_build()
        self.assertIn("cargo was not found in the trusted Rust installation", str(caught.exception))
        # A tool that is only on PATH somewhere else is not accepted.
        elsewhere = self.ws.root / "elsewhere"
        elsewhere.mkdir()
        make_executable(elsewhere / "cargo", "exit 0\n")
        with self.assertRaises(mla.ActionError):
            mla.build(self.build_env(PATH=str(elsewhere)), home=str(self.home))

    def test_required_variables_are_enforced(self):
        for name in ("MLA_ACTION_ROOT", "MLA_STATE_DIR", "RUNNER_TEMP"):
            env = self.build_env()
            del env[name]
            with self.assertRaises(mla.ActionError, msg=name):
                mla.build(env, home=str(self.home))

    def test_build_sh_refuses_to_run_outside_the_controlled_environment(self):
        result = subprocess.run(["bash", str(BUILD_SH)], capture_output=True, text=True,
                                env={"PATH": os.environ["PATH"], "RUNNER_TEMP": str(self.ws.tmp),
                                     "MLA_ACTION_ROOT": str(self.ws.action), "MLA_STATE_DIR": str(self.state)})
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("controlled environment", result.stderr)
        self.assertFalse(self.log.exists())

    def test_build_sh_rejects_tools_that_are_not_from_cargo_home(self):
        elsewhere = self.ws.root / "elsewhere"
        elsewhere.mkdir()
        for tool in ("rustup", "cargo"):
            make_executable(elsewhere / tool, "exit 0\n")
        result = subprocess.run(
            ["bash", str(BUILD_SH)], capture_output=True, text=True,
            env={"PATH": "%s:%s" % (elsewhere, os.environ["PATH"]), "RUNNER_TEMP": str(self.ws.tmp),
                 "MLA_ACTION_ROOT": str(self.ws.action), "MLA_STATE_DIR": str(self.state),
                 "MLA_CONTROLLED_ENV": "1", "CARGO_HOME": str(self.home / ".cargo")})
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("trusted Rust installation", result.stderr)


if __name__ == "__main__":
    unittest.main()
