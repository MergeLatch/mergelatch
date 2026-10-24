"""Tests for input validation, scanner invocation, and the build script.

The scanner and the Rust tools are replaced by small fake programs here, so
these tests check how the Action calls them, not what they do. The real
scanner is exercised in test_real_scanner.py and in the GitHub-hosted smoke test.
"""

import json
import os
import pathlib
import stat
import subprocess
import tempfile
import unittest

from helpers import ACTION_DIR, Workspace, github_env, mla, raw, read_outputs, report, finding

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
        (self.ws.workspace / ".git").rmdir()
        _, out, state = self.prepare()
        self.assertEqual(out["ok"], "false")
        self.assertIn("no checkout", state["error"])

    def test_git_file_counts_as_a_checkout(self):
        (self.ws.workspace / ".git").rmdir()
        (self.ws.workspace / ".git").write_text("gitdir: elsewhere\n")
        _, out, _ = self.prepare()
        self.assertEqual(out["ok"], "true")

    def test_privileged_events_are_refused(self):
        for event in ("pull_request_target", "workflow_run"):
            _, out, state = self.prepare(MLA_EVENT_NAME=event)
            self.assertEqual(out["ok"], "false", event)
            self.assertIn("pull_request event", state["error"])
        for event in ("pull_request", "push", "workflow_dispatch", "schedule"):
            _, out, _ = self.prepare(MLA_EVENT_NAME=event)
            self.assertEqual(out["ok"], "true", event)

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
        (self.ws.workspace / ".git").rmdir()
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
    """Runs build.sh with fake rustup, cargo and rustc to see how they are called."""

    def setUp(self):
        self.ws = Workspace()
        self.addCleanup(self.ws.cleanup)
        self.bin = self.ws.root / "bin"
        self.bin.mkdir()
        self.log = self.ws.root / "calls.log"
        for tool in ("rustup", "cargo"):
            make_executable(
                self.bin / tool,
                'printf "%%s|cwd=%%s|target=%%s|toolchain=%%s|flags=%%s|wrapper=%%s|args=%%s\\n" '
                '"%s" "$(pwd)" "${CARGO_TARGET_DIR-}" "${RUSTUP_TOOLCHAIN-}" "${RUSTFLAGS-}" '
                '"${RUSTC_WRAPPER-}" "$*" >> %s\n' % (tool, self.log),
            )
        make_executable(self.bin / "rustc", 'echo "rustc 1.99.1 (fake)"\n')
        self.state = self.ws.root / "state"
        self.state.mkdir()

    def run_build(self, **extra):
        env = {
            "PATH": "%s:%s" % (self.bin, os.environ["PATH"]),
            "HOME": os.environ["HOME"],
            "RUNNER_TEMP": str(self.ws.tmp),
            "MLA_ACTION_ROOT": str(self.ws.action),
            "MLA_STATE_DIR": str(self.state),
        }
        env.update(extra)
        return subprocess.run(["bash", str(BUILD_SH)], env=env, capture_output=True, text=True, cwd=str(self.ws.workspace))

    def test_builds_from_the_action_directory_with_a_locked_release_build(self):
        result = self.run_build()
        self.assertEqual(result.returncode, 0, result.stderr)
        calls = self.log.read_text().splitlines()
        self.assertEqual(len(calls), 2)
        self.assertTrue(calls[0].startswith("rustup|cwd=%s|" % self.ws.action))
        self.assertIn("args=toolchain install --no-self-update", calls[0])
        self.assertTrue(calls[1].startswith("cargo|cwd=%s|" % self.ws.action))
        self.assertIn("args=build --locked --release -p mergelatch-cli", calls[1])
        self.assertIn("target=%s/mergelatch-cargo-target|" % self.ws.tmp, calls[1])
        self.assertEqual((self.state / "binary-path.txt").read_text().strip(),
                         "%s/mergelatch-cargo-target/release/mergelatch" % self.ws.tmp)
        self.assertIn("rustc 1.99.1", (self.state / "rustc-version.txt").read_text())

    def test_the_scanned_directory_is_never_the_working_directory_or_an_argument(self):
        hostile = self.ws.workspace / "hostile"
        (hostile / ".cargo").mkdir(parents=True)
        (hostile / "rust-toolchain.toml").write_text('[toolchain]\nchannel = "0.0.1"\n')
        (hostile / "Cargo.toml").write_text("[package]\nname='x'\n")
        (hostile / ".cargo" / "config.toml").write_text("[build]\nrustc = 'false'\n")
        result = self.run_build(MLA_SCAN_DIRECTORY=str(hostile))
        self.assertEqual(result.returncode, 0, result.stderr)
        text = self.log.read_text()
        self.assertNotIn("hostile", text)
        self.assertNotIn(str(self.ws.workspace), text)

    def test_environment_that_could_redirect_the_build_is_cleared(self):
        result = self.run_build(RUSTUP_TOOLCHAIN="evil", RUSTFLAGS="-Cevil", RUSTC_WRAPPER="/tmp/evil",
                                CARGO_TARGET_DIR="/tmp/elsewhere")
        self.assertEqual(result.returncode, 0, result.stderr)
        for call in self.log.read_text().splitlines():
            self.assertIn("toolchain=|flags=|wrapper=|", call)
        self.assertNotIn("/tmp/elsewhere", self.log.read_text())

    def test_a_failing_build_fails_the_script_and_leaves_no_binary_path(self):
        make_executable(self.bin / "cargo", "exit 101\n")
        result = self.run_build()
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse((self.state / "binary-path.txt").exists())

    def test_required_variables_are_enforced(self):
        for name in ("MLA_ACTION_ROOT", "MLA_STATE_DIR", "RUNNER_TEMP"):
            env = {"PATH": "%s:%s" % (self.bin, os.environ["PATH"]), "HOME": os.environ["HOME"],
                   "RUNNER_TEMP": str(self.ws.tmp), "MLA_ACTION_ROOT": str(self.ws.action),
                   "MLA_STATE_DIR": str(self.state)}
            del env[name]
            result = subprocess.run(["bash", str(BUILD_SH)], env=env, capture_output=True, text=True)
            self.assertNotEqual(result.returncode, 0, name)


if __name__ == "__main__":
    unittest.main()
