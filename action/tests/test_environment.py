"""Tests for the controlled environment: nothing the workflow exported may
influence the Action's own execution or the scanner build.

Several tests here run REAL processes (real python3 -I, real bash, real cargo
and rustup, a real C compiler for the loader test) with hostile settings that
point at marker-writing scripts inside a fake "scanned workspace". The markers
are harmless files. Tests that need a tool skip when it is missing.
"""

import os
import pathlib
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest

from helpers import ACTION_DIR, REPO_ROOT, Workspace, mla, read_outputs, read_summary

HELPER = ACTION_DIR / "mergelatch_action.py"
ACTION_YML = (REPO_ROOT / "action.yml").read_text()
TRUSTED_HOME = pathlib.Path(mla.trusted_home())
HAVE_RUST = (TRUSTED_HOME / ".cargo" / "bin" / "cargo").exists() and (TRUSTED_HOME / ".cargo" / "bin" / "rustup").exists()
HAVE_CC = shutil.which("cc") is not None
TRIPLE_VAR = "CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER"


def script(path: pathlib.Path, body: str) -> pathlib.Path:
    path.write_text("#!/bin/sh\n" + body)
    path.chmod(path.stat().st_mode | stat.S_IXUSR)
    return path


def bootstrap(step_id: str) -> str:
    """The Python source of one step in action.yml, exactly as the runner would run it."""
    lines = ACTION_YML.splitlines()
    start = lines.index("      id: %s" % step_id)
    run = next(n for n in range(start, len(lines)) if lines[n] == "      run: |")
    body = []
    for line in lines[run + 1:]:
        if not line.startswith("        "):
            break
        body.append(line[8:])
    return "\n".join(body) + "\n"


class Hostile:
    """A fake scanned workspace holding marker-writing scripts, and the
    environment variables that would run them if they were honored."""

    def __init__(self, root: pathlib.Path):
        self.dir = root / "scanned-workspace" / "evil"
        self.dir.mkdir(parents=True)
        self.markers = root / "markers"
        self.markers.mkdir()
        self.cargo_home = self.dir / "cargo-home"
        self.cargo_home.mkdir()
        mark = lambda name: "touch %s/%s\n" % (self.markers, name)
        self.bash_env = script(self.dir / "bash_env.sh", mark("BASH_ENV"))
        self.linker = script(self.dir / "linker.sh", mark("LINKER") + 'exec cc "$@"\n')
        self.wrapper = script(self.dir / "wrapper.sh", mark("RUSTC_WRAPPER") + 'exec "$@"\n')
        self.config_wrapper = script(self.dir / "config_wrapper.sh", mark("CARGO_HOME_CONFIG") + 'exec "$@"\n')
        (self.cargo_home / "config.toml").write_text('[build]\nrustc-wrapper = "%s"\n' % self.config_wrapper)

    def env(self) -> dict:
        return {
            "BASH_ENV": str(self.bash_env), "ENV": str(self.bash_env),
            "CARGO_HOME": str(self.cargo_home), TRIPLE_VAR: str(self.linker),
            "RUSTC_WRAPPER": str(self.wrapper), "CARGO_BUILD_RUSTC_WRAPPER": str(self.wrapper),
            "RUSTUP_DIST_SERVER": "http://127.0.0.1:9", "RUSTUP_UPDATE_ROOT": "http://127.0.0.1:9",
            "RUSTFLAGS": "-C link-arg=-fno-such-flag", "CARGO_BUILD_RUSTFLAGS": "-C link-arg=-fno-such-flag",
            "CARGO_NET_OFFLINE": "true", "CARGO_REGISTRIES_CRATES_IO_PROTOCOL": "sparse",
            "CC": str(self.linker),
        }

    def fired(self) -> list:
        return sorted(p.name for p in self.markers.iterdir())


class Mechanisms(unittest.TestCase):
    """Positive controls: the hostile settings DO run code when they are honored.
    If these ever stopped working, the isolation tests below would prove nothing."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.root = pathlib.Path(self._tmp.name).resolve()
        self.hostile = Hostile(self.root)

    def test_bash_env_runs_before_the_first_command_of_a_bash_step(self):
        step = self.root / "step.sh"
        step.write_text("echo trusted\n")
        # The runner's own invocation for `shell: bash`.
        env = dict(os.environ, BASH_ENV=str(self.hostile.bash_env))
        subprocess.run(["bash", "--noprofile", "--norc", "-eo", "pipefail", str(step)], env=env,
                       capture_output=True, check=True)
        self.assertEqual(self.hostile.fired(), ["BASH_ENV"])

    @unittest.skipUnless(HAVE_RUST, "needs rustup and cargo")
    def test_cargo_honors_these_settings_when_they_are_inherited(self):
        crate = self.root / "tiny"
        (crate / "src").mkdir(parents=True)
        (crate / "Cargo.toml").write_text('[package]\nname = "tiny"\nversion = "0.0.0"\nedition = "2021"\n')
        (crate / "src" / "main.rs").write_text("fn main() {}\n")
        toolchain = [str(TRUSTED_HOME / ".cargo" / "bin" / "cargo")]
        tag = (REPO_ROOT / "rust-toolchain.toml").read_text()
        version = re.search(r'channel = "([^"]+)"', tag).group(1)
        base = dict(os.environ)
        for name, extra in (("CARGO_HOME_CONFIG", {"CARGO_HOME": str(self.hostile.cargo_home)}),
                            ("RUSTC_WRAPPER", {"RUSTC_WRAPPER": str(self.hostile.wrapper)}),
                            ("LINKER", {TRIPLE_VAR: str(self.hostile.linker)})):
            subprocess.run(toolchain + ["+" + version, "build", "--offline", "-q"], cwd=crate,
                           env=dict(base, **extra), capture_output=True)
            shutil.rmtree(crate / "target", ignore_errors=True)
            self.assertIn(name, self.hostile.fired(), name)

    @unittest.skipUnless(HAVE_CC, "needs a C compiler")
    def test_ld_preload_runs_even_inside_python_isolated_mode(self):
        (self.root / "pre.c").write_text(
            '#include <stdio.h>\n__attribute__((constructor)) static void i(void){FILE*f=fopen("%s/LD_PRELOAD","w");if(f)fclose(f);}\n'
            % self.hostile.markers)
        subprocess.run(["cc", "-shared", "-fPIC", "-o", str(self.root / "pre.so"), str(self.root / "pre.c")], check=True)
        subprocess.run(["/usr/bin/python3", "-I", "-c", "pass"], env=dict(os.environ, LD_PRELOAD=str(self.root / "pre.so")),
                       capture_output=True, check=True)
        self.assertEqual(self.hostile.fired(), ["LD_PRELOAD"])


class TrustedEnvironment(unittest.TestCase):
    def test_home_comes_from_the_account_database_not_the_variable(self):
        old = os.environ.get("HOME")
        os.environ["HOME"] = "/workspace/evil-home"
        try:
            self.assertNotEqual(mla.trusted_home(), "/workspace/evil-home")
            env = mla.trusted_environment()
            self.assertNotIn("evil", " ".join(env.values()))
        finally:
            if old is None:
                del os.environ["HOME"]
            else:
                os.environ["HOME"] = old

    def test_the_environment_is_exactly_the_fixed_values_plus_what_is_asked_for(self):
        env = mla.trusted_environment({"EXTRA": "1"}, home="/home/runner")
        self.assertEqual(env, {
            "PATH": "/home/runner/.cargo/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
            "HOME": "/home/runner", "CARGO_HOME": "/home/runner/.cargo",
            "RUSTUP_HOME": "/home/runner/.rustup", "LANG": "C.UTF-8", "EXTRA": "1",
        })

    def test_loader_variables_are_a_hard_error(self):
        for name in ("LD_PRELOAD", "LD_LIBRARY_PATH", "LD_AUDIT", "LD_ANYTHING", "GCONV_PATH"):
            with self.assertRaises(mla.ActionError, msg=name) as caught:
                mla.check_inherited_environment({name: "/workspace/x"})
            self.assertIn(name, str(caught.exception))
            self.assertNotIn("/workspace/x", str(caught.exception))

    def test_other_inherited_settings_are_ignored_not_errors(self):
        mla.check_inherited_environment({"BASH_ENV": "/x", "CARGO_HOME": "/x", "RUSTFLAGS": "-C x", "PATH": "/x"})

    def test_ignored_settings_are_listed_by_name_only(self):
        env = {"BASH_ENV": "/x", "CARGO_HOME": "/home/runner/.cargo", "RUSTUP_HOME": "/elsewhere",
               "RUSTFLAGS": "secret-looking", "CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER": "/x",
               "GITHUB_TOKEN": "t", "HOME": "/x", "bad name": "1", "RUSTC_WRAPPER": "/w"}
        names = mla.ignored_build_settings(env, "/home/runner")
        self.assertEqual(names, ["BASH_ENV", "CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER",
                                 "RUSTC_WRAPPER", "RUSTFLAGS", "RUSTUP_HOME"])

    def test_runner_restrictions_are_enforced(self):
        with tempfile.TemporaryDirectory() as tmp:
            ubuntu = pathlib.Path(tmp, "os-release")
            ubuntu.write_text('NAME="Ubuntu"\nID=ubuntu\n')
            good = {"MLA_RUNNER_OS": "Linux", "MLA_RUNNER_ARCH": "X64", "MLA_RUNNER_ENVIRONMENT": "github-hosted"}
            mla.check_runner(good, str(ubuntu))
            for change, fragment in (({"MLA_RUNNER_OS": "Windows"}, "Linux"), ({"MLA_RUNNER_OS": "macOS"}, "Linux"),
                                     ({"MLA_RUNNER_ENVIRONMENT": "self-hosted"}, "GitHub-hosted"),
                                     ({"MLA_RUNNER_ENVIRONMENT": ""}, "GitHub-hosted"),
                                     ({"MLA_RUNNER_ARCH": "ARM64"}, "x86-64")):
                with self.assertRaises(mla.ActionError, msg=change) as caught:
                    mla.check_runner(dict(good, **change), str(ubuntu))
                self.assertIn(fragment, str(caught.exception))
            for text in ('ID=debian\n', 'ID="ubuntu"\n', 'ID_LIKE=ubuntu\n', ''):
                other = pathlib.Path(tmp, "other")
                other.write_text(text)
                with self.assertRaises(mla.ActionError, msg=text):
                    mla.check_runner(good, str(other))
            with self.assertRaises(mla.ActionError):
                mla.check_runner(good, str(pathlib.Path(tmp, "missing")))


class PrepareChecksTheEnvironment(unittest.TestCase):
    def setUp(self):
        self.ws = Workspace()
        self.addCleanup(self.ws.cleanup)

    def prepare(self, **extra):
        mla.main(["x", "prepare"], self.ws.env(**extra))
        out = read_outputs(self.ws.tmp)
        import json
        state = json.loads(pathlib.Path(out["state-dir"], "state.json").read_text())
        return out, state

    def test_a_clean_environment_passes(self):
        out, state = self.prepare()
        self.assertEqual(out["ok"], "true")
        self.assertEqual(state["ignored_env"], [])

    def test_loader_variables_stop_the_scan_with_a_clear_error(self):
        out, state = self.prepare(LD_PRELOAD="/workspace/evil.so")
        self.assertEqual(out["ok"], "false")
        self.assertIn("LD_PRELOAD", state["error"])
        self.assertIn("cannot be neutralized", state["error"])

    def test_unsupported_runners_stop_the_scan(self):
        for change in ({"MLA_RUNNER_ENVIRONMENT": "self-hosted"}, {"MLA_RUNNER_OS": "Windows"}, {"MLA_RUNNER_ARCH": "ARM64"}):
            out, state = self.prepare(**change)
            self.assertEqual(out["ok"], "false", change)
        self.ws.os_release.write_text("ID=debian\n")
        out, _ = self.prepare()
        self.assertEqual(out["ok"], "false")

    def test_ignored_settings_are_recorded_and_reported(self):
        out, state = self.prepare(BASH_ENV="/workspace/evil.sh", CARGO_HOME="/workspace/cargo", RUSTFLAGS="-Cx")
        self.assertEqual(out["ok"], "true")
        self.assertEqual(state["ignored_env"], ["BASH_ENV", "CARGO_HOME", "RUSTFLAGS"])
        pathlib.Path(out["state-dir"], "scan-exit-code.txt").write_text("0\n")
        from helpers import raw, report
        pathlib.Path(out["state-dir"], "report.json").write_bytes(raw(report()))
        env = self.ws.env(MLA_STATE_DIR=out["state-dir"])
        self.assertEqual(mla.main(["x", "report"], env), 0)
        self.assertEqual(read_outputs(self.ws.tmp)["ignored-environment-count"], "3")
        summary = read_summary(self.ws.tmp)
        self.assertIn("Inherited build settings ignored", summary)
        self.assertIn("BASH\\_ENV", summary)
        self.assertNotIn("/workspace/evil", summary)


class RunnerShell(unittest.TestCase):
    """Runs the real step bootstrap from action.yml the way the runner does."""

    def test_every_step_uses_an_absolute_python_shell_and_never_bash(self):
        self.assertNotIn("shell: bash", ACTION_YML)
        shells = re.findall(r"(?m)^      shell: (.*)$", ACTION_YML)
        self.assertEqual(shells, ["/usr/bin/python3 -I {0}"] * 4)

    def test_a_hostile_bash_env_does_not_run_and_the_step_works(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp).resolve()
            hostile = Hostile(root)
            ws = Workspace()
            self.addCleanup(ws.cleanup)
            code = root / "step.py"
            code.write_text(bootstrap("prepare"))
            env = ws.env(MLA_INPUT_SCAN_DIRECTORY=".", MLA_ACTION_PATH=str(REPO_ROOT))
            env.update(hostile.env())
            env.pop("CARGO_HOME")  # prepare() compares it with the trusted default; keep the focus on BASH_ENV
            result = subprocess.run(["/usr/bin/python3", "-I", str(code)], env=env, capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(hostile.fired(), [])
            # The real /etc/os-release is read here, so on a non-Ubuntu development
            # machine the runner check (correctly) refuses; nothing else may.
            import json
            state = json.loads(pathlib.Path(read_outputs(ws.tmp)["state-dir"], "state.json").read_text())
            if state["error"] is not None:
                self.assertEqual(state["error"], "only Ubuntu runner images are supported")
            else:
                self.assertEqual(read_outputs(ws.tmp)["ok"], "true")
                self.assertIn("BASH_ENV", state["ignored_env"])


@unittest.skipUnless(HAVE_RUST, "needs rustup and cargo in the trusted home")
class RealBuildIsolation(unittest.TestCase):
    """Builds a small stand-in for the scanner with the real build step under
    hostile inherited settings."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.root = pathlib.Path(self._tmp.name).resolve()
        self.hostile = Hostile(self.root)
        self.action = self.root / "action"
        (self.action / "crates" / "cli" / "src").mkdir(parents=True)
        (self.action / "Cargo.toml").write_text('[workspace]\nresolver = "3"\nmembers = ["crates/cli"]\n')
        (self.action / "crates" / "cli" / "Cargo.toml").write_text(
            '[package]\nname = "mergelatch-cli"\nversion = "0.0.0"\nedition = "2024"\n\n'
            '[[bin]]\nname = "mergelatch"\npath = "src/main.rs"\n')
        (self.action / "crates" / "cli" / "src" / "main.rs").write_text('fn main() { println!("stand-in scanner"); }\n')
        shutil.copy(REPO_ROOT / "rust-toolchain.toml", self.action / "rust-toolchain.toml")
        clean = mla.trusted_environment()
        subprocess.run([str(TRUSTED_HOME / ".cargo" / "bin" / "cargo"), "generate-lockfile", "--offline"],
                       cwd=self.action, env=clean, check=True, capture_output=True)
        self.state = self.root / "state"
        self.state.mkdir()
        self.temp = self.root / "runner-temp"
        self.temp.mkdir()

    def run_build(self, env_extra):
        env = dict(os.environ)
        env.update(env_extra)
        env.update({"RUNNER_TEMP": str(self.temp), "MLA_ACTION_ROOT": str(self.action), "MLA_STATE_DIR": str(self.state)})
        return subprocess.run(["/usr/bin/python3", "-I", str(HELPER), "build"], env=env, capture_output=True, text=True)

    def test_the_trusted_source_builds_and_runs_despite_hostile_settings(self):
        result = self.run_build(self.hostile.env())
        self.assertEqual(result.returncode, 0, result.stdout[-1500:] + result.stderr[-1500:])
        self.assertEqual(self.hostile.fired(), [], "inherited settings ran code during the build")
        binary = pathlib.Path((self.state / "binary-path.txt").read_text().strip())
        self.assertEqual(binary, self.temp / "mergelatch-cargo-target" / "release" / "mergelatch")
        out = subprocess.run([str(binary)], capture_output=True, text=True)
        self.assertEqual(out.stdout.strip(), "stand-in scanner")
        self.assertIn("rustc", (self.state / "rustc-version.txt").read_text())

    def test_the_build_uses_the_locked_pinned_toolchain_from_the_action_directory(self):
        hostile_toolchain = self.root / "scanned-workspace" / "rust-toolchain.toml"
        hostile_toolchain.write_text('[toolchain]\nchannel = "0.0.1-hostile"\n')
        result = self.run_build({"RUSTUP_TOOLCHAIN": "0.0.1-hostile"})
        self.assertEqual(result.returncode, 0, result.stdout[-800:] + result.stderr[-800:])
        pinned = re.search(r'channel = "([^"]+)"', (REPO_ROOT / "rust-toolchain.toml").read_text()).group(1)
        self.assertIn(pinned, (self.state / "rustc-version.txt").read_text())

    def test_a_missing_lockfile_fails_the_locked_build(self):
        (self.action / "Cargo.lock").unlink()
        result = self.run_build({})
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse((self.state / "binary-path.txt").exists())

    def test_loader_variables_do_not_reach_the_build_children(self):
        env_dump = self.root / "env-seen"
        make_wrapper = script(self.root / "dump-wrapper.sh", 'env > %s\nexec "$@"\n' % env_dump)
        # RUSTC_WRAPPER is not honored, so the dump never happens: nothing was inherited.
        result = self.run_build({"RUSTC_WRAPPER": str(make_wrapper), "LD_LIBRARY_PATH": "/workspace/evil"})
        self.assertEqual(result.returncode, 0, result.stderr[-800:])
        self.assertFalse(env_dump.exists())


if __name__ == "__main__":
    unittest.main()
