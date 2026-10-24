"""Shared helpers for the Action tests. Standard library only."""

import copy
import importlib.util
import json
import os
import pathlib
import tempfile

ACTION_DIR = pathlib.Path(__file__).resolve().parent.parent
REPO_ROOT = ACTION_DIR.parent

_spec = importlib.util.spec_from_file_location("mergelatch_action", ACTION_DIR / "mergelatch_action.py")
mla = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(mla)

SHA_MERGE = "a" * 40
SHA_HEAD = "b" * 40
SHA_OTHER = "c" * 40
SHA_ACTION = "d" * 40

CLEAN = {
    "schema_version": 1,
    "scanner": {"name": "mergelatch-core", "version": "0.1.0"},
    "ruleset": {"id": "mergelatch-builtin", "version": "1",
                "rules": ["ML-GHA-001", "ML-GHA-002", "ML-GHA-003", "ML-GHA-004"]},
    "limits": {"max_file_bytes": 1048576, "max_total_bytes": 16777216, "max_entries": 1000,
               "max_yaml_depth": 64, "timeout_seconds": 30},
    "target": {"path": "/work/repo", "revision": {"commit": SHA_MERGE, "reference": None}},
    "status": "clean",
    "summary": {"files_inspected": 2, "findings": 0, "incomplete": 0},
    "findings": [],
    "incomplete": [],
}


def finding(**overrides):
    base = {
        "rule_id": "ML-GHA-002", "severity": "medium",
        "title": "External reference is not pinned to an immutable revision",
        "file": ".github/workflows/ci.yml", "line": 7,
        "location": "jobs.build.steps[0].uses", "message": "message",
        "evidence": "uses: actions/checkout@v4", "remediation": "Pin it.",
    }
    base.update(overrides)
    return base


def gap(**overrides):
    base = {"path": ".github/workflows/ci.yml", "kind": "invalid_yaml", "detail": "bad yaml"}
    base.update(overrides)
    return base


def report(status="clean", findings=(), gaps=(), **top):
    data = copy.deepcopy(CLEAN)
    data["status"] = status
    data["findings"] = list(findings)
    data["incomplete"] = list(gaps)
    data["summary"]["findings"] = len(data["findings"])
    data["summary"]["incomplete"] = len(data["incomplete"])
    data.update(top)
    return data


def raw(data):
    return json.dumps(data).encode()


def context(**overrides):
    base = {
        "event": "pull_request", "merge_sha": SHA_MERGE, "head_sha": SHA_HEAD,
        "base_sha": SHA_OTHER, "repository": "octo/repo", "run_id": "123", "run_attempt": "1",
        "action_ref": SHA_ACTION, "action_sha": SHA_ACTION, "action_repository": "MergeLatch/mergelatch",
    }
    base.update(overrides)
    return base


def github_env(tmp, **extra):
    """An environment like the one GitHub gives a step, with real files."""
    tmp = pathlib.Path(tmp)
    env = {
        "GITHUB_OUTPUT": str(tmp / "output"),
        "GITHUB_STEP_SUMMARY": str(tmp / "summary.md"),
        "RUNNER_TEMP": str(tmp / "runner-temp"),
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "HOME": os.environ.get("HOME", "/"),
    }
    (tmp / "runner-temp").mkdir(exist_ok=True)
    for name in ("output", "summary.md"):
        (tmp / name).write_text("")
    env.update(extra)
    return env


def read_outputs(tmp):
    out = {}
    for line in pathlib.Path(tmp, "output").read_text().splitlines():
        name, _, value = line.partition("=")
        out[name] = value
    return out


def read_summary(tmp):
    return pathlib.Path(tmp, "summary.md").read_text()


class Workspace:
    """A temporary 'workspace' with a .git entry, and a fake 'action' directory
    holding the files prepare() looks for."""

    def __init__(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = pathlib.Path(self._tmp.name).resolve()
        self.workspace = self.root / "work" / "repo"
        self.workspace.mkdir(parents=True)
        (self.workspace / ".git").mkdir()
        # Like actions/checkout on pull_request: a detached HEAD at the merge commit.
        (self.workspace / ".git" / "HEAD").write_text(SHA_MERGE + "\n")
        self.action = self.root / "actions" / "mergelatch"
        self.action.mkdir(parents=True)
        for name in ("Cargo.toml", "Cargo.lock", "rust-toolchain.toml"):
            (self.action / name).write_text("")
        self.tmp = self.root / "tmp"
        self.tmp.mkdir()
        # A fixed os-release so the tests do not depend on the machine they run on.
        self.os_release = self.root / "os-release"
        self.os_release.write_text('NAME="Ubuntu"\nID=ubuntu\n')
        self._saved_os_release = mla.OS_RELEASE_PATH
        mla.OS_RELEASE_PATH = str(self.os_release)

    def cleanup(self):
        mla.OS_RELEASE_PATH = self._saved_os_release
        self._tmp.cleanup()

    def env(self, **extra):
        env = github_env(self.tmp,
                         MLA_WORKSPACE=str(self.workspace),
                         MLA_ACTION_PATH=str(self.action),
                         MLA_EVENT_NAME="pull_request",
                         MLA_SHA=SHA_MERGE, MLA_PR_HEAD_SHA=SHA_HEAD,
                         MLA_RUNNER_OS="Linux", MLA_RUNNER_ARCH="X64",
                         MLA_RUNNER_ENVIRONMENT="github-hosted")
        env.update(extra)
        return env
