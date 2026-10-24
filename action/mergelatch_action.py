#!/usr/bin/env python3
"""Trusted helper for the MergeLatch advisory GitHub Action.

This file runs from the Action's own directory. It never imports, builds, or
runs anything from the scanned repository: the scanned directory is only passed
to the scanner binary as a path argument.

Commands (selected by the first argument, configuration comes from environment
variables so that no untrusted text is ever placed in a shell command):

  prepare  validate the runner, environment, inputs and checkout; create a state directory
  build    build the scanner from the Action directory in a controlled environment
  scan     run the scanner on the validated directory and keep its raw output
  report   validate the scanner output, write outputs and the job summary

Everything read from the scanner's report is treated as untrusted text. It is
validated, truncated, and escaped before it reaches the job summary, and it is
never printed to the workflow log.

Only the Python standard library is used.
"""

from __future__ import annotations

import json
import os
import pwd
import re
import resource
import stat
import string
import subprocess
import sys
import tempfile
import unicodedata

SCHEMA_VERSION = 1
MAX_REPORT_BYTES = 5 * 1024 * 1024
SCANNER_OUTPUT_LIMIT = 16 * 1024 * 1024
SCAN_TIMEOUT_SECONDS = 300
MAX_SUMMARY_BYTES = 60 * 1024
DEFAULT_MAX_FINDINGS = 25
EXIT_FOR_STATUS = {"clean": 0, "findings": 1, "incomplete": 2}

STATUSES = ("clean", "findings", "incomplete", "error")
SEVERITIES = ("low", "medium", "high")

HEX40 = re.compile(r"\A[0-9a-f]{40}\Z")
HEX_OBJECT_ID = re.compile(r"\A(?:[0-9a-f]{40}|[0-9a-f]{64})\Z")
TOKEN = re.compile(r"\A[A-Za-z0-9._+-]{1,64}\Z")
REPOSITORY = re.compile(r"\A[A-Za-z0-9_.-]{1,100}/[A-Za-z0-9_.-]{1,100}\Z")
DIGITS = re.compile(r"\A[0-9]{1,20}\Z")
KIND = re.compile(r"\A[a-z_]{1,40}\Z")
RULE_ID = re.compile(r"\A[A-Z0-9-]{1,32}\Z")

# The only event this Action runs on. Matching is exact: names are not
# normalized, so other events (including the privileged pull_request_target
# and workflow_run, which give a workflow secrets or a write-capable token
# that an untrusted checkout must never share) are rejected, as is any
# empty, missing, differently capitalized or padded name.
SUPPORTED_EVENTS = ("pull_request",)

# Longest workspace HEAD file that is read; a detached HEAD is a commit ID and a newline.
MAX_HEAD_BYTES = 256

BUILD_TIMEOUT_SECONDS = 1500
OS_RELEASE_PATH = "/etc/os-release"

# Variables that make the dynamic loader or C library load code into every
# process, including this one, before any line of the Action runs. They cannot
# be undone from inside the Action, so their presence is a hard error.
LOADER_VARIABLE_PREFIXES = ("LD_",)
LOADER_VARIABLES = ("GCONV_PATH",)

# Used only to tell the user which inherited build settings were ignored. The
# protection does not depend on this list: child processes get an environment
# built from scratch (see trusted_environment).
BUILD_SETTING_NAMES = re.compile(
    r"\A(CARGO|RUSTUP|RUSTC|RUSTFLAGS|RUSTDOC|BASH_ENV\Z|ENV\Z|BASH_FUNC|SHELLOPTS|BASHOPTS|"
    r"CC\Z|CXX\Z|AR\Z|CFLAGS|CXXFLAGS|LDFLAGS|PYTHON)"
)
VARIABLE_NAME = re.compile(r"\A[A-Z0-9_]{1,80}\Z")


class ActionError(Exception):
    """An operational failure. The message is written by this file only."""


class ReportError(Exception):
    """The scanner output cannot be trusted. The message names fields only."""


# --------------------------------------------------------------------------
# Escaping untrusted text for the job summary
# --------------------------------------------------------------------------

_LEAVE_ALONE = set("/,;'\"=%^?-")
_PUNCTUATION = set(string.punctuation) - _LEAVE_ALONE
_ENTITIES = {"&": "&amp;", "<": "&lt;", ">": "&gt;"}


def _escape_char(ch: str) -> str:
    if ch in _ENTITIES:
        return _ENTITIES[ch]
    if ch in _PUNCTUATION:
        return "\\" + ch
    if unicodedata.category(ch) in ("Cc", "Cf", "Cs", "Co", "Cn", "Zl", "Zp"):
        return "\\u{%x}" % ord(ch)
    return ch


def md(value: object, limit: int = 120) -> str:
    """Makes untrusted text safe to place in a Markdown table cell.

    Markdown and HTML punctuation is escaped (which also stops automatic
    links, mentions, math, and emoji), control and format characters such as
    newlines and bidirectional overrides are shown as ``\\u{..}``, and the
    text is cut to ``limit`` characters.
    """
    text = value if isinstance(value, str) else str(value)
    cut = len(text) > limit
    out = "".join(_escape_char(ch) for ch in text[:limit])
    return out + "..." if cut else out


def plain(value: object, limit: int = 120) -> str:
    """Like md() but for text that is not placed in Markdown, only logged."""
    text = value if isinstance(value, str) else str(value)
    cut = len(text) > limit
    out = "".join(
        ch if unicodedata.category(ch) not in ("Cc", "Cf", "Cs", "Co", "Cn", "Zl", "Zp")
        else "\\u{%x}" % ord(ch)
        for ch in text[:limit]
    )
    return out.replace("::", ": :") + ("..." if cut else "")


# --------------------------------------------------------------------------
# GitHub file commands
# --------------------------------------------------------------------------

_OUTPUT_NAME = re.compile(r"\A[a-z][a-z0-9-]{0,40}\Z")
_OUTPUT_VALUE = re.compile(r"\A[A-Za-z0-9._+/-]{0,200}\Z")


def write_output(env: dict, name: str, value: object) -> None:
    """Appends one output. Only plain tokens are allowed as values, so a value
    can never contain a newline or start a second output."""
    text = str(value)
    if not _OUTPUT_NAME.match(name) or not _OUTPUT_VALUE.match(text):
        raise ActionError("internal error: unsafe output value for %s" % name)
    path = env.get("GITHUB_OUTPUT")
    if not path:
        raise ActionError("GITHUB_OUTPUT is not set")
    try:
        with open(path, "a", encoding="utf-8") as handle:
            handle.write("%s=%s\n" % (name, text))
    except OSError as exc:
        raise ActionError("cannot write GITHUB_OUTPUT: %s" % exc.strerror) from exc


def write_summary(env: dict, text: str) -> None:
    path = env.get("GITHUB_STEP_SUMMARY")
    if not path:
        raise ActionError("GITHUB_STEP_SUMMARY is not set")
    data = text.encode("utf-8")
    if len(data) > MAX_SUMMARY_BYTES:
        note = "\n\n_The summary was cut because it was too long._\n".encode()
        data = data[: MAX_SUMMARY_BYTES - len(note)].decode("utf-8", "ignore").encode() + note
    try:
        with open(path, "ab") as handle:
            handle.write(data)
    except OSError as exc:
        raise ActionError("cannot write GITHUB_STEP_SUMMARY: %s" % exc.strerror) from exc


# --------------------------------------------------------------------------
# The trusted environment
# --------------------------------------------------------------------------
#
# Every step of this Action runs under `/usr/bin/python3 -I`, not under bash, so
# BASH_ENV, ENV, and other shell start-up settings are never read. Child
# processes (the build and the scanner) are started with an environment that is
# assembled here from fixed values, not filtered from what the workflow passed
# in. Nothing that could point cargo, rustup, a compiler, or a shell at files in
# the scanned checkout is carried over.

def trusted_home() -> str:
    """The runner user's home directory from the account database, not from
    the HOME variable, which a workflow can change."""
    try:
        home = pwd.getpwuid(os.getuid()).pw_dir
    except KeyError as exc:
        raise ActionError("the runner user has no home directory") from exc
    if not home.startswith("/") or not os.path.isdir(home):
        raise ActionError("the runner user's home directory is not usable")
    return home


def trusted_environment(extra: dict | None = None, home: str | None = None) -> dict:
    """The complete environment for a child process."""
    home = home or trusted_home()
    cargo_home = os.path.join(home, ".cargo")
    env = {
        "PATH": ":".join([os.path.join(cargo_home, "bin"), "/usr/local/sbin", "/usr/local/bin",
                          "/usr/sbin", "/usr/bin", "/sbin", "/bin"]),
        "HOME": home,
        "CARGO_HOME": cargo_home,
        "RUSTUP_HOME": os.path.join(home, ".rustup"),
        "LANG": "C.UTF-8",
    }
    env.update(extra or {})
    return env


def check_inherited_environment(env: dict) -> None:
    """Refuses to run when the environment already loads code that this Action
    cannot keep out of its own process."""
    bad = sorted(name for name in env
                 if name.startswith(LOADER_VARIABLE_PREFIXES) or name in LOADER_VARIABLES)
    if bad:
        raise ActionError(
            "the inherited environment sets %s, which loads code into every process this Action "
            "starts and cannot be neutralized; remove it from the workflow" %
            ", ".join(plain(name, 40) for name in bad[:5])
        )


def ignored_build_settings(env: dict, home: str) -> list:
    """Names of inherited build settings that the trusted environment replaces."""
    expected = {"CARGO_HOME": os.path.join(home, ".cargo"), "RUSTUP_HOME": os.path.join(home, ".rustup")}
    names = []
    for name, value in env.items():
        if not BUILD_SETTING_NAMES.match(name) or not VARIABLE_NAME.match(name):
            continue
        if name in expected and value == expected[name]:
            continue
        names.append(name)
    return sorted(names)[:50]


def check_runner(env: dict, os_release: str | None = None) -> None:
    """Refuses runners other than GitHub-hosted Ubuntu on x86-64, the only
    combination on which the scanner's file confinement has been verified."""
    if env.get("MLA_RUNNER_OS") != "Linux":
        raise ActionError("only Linux runners are supported")
    if env.get("MLA_RUNNER_ENVIRONMENT") != "github-hosted":
        raise ActionError("only GitHub-hosted runners are supported")
    if env.get("MLA_RUNNER_ARCH") != "X64":
        raise ActionError("only x86-64 runners are supported")
    try:
        with open(os_release or OS_RELEASE_PATH, encoding="utf-8") as handle:
            ids = [line.strip() for line in handle if line.startswith("ID=")]
    except OSError:
        ids = []
    if ids != ["ID=ubuntu"]:
        raise ActionError("only Ubuntu runner images are supported")


# --------------------------------------------------------------------------
# prepare
# --------------------------------------------------------------------------

def _inside(path: str, root: str) -> bool:
    return path == root or path.startswith(root.rstrip(os.sep) + os.sep)


def resolve_scan_directory(workspace: str, raw: str) -> str:
    """Returns the real path of the directory to scan, inside the workspace."""
    raw = raw if raw != "" else "."
    if "\0" in raw or "\n" in raw or "\r" in raw:
        raise ActionError("scan-directory must not contain control characters")
    if raw.startswith(("/", "\\")) or re.match(r"\A[A-Za-z]:", raw):
        raise ActionError("scan-directory must be a path relative to the workspace")
    if any(part == ".." for part in re.split(r"[\\/]", raw)):
        raise ActionError("scan-directory must not contain '..'")
    candidate = os.path.realpath(os.path.join(workspace, raw))
    if not _inside(candidate, workspace):
        raise ActionError("scan-directory resolves outside the workspace")
    if not os.path.isdir(candidate):
        raise ActionError("scan-directory does not exist or is not a directory")
    return candidate


def prepare(env: dict) -> int:
    runner_temp = env.get("RUNNER_TEMP") or tempfile.gettempdir()
    state_dir = tempfile.mkdtemp(prefix="mergelatch-", dir=runner_temp)
    os.chmod(state_dir, 0o700)
    state: dict = {"error": None, "scan_dir": None}
    try:
        check_runner(env)
        check_inherited_environment(env)
        workspace_raw = env.get("MLA_WORKSPACE", "")
        if not workspace_raw or not os.path.isdir(workspace_raw):
            raise ActionError("the workspace directory is missing")
        workspace = os.path.realpath(workspace_raw)
        state["workspace"] = workspace

        event = env.get("MLA_EVENT_NAME", "")
        if event not in SUPPORTED_EVENTS:
            raise ActionError(
                "this Action supports only the pull_request event; "
                "it was started by a different or unrecognized event"
            )

        action_root = os.path.realpath(env.get("MLA_ACTION_PATH", ""))
        for needed in ("Cargo.toml", "Cargo.lock", "rust-toolchain.toml"):
            if not os.path.isfile(os.path.join(action_root, needed)):
                raise ActionError("the Action directory does not contain the scanner source")
        state["action_root"] = action_root
        state["scanner_source"] = "workspace" if _inside(action_root, workspace) else "action-checkout"
        state["ignored_env"] = ignored_build_settings(env, trusted_home())

        raw_max = env.get("MLA_INPUT_MAX_FINDINGS", "") or str(DEFAULT_MAX_FINDINGS)
        if not DIGITS.match(raw_max) or not 1 <= int(raw_max) <= 100:
            raise ActionError("max-findings-in-summary must be a number from 1 to 100")
        state["max_findings"] = int(raw_max)

        if not os.path.lexists(os.path.join(workspace, ".git")):
            raise ActionError(
                "no checkout was found in the workspace; run actions/checkout before this Action"
            )
        state["scan_dir"] = resolve_scan_directory(workspace, env.get("MLA_INPUT_SCAN_DIRECTORY", ""))
    except ActionError as exc:
        state["error"] = str(exc)

    with open(os.path.join(state_dir, "state.json"), "w", encoding="utf-8") as handle:
        json.dump(state, handle)
    write_output(env, "state-dir", state_dir)
    write_output(env, "ok", "true" if state["error"] is None else "false")
    if state["error"] is None:
        write_output(env, "action-root", state["action_root"])
    return 0


# --------------------------------------------------------------------------
# scan
# --------------------------------------------------------------------------

def _limit_output() -> None:
    resource.setrlimit(resource.RLIMIT_FSIZE, (SCANNER_OUTPUT_LIMIT, SCANNER_OUTPUT_LIMIT))


def load_state(state_dir: str) -> dict:
    with open(os.path.join(state_dir, "state.json"), encoding="utf-8") as handle:
        state = json.load(handle)
    if not isinstance(state, dict):
        raise ActionError("the state file is invalid")
    return state


def build(env: dict, home: str | None = None) -> int:
    """Builds the scanner with a controlled environment.

    The build script is started by absolute path under a fresh environment, so
    nothing the workflow exported (BASH_ENV, CARGO_HOME, linker or compiler
    overrides, rustup settings) reaches cargo, rustup, or the shell.
    """
    action_root = env.get("MLA_ACTION_ROOT", "")
    state_dir = env.get("MLA_STATE_DIR", "")
    runner_temp = env.get("RUNNER_TEMP", "")
    for label, value in (("action directory", action_root), ("state directory", state_dir),
                         ("runner temp directory", runner_temp)):
        if not value.startswith("/") or not os.path.isdir(value):
            raise ActionError("the %s is missing" % label)
    home = home or trusted_home()
    cargo_bin = os.path.join(home, ".cargo", "bin")
    for tool in ("rustup", "cargo"):
        if not os.access(os.path.join(cargo_bin, tool), os.X_OK):
            raise ActionError("%s was not found in the trusted Rust installation (%s)" % (tool, cargo_bin))
    bash = next((p for p in ("/usr/bin/bash", "/bin/bash") if os.access(p, os.X_OK)), None)
    if bash is None:
        raise ActionError("bash was not found at a trusted location")
    script = os.path.join(os.path.dirname(os.path.abspath(__file__)), "build.sh")
    child = trusted_environment({
        "RUNNER_TEMP": runner_temp,
        "MLA_ACTION_ROOT": action_root,
        "MLA_STATE_DIR": state_dir,
        "MLA_CONTROLLED_ENV": "1",
    }, home)
    try:
        result = subprocess.run([bash, "--noprofile", "--norc", script], cwd=action_root, env=child,
                                stdin=subprocess.DEVNULL, timeout=BUILD_TIMEOUT_SECONDS, check=False)
    except subprocess.TimeoutExpired as exc:
        raise ActionError("the scanner build exceeded its time limit") from exc
    except OSError as exc:
        raise ActionError("the scanner build could not be started: %s" % exc.strerror) from exc
    return result.returncode


def scan(env: dict) -> int:
    state_dir = env.get("MLA_STATE_DIR", "")
    state = load_state(state_dir)
    if state.get("error") or not state.get("scan_dir"):
        return 0
    binary_file = os.path.join(state_dir, "binary-path.txt")
    code = 127
    try:
        with open(binary_file, encoding="utf-8") as handle:
            binary = handle.read().strip()
        argv = [binary, "scan", "--format", "json", state["scan_dir"]]
        timeout = int(env.get("MLA_SCAN_TIMEOUT", SCAN_TIMEOUT_SECONDS))
        with open(os.path.join(state_dir, "report.json"), "wb") as out, open(
            os.path.join(state_dir, "scanner-stderr.txt"), "wb"
        ) as err:
            result = subprocess.run(
                argv,
                cwd=state_dir,
                env=trusted_environment(),
                stdin=subprocess.DEVNULL,
                stdout=out,
                stderr=err,
                timeout=timeout,
                preexec_fn=_limit_output,
                check=False,
            )
        code = result.returncode if result.returncode >= 0 else 128 - result.returncode
    except subprocess.TimeoutExpired:
        code = 124
    except (OSError, ValueError):
        code = 127
    with open(os.path.join(state_dir, "scan-exit-code.txt"), "w", encoding="utf-8") as handle:
        handle.write("%d\n" % code)
    return 0


# --------------------------------------------------------------------------
# Validating the scanner report
# --------------------------------------------------------------------------

def _no_duplicates(pairs: list) -> dict:
    seen: dict = {}
    for key, value in pairs:
        if key in seen:
            raise ReportError("duplicate key in the report")
        seen[key] = value
    return seen


def _reject_constant(_name: str) -> None:
    raise ReportError("non-standard number in the report")


def _is_int(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value >= 0


def _need(cond: bool, what: str) -> None:
    if not cond:
        raise ReportError(what)


def _obj(value: object, what: str) -> dict:
    _need(isinstance(value, dict), what)
    return value  # type: ignore[return-value]


def _str(value: object, what: str) -> str:
    _need(isinstance(value, str), what)
    return value  # type: ignore[return-value]


def parse_report(raw: bytes) -> dict:
    """Parses and validates a scan report or an error report (schema 1)."""
    _need(len(raw) > 0, "the scanner produced no output")
    _need(len(raw) <= MAX_REPORT_BYTES, "the scanner output is too large")
    try:
        data = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_no_duplicates,
            parse_constant=_reject_constant,
        )
    except (ValueError, RecursionError) as exc:
        if isinstance(exc, ReportError):
            raise
        raise ReportError("the scanner output is not valid JSON") from exc
    top = _obj(data, "the report is not an object")
    _need(top.get("schema_version") == SCHEMA_VERSION and _is_int(top.get("schema_version")),
          "unsupported schema version")
    status = top.get("status")
    _need(status in STATUSES, "unknown status")

    if status == "error":
        _str(top.get("message"), "error report without a message")
        return top

    scanner = _obj(top.get("scanner"), "missing scanner")
    _need(isinstance(scanner.get("name"), str) and isinstance(scanner.get("version"), str),
          "invalid scanner")
    _need(bool(TOKEN.match(scanner["version"])), "invalid scanner version")
    ruleset = _obj(top.get("ruleset"), "missing ruleset")
    _need(bool(TOKEN.match(_str(ruleset.get("id"), "invalid ruleset"))), "invalid ruleset id")
    _need(bool(TOKEN.match(_str(ruleset.get("version"), "invalid ruleset"))), "invalid ruleset version")
    _need(isinstance(ruleset.get("rules"), list)
          and all(isinstance(r, str) for r in ruleset["rules"]), "invalid ruleset rules")
    _obj(top.get("limits"), "missing limits")

    target = _obj(top.get("target"), "missing target")
    _str(target.get("path"), "invalid target path")
    revision = target.get("revision")
    if revision is not None:
        revision = _obj(revision, "invalid revision")
        commit = revision.get("commit")
        _need(commit is None or (isinstance(commit, str) and bool(HEX_OBJECT_ID.match(commit))),
              "invalid revision commit")
        _need(revision.get("reference") is None or isinstance(revision.get("reference"), str),
              "invalid revision reference")

    summary = _obj(top.get("summary"), "missing summary")
    for key in ("files_inspected", "findings", "incomplete"):
        _need(_is_int(summary.get(key)), "invalid summary")

    findings = top.get("findings")
    incomplete = top.get("incomplete")
    _need(isinstance(findings, list) and isinstance(incomplete, list), "invalid lists")
    for item in findings:
        item = _obj(item, "invalid finding")
        _need(isinstance(item.get("rule_id"), str) and bool(RULE_ID.match(item["rule_id"])),
              "invalid finding rule id")
        _need(item.get("severity") in SEVERITIES, "invalid finding severity")
        for key in ("title", "file", "location", "message", "evidence", "remediation"):
            _str(item.get(key), "invalid finding field")
        _need(item.get("line") is None or _is_int(item.get("line")), "invalid finding line")
    for item in incomplete:
        item = _obj(item, "invalid incomplete entry")
        _need(item.get("path") is None or isinstance(item.get("path"), str),
              "invalid incomplete path")
        _need(isinstance(item.get("kind"), str) and bool(KIND.match(item["kind"])),
              "invalid incomplete kind")
        _str(item.get("detail"), "invalid incomplete detail")

    _need(summary["findings"] == len(findings), "finding count does not match the list")
    _need(summary["incomplete"] == len(incomplete), "incomplete count does not match the list")
    if status == "clean":
        _need(not findings and not incomplete, "clean report with findings or gaps")
    elif status == "findings":
        _need(bool(findings) and not incomplete, "findings status does not match the lists")
    else:
        _need(bool(incomplete), "incomplete status without incomplete entries")
    return top


# --------------------------------------------------------------------------
# Evaluating a scan
# --------------------------------------------------------------------------

def _valid(pattern: re.Pattern, value: object) -> str | None:
    return value if isinstance(value, str) and pattern.match(value) else None


def read_context(env: dict) -> dict:
    """Trusted GitHub context, validated. Invalid values are dropped."""
    action_ref = env.get("MLA_ACTION_REF", "")
    return {
        "event": _valid(TOKEN, env.get("MLA_EVENT_NAME", "")),
        "merge_sha": _valid(HEX40, env.get("MLA_SHA", "")),
        "head_sha": _valid(HEX40, env.get("MLA_PR_HEAD_SHA", "")),
        "base_sha": _valid(HEX40, env.get("MLA_PR_BASE_SHA", "")),
        "repository": _valid(REPOSITORY, env.get("MLA_REPOSITORY", "")),
        "run_id": _valid(DIGITS, env.get("MLA_RUN_ID", "")),
        "run_attempt": _valid(DIGITS, env.get("MLA_RUN_ATTEMPT", "")),
        "action_ref": action_ref,
        "action_sha": _valid(HEX40, action_ref),
        "action_repository": _valid(REPOSITORY, env.get("MLA_ACTION_REPOSITORY", "")),
    }


def check_revision(context: dict, observed: str | None) -> str:
    """Compares the revision the checkout recorded with the expected ones.

    Only the `pull_request` event has expected revisions. The result never
    claims that more than the observed revision was scanned.
    """
    if context["event"] != "pull_request" or not (context["merge_sha"] or context["head_sha"]):
        return "not-applicable"
    if observed is None:
        return "unavailable"
    if observed == context["merge_sha"]:
        return "matches-merge"
    if observed == context["head_sha"]:
        return "matches-head"
    return "mismatch"


def read_workspace_head(workspace: str) -> str | None:
    """The commit that the workspace's own checkout recorded, or None.

    Used when the scanned directory is not the checkout root and so has no
    revision of its own. Only a detached HEAD holding a commit ID is accepted,
    which is what actions/checkout writes; a symbolic ref, a `.git` file, or
    anything unusual is "unavailable". Every step is relative to an opened
    directory and refuses symbolic links, so a link inside the pull request's
    files cannot redirect the read.
    """
    fds: list = []
    try:
        fds.append(os.open(workspace, os.O_RDONLY | os.O_DIRECTORY))
        fds.append(os.open(".git", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fds[-1]))
        fds.append(os.open("HEAD", os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fds[-1]))
        info = os.fstat(fds[-1])
        if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_HEAD_BYTES:
            return None
        # One byte more than allowed, so a longer file is seen as longer and not
        # silently cut to a prefix that happens to look like a commit ID.
        data = os.read(fds[-1], MAX_HEAD_BYTES + 1)
        if len(data) > MAX_HEAD_BYTES:
            return None
        text = data.decode("ascii", "replace").strip()
    except OSError:
        return None
    finally:
        for fd in fds:
            os.close(fd)
    return text if HEX_OBJECT_ID.match(text) else None


def inside_nested_checkout(workspace: str, scan_dir: str) -> bool:
    """True when the scanned directory, or a directory between it and the
    workspace root, has a `.git` entry of its own (a nested repository, a
    submodule or worktree `.git` file, or a link). Such a directory's revision
    is its own: when it cannot be read, the parent's must not stand in for it."""
    current = scan_dir
    while current != workspace and current.startswith(workspace.rstrip(os.sep) + os.sep):
        if os.path.lexists(os.path.join(current, ".git")):
            return True
        current = os.path.dirname(current)
    return False


def evaluate(raw: bytes | None, exit_code: int | None, context: dict,
             prepare_error: str | None = None, build_outcome: str | None = None,
             workspace_revision: str | None = None) -> dict:
    """Turns raw scanner output into a trusted result.

    On a pull_request, a result whose revision cannot be verified is an error,
    never clean: either the checkout recorded no readable commit (neither the
    scanned directory nor the workspace root), or GitHub supplied no expected
    commit to compare with. `workspace_revision` is the fallback used when the
    scanned directory has no revision of its own.

    The result always has `status` in clean/findings/incomplete/error. An
    `error` result carries `reason`, written by this file, and `report` is None.
    """
    result: dict = {
        "status": "error", "reason": None, "report": None, "exit_code": exit_code,
        "revision_check": "not-checked", "observed_revision": None,
    }
    if prepare_error:
        result["reason"] = "The scan could not start: %s." % prepare_error
        return result
    if build_outcome is not None and build_outcome != "success":
        result["reason"] = "The scanner could not be built from the Action source."
        return result
    if exit_code is None:
        result["reason"] = "The scanner did not run."
        return result
    if exit_code == 127:
        result["reason"] = "The scanner binary could not be started."
        return result
    if exit_code == 124:
        result["reason"] = "The scanner exceeded its time limit."
        return result
    if exit_code not in (0, 1, 2, 3):
        result["reason"] = "The scanner stopped abnormally (exit code %d)." % exit_code
        return result

    try:
        report = parse_report(raw or b"")
    except ReportError as exc:
        result["reason"] = "The scanner output cannot be trusted: %s." % exc
        return result

    if exit_code == 3 or report["status"] == "error":
        message = report.get("message", "") if report["status"] == "error" else ""
        if exit_code == 3 and report["status"] == "error":
            result["reason"] = "The scanner reported an error."
            result["scanner_message"] = message
        else:
            result["reason"] = "The scanner exit code does not match its report."
        return result
    if EXIT_FOR_STATUS[report["status"]] != exit_code:
        result["reason"] = "The scanner exit code does not match its report status."
        return result

    revision = (report["target"].get("revision") or {}).get("commit") or workspace_revision
    check = check_revision(context, revision)
    result.update(report=report, observed_revision=revision, revision_check=check)
    if check == "mismatch":
        result["status"] = "error"
        result["reason"] = (
            "The checked-out revision is neither the expected merge commit nor the "
            "expected pull request head, so the scan may describe different content."
        )
        return result
    if context["event"] == "pull_request" and check in ("unavailable", "not-applicable"):
        result["status"] = "error"
        result["reason"] = (
            "The checked-out revision could not be verified, so the scan may describe different "
            "content: the checkout recorded no readable commit." if check == "unavailable" else
            "GitHub supplied no expected merge or head commit to compare the checkout with."
        )
        return result
    result["status"] = report["status"]
    return result


# --------------------------------------------------------------------------
# Output and summary
# --------------------------------------------------------------------------

_HEADLINE = {
    "clean": "No findings in the supported checks",
    "findings": "Findings require review",
    "incomplete": "Incomplete: this is not a pass",
    "error": "Error: results cannot be trusted",
}

_DISCLAIMER = (
    "> **Advisory only.** A green check does not mean this pull request is safe. "
    "MergeLatch runs a small set of checks on GitHub workflow files and does not "
    "scan source code for malware. This check can be changed by the pull request "
    "itself and is not a merge gate."
)


def _revision_label(check: str) -> str:
    return {
        "matches-merge": "matches the expected merge commit",
        "matches-head": "matches the expected pull request head",
        "mismatch": "does NOT match the expected merge commit or head",
        "unavailable": "could not be read from the checkout",
        "not-applicable": "no expected revision for this event",
        "not-checked": "not checked (there was no scan result to compare)",
    }[check]


def _action_revision_label(context: dict) -> str:
    """The immutable revision GitHub loaded the Action from, as reported by the
    runner, or a clear statement that there is none."""
    repository = context["action_repository"] or "unknown repository"
    if context["action_sha"] and context["action_repository"]:
        # Both parts were validated against strict patterns (no backticks or
        # markup). A code span is used because GitHub rewrites "owner/repo@sha"
        # in ordinary text into "owner/repo@abc1234", hiding most of the SHA.
        return "`%s@%s`" % (repository, context["action_sha"])
    if context["action_sha"]:
        return "`%s`" % context["action_sha"]
    if context["action_ref"]:
        return "NOT a full commit SHA (reference: %s)" % md(context["action_ref"], 40)
    return "not reported (a local Action has no reference)"


def _source_label(source: str, context: dict) -> str:
    if source not in ("workspace", "action-checkout"):
        return "not determined (the preparation step did not finish)"
    if source == "workspace":
        return ("scanner built from the checked-out workspace (a local Action): "
                "NOT an independently pinned release")
    if context["action_sha"]:
        return "scanner built from the Action checkout pinned at the full commit SHA"
    return ("scanner built from an Action reference that is NOT a full commit SHA "
            "(%s)" % md(context["action_ref"] or "unknown", 40))


def build_summary(result: dict, context: dict, source: str, max_findings: int,
                  toolchain: str | None, ignored: tuple | list = ()) -> str:
    status = result["status"]
    lines = ["### MergeLatch advisory scan: %s" % _HEADLINE[status], "", _DISCLAIMER, ""]
    report = result["report"]

    if status == "error":
        lines += ["**%s**" % md(result["reason"] or "Unknown error.", 300), ""]
        message = result.get("scanner_message")
        if message:
            lines += ["Scanner message: %s" % md(message, 300), ""]
        lines += ["The job failed on purpose so that this is not mistaken for a pass.", ""]
    elif status == "findings":
        lines += ["**%d finding(s) require review.** A finding is a configuration to check, "
                  "not proof of an attack." % len(report["findings"]), ""]
    elif status == "incomplete":
        lines += ["**%d inspection(s) did not finish.** Nothing here shows the scanned files "
                  "are safe." % len(report["incomplete"]), ""]
    elif report["summary"]["files_inspected"] == 0:
        lines += ["**No workflow files were inspected**, so there was nothing to check.", ""]
    else:
        lines += ["No findings in the supported checks. This does not show the pull request "
                  "is safe.", ""]

    rows = [("Event", md(context["event"] or "unknown", 40)),
            ("Repository", md(context["repository"] or "unknown", 80)),
            ("Run", md("%s (attempt %s)" % (context["run_id"] or "?", context["run_attempt"] or "?"), 40)),
            ("Expected merge commit", md(context["merge_sha"] or "not available", 64)),
            ("Expected PR head commit", md(context["head_sha"] or "not available", 64)),
            ("Scanned revision (as recorded by the checkout)", md(result["observed_revision"] or "not available", 64)),
            ("Revision check", _revision_label(result["revision_check"])),
            ("Action revision", _action_revision_label(context)),
            ("Scanner source", _source_label(source, context)),
            ("Rust toolchain", md(toolchain or "unknown", 60))]
    if ignored:
        names = ", ".join(md(name, 40) for name in ignored[:10])
        more = " and %d more" % (len(ignored) - 10) if len(ignored) > 10 else ""
        rows.append(("Inherited build settings ignored", names + more))
    if report:
        rows[:0] = [
            ("Scanner version", md(report["scanner"]["version"], 40)),
            ("Ruleset", md("%s %s" % (report["ruleset"]["id"], report["ruleset"]["version"]), 80)),
            ("Workflow files inspected", str(report["summary"]["files_inspected"])),
            ("Findings", str(report["summary"]["findings"])),
            ("Incomplete inspections", str(report["summary"]["incomplete"])),
        ]
    rows.append(("Scanner exit code", "unavailable" if result["exit_code"] is None else str(result["exit_code"])))
    lines += ["| | |", "|---|---|"] + ["| %s | %s |" % row for row in rows] + [""]

    if report and report["findings"]:
        by_rule: dict = {}
        for item in report["findings"]:
            entry = by_rule.setdefault(item["rule_id"], [item["severity"], item["title"], 0])
            entry[2] += 1
        lines += ["#### Rules matched", "", "| Rule | Severity | Count | Description |", "|---|---|---|---|"]
        for rule_id in sorted(by_rule):
            severity, title, count = by_rule[rule_id]
            lines.append("| %s | %s | %d | %s |" % (md(rule_id, 32), md(severity, 10), count, md(title, 100)))
        lines += ["", "#### Findings", "", "| Rule | File | Location | Evidence |", "|---|---|---|---|"]
        for item in report["findings"][:max_findings]:
            place = item["file"] + (":%d" % item["line"] if item["line"] is not None else "")
            lines.append("| %s | %s | %s | %s |" % (
                md(item["rule_id"], 32), md(place, 100), md(item["location"], 80), md(item["evidence"], 100)))
        hidden = len(report["findings"]) - max_findings
        if hidden > 0:
            lines += ["", "_%d more finding(s) are not shown._" % hidden]
        lines.append("")

    if report and report["incomplete"]:
        lines += ["#### Incomplete inspections", "", "| File | Reason | Detail |", "|---|---|---|"]
        for item in report["incomplete"][:max_findings]:
            lines.append("| %s | %s | %s |" % (
                md(item["path"] or "(whole scan)", 100), md(item["kind"], 40), md(item["detail"], 160)))
        hidden = len(report["incomplete"]) - max_findings
        if hidden > 0:
            lines += ["", "_%d more entr(ies) are not shown._" % hidden]
        lines.append("")

    lines += ["Supported checks: ML-GHA-001 to ML-GHA-004 on `.github/workflows/*.yml` and "
              "`*.yaml` at the root of the scanned directory. See `docs/RULES.md` for coverage "
              "and limits.", ""]
    return "\n".join(lines)


def _count(report: dict | None, key: str) -> str:
    return str(report["summary"][key]) if report else "0"


def report_command(env: dict) -> int:
    state_dir = env.get("MLA_STATE_DIR", "")
    context = read_context(env)
    state: dict = {}
    prepare_error: str | None = None
    try:
        state = load_state(state_dir)
        prepare_error = state.get("error")
    except (OSError, ValueError, ActionError):
        prepare_error = "the preparation step did not complete"

    raw: bytes | None = None
    exit_code: int | None = None
    if not prepare_error:
        try:
            with open(os.path.join(state_dir, "scan-exit-code.txt"), encoding="utf-8") as handle:
                text = handle.read().strip()
            exit_code = int(text) if DIGITS.match(text) else None
        except OSError:
            exit_code = None
        try:
            path = os.path.join(state_dir, "report.json")
            with open(path, "rb") as handle:
                raw = handle.read(MAX_REPORT_BYTES + 1)
        except OSError:
            raw = None

    toolchain: str | None = None
    try:
        with open(os.path.join(state_dir, "rustc-version.txt"), encoding="utf-8") as handle:
            toolchain = handle.read().strip()[:60]
    except OSError:
        pass

    build_outcome = env.get("MLA_BUILD_OUTCOME") or None
    workspace = state.get("workspace")
    scan_dir = state.get("scan_dir")
    workspace_revision = None
    if workspace and scan_dir and not prepare_error and not inside_nested_checkout(workspace, scan_dir):
        workspace_revision = read_workspace_head(workspace)
    result = evaluate(raw, exit_code, context, prepare_error, build_outcome, workspace_revision)
    report = result["report"]
    source = state.get("scanner_source", "unknown")
    max_findings = int(state.get("max_findings", DEFAULT_MAX_FINDINGS))

    pinned = "true" if context["action_sha"] else "false"
    outputs = [
        ("status", result["status"]),
        ("findings-count", _count(report, "findings")),
        ("incomplete-count", _count(report, "incomplete")),
        ("files-inspected", _count(report, "files_inspected")),
        ("scanner-exit-code", "" if result["exit_code"] is None else str(result["exit_code"])),
        ("revision-check", result["revision_check"]),
        ("scanned-revision", result["observed_revision"] or ""),
        ("scanner-version", report["scanner"]["version"] if report else ""),
        ("ruleset", "%s-%s" % (report["ruleset"]["id"], report["ruleset"]["version"]) if report else ""),
        ("scanner-source", source),
        ("action-pinned", pinned),
        ("action-revision", context["action_sha"] or ""),
        ("ignored-environment-count", str(len(state.get("ignored_env") or []))),
    ]
    failures: list = []
    for name, value in outputs:
        try:
            write_output(env, name, value)
        except ActionError as exc:
            failures.append(str(exc))
    try:
        write_summary(env, build_summary(result, context, source, max_findings, toolchain,
                                         state.get("ignored_env") or []))
    except ActionError as exc:
        failures.append(str(exc))

    # Static text only: nothing from the report is printed to the log.
    if result["status"] == "error":
        print("::error title=MergeLatch advisory scan::The scan did not produce a trustworthy "
              "result. See the job summary.")
    elif result["status"] == "findings":
        print("::warning title=MergeLatch advisory scan::Findings require review (%s). "
              "This check is advisory." % _count(report, "findings"))
    elif result["status"] == "incomplete":
        print("::warning title=MergeLatch advisory scan::The scan is incomplete and is not a "
              "pass (%s)." % _count(report, "incomplete"))
    else:
        print("MergeLatch advisory scan finished with no findings. This is not proof of safety.")
    for failure in failures:
        print("::error title=MergeLatch advisory scan::%s" % plain(failure, 100))
    return 1 if (result["status"] == "error" or failures) else 0


def main(argv: list, env: dict | None = None) -> int:
    env = dict(os.environ) if env is None else env
    commands = {"prepare": prepare, "build": build, "scan": scan, "report": report_command}
    if len(argv) != 2 or argv[1] not in commands:
        print("usage: mergelatch_action.py prepare|build|scan|report", file=sys.stderr)
        return 2
    try:
        return commands[argv[1]](env)
    except ActionError as exc:
        print("::error title=MergeLatch advisory scan::%s" % plain(str(exc), 120))
        return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
