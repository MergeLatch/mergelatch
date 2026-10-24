"""Static checks on action.yml and every workflow file in the repository.

These read the files as text, so they need no YAML library. They guard the trust
boundary: untrusted values never reach a shell command, tokens stay read-only,
privileged triggers are never used, and external Actions are pinned.
"""

import json
import pathlib
import re
import tempfile
import unittest

from helpers import REPO_ROOT, SHA_ACTION, SHA_MERGE, Workspace, finding, github_env, mla, raw, report

WORKFLOWS = sorted((REPO_ROOT / ".github" / "workflows").glob("*.yml"))
EXAMPLE = REPO_ROOT / "docs" / "examples" / "pull-request-scan.yml"
ACTION_YML = (REPO_ROOT / "action.yml").read_text()

ATTACKER_FIELDS = re.compile(
    r"github\.event\.(pull_request\.(title|body|head\.(ref|label))|issue\.|comment\.|review|"
    r"discussion|head_commit|commits|pages)|github\.head_ref"
)


def uncommented(text):
    return "\n".join(line for line in text.splitlines() if not line.lstrip().startswith("#"))


class ActionMetadata(unittest.TestCase):
    def test_it_is_a_composite_action_and_every_step_names_its_shell(self):
        self.assertIn("using: composite", ACTION_YML)
        steps = re.findall(r"(?m)^    - ", ACTION_YML)
        self.assertEqual(len(steps), len(re.findall(r"(?m)^      shell: bash$", ACTION_YML)))
        self.assertEqual(len(steps), 4)

    def test_no_expression_is_ever_placed_in_a_run_command(self):
        for line in ACTION_YML.splitlines():
            if line.lstrip().startswith("run:"):
                self.assertNotIn("${{", line)
                self.assertIn('"$MLA_ACTION_PATH/action/', line)

    def test_inputs_and_context_reach_scripts_only_through_env(self):
        for number, line in enumerate(ACTION_YML.splitlines(), 1):
            if "${{" in line and not line.lstrip().startswith(("value:", "if:")):
                self.assertRegex(line, r"^\s+MLA_[A-Z_]+: \$\{\{ [a-z.\-_]+ \}\}$", "line %d" % number)

    def test_no_attacker_controlled_context_is_used_anywhere(self):
        self.assertIsNone(ATTACKER_FIELDS.search(ACTION_YML))

    def test_only_trusted_commit_identifiers_are_read_from_the_pull_request(self):
        fields = set(re.findall(r"github\.event\.[a-z_.]+", ACTION_YML))
        self.assertEqual(fields, {"github.event.pull_request.head.sha", "github.event.pull_request.base.sha"})

    def test_the_action_uses_no_other_actions(self):
        self.assertNotRegex(uncommented(ACTION_YML), r"(?m)^\s+uses:")

    def test_declared_outputs_match_the_outputs_the_helper_writes(self):
        declared = set(re.findall(r"(?m)^  ([a-z-]+):\n    description:.*\n(?:    description:.*\n)*    value: \$\{\{ steps\.report\.outputs", ACTION_YML))
        declared |= set(re.findall(r"(?m)^  ([a-z-]+):\n    description: [^\n]*\n(?:      [^\n]*\n)*    value: \$\{\{ steps\.report\.outputs", ACTION_YML))
        with tempfile.TemporaryDirectory() as tmp:
            state = pathlib.Path(tmp, "state")
            state.mkdir()
            (state / "state.json").write_text(json.dumps({"error": None, "scan_dir": "/x"}))
            (state / "report.json").write_bytes(raw(report()))
            (state / "scan-exit-code.txt").write_text("0\n")
            env = github_env(tmp, MLA_STATE_DIR=str(state))
            mla.report_command(env)
            written = {l.split("=")[0] for l in pathlib.Path(tmp, "output").read_text().splitlines()}
        self.assertEqual(declared, written)

    def test_outputs_are_all_read_from_the_report_step(self):
        for value in re.findall(r"value: (.*)", ACTION_YML):
            self.assertTrue(value.startswith("${{ steps.report.outputs."), value)

    def test_inputs_have_safe_defaults_and_there_is_no_enforcement_input(self):
        self.assertRegex(ACTION_YML, r"(?s)scan-directory:.*?default: '\.'")
        self.assertNotRegex(ACTION_YML, r"(?i)\b(fail|enforce|block|strict)[a-z-]*:")

    def test_the_scan_never_depends_on_files_in_the_scanned_repository(self):
        for path in (pathlib.Path(__file__).parent.parent / "build.sh", pathlib.Path(__file__).parent.parent / "mergelatch_action.py"):
            text = path.read_text()
            self.assertNotIn("MLA_SCAN_DIRECTORY", text)
            self.assertNotRegex(text, r"(?m)^\s*(source|\.)\s+\S*scan")
        build = (pathlib.Path(__file__).parent.parent / "build.sh").read_text()
        self.assertIn('cd -- "${MLA_ACTION_ROOT}"', build)
        self.assertIn("--locked", build)


class Workflows(unittest.TestCase):
    def files(self):
        return [*WORKFLOWS, EXAMPLE]

    def test_there_are_workflows_to_check(self):
        self.assertGreaterEqual(len(WORKFLOWS), 2)
        self.assertTrue(EXAMPLE.exists())

    def test_the_trigger_is_never_privileged(self):
        for path in self.files():
            text = uncommented(path.read_text())
            self.assertNotIn("pull_request_target", text, path.name)
            self.assertNotIn("workflow_run", text, path.name)
            self.assertIn("pull_request", text, path.name)

    def test_tokens_are_read_only_and_there_are_no_secrets(self):
        for path in self.files():
            text = uncommented(path.read_text())
            self.assertNotRegex(text, r":\s*write", path.name)
            self.assertNotRegex(text, r"permissions:\s*write-all", path.name)
            self.assertNotIn("secrets.", text, path.name)
            self.assertNotIn("GITHUB_TOKEN", text, path.name)
            self.assertRegex(text, r"(?m)^permissions:\n  contents: read\n", path.name)
            for match in re.finditer(r"(?m)^( +)permissions:\n\1  (.+)$", text):
                self.assertEqual(match.group(2).strip(), "contents: read", path.name)

    def test_external_actions_are_pinned_to_full_commit_shas(self):
        for path in self.files():
            for line in uncommented(path.read_text()).splitlines():
                match = re.match(r"\s*(?:- )?uses:\s*(\S+)", line)
                if not match:
                    continue
                value = match.group(1)
                if value == "./":
                    continue
                if path == EXAMPLE and value.startswith("MergeLatch/mergelatch@"):
                    # The placeholder must be obviously not a real reference.
                    self.assertEqual(value, "MergeLatch/mergelatch@REPLACE_WITH_REVIEWED_40_CHARACTER_COMMIT_SHA")
                    continue
                self.assertRegex(value, r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_./-]+@[0-9a-f]{40}$", (path.name, value))

    def test_every_checkout_drops_credentials(self):
        for path in self.files():
            text = uncommented(path.read_text())
            checkouts = len(re.findall(r"uses: actions/checkout@", text))
            self.assertEqual(checkouts, len(re.findall(r"persist-credentials: false", text)), path.name)

    def test_runners_are_github_hosted_linux(self):
        for path in self.files():
            for runner in re.findall(r"runs-on:\s*(\S+)", path.read_text()):
                self.assertEqual(runner, "ubuntu-24.04", path.name)

    def test_expressions_are_never_placed_in_run_scripts(self):
        # Multi-line run blocks and single-line runs alike: values go through env.
        for path in self.files():
            text = uncommented(path.read_text())
            for block in re.finditer(r"(?m)^(\s*)run:(.*(?:\n\1\s+.*)*)", text):
                self.assertNotIn("${{", block.group(2), (path.name, block.group(0)[:60]))

    def test_the_required_check_job_name_is_unchanged(self):
        text = (REPO_ROOT / ".github" / "workflows" / "rust.yml").read_text()
        self.assertIn("name: fmt, clippy, test", text)

    def test_the_new_workflows_do_not_reuse_the_required_check_name(self):
        for path in WORKFLOWS:
            if path.name != "rust.yml":
                self.assertNotIn("fmt, clippy, test", path.read_text(), path.name)

    def test_the_example_pins_a_checkout_and_marks_itself_not_runnable(self):
        text = EXAMPLE.read_text()
        self.assertIn("NOT RUNNABLE YET", text)
        self.assertNotRegex(text, r"MergeLatch/mergelatch@(main|master|v\d)")
        self.assertIn("runs-on: ubuntu-24.04", text)

    def test_the_example_scans_the_merge_commit_unless_told_otherwise(self):
        text = uncommented(EXAMPLE.read_text())
        self.assertNotIn("ref:", text)


class PlaceholdersAreNotRealShas(unittest.TestCase):
    def test_no_made_up_future_action_sha_appears_in_the_docs(self):
        for path in (REPO_ROOT / "README.md", REPO_ROOT / "docs" / "ACTION.md", EXAMPLE):
            if not path.exists():
                continue
            for sha in re.findall(r"MergeLatch/mergelatch@([0-9a-f]{40})", path.read_text()):
                self.fail("%s names a MergeLatch commit that cannot exist yet: %s" % (path.name, sha))


if __name__ == "__main__":
    unittest.main()
