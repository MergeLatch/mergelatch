//! A small, conservative reader for shell scripts in `run:` steps.
//!
//! It never runs anything. It splits a script into commands and sorts each
//! first word into: runs repository code, known not to, or unrecognized.
//! It is not a shell parser; anything it cannot classify is reported as
//! unrecognized so that callers fail closed.

/// Placeholder that callers put in place of expressions that refer to
/// untrusted pull request code.
pub(crate) const UNTRUSTED_MARK: &str = "UNTRUSTED_EXPR";

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Cmd {
    /// A command that builds, installs, tests, or runs code from the checkout.
    Exec(String),
    /// A command this reader does not recognize.
    Unknown(String),
    /// A command that fetches pull request code into the workspace.
    UntrustedCheckout(String),
}

/// Tools that run project code: package managers with lifecycle scripts, test
/// runners, build tools, interpreters, shells, and container builds.
const EXEC: &[&str] = &[
    "npm",
    "npx",
    "yarn",
    "pnpm",
    "bun",
    "bunx",
    "deno",
    "node",
    "nodejs",
    "pip",
    "pip3",
    "pipx",
    "python",
    "python3",
    "py",
    "pytest",
    "poetry",
    "pdm",
    "uv",
    "uvx",
    "tox",
    "nox",
    "make",
    "gmake",
    "cmake",
    "ctest",
    "ninja",
    "meson",
    "cargo",
    "rustc",
    "rustup",
    "go",
    "gradle",
    "gradlew",
    "mvn",
    "mvnw",
    "ant",
    "bundle",
    "bundler",
    "gem",
    "rake",
    "ruby",
    "rspec",
    "dotnet",
    "msbuild",
    "nuget",
    "php",
    "composer",
    "java",
    "javac",
    "kotlin",
    "sbt",
    "swift",
    "xcodebuild",
    "docker",
    "docker-compose",
    "podman",
    "bash",
    "sh",
    "zsh",
    "dash",
    "ksh",
    "source",
    ".",
    "eval",
    "perl",
    "lua",
    "Rscript",
    "julia",
    "terraform",
    "ansible",
    "pre-commit",
    "husky",
    "lerna",
    "nx",
    "turbo",
    "tsc",
    "eslint",
    "jest",
    "vitest",
    "mocha",
    "prettier",
    "ts-node",
];

/// Commands that do not execute files from the working tree.
const SAFE: &[&str] = &[
    "echo", "printf", "cat", "ls", "pwd", "cd", "mkdir", "cp", "mv", "rm", "touch", "test", "[",
    "[[", "true", "false", "exit", "set", "export", "unset", "git", "gh", "grep", "egrep", "fgrep",
    "sed", "awk", "head", "tail", "wc", "sort", "uniq", "cut", "tr", "diff", "jq", "curl", "wget",
    "tar", "unzip", "zip", "date", "sleep", "read", "local", ":", "tee", "basename", "dirname",
    "readlink", "stat", "chmod", "ln",
];

/// Prefixes that run another command.
const WRAPPERS: &[&str] = &[
    "sudo", "env", "nohup", "timeout", "command", "exec", "nice", "xargs", "stdbuf", "builtin",
];

const SKIPPED: &[&str] = &[
    "if", "elif", "while", "until", "then", "do", "else", "!", "{", "}", "time", "fi", "done",
    "esac", "in",
];

/// Classifies the commands in `script`, in order.
pub(crate) fn analyze(script: &str) -> Vec<Cmd> {
    let script = strip_heredocs(&join_continuations(script));
    let mut out = Vec::new();
    for words in segments(&script) {
        if let Some(cmd) = classify(&words) {
            out.push(cmd);
        }
    }
    out
}

fn join_continuations(script: &str) -> String {
    script.replace("\\\r\n", " ").replace("\\\n", " ")
}

/// Removes here-document bodies, which are data and not commands.
fn strip_heredocs(script: &str) -> String {
    let mut out = String::new();
    let mut delimiter: Option<String> = None;
    for line in script.lines() {
        if let Some(d) = &delimiter {
            if line.trim() == d {
                delimiter = None;
            }
            continue;
        }
        if let Some(pos) = line.find("<<") {
            let rest = line[pos + 2..].trim_start_matches(['-', ' ']);
            let word: String = rest
                .chars()
                .take_while(|c| !c.is_whitespace() && !matches!(c, ';' | '|' | '&' | ')'))
                .filter(|c| !matches!(c, '\'' | '"' | '\\'))
                .collect();
            if !word.is_empty() && !line[pos..].starts_with("<<<") {
                delimiter = Some(word);
            }
        }
        out.push_str(line);
        out.push('\n');
    }
    out
}

/// Splits a script into commands, each a list of unquoted words.
///
/// Separators are `;`, `|`, `&`, newlines, and the start and end of `$(...)`
/// and backtick substitutions. Quotes group words and hide separators.
fn segments(script: &str) -> Vec<Vec<String>> {
    #[derive(Default)]
    struct Out {
        segs: Vec<Vec<String>>,
        words: Vec<String>,
        word: String,
        have_word: bool,
    }
    impl Out {
        fn end_word(&mut self) {
            if self.have_word {
                self.words.push(std::mem::take(&mut self.word));
                self.have_word = false;
            }
        }
        fn end_segment(&mut self) {
            self.end_word();
            if !self.words.is_empty() {
                self.segs.push(std::mem::take(&mut self.words));
            }
        }
        fn push(&mut self, c: char) {
            self.word.push(c);
            self.have_word = true;
        }
    }

    let chars: Vec<char> = script.chars().collect();
    let mut out = Out::default();
    let (mut single, mut double, mut backtick) = (false, false, false);
    // Saved quote state for each open `$(` or backtick.
    let mut subs: Vec<bool> = Vec::new();

    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        let next = chars.get(i + 1).copied();
        if single {
            if c == '\'' {
                single = false;
            } else {
                out.word.push(c);
            }
            i += 1;
            continue;
        }
        if c == '\\' {
            if let Some(n) = next {
                out.push(n);
                i += 2;
                continue;
            }
        } else if c == '\'' && !double {
            single = true;
            out.have_word = true;
        } else if c == '"' {
            double = !double;
            out.have_word = true;
        } else if c == '$' && next == Some('(') {
            out.end_segment();
            subs.push(double);
            double = false;
            i += 2;
            continue;
        } else if c == '`' {
            out.end_segment();
            if backtick {
                double = subs.pop().unwrap_or(false);
            } else {
                subs.push(double);
                double = false;
            }
            backtick = !backtick;
        } else if c == ')' && !double && !backtick && !subs.is_empty() {
            out.end_segment();
            double = subs.pop().unwrap_or(false);
        } else if c == '#' && !double && !out.have_word {
            while i < chars.len() && chars[i] != '\n' {
                i += 1;
            }
            continue;
        } else if c == '&' && !double && (next == Some('>') || (i > 0 && chars[i - 1] == '>')) {
            // A redirection such as `2>&1` or `&>file`, not a background operator.
            out.push(c);
        } else if matches!(c, ';' | '|' | '&' | '\n' | '(' | ')') && !double {
            out.end_segment();
        } else if c.is_whitespace() && !double {
            out.end_word();
        } else {
            out.push(c);
        }
        i += 1;
    }
    out.end_segment();
    out.segs
}

fn is_assignment(word: &str) -> bool {
    match word.split_once('=') {
        Some((name, _)) => {
            !name.is_empty()
                && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
                && !name.starts_with(|c: char| c.is_ascii_digit())
        }
        None => false,
    }
}

fn is_redirection(word: &str) -> bool {
    let trimmed = word.trim_start_matches(|c: char| c.is_ascii_digit());
    trimmed.starts_with('>') || trimmed.starts_with('<')
}

fn classify(words: &[String]) -> Option<Cmd> {
    let mut i = 0;
    while let Some(w) = words.get(i) {
        let w = w.as_str();
        if matches!(w, "for" | "case" | "select" | "function") {
            return None;
        }
        if is_assignment(w) || is_redirection(w) || SKIPPED.contains(&w) {
            i += 1;
        } else if WRAPPERS.contains(&w) {
            i += 1;
            while let Some(arg) = words.get(i) {
                if arg.starts_with('-')
                    || is_assignment(arg)
                    || arg.chars().all(|c| c.is_ascii_digit() || c == '.')
                {
                    i += 1;
                } else {
                    break;
                }
            }
        } else {
            break;
        }
    }
    let rest = words.get(i..)?;
    let first = rest.first()?.as_str();
    if first.is_empty() {
        return None;
    }

    if let Some(kind) = untrusted_checkout(rest) {
        return Some(Cmd::UntrustedCheckout(kind));
    }
    let shown = first.chars().take(60).collect::<String>();
    if first.starts_with('/') || first.starts_with('~') || first.starts_with('$') {
        return Some(Cmd::Unknown(shown));
    }
    // A path inside the working tree, such as ./build.sh or scripts/test.
    if first.contains('/') || EXEC.contains(&first) {
        return Some(Cmd::Exec(shown));
    }
    if SAFE.contains(&first) {
        return None;
    }
    Some(Cmd::Unknown(shown))
}

/// Recognizes commands that bring pull request code into the workspace.
fn untrusted_checkout(words: &[String]) -> Option<String> {
    let first = words.first()?.as_str();
    let second = words.get(1).map(String::as_str).unwrap_or("");
    let third = words.get(2).map(String::as_str).unwrap_or("");
    if first == "gh" && second == "pr" && third == "checkout" {
        return Some("gh pr checkout".to_string());
    }
    if first == "git"
        && matches!(
            second,
            "fetch"
                | "pull"
                | "checkout"
                | "switch"
                | "merge"
                | "cherry-pick"
                | "reset"
                | "rebase"
                | "am"
                | "apply"
        )
        && words
            .iter()
            .any(|w| w.contains(UNTRUSTED_MARK) || w.contains("refs/pull/") || is_pull_ref(w))
    {
        return Some(format!("git {second}"));
    }
    None
}

/// `pull/123/head`, `pull/123/merge`, or `pull/EXPR/head`.
fn is_pull_ref(word: &str) -> bool {
    word.split(':').any(|refspec| {
        let parts: Vec<&str> = refspec.split('/').collect();
        parts
            .windows(3)
            .any(|w| w[0] == "pull" && matches!(w[2], "head" | "merge"))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn exec(c: &str) -> Cmd {
        Cmd::Exec(c.to_string())
    }
    fn unknown(c: &str) -> Cmd {
        Cmd::Unknown(c.to_string())
    }

    #[test]
    fn build_and_test_tools_are_exec() {
        let cmds = analyze(
            "npm ci\nnpm test\nmake -j4\n./gradlew build\npython3 -m pytest\nbash scripts/x.sh",
        );
        assert_eq!(
            cmds,
            [
                exec("npm"),
                exec("npm"),
                exec("make"),
                exec("./gradlew"),
                exec("python3"),
                exec("bash")
            ]
        );
    }

    #[test]
    fn safe_commands_are_not_reported() {
        assert!(analyze("echo hi\ncat file.txt | grep x\ngit diff --stat\ngh pr comment 1 --body ok\ncd src && ls\n").is_empty());
    }

    #[test]
    fn relative_paths_run_repository_files_and_absolute_paths_are_unknown() {
        assert_eq!(analyze("./run.sh"), [exec("./run.sh")]);
        assert_eq!(analyze("scripts/build"), [exec("scripts/build")]);
        assert_eq!(analyze("/usr/bin/thing"), [unknown("/usr/bin/thing")]);
        assert_eq!(analyze("$TOOL run"), [unknown("$TOOL")]);
        assert_eq!(analyze("frobnicate --now"), [unknown("frobnicate")]);
    }

    #[test]
    fn separators_pipes_and_conditionals_are_split() {
        assert_eq!(
            analyze("echo a && npm ci || echo b; make"),
            [exec("npm"), exec("make")]
        );
        assert_eq!(analyze("cat x | sh"), [exec("sh")]);
        assert_eq!(analyze("if npm test; then echo ok; fi"), [exec("npm")]);
        assert_eq!(
            analyze("while make check; do sleep 1; done"),
            [exec("make")]
        );
    }

    #[test]
    fn wrappers_env_assignments_and_redirections_are_skipped() {
        assert_eq!(analyze("CI=1 NODE_ENV=test npm test"), [exec("npm")]);
        assert_eq!(analyze("sudo -E npm ci"), [exec("npm")]);
        assert_eq!(analyze("env FOO=1 make"), [exec("make")]);
        assert_eq!(analyze("timeout 60 pytest"), [exec("pytest")]);
        assert_eq!(analyze("echo hi >out.txt 2>&1"), Vec::<Cmd>::new());
        assert_eq!(analyze("xargs -n1 ./check"), [exec("./check")]);
    }

    #[test]
    fn quotes_hide_separators_and_text() {
        assert!(analyze("echo \"a; npm ci && make\"\necho 'x | sh'").is_empty());
    }

    #[test]
    fn command_substitution_is_analyzed() {
        assert_eq!(analyze("echo $(npm run build)"), [exec("npm")]);
        assert_eq!(analyze("echo \"$(make)\""), [exec("make")]);
        assert_eq!(analyze("x=`./gen`"), [exec("./gen")]);
        assert!(analyze("echo \"$(date)\"").is_empty());
    }

    #[test]
    fn comments_and_heredoc_bodies_are_ignored() {
        assert!(analyze("# npm ci\necho hi # make").is_empty());
        let script = "cat <<'EOF'\nnpm ci\nmake\nEOF\nnpm test\n";
        assert_eq!(analyze(script), [exec("npm")]);
    }

    #[test]
    fn line_continuations_join_commands() {
        assert_eq!(analyze("npm \\\n  ci"), [exec("npm")]);
    }

    #[test]
    fn untrusted_checkout_commands_are_recognized() {
        assert_eq!(
            analyze("gh pr checkout 12"),
            [Cmd::UntrustedCheckout("gh pr checkout".into())]
        );
        assert_eq!(
            analyze("git fetch origin pull/12/head:pr"),
            [Cmd::UntrustedCheckout("git fetch".into())]
        );
        assert_eq!(
            analyze("git fetch origin refs/pull/12/merge"),
            [Cmd::UntrustedCheckout("git fetch".into())]
        );
        assert_eq!(
            analyze("git checkout UNTRUSTED_EXPR"),
            [Cmd::UntrustedCheckout("git checkout".into())]
        );
        // Ordinary git use is neither.
        assert!(analyze("git checkout main\ngit fetch origin main\ngit log -1").is_empty());
    }
}
