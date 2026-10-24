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
    "sed", "awk", "gawk", "mawk", "nawk", "head", "tail", "wc", "sort", "uniq", "cut", "tr",
    "diff", "jq", "curl", "wget", "tar", "unzip", "zip", "date", "sleep", "read", "local", ":",
    "tee", "basename", "dirname", "readlink", "stat", "chmod", "ln",
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
            let options: Vec<&str> = words[i + 1..]
                .iter()
                .map(String::as_str)
                .take_while(|a| a.starts_with('-'))
                .collect();
            match w {
                // `command -v name` only looks a name up.
                "command" if options.iter().any(|o| matches!(*o, "-v" | "-V")) => return None,
                // `env -S` splits a string into a command line.
                "env"
                    if options.iter().any(|o| {
                        *o == "-S"
                            || o.starts_with("--split-string")
                            || (o.starts_with("-S") && !o.starts_with("--"))
                    }) =>
                {
                    return Some(Cmd::Exec("env -S".into()));
                }
                // `sudo -s` and `-i` start a shell.
                "sudo"
                    if options
                        .iter()
                        .any(|o| matches!(*o, "-s" | "-i" | "--shell" | "--login")) =>
                {
                    return Some(Cmd::Exec("sudo shell".into()));
                }
                _ => {}
            }
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
        return match by_arguments(first, &rest[1..]) {
            Safety::Safe => None,
            Safety::Exec(what) => Some(Cmd::Exec(what)),
            Safety::Unknown(what) => Some(Cmd::Unknown(what)),
        };
    }
    Some(Cmd::Unknown(shown))
}

/// Result of looking at the arguments of an otherwise-safe command.
#[derive(Debug, PartialEq, Eq)]
enum Safety {
    Safe,
    /// The arguments make the command run another program or a script.
    Exec(String),
    /// The form is not one this reader can judge.
    Unknown(String),
}

/// Some commands are safe with most arguments but can run programs with
/// others: Git aliases and `-c` settings, `sed`'s `e` command, `awk`'s
/// `system()`, `tar --to-command`. Names alone are not enough to trust them.
fn by_arguments(command: &str, args: &[String]) -> Safety {
    match command {
        "git" => git(args),
        "gh" => gh(args),
        "sed" => sed(args),
        "awk" | "gawk" | "mawk" | "nawk" => awk(args),
        "tar" => {
            let runs_helper = args.iter().any(|a| {
                a.starts_with("--to-command")
                    || a.starts_with("--checkpoint-action")
                    || a.starts_with("--use-compress-program")
                    || a.starts_with("--rsh-command")
                    || a.starts_with("--info-script")
                    || a.starts_with("--new-volume-script")
                    || a == "-F"
                    || (a.starts_with("-I") && !a.starts_with("--"))
            });
            if runs_helper {
                Safety::Exec("tar (runs a helper program)".into())
            } else {
                Safety::Safe
            }
        }
        "zip"
            if args
                .iter()
                .any(|a| a == "-TT" || a.starts_with("--unzip-command")) =>
        {
            Safety::Exec("zip -TT".into())
        }
        "sort" if args.iter().any(|a| a.starts_with("--compress-program")) => {
            Safety::Exec("sort --compress-program".into())
        }
        _ => Safety::Safe,
    }
}

/// Git subcommands that read or change repository data without running a
/// program chosen by the working tree. They can still run hooks if
/// `core.hooksPath` was set earlier; setting it is itself classified as
/// execution, as is any command that installs dependencies.
const GIT_SAFE: &[&str] = &[
    "add",
    "am",
    "apply",
    "blame",
    "branch",
    "cat-file",
    "checkout",
    "cherry-pick",
    "clean",
    "clone",
    "commit",
    "describe",
    "diff",
    "diff-tree",
    "fetch",
    "help",
    "init",
    "log",
    "ls-files",
    "ls-remote",
    "ls-tree",
    "merge",
    "merge-base",
    "mv",
    "pull",
    "push",
    "remote",
    "reset",
    "restore",
    "rev-list",
    "rev-parse",
    "rm",
    "shortlog",
    "show",
    "show-ref",
    "stash",
    "status",
    "switch",
    "tag",
    "version",
];

/// Arguments that make a Git command run a program.
fn git_exec_argument(arg: &str) -> bool {
    arg.starts_with("--upload-pack")
        || arg.starts_with("--receive-pack")
        || arg.starts_with("--exec")
        || arg == "--ext-diff"
        || arg == "--textconv"
        || arg.starts_with("--open-files-in-pager")
}

fn git(args: &[String]) -> Safety {
    // Global options come before the subcommand. `-c name=value` and
    // `--config-env` can set aliases, pagers, and other command-valued
    // settings.
    let mut i = 0;
    let mut sub = None;
    while let Some(arg) = args.get(i) {
        let arg = arg.as_str();
        if arg == "-c"
            || arg.starts_with("--config-env")
            || (arg.starts_with("-c") && !arg.starts_with("--"))
        {
            return Safety::Exec("git -c (sets configuration, including aliases)".into());
        }
        if arg.starts_with("--exec-path") {
            return Safety::Exec("git --exec-path".into());
        }
        if arg == "-C" {
            i += 2;
        } else if arg.starts_with('-') {
            i += 1;
        } else {
            sub = Some(arg);
            break;
        }
    }
    let Some(sub) = sub else { return Safety::Safe };
    let rest = &args[i + 1..];

    if rest.iter().any(|a| git_exec_argument(a))
        || (sub == "grep" && rest.iter().any(|a| a == "-O" || a.starts_with("-O")))
    {
        return Safety::Exec(format!("git {sub} (runs a program given in its arguments)"));
    }
    match sub {
        "difftool" | "mergetool" | "filter-branch" | "hook" | "instaweb" => {
            Safety::Exec(format!("git {sub}"))
        }
        "submodule" if rest.iter().any(|a| a == "foreach") => {
            Safety::Exec("git submodule foreach".into())
        }
        "submodule" => Safety::Unknown("git submodule".into()),
        "bisect" if rest.iter().any(|a| a == "run") => Safety::Exec("git bisect run".into()),
        "bisect" => Safety::Safe,
        "rebase"
            if rest.iter().any(|a| {
                a == "-x" || a == "-i" || a == "--interactive" || a.starts_with("--exec")
            }) =>
        {
            Safety::Exec("git rebase --exec".into())
        }
        "rebase" | "grep" => Safety::Safe,
        "config" => {
            let reads = rest.iter().any(|a| {
                matches!(
                    a.as_str(),
                    "--get" | "--get-all" | "--get-regexp" | "--get-urlmatch" | "--list" | "-l"
                )
            });
            if reads {
                Safety::Safe
            } else {
                Safety::Exec("git config (can set aliases and command settings)".into())
            }
        }
        s if GIT_SAFE.contains(&s) => Safety::Safe,
        // Not a built-in subcommand this reader knows: it may be an alias or
        // an external `git-<name>` program.
        other => Safety::Unknown(format!(
            "git {}",
            other.chars().take(40).collect::<String>()
        )),
    }
}

/// GitHub CLI subcommands that only call the API or manage GitHub objects.
const GH_SAFE: &[&str] = &[
    "pr", "issue", "repo", "api", "release", "run", "workflow", "label", "search", "status",
    "auth", "browse", "gist", "project", "variable", "secret", "cache", "ruleset", "org",
    "version", "help",
];

fn gh(args: &[String]) -> Safety {
    let mut i = 0;
    let mut sub = None;
    while let Some(arg) = args.get(i) {
        let arg = arg.as_str();
        if matches!(arg, "-R" | "--repo") {
            i += 2;
        } else if arg.starts_with('-') {
            i += 1;
        } else {
            sub = Some(arg);
            break;
        }
    }
    let Some(sub) = sub else { return Safety::Safe };
    let rest = &args[i + 1..];
    match sub {
        // Aliases can wrap shell commands; extensions are programs.
        "alias" | "extension" | "ext" => Safety::Exec(format!("gh {sub}")),
        "config" if rest.first().is_some_and(|a| a == "set") => {
            Safety::Exec("gh config set (can set editor and pager programs)".into())
        }
        "config" => Safety::Safe,
        s if GH_SAFE.contains(&s) => Safety::Safe,
        // Anything else may be an installed extension.
        other => Safety::Unknown(format!("gh {}", other.chars().take(40).collect::<String>())),
    }
}

fn sed(args: &[String]) -> Safety {
    let mut scripts: Vec<&str> = Vec::new();
    let mut from_file = false;
    let mut sandbox = false;
    let mut script_taken = false;
    let mut i = 0;
    while let Some(arg) = args.get(i) {
        let arg = arg.as_str();
        i += 1;
        if arg == "--sandbox" {
            sandbox = true;
        } else if let Some(script) = arg.strip_prefix("--expression=") {
            scripts.push(script);
            script_taken = true;
        } else if arg == "--expression" || arg == "-e" {
            if let Some(script) = args.get(i) {
                scripts.push(script);
            }
            script_taken = true;
            i += 1;
        } else if arg == "-f" || arg == "--file" || arg.starts_with("--file=") {
            from_file = true;
            script_taken = true;
            if arg != "--file=" && !arg.contains('=') {
                i += 1;
            }
        } else if arg.starts_with("--") {
            // Long options without a script.
        } else if arg.starts_with('-') && arg.len() > 1 {
            // Short option clusters such as -n, -i, -E, or -ne. A cluster that
            // ends in e or f takes the next word as its script or file.
            if arg.ends_with('e') {
                if let Some(script) = args.get(i) {
                    scripts.push(script);
                }
                script_taken = true;
                i += 1;
            } else if arg.ends_with('f') {
                from_file = true;
                script_taken = true;
                i += 1;
            }
        } else if !script_taken {
            scripts.push(arg);
            script_taken = true;
        }
    }
    if sandbox {
        return Safety::Safe;
    }
    if from_file {
        return Safety::Unknown("sed -f (script read from a file)".into());
    }
    for script in scripts {
        match sed_script(script) {
            SedScript::Plain => {}
            SedScript::Executes => return Safety::Exec("sed (e command or s///e flag)".into()),
            SedScript::Unparsed => {
                return Safety::Unknown("sed (script not understood)".into());
            }
        }
    }
    Safety::Safe
}

#[derive(Debug, PartialEq, Eq)]
enum SedScript {
    Plain,
    /// Uses the GNU `e` command or the `e` flag of `s`, which run a shell command.
    Executes,
    /// The reader could not follow the script.
    Unparsed,
}

/// A small reader for sed scripts, enough to see commands and `s` flags.
fn sed_script(script: &str) -> SedScript {
    let c: Vec<char> = script.chars().collect();
    let mut i = 0;
    // Reads text up to the next unescaped `delim`, returning false at end of input.
    fn skip_to(c: &[char], i: &mut usize, delim: char) -> bool {
        while *i < c.len() {
            if c[*i] == '\\' {
                *i += 2;
            } else if c[*i] == delim {
                *i += 1;
                return true;
            } else {
                *i += 1;
            }
        }
        false
    }
    while i < c.len() {
        // Separators and block braces between commands.
        while i < c.len() && (c[i].is_whitespace() || matches!(c[i], ';' | '{' | '}')) {
            i += 1;
        }
        // An optional address: line numbers, `$`, `/re/`, `\cREc`, ranges, `!`.
        loop {
            match c.get(i) {
                Some(ch)
                    if ch.is_ascii_digit() || matches!(ch, '$' | ',' | '~' | '+' | '!' | ' ') =>
                {
                    i += 1
                }
                Some('/') => {
                    i += 1;
                    if !skip_to(&c, &mut i, '/') {
                        return SedScript::Unparsed;
                    }
                    while matches!(c.get(i), Some('I') | Some('M')) {
                        i += 1;
                    }
                }
                Some('\\') => {
                    let Some(&d) = c.get(i + 1) else {
                        return SedScript::Unparsed;
                    };
                    i += 2;
                    if !skip_to(&c, &mut i, d) {
                        return SedScript::Unparsed;
                    }
                }
                _ => break,
            }
        }
        let Some(&cmd) = c.get(i) else { break };
        i += 1;
        match cmd {
            'e' => return SedScript::Executes,
            's' => {
                let Some(&d) = c.get(i) else {
                    return SedScript::Unparsed;
                };
                i += 1;
                if !skip_to(&c, &mut i, d) || !skip_to(&c, &mut i, d) {
                    return SedScript::Unparsed;
                }
                while let Some(&f) = c.get(i) {
                    if f == 'e' {
                        return SedScript::Executes;
                    }
                    if f == 'w' {
                        // The file name runs to the end of the line.
                        while i < c.len() && c[i] != '\n' {
                            i += 1;
                        }
                        break;
                    }
                    if f.is_ascii_alphanumeric() {
                        i += 1;
                    } else {
                        break;
                    }
                }
            }
            'y' => {
                let Some(&d) = c.get(i) else {
                    return SedScript::Unparsed;
                };
                i += 1;
                if !skip_to(&c, &mut i, d) || !skip_to(&c, &mut i, d) {
                    return SedScript::Unparsed;
                }
            }
            // Text, file names, and labels run to the end of the line.
            'a' | 'i' | 'c' | 'r' | 'R' | 'w' | 'W' | 'b' | 't' | 'T' | ':' => {
                while i < c.len() && c[i] != '\n' {
                    i += 1;
                }
            }
            'p' | 'P' | 'd' | 'D' | 'g' | 'G' | 'h' | 'H' | 'n' | 'N' | 'x' | 'z' | '=' | 'l'
            | 'q' | 'Q' | 'F' | 'L' => {
                // Some take an optional number argument.
                while matches!(c.get(i), Some(ch) if ch.is_ascii_digit()) {
                    i += 1;
                }
            }
            '#' => {
                while i < c.len() && c[i] != '\n' {
                    i += 1;
                }
            }
            _ => return SedScript::Unparsed,
        }
    }
    SedScript::Plain
}

fn awk(args: &[String]) -> Safety {
    let mut program: Option<&str> = None;
    let mut i = 0;
    while let Some(arg) = args.get(i) {
        let arg = arg.as_str();
        i += 1;
        match arg {
            "-f" | "--file" | "-i" | "--include" | "-l" | "--load" | "-E" | "--exec" => {
                return Safety::Unknown("awk (program or library read from a file)".into());
            }
            "-F" | "-v" | "--field-separator" | "--assign" => i += 1,
            _ if arg.starts_with("--file=")
                || arg.starts_with("--include=")
                || arg.starts_with("--load=")
                || arg.starts_with("-f") && arg.len() > 2 =>
            {
                return Safety::Unknown("awk (program or library read from a file)".into());
            }
            _ if arg.starts_with('-') && arg.len() > 1 => {}
            _ => {
                program = Some(arg);
                break;
            }
        }
    }
    let Some(program) = program else {
        return Safety::Safe;
    };
    let without_or = program.replace("||", "");
    if program.contains("system") || program.contains("popen") || without_or.contains('|') {
        return Safety::Exec("awk (system() or a pipe to or from a command)".into());
    }
    if program.contains("@load") || program.contains("@include") {
        return Safety::Unknown("awk (loads an extension or library)".into());
    }
    Safety::Safe
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
pub(crate) fn is_pull_ref(word: &str) -> bool {
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

    // ---- Argument-aware classification ------------------------------------

    fn is_exec(script: &str) -> bool {
        matches!(analyze(script).as_slice(), [Cmd::Exec(_)])
    }
    fn is_unknown(script: &str) -> bool {
        matches!(analyze(script).as_slice(), [Cmd::Unknown(_)])
    }
    fn is_safe(script: &str) -> bool {
        analyze(script).is_empty()
    }

    #[test]
    fn git_configuration_and_aliases_can_run_programs() {
        for script in [
            "git -c alias.x='!sh -c id' x",
            "git -calias.x=!id x",
            "git -c core.pager=sh log",
            "git --config-env=alias.x=VAR x",
            "git config alias.co '!npm test'",
            "git config --global core.hooksPath .githooks",
            "git config user.name someone",
            "git difftool",
            "git mergetool",
            "git bisect run ./check",
            "git rebase --exec make main",
            "git rebase -x make main",
            "git rebase -i main",
            "git submodule foreach 'npm install'",
            "git filter-branch --tree-filter id",
            "git grep -O vim needle",
            "git diff --ext-diff",
            "git log --textconv",
            "git fetch --upload-pack=sh origin",
            "git hook run pre-commit",
            "git --exec-path=/tmp/x status",
        ] {
            assert!(is_exec(script), "{script}: {:?}", analyze(script));
        }
    }

    #[test]
    fn unrecognized_git_subcommands_are_unknown() {
        // A user-defined alias or an external git-<name> program.
        for script in [
            "git co",
            "git mycommand --flag",
            "git submodule update --init",
        ] {
            assert!(is_unknown(script), "{script}: {:?}", analyze(script));
        }
    }

    #[test]
    fn ordinary_git_operations_stay_safe() {
        for script in [
            "git diff --stat",
            "git diff --stat origin/main...HEAD",
            "git -C sub log --oneline -n 5",
            "git --no-pager show HEAD",
            "git status --short",
            "git rev-parse HEAD",
            "git commit -m 'message'",
            "git push origin HEAD",
            "git fetch origin main",
            "git checkout main",
            "git config --get remote.origin.url",
            "git config -l",
            "git rebase main",
            "git bisect start",
            "git grep needle",
            "git add -A && git commit -m x",
        ] {
            assert!(is_safe(script), "{script}: {:?}", analyze(script));
        }
    }

    #[test]
    fn gh_aliases_extensions_and_unknown_subcommands_are_not_safe() {
        for script in [
            "gh alias set x '!npm test'",
            "gh extension exec foo",
            "gh ext install owner/gh-tool",
            "gh config set editor vim",
        ] {
            assert!(is_exec(script), "{script}: {:?}", analyze(script));
        }
        assert!(is_unknown("gh some-extension --flag"));
    }

    #[test]
    fn ordinary_gh_operations_stay_safe() {
        for script in [
            "gh pr comment 1 --body hi",
            "gh pr view 1 --json title",
            "gh api repos/o/r/pulls",
            "gh --repo o/r issue list",
            "gh -R o/r pr list",
            "gh config get editor",
            "gh release download v1",
        ] {
            assert!(is_safe(script), "{script}: {:?}", analyze(script));
        }
        assert_eq!(
            analyze("gh pr checkout 1"),
            [Cmd::UntrustedCheckout("gh pr checkout".into())]
        );
    }

    #[test]
    fn sed_that_executes_commands_is_exec() {
        for script in [
            "sed 's/a/b/e' f",
            "sed 's/a/b/ge' f",
            "sed -e 'e id' f",
            "sed -ne '1e id' f",
            "sed '1e id' f",
            "sed -n '/x/e id' f",
            "sed --expression='e id' f",
            "sed -e 'p;e id' f",
            "sed 's|a|b|e' f",
        ] {
            assert!(is_exec(script), "{script}: {:?}", analyze(script));
        }
    }

    #[test]
    fn sed_script_files_and_unparsed_scripts_are_unknown() {
        assert!(is_unknown("sed -f script.sed f"));
        assert!(is_unknown("sed --file=script.sed f"));
        assert!(is_unknown("sed 's/unterminated' f"));
    }

    #[test]
    fn plain_sed_stays_safe() {
        for script in [
            "sed -n '1p' f",
            "sed -i 's/a/b/g' f",
            "sed 's|a|b|gI' f",
            "sed '/x/d' f",
            "sed '$!N;P;D' f",
            "sed 's/a/b/w out.txt' f",
            "sed 's/a\\/e/b/' f",
            "sed -E 's/(a|b)+/c/' f",
            "sed --sandbox 's/a/b/e' f",
            "sed -n -e '2,4p' f",
            "sed 'y/abc/xyz/' f",
            "sed '1!G;h;$!d' f",
        ] {
            assert!(is_safe(script), "{script}: {:?}", analyze(script));
        }
    }

    #[test]
    fn awk_that_runs_commands_is_exec() {
        for script in [
            "awk 'BEGIN{system(\"id\")}'",
            "gawk 'BEGIN { system(\"id\") }'",
            "awk '{print | \"sh\"}' f",
            "awk '{ \"date\" | getline d }' f",
            "awk 'BEGIN{ \"id\" | getline }'",
            "awk -F: -v a=1 'BEGIN{system(a)}'",
        ] {
            assert!(is_exec(script), "{script}: {:?}", analyze(script));
        }
    }

    #[test]
    fn awk_program_files_are_unknown_and_plain_awk_is_safe() {
        assert!(is_unknown("awk -f prog.awk f"));
        assert!(is_unknown("gawk -i inplace '{print}' f"));
        for script in [
            "awk '{print $1}' f",
            "awk -F: '$1==\"x\" || $2' f",
            "awk -v a=1 '{print a}' f",
            "awk 'END{print NR}' f",
        ] {
            assert!(is_safe(script), "{script}: {:?}", analyze(script));
        }
    }

    #[test]
    fn archive_and_sort_helpers_that_run_programs_are_exec() {
        for script in [
            "tar -xf a.tar --to-command=sh",
            "tar --checkpoint=1 --checkpoint-action=exec=sh -cf x.tar y",
            "tar -I zstd -xf a.tar.zst",
            "tar --use-compress-program=gzip -xf a",
            "sort --compress-program=sh f",
            "zip -T -TT 'sh -c id' a.zip f",
        ] {
            assert!(is_exec(script), "{script}: {:?}", analyze(script));
        }
        for script in [
            "tar -xzf a.tgz",
            "tar -cf a.tar dir",
            "sort -u f",
            "zip -r a.zip dir",
        ] {
            assert!(is_safe(script), "{script}: {:?}", analyze(script));
        }
    }

    #[test]
    fn wrappers_that_run_other_programs_are_followed() {
        for script in [
            "env -S 'npm test'",
            "env -i make",
            "sudo -s",
            "sudo -i",
            "sudo npm ci",
            "exec npm test",
            "command npm test",
            "nohup ./run.sh",
        ] {
            assert!(is_exec(script), "{script}: {:?}", analyze(script));
        }
        assert!(is_safe("command -v npm"));
        assert!(is_safe("command -V git"));
    }

    #[test]
    fn compound_commands_and_substitutions_are_classified_per_command() {
        assert_eq!(
            analyze("git diff --stat && git -c alias.x='!id' x"),
            [Cmd::Exec(
                "git -c (sets configuration, including aliases)".into()
            )]
        );
        assert_eq!(analyze("git diff $(npm bin)"), [exec("npm")]);
        assert!(matches!(
            analyze("echo $(git -c core.pager=sh log)").as_slice(),
            [Cmd::Exec(_)]
        ));
        assert_eq!(analyze("git log | sh"), [exec("sh")]);
        assert!(is_safe("git diff --stat | head -5 | wc -l"));
    }

    #[test]
    fn shell_alias_definitions_are_not_safe() {
        assert!(is_unknown("alias ll='ls -l'"));
        assert!(is_unknown("unalias ll"));
    }
}
