//! Static reading of GitHub Actions `${{ ... }}` expressions.
//!
//! Expressions are tokenized and the context references in them are listed.
//! Nothing is evaluated: there is no value for any context. The goal is to
//! answer "does this text mention a given context path?" without being fooled
//! by case, bracket syntax, or string literals.

/// A `${{ ... }}` expression found in a piece of text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Expression {
    /// The full source text, from `${{` to `}}`.
    pub text: String,
    /// Byte offset of `${{` in the scanned text.
    pub offset: usize,
    /// Context paths referenced, lowercased. Numeric and `*` accessors are `*`.
    pub paths: Vec<Vec<String>>,
    /// Paths whose next accessor is computed (`github.event[matrix.x]`), so the
    /// property actually read cannot be known statically.
    pub dynamic: Vec<Vec<String>>,
    /// The expression can only produce true or false (a comparison, a
    /// negation, or a single `contains`/`startsWith`/`endsWith` call).
    pub boolean: bool,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum ExprError {
    /// `${{` with no closing `}}` at this byte offset.
    Unterminated(usize),
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Tok {
    Ident(String),
    Str(String),
    Num,
    Sym(String),
}

fn is_sym(tok: Option<&Tok>, s: &str) -> bool {
    matches!(tok, Some(Tok::Sym(x)) if x == s)
}

/// Finds every expression in `text`.
pub(crate) fn find_expressions(text: &str) -> Result<Vec<Expression>, ExprError> {
    let mut found = Vec::new();
    let mut from = 0;
    while let Some(rel) = text[from..].find("${{") {
        let start = from + rel;
        let end = find_close(text, start + 3).ok_or(ExprError::Unterminated(start))?;
        let toks = lex(&text[start + 3..end]);
        let (paths, dynamic) = extract_paths(&toks);
        found.push(Expression {
            text: text[start..end + 2].to_string(),
            offset: start,
            paths,
            dynamic,
            boolean: is_boolean(&toks),
        });
        from = end + 2;
    }
    Ok(found)
}

/// Index of the `}}` that closes an expression, skipping string literals.
fn find_close(text: &str, from: usize) -> Option<usize> {
    let bytes = text.as_bytes();
    let mut i = from;
    let mut in_string = false;
    while i < bytes.len() {
        match bytes[i] {
            b'\'' => in_string = !in_string,
            b'}' if !in_string && bytes.get(i + 1) == Some(&b'}') => return Some(i),
            _ => {}
        }
        i += 1;
    }
    None
}

fn lex(inner: &str) -> Vec<Tok> {
    let chars: Vec<char> = inner.chars().collect();
    let mut toks = Vec::new();
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        if c.is_whitespace() {
            i += 1;
        } else if c == '\'' {
            let mut s = String::new();
            i += 1;
            while i < chars.len() {
                if chars[i] == '\'' {
                    if chars.get(i + 1) == Some(&'\'') {
                        s.push('\'');
                        i += 2;
                        continue;
                    }
                    break;
                }
                s.push(chars[i]);
                i += 1;
            }
            i += 1;
            toks.push(Tok::Str(s));
        } else if c.is_ascii_alphabetic() || c == '_' {
            let start = i;
            while i < chars.len()
                && (chars[i].is_ascii_alphanumeric() || chars[i] == '_' || chars[i] == '-')
            {
                i += 1;
            }
            toks.push(Tok::Ident(chars[start..i].iter().collect()));
        } else if c.is_ascii_digit() {
            while i < chars.len() && (chars[i].is_ascii_alphanumeric() || chars[i] == '.') {
                i += 1;
            }
            toks.push(Tok::Num);
        } else {
            let two: String = chars[i..chars.len().min(i + 2)].iter().collect();
            if matches!(two.as_str(), "==" | "!=" | "<=" | ">=" | "&&" | "||") {
                toks.push(Tok::Sym(two));
                i += 2;
            } else {
                toks.push(Tok::Sym(c.to_string()));
                i += 1;
            }
        }
    }
    toks
}

type Paths = Vec<Vec<String>>;

fn extract_paths(toks: &[Tok]) -> (Paths, Paths) {
    let mut paths = Vec::new();
    let mut dynamic = Vec::new();
    let mut idx = 0;
    while idx < toks.len() {
        let Tok::Ident(name) = &toks[idx] else {
            idx += 1;
            continue;
        };
        let after_dot = idx > 0 && is_sym(toks.get(idx - 1), ".");
        let lower = name.to_ascii_lowercase();
        if after_dot
            || is_sym(toks.get(idx + 1), "(")
            || matches!(lower.as_str(), "true" | "false" | "null")
        {
            idx += 1;
            continue;
        }
        let mut path = vec![lower];
        let mut j = idx + 1;
        loop {
            if is_sym(toks.get(j), ".") {
                match toks.get(j + 1) {
                    Some(Tok::Ident(n)) => {
                        path.push(n.to_ascii_lowercase());
                        j += 2;
                    }
                    Some(Tok::Sym(s)) if s == "*" => {
                        path.push("*".into());
                        j += 2;
                    }
                    _ => break,
                }
            } else if is_sym(toks.get(j), "[") {
                match (toks.get(j + 1), toks.get(j + 2)) {
                    (Some(Tok::Str(s)), close) if is_sym(close, "]") => {
                        path.push(s.to_ascii_lowercase());
                        j += 3;
                    }
                    (Some(Tok::Num), close) if is_sym(close, "]") => {
                        path.push("*".into());
                        j += 3;
                    }
                    (Some(Tok::Sym(s)), close) if s == "*" && is_sym(close, "]") => {
                        path.push("*".into());
                        j += 3;
                    }
                    _ => {
                        // Computed accessor. Record the prefix and keep reading
                        // inside the brackets as ordinary tokens.
                        dynamic.push(path.clone());
                        j += 1;
                        break;
                    }
                }
            } else {
                break;
            }
        }
        paths.push(path);
        idx = j;
    }
    (paths, dynamic)
}

fn is_boolean(toks: &[Tok]) -> bool {
    let mut depth = 0i32;
    let mut has_logic = false;
    let mut has_comparison = false;
    for tok in toks {
        if let Tok::Sym(s) = tok {
            match s.as_str() {
                "(" | "[" => depth += 1,
                ")" | "]" => depth -= 1,
                "&&" | "||" if depth == 0 => has_logic = true,
                "==" | "!=" | "<" | ">" | "<=" | ">=" if depth == 0 => has_comparison = true,
                _ => {}
            }
        }
    }
    if has_logic {
        return false;
    }
    if has_comparison || is_sym(toks.first(), "!") {
        return true;
    }
    // A single call to a function that always returns a boolean.
    if let Some(Tok::Ident(f)) = toks.first()
        && is_sym(toks.get(1), "(")
        && matches!(
            f.to_ascii_lowercase().as_str(),
            "contains" | "startswith" | "endswith"
        )
    {
        let mut depth = 0;
        for (i, tok) in toks.iter().enumerate().skip(1) {
            if is_sym(Some(tok), "(") {
                depth += 1;
            } else if is_sym(Some(tok), ")") {
                depth -= 1;
                if depth == 0 {
                    return i == toks.len() - 1;
                }
            }
        }
    }
    false
}

/// How a referenced path relates to a pattern such as `github.event.issue.title`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PathMatch {
    /// The path names the pattern (a trailing `**` also accepts deeper paths).
    Exact,
    /// The path names an enclosing object, so the whole object, including the
    /// pattern's property, is referenced.
    Whole,
}

fn seg_eq(a: &str, b: &str) -> bool {
    a == "*" || b == "*" || a == b
}

pub(crate) fn match_path(path: &[String], pattern: &str) -> Option<PathMatch> {
    let mut segs: Vec<&str> = pattern.split('.').collect();
    let open_ended = segs.last() == Some(&"**");
    if open_ended {
        segs.pop();
    }
    let common = path.len().min(segs.len());
    if !path[..common].iter().zip(&segs).all(|(a, b)| seg_eq(a, b)) {
        return None;
    }
    if path.len() == segs.len() || (open_ended && path.len() > segs.len()) {
        Some(PathMatch::Exact)
    } else if path.len() < segs.len() {
        Some(PathMatch::Whole)
    } else {
        None
    }
}

/// Whether a computed accessor after `prefix` could select `pattern`.
pub(crate) fn dynamic_could_reach(prefix: &[String], pattern: &str) -> bool {
    let segs: Vec<&str> = pattern.split('.').collect();
    prefix.len() < segs.len() && prefix.iter().zip(&segs).all(|(a, b)| seg_eq(a, b))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn one(text: &str) -> Expression {
        let mut all = find_expressions(text).unwrap();
        assert_eq!(all.len(), 1, "{text}");
        all.remove(0)
    }

    fn p(parts: &[&str]) -> Vec<String> {
        parts.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn simple_path_is_lowercased() {
        let e = one("echo ${{ GitHub.Event.Pull_Request.Title }}");
        assert_eq!(e.paths, [p(&["github", "event", "pull_request", "title"])]);
        assert_eq!(e.offset, 5);
        assert_eq!(e.text, "${{ GitHub.Event.Pull_Request.Title }}");
    }

    #[test]
    fn bracket_syntax_is_equivalent() {
        let e = one("${{ github['event']['pull_request'].title }}");
        assert_eq!(e.paths, [p(&["github", "event", "pull_request", "title"])]);
        let e = one("${{ github.event.commits[0].message }}");
        assert_eq!(
            e.paths,
            [p(&["github", "event", "commits", "*", "message"])]
        );
        let e = one("${{ github.event.commits.*.message }}");
        assert_eq!(
            e.paths,
            [p(&["github", "event", "commits", "*", "message"])]
        );
    }

    #[test]
    fn computed_accessor_is_recorded_as_dynamic() {
        let e = one("${{ github.event[matrix.field] }}");
        assert_eq!(e.dynamic, [p(&["github", "event"])]);
        assert!(e.paths.contains(&p(&["matrix", "field"])));
    }

    #[test]
    fn string_literals_are_not_paths_and_may_contain_braces() {
        let e = one("${{ format('{0} }} github.event.issue.title', env.X) }}");
        assert_eq!(e.paths, [p(&["env", "x"])]);
    }

    #[test]
    fn functions_and_literals_are_not_paths() {
        let e = one("${{ format('{0}', github.head_ref) }}");
        assert_eq!(e.paths, [p(&["github", "head_ref"])]);
        let e = one("${{ true && null }}");
        assert!(e.paths.is_empty());
    }

    #[test]
    fn several_expressions_and_unterminated_ones() {
        assert_eq!(find_expressions("${{ a }} and ${{ b }}").unwrap().len(), 2);
        assert_eq!(
            find_expressions("echo ${{ github.head_ref"),
            Err(ExprError::Unterminated(5))
        );
        assert!(
            find_expressions("no expressions $HOME {{ x }}")
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn boolean_valued_expressions_are_recognized() {
        for t in [
            "${{ github.head_ref == 'main' }}",
            "${{ !contains(github.head_ref, 'x') }}",
            "${{ contains(github.head_ref, 'x') }}",
            "${{ startsWith(github.head_ref, 'x') }}",
            "${{ a != b }}",
        ] {
            assert!(one(t).boolean, "{t}");
        }
        for t in [
            "${{ github.head_ref }}",
            "${{ github.head_ref || 'x' }}",
            "${{ github.head_ref == 'x' && github.event.issue.title }}",
            "${{ format('{0}', github.head_ref) }}",
            "${{ contains(a, 'b') && github.head_ref }}",
            "${{ toJSON(github.event) }}",
        ] {
            assert!(!one(t).boolean, "{t}");
        }
    }

    #[test]
    fn path_matching() {
        let path = |s: &str| s.split('.').map(str::to_string).collect::<Vec<_>>();
        let pat = "github.event.commits.*.message";
        assert_eq!(
            match_path(&path("github.event.commits.*.message"), pat),
            Some(PathMatch::Exact)
        );
        assert_eq!(
            match_path(&path("github.event.commits"), pat),
            Some(PathMatch::Whole)
        );
        assert_eq!(match_path(&path("github"), pat), Some(PathMatch::Whole));
        assert_eq!(match_path(&path("github.event.commits.*.id"), pat), None);
        assert_eq!(
            match_path(&path("github.event.commits.*.message.x"), pat),
            None
        );
        assert_eq!(match_path(&path("github.event_name"), pat), None);
        let head = "github.event.pull_request.head.**";
        assert_eq!(
            match_path(&path("github.event.pull_request.head.sha"), head),
            Some(PathMatch::Exact)
        );
        assert_eq!(
            match_path(&path("github.event.pull_request.head"), head),
            Some(PathMatch::Exact)
        );
        assert_eq!(
            match_path(&path("github.event.pull_request.base.sha"), head),
            None
        );
        assert!(dynamic_could_reach(&path("github.event"), pat));
        assert!(!dynamic_could_reach(&path("matrix"), pat));
        assert!(!dynamic_could_reach(
            &path("github.event.commits.*.message"),
            pat
        ));
    }
}
