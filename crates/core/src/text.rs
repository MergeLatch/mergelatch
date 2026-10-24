use std::fmt::Write;

/// Makes text taken from a scanned repository safe to print.
///
/// Control characters, including terminal escape sequences, are replaced with
/// visible `\u{..}` escapes. Text longer than `max_chars` is truncated and
/// marked with `...`.
pub fn sanitize_text(input: &str, max_chars: usize) -> String {
    let mut out = String::new();
    for (count, ch) in input.chars().enumerate() {
        if count >= max_chars {
            out.push_str("...");
            break;
        }
        if ch.is_control() {
            let _ = write!(out, "\\u{{{:x}}}", ch as u32);
        } else {
            out.push(ch);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plain_text_is_unchanged() {
        assert_eq!(
            sanitize_text("permissions: write-all", 100),
            "permissions: write-all"
        );
    }

    #[test]
    fn control_characters_are_escaped() {
        assert_eq!(sanitize_text("a\u{1b}[31mb\n", 100), "a\\u{1b}[31mb\\u{a}");
    }

    #[test]
    fn long_text_is_truncated() {
        assert_eq!(sanitize_text("abcdef", 3), "abc...");
    }
}
