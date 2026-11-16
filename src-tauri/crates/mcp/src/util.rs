//! Small helpers shared by tool handlers: shell quoting, argument validation and safe truncation.

use crate::error::McpError;
use serde_json::Value;

/// Quote one argument for a POSIX shell (`'...'`, with embedded quotes escaped).
pub fn shell_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\\''"))
}

/// Truncate to at most `max` bytes without splitting a UTF-8 character.
pub fn truncate_utf8(s: &str, max: usize) -> &str {
    if s.len() <= max {
        return s;
    }
    let mut end = max;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    &s[..end]
}

/// Remove ANSI escape sequences (CSI / OSC) and stray carriage returns from terminal output.
pub fn strip_ansi(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let mut chars = input.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '\u{1b}' => match chars.peek() {
                Some('[') => {
                    chars.next();
                    // CSI: parameters/intermediates until a final byte in 0x40..=0x7e.
                    for n in chars.by_ref() {
                        if ('\u{40}'..='\u{7e}').contains(&n) {
                            break;
                        }
                    }
                }
                Some(']') => {
                    chars.next();
                    // OSC: until BEL or ST (ESC \).
                    while let Some(n) = chars.next() {
                        if n == '\u{7}' {
                            break;
                        }
                        if n == '\u{1b}' && chars.peek() == Some(&'\\') {
                            chars.next();
                            break;
                        }
                    }
                }
                Some(_) => {
                    chars.next();
                }
                None => {}
            },
            '\r' => {}
            _ => out.push(c),
        }
    }
    out
}

/// Required string argument.
pub fn req_str<'a>(args: &'a Value, key: &str) -> Result<&'a str, McpError> {
    args.get(key)
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .ok_or_else(|| McpError::InvalidArguments(format!("Missing required argument '{key}'")))
}

/// Optional string argument (empty strings count as missing).
pub fn opt_str<'a>(args: &'a Value, key: &str) -> Option<&'a str> {
    args.get(key)
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
}

/// Optional integer argument clamped to `[min, max]`.
pub fn opt_u64(args: &Value, key: &str, default: u64, min: u64, max: u64) -> u64 {
    args.get(key)
        .and_then(|v| v.as_u64())
        .unwrap_or(default)
        .clamp(min, max)
}

/// A remote path argument: non-empty, no NUL / newlines (they cannot be quoted safely).
pub fn validate_path<'a>(path: &'a str, field: &str) -> Result<&'a str, McpError> {
    if path.is_empty() || path.contains(['\0', '\n', '\r']) {
        return Err(McpError::InvalidArguments(format!("{field}: invalid path")));
    }
    Ok(path)
}

/// Identifier-like value (package, unit, user, namespace, container…): no shell metacharacters
/// and no leading '-' (which would be parsed as an option).
pub fn validate_token<'a>(
    value: &'a str,
    field: &str,
    extra: &[char],
) -> Result<&'a str, McpError> {
    let ok = !value.is_empty()
        && value.len() <= 253
        && !value.starts_with('-')
        && value.chars().all(|c| {
            c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.') || extra.contains(&c)
        });
    if !ok {
        return Err(McpError::InvalidArguments(format!(
            "{field}: '{value}' contains characters that are not allowed"
        )));
    }
    Ok(value)
}

/// A heredoc delimiter that does not occur as a line in `body`.
pub fn heredoc_delimiter(body: &str) -> String {
    let mut n = 0u32;
    loop {
        let candidate = if n == 0 {
            "SSHBOOL_EOF".to_string()
        } else {
            format!("SSHBOOL_EOF_{n}")
        };
        if !body.lines().any(|l| l.trim_end() == candidate) {
            return candidate;
        }
        n += 1;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quoting_neutralises_metacharacters() {
        assert_eq!(shell_quote("a b"), "'a b'");
        assert_eq!(shell_quote("x'; rm -rf ~; '"), "'x'\\''; rm -rf ~; '\\'''");
    }

    #[test]
    fn truncation_respects_char_boundaries() {
        let s = "ab€cd"; // € is 3 bytes
        assert_eq!(truncate_utf8(s, 3), "ab");
        assert_eq!(truncate_utf8(s, 5), "ab€");
        assert_eq!(truncate_utf8(s, 100), s);
    }

    #[test]
    fn ansi_is_stripped() {
        assert_eq!(
            strip_ansi("\u{1b}[1;31mred\u{1b}[0m\r\n\u{1b}]0;title\u{7}ok"),
            "red\nok"
        );
    }

    #[test]
    fn tokens_reject_injection() {
        assert!(validate_token("nginx", "package", &[]).is_ok());
        assert!(validate_token("getty@tty1.service", "unit", &['@']).is_ok());
        for bad in ["", "-rf", "a;b", "a b", "$(id)", "a|b"] {
            assert!(validate_token(bad, "x", &[]).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn heredoc_delimiter_avoids_collisions() {
        assert_eq!(heredoc_delimiter("echo hi"), "SSHBOOL_EOF");
        assert_eq!(heredoc_delimiter("x\nSSHBOOL_EOF\ny"), "SSHBOOL_EOF_1");
    }
}
