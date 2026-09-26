//! Small helpers. Port of `cpdaemon/pkg/cpm/utils.go`.

/// Split an argument string honoring single/double quotes. Port of `splitArgs`.
pub fn split_args(input: &str) -> Result<Vec<String>, String> {
    let mut args: Vec<String> = Vec::new();
    let mut current = String::new();
    let mut in_quote: Option<char> = None;

    for c in input.chars() {
        if c == '\\' && in_quote.is_some() {
            // simple escape handling inside quotes: drop the backslash
            continue;
        } else if in_quote == Some(c) {
            in_quote = None;
        } else if (c == '\'' || c == '"') && in_quote.is_none() {
            in_quote = Some(c);
        } else if c == ' ' && in_quote.is_none() {
            if !current.is_empty() {
                args.push(std::mem::take(&mut current));
            }
        } else {
            current.push(c);
        }
    }

    if !current.is_empty() {
        args.push(current);
    }
    if in_quote.is_some() {
        return Err("unclosed quote".to_string());
    }
    Ok(args)
}

/// Port of `isUnknownFlagError`.
#[allow(dead_code)] // ported helper, not yet wired (PARITY.md §5)
pub fn is_unknown_flag_error(err: &str) -> bool {
    err.contains("unknown flag")
}
