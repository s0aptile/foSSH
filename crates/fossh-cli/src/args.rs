//! Minimal shared flag-parsing helpers (ADR-0003: hand-rolled, not
//! `clap` — see `DECISIONS.md`).

/// Finds `--name VALUE` in `args`, accepting either `--name value` (two
/// tokens) or `--name=value` (one token).
pub fn flag_value<'a>(args: &'a [String], name: &str) -> Option<&'a str> {
    for (i, arg) in args.iter().enumerate() {
        if arg == name {
            return args.get(i + 1).map(String::as_str);
        }
        if let Some(rest) = arg.strip_prefix(name)
            && let Some(v) = rest.strip_prefix('=')
        {
            return Some(v);
        }
    }
    None
}

/// Whether a bare boolean flag (e.g. `--public-key`) is present.
pub fn has_flag(args: &[String], name: &str) -> bool {
    args.iter().any(|a| a == name)
}

/// The first argument, if it doesn't look like a flag — used for
/// required positional arguments like `<slug>`.
pub fn positional(args: &[String]) -> Option<&str> {
    args.first()
        .map(String::as_str)
        .filter(|s| !s.starts_with("--"))
}

/// Splits a comma-separated flag value into trimmed, non-empty parts —
/// `--allow a,b, c` -> `["a", "b", "c"]`.
pub fn comma_list(value: &str) -> Vec<String> {
    value
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v(items: &[&str]) -> Vec<String> {
        items.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn flag_value_two_token_form() {
        let args = v(&["site", "--allow", "pageview,signup"]);
        assert_eq!(flag_value(&args, "--allow"), Some("pageview,signup"));
    }

    #[test]
    fn flag_value_equals_form() {
        let args = v(&["site", "--allow=pageview,signup"]);
        assert_eq!(flag_value(&args, "--allow"), Some("pageview,signup"));
    }

    #[test]
    fn flag_value_missing_is_none() {
        let args = v(&["site", "create", "blog"]);
        assert_eq!(flag_value(&args, "--allow"), None);
    }

    #[test]
    fn flag_value_at_end_with_no_value_is_none() {
        let args = v(&["--allow"]);
        assert_eq!(flag_value(&args, "--allow"), None);
    }

    #[test]
    fn has_flag_detects_bare_flag() {
        let args = v(&["create", "blog", "--public-key"]);
        assert!(has_flag(&args, "--public-key"));
        assert!(!has_flag(&args, "--other"));
    }

    #[test]
    fn positional_skips_nothing_but_rejects_flags() {
        assert_eq!(positional(&v(&["blog", "--public-key"])), Some("blog"));
        assert_eq!(positional(&v(&["--public-key"])), None);
        assert_eq!(positional(&[]), None);
    }

    #[test]
    fn comma_list_trims_and_drops_empties() {
        assert_eq!(comma_list("a,b, c ,,d"), vec!["a", "b", "c", "d"]);
        assert_eq!(comma_list(""), Vec::<String>::new());
    }
}
