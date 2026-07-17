use regex::RegexBuilder;

use crate::{
    config::{AutoResponseRule, BreakpointRule, ResponseRewriteRule},
    model::BreakpointPhase,
};

pub fn host_is_hidden(host: &str, hidden_hosts: &[String]) -> bool {
    hidden_hosts
        .iter()
        .any(|pattern| pattern_matches(pattern, host, false))
}

pub fn find_auto_response<'a>(
    method: &str,
    host: &str,
    path: &str,
    rules: &'a [AutoResponseRule],
) -> Option<&'a AutoResponseRule> {
    rules.iter().find(|rule| {
        rule.enabled
            && (rule.method.is_empty() || pattern_matches(&rule.method, method, false))
            && pattern_matches(&rule.host, host, false)
            && pattern_matches(&rule.path, path, true)
    })
}

pub fn matching_rewrites<'a>(
    host: &str,
    rules: &'a [ResponseRewriteRule],
) -> Vec<&'a ResponseRewriteRule> {
    rules
        .iter()
        .filter(|rule| !rule.find_text.is_empty() && pattern_matches(&rule.host, host, false))
        .collect()
}

pub fn find_breakpoint<'a>(
    phase: BreakpointPhase,
    method: &str,
    host: &str,
    path: &str,
    status: Option<u16>,
    rules: &'a [BreakpointRule],
) -> Option<&'a BreakpointRule> {
    rules.iter().find(|rule| {
        rule.enabled
            && rule.phase == phase
            && (rule.method.is_empty() || pattern_matches(&rule.method, method, false))
            && pattern_matches(&rule.host, host, false)
            && pattern_matches(&rule.path, path, true)
            && (phase == BreakpointPhase::Request
                || rule.status.is_empty()
                || status
                    .is_some_and(|value| pattern_matches(&rule.status, &value.to_string(), true)))
    })
}

pub fn apply_rewrite(text: &str, rule: &ResponseRewriteRule) -> (String, usize) {
    if rule.find_text.is_empty() {
        return (text.to_owned(), 0);
    }
    if let Some(source) = regex_source(&rule.find_text) {
        let Ok(regex) = RegexBuilder::new(source).build() else {
            return (text.to_owned(), 0);
        };
        let count = regex.find_iter(text).count();
        return (
            regex
                .replace_all(text, rule.replace_text.as_str())
                .into_owned(),
            count,
        );
    }
    let count = text.matches(&rule.find_text).count();
    (text.replace(&rule.find_text, &rule.replace_text), count)
}

pub fn pattern_matches(pattern: &str, value: &str, case_sensitive: bool) -> bool {
    if let Some(source) = regex_source(pattern) {
        return RegexBuilder::new(source)
            .case_insensitive(!case_sensitive)
            .build()
            .is_ok_and(|regex| regex.is_match(value));
    }
    wildcard_matches(pattern, value, case_sensitive)
}

pub fn text_contains_pattern(text: &str, pattern: &str, case_sensitive: bool) -> bool {
    if regex_source(pattern).is_some() {
        return pattern_matches(pattern, text, case_sensitive);
    }
    if case_sensitive {
        text.contains(pattern)
    } else {
        text.to_lowercase().contains(&pattern.to_lowercase())
    }
}

pub fn regex_source(pattern: &str) -> Option<&str> {
    pattern
        .strip_prefix("re:")
        .or_else(|| pattern.strip_prefix("regex:"))
}

pub fn regex_notation_error(pattern: &str) -> Option<String> {
    let source = regex_source(pattern)?;
    RegexBuilder::new(source)
        .build()
        .err()
        .map(|error| error.to_string())
}

pub fn wildcard_matches(pattern: &str, value: &str, case_sensitive: bool) -> bool {
    let (pattern, value) = if case_sensitive {
        (pattern.to_owned(), value.to_owned())
    } else {
        (pattern.to_lowercase(), value.to_lowercase())
    };
    let pattern = pattern.as_bytes();
    let value = value.as_bytes();
    let (mut p, mut v, mut star, mut retry) = (0, 0, None, 0);
    while v < value.len() {
        if p < pattern.len() && pattern[p] == value[v] {
            p += 1;
            v += 1;
        } else if p < pattern.len() && pattern[p] == b'*' {
            star = Some(p);
            p += 1;
            retry = v;
        } else if let Some(star_index) = star {
            p = star_index + 1;
            retry += 1;
            v = retry;
        } else {
            return false;
        }
    }
    while p < pattern.len() && pattern[p] == b'*' {
        p += 1;
    }
    p == pattern.len()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wildcard_supports_host_and_path_rules() {
        assert!(wildcard_matches("*.example.com", "API.EXAMPLE.COM", false));
        assert!(wildcard_matches("/api/*", "/api/users/1", true));
        assert!(!wildcard_matches("/api/*", "/API/users", true));
    }

    #[test]
    fn regex_notation_matches_rule_fields() {
        assert!(pattern_matches(
            r"re:^api\d+\.example\.com$",
            "API12.EXAMPLE.COM",
            false
        ));
        assert!(pattern_matches(r"re:^/users/\d+$", "/users/42", true));
        assert!(!pattern_matches(r"re:^/users/\d+$", "/users/admin", true));
    }

    #[test]
    fn plain_rewrite_matches_host_and_is_case_sensitive() {
        let rule = ResponseRewriteRule {
            host: "api.example.com".into(),
            find_text: "user123".into(),
            replace_text: "admin123".into(),
            ..Default::default()
        };
        assert_eq!(
            apply_rewrite("USER123 user123", &rule),
            ("USER123 admin123".into(), 1)
        );
        let rules = [rule];
        assert_eq!(matching_rewrites("API.EXAMPLE.COM", &rules).len(), 1);
        assert!(matching_rewrites("www.example.com", &rules).is_empty());
    }

    #[test]
    fn regex_rewrite_supports_capture_groups() {
        let rule = ResponseRewriteRule {
            find_text: r"re:user-(\d+)".into(),
            replace_text: "account-$1".into(),
            ..Default::default()
        };
        assert_eq!(
            apply_rewrite("user-12 and user-34", &rule),
            ("account-12 and account-34".into(), 2)
        );
    }

    #[test]
    fn breakpoints_match_phase_and_regex_fields() {
        let rules = [BreakpointRule {
            enabled: true,
            phase: BreakpointPhase::Response,
            method: "re:^(GET|POST)$".into(),
            host: "re:^api\\d+\\.example\\.com$".into(),
            path: "re:^/users/\\d+$".into(),
            status: "re:^4\\d\\d$".into(),
            ..Default::default()
        }];
        assert!(
            find_breakpoint(
                BreakpointPhase::Response,
                "GET",
                "API12.EXAMPLE.COM",
                "/users/42",
                Some(403),
                &rules,
            )
            .is_some()
        );
        assert!(
            find_breakpoint(
                BreakpointPhase::Request,
                "GET",
                "api12.example.com",
                "/users/42",
                None,
                &rules,
            )
            .is_none()
        );
    }
}
