use crate::{
    model::{Session, header_value},
    rules::{pattern_matches, regex_source, text_contains_pattern},
};

pub fn matches_filter(session: &Session, expression: &str) -> bool {
    let expression = expression.trim();
    if expression.is_empty() {
        return true;
    }
    expression.split_whitespace().all(|token| {
        if regex_source(token).is_some() {
            return text_contains_pattern(&session.searchable_text(), token, false);
        }
        match token.split_once(':') {
            Some((field, value)) => field_matches(session, field, value),
            None => text_contains_pattern(&session.searchable_text(), token, false),
        }
    })
}

fn field_matches(session: &Session, field: &str, value: &str) -> bool {
    match (field.to_ascii_lowercase().as_str(), session) {
        ("method", Session::Http(item)) => wildcard(&item.request.method, value),
        ("host", Session::Http(item)) => wildcard(&item.request.host, value),
        ("host", Session::WebSocket(item)) => wildcard(&item.host, value),
        ("path", Session::Http(item)) => wildcard(&item.request.path, value),
        ("path", Session::WebSocket(item)) => wildcard(&item.path, value),
        ("process", Session::Http(item)) => wildcard(&item.request.process, value),
        ("status", Session::Http(item)) => item
            .response
            .as_ref()
            .is_some_and(|response| numeric_match(response.status as f64, value)),
        ("duration", Session::Http(item)) => item.response.as_ref().is_some_and(|response| {
            numeric_match(response.duration_ms, value.trim_end_matches("ms"))
        }),
        ("content-type", Session::Http(item)) => item
            .response
            .as_ref()
            .and_then(|response| header_value(&response.headers, "content-type"))
            .is_some_and(|content_type| wildcard(content_type, value)),
        _ => text_contains_pattern(&session.searchable_text(), value, false),
    }
}

fn wildcard(actual: &str, expected: &str) -> bool {
    pattern_matches(expected, actual, false)
}

fn numeric_match(actual: f64, expression: &str) -> bool {
    for operator in [">=", "<=", ">", "<", "="] {
        if let Some(value) = expression
            .strip_prefix(operator)
            .and_then(|v| v.parse::<f64>().ok())
        {
            return match operator {
                ">=" => actual >= value,
                "<=" => actual <= value,
                ">" => actual > value,
                "<" => actual < value,
                _ => (actual - value).abs() < f64::EPSILON,
            };
        }
    }
    expression
        .parse::<f64>()
        .is_ok_and(|value| (actual - value).abs() < f64::EPSILON)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{CapturedExchange, CapturedRequest, CapturedResponse, Session};
    use chrono::Utc;
    use uuid::Uuid;

    fn session() -> Session {
        Session::Http(CapturedExchange {
            id: Uuid::new_v4(),
            sequence: 1,
            request: CapturedRequest {
                method: "POST".into(),
                scheme: "https".into(),
                host: "api.example.com".into(),
                port: 443,
                path: "/users".into(),
                version: "HTTP/2.0".into(),
                headers: Vec::new(),
                body: Vec::new(),
                timestamp: Utc::now(),
                client_addr: String::new(),
                process: "firefox.exe".into(),
                pid: None,
            },
            response: Some(CapturedResponse {
                status: 404,
                reason: "Not Found".into(),
                version: "HTTP/2.0".into(),
                headers: Vec::new(),
                body: Vec::new(),
                duration_ms: 650.0,
            }),
            rule_matched: None,
            error: None,
            synthetic: false,
            pinned: false,
            notes: String::new(),
        })
    }

    #[test]
    fn supports_field_and_numeric_filters() {
        let session = session();
        assert!(matches_filter(
            &session,
            "method:POST host:*.example.com status:>=400 duration:>500ms"
        ));
        assert!(!matches_filter(&session, "process:chrome"));
    }

    #[test]
    fn supports_regex_in_free_text_and_field_filters() {
        let session = session();
        assert!(matches_filter(
            &session,
            r"host:re:^api\..*\.com$ path:re:^/us(er|ers)$"
        ));
        assert!(matches_filter(&session, r"re:api\.example\.com"));
        assert!(matches_filter(&session, r"process:re:^firefox\.exe$"));
        assert!(!matches_filter(&session, r"host:re:^www\."));
    }
}
