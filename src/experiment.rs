use std::collections::{BTreeMap, BTreeSet};

use serde_json::Value;

use crate::model::{Header, Session};

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ExperimentReport {
    pub before_events: usize,
    pub after_events: usize,
    pub new_endpoints: Vec<String>,
    pub missing_endpoints: Vec<String>,
    pub changed_counts: Vec<String>,
    pub new_headers: Vec<String>,
    pub new_cookies: Vec<String>,
    pub changed_json: Vec<String>,
    pub websocket_changes: Vec<String>,
}

impl ExperimentReport {
    pub fn render(&self) -> String {
        let mut lines = vec![format!(
            "Before events: {}\nAfter events: {}",
            self.before_events, self.after_events
        )];
        append_section(&mut lines, "New endpoints", &self.new_endpoints);
        append_section(
            &mut lines,
            "Endpoints missing from After",
            &self.missing_endpoints,
        );
        append_section(&mut lines, "Request count changes", &self.changed_counts);
        append_section(&mut lines, "New headers", &self.new_headers);
        append_section(&mut lines, "New cookies", &self.new_cookies);
        append_section(&mut lines, "Changed JSON fields", &self.changed_json);
        append_section(
            &mut lines,
            "WebSocket message changes",
            &self.websocket_changes,
        );
        if lines.len() == 1 {
            lines.push("\nNo semantic differences detected.".into());
        }
        lines.join("\n")
    }
}

pub fn compare(before: &[Session], after: &[Session]) -> ExperimentReport {
    let before_summary = summarize(before);
    let after_summary = summarize(after);
    let mut report = ExperimentReport {
        before_events: before.len(),
        after_events: after.len(),
        ..Default::default()
    };
    report.new_endpoints = difference(
        after_summary.endpoints.keys(),
        before_summary.endpoints.keys(),
    );
    report.missing_endpoints = difference(
        before_summary.endpoints.keys(),
        after_summary.endpoints.keys(),
    );
    for endpoint in before_summary
        .endpoints
        .keys()
        .filter(|endpoint| after_summary.endpoints.contains_key(*endpoint))
    {
        let before_count = before_summary.endpoints[endpoint];
        let after_count = after_summary.endpoints[endpoint];
        if before_count != after_count {
            report.changed_counts.push(format!(
                "{endpoint}: {before_count} before, {after_count} after"
            ));
        }
    }
    report.new_headers = difference(after_summary.headers.iter(), before_summary.headers.iter());
    report.new_cookies = difference(after_summary.cookies.iter(), before_summary.cookies.iter());
    for (field, after_values) in &after_summary.json_values {
        let Some(before_values) = before_summary.json_values.get(field) else {
            report.changed_json.push(format!(
                "{field}: new field ({})",
                join_values(after_values)
            ));
            continue;
        };
        if before_values != after_values {
            report.changed_json.push(format!(
                "{field}: {} -> {}",
                join_values(before_values),
                join_values(after_values)
            ));
        }
    }
    for kind in before_summary
        .websocket_types
        .keys()
        .chain(after_summary.websocket_types.keys())
        .collect::<BTreeSet<_>>()
    {
        let before_count = before_summary
            .websocket_types
            .get(kind)
            .copied()
            .unwrap_or_default();
        let after_count = after_summary
            .websocket_types
            .get(kind)
            .copied()
            .unwrap_or_default();
        if before_count != after_count {
            report.websocket_changes.push(format!(
                "{kind}: {before_count} before, {after_count} after"
            ));
        }
    }
    report
}

#[derive(Default)]
struct Summary {
    endpoints: BTreeMap<String, usize>,
    headers: BTreeSet<String>,
    cookies: BTreeSet<String>,
    json_values: BTreeMap<String, BTreeSet<String>>,
    websocket_types: BTreeMap<String, usize>,
}

fn summarize(sessions: &[Session]) -> Summary {
    let mut summary = Summary::default();
    for session in sessions {
        match session {
            Session::Http(exchange) => {
                let request = &exchange.request;
                let endpoint = format!(
                    "{} {}{}",
                    request.method,
                    request.host,
                    request
                        .path
                        .split_once('?')
                        .map_or(request.path.as_str(), |(path, _)| path)
                );
                *summary.endpoints.entry(endpoint.clone()).or_default() += 1;
                collect_headers("request", &request.headers, &mut summary);
                collect_json(
                    &endpoint,
                    "request",
                    &request.body,
                    &mut summary.json_values,
                );
                if let Some(response) = &exchange.response {
                    collect_headers("response", &response.headers, &mut summary);
                    collect_json(
                        &endpoint,
                        "response",
                        &response.body,
                        &mut summary.json_values,
                    );
                }
            }
            Session::WebSocket(message) => {
                let kind = if message.analysis.message_type.is_empty() {
                    format!("{} {} <untyped>", message.direction.label(), message.host)
                } else {
                    format!(
                        "{} {} {}",
                        message.direction.label(),
                        message.host,
                        message.analysis.message_type
                    )
                };
                *summary.websocket_types.entry(kind).or_default() += 1;
            }
        }
    }
    summary
}

fn collect_headers(prefix: &str, headers: &[Header], summary: &mut Summary) {
    for header in headers {
        summary
            .headers
            .insert(format!("{prefix}:{}", header.name.to_ascii_lowercase()));
    }
    for name in ["cookie", "set-cookie"] {
        for value in headers
            .iter()
            .filter(|header| header.name.eq_ignore_ascii_case(name))
            .map(|header| header.value.as_str())
        {
            for cookie in value.split(';') {
                if let Some((cookie_name, _)) = cookie.trim().split_once('=')
                    && !cookie_name.trim().is_empty()
                    && !matches!(
                        cookie_name.trim().to_ascii_lowercase().as_str(),
                        "path" | "domain" | "expires" | "max-age" | "samesite"
                    )
                {
                    summary
                        .cookies
                        .insert(format!("{prefix}:{}", cookie_name.trim()));
                }
            }
        }
    }
}

fn collect_json(
    endpoint: &str,
    direction: &str,
    body: &[u8],
    output: &mut BTreeMap<String, BTreeSet<String>>,
) {
    let Ok(text) = std::str::from_utf8(body) else {
        return;
    };
    let Ok(value) = serde_json::from_str::<Value>(text) else {
        return;
    };
    flatten_json(&format!("{endpoint} {direction} $"), &value, output, 0);
}

fn flatten_json(
    path: &str,
    value: &Value,
    output: &mut BTreeMap<String, BTreeSet<String>>,
    depth: usize,
) {
    if depth > 6 || output.len() >= 2_000 {
        return;
    }
    match value {
        Value::Object(values) => {
            for (key, value) in values {
                flatten_json(&format!("{path}.{key}"), value, output, depth + 1);
            }
        }
        Value::Array(values) => {
            for value in values.iter().take(5) {
                flatten_json(&format!("{path}[]"), value, output, depth + 1);
            }
        }
        value => {
            let rendered = match value {
                Value::String(value) => value.chars().take(80).collect(),
                _ => value.to_string(),
            };
            let values = output.entry(path.into()).or_default();
            if values.len() < 12 {
                values.insert(rendered);
            }
        }
    }
}

fn difference<'a>(
    left: impl Iterator<Item = &'a String>,
    right: impl Iterator<Item = &'a String>,
) -> Vec<String> {
    let right = right.collect::<BTreeSet<_>>();
    left.filter(|value| !right.contains(value))
        .cloned()
        .collect()
}

fn join_values(values: &BTreeSet<String>) -> String {
    values
        .iter()
        .take(6)
        .cloned()
        .collect::<Vec<_>>()
        .join(" | ")
}

fn append_section(lines: &mut Vec<String>, title: &str, values: &[String]) {
    if values.is_empty() {
        return;
    }
    lines.push(format!("\n{title}"));
    lines.extend(values.iter().take(250).map(|value| format!("  {value}")));
}

#[cfg(test)]
mod tests {
    use chrono::Utc;
    use uuid::Uuid;

    use super::*;
    use crate::model::{
        BehaviorAssessment, CapturedExchange, CapturedRequest, GuardAssessment, ProcessProvenance,
        ThreatAssessment,
    };

    fn session(path: &str, body: &str) -> Session {
        Session::Http(CapturedExchange {
            id: Uuid::new_v4(),
            sequence: 1,
            request: CapturedRequest {
                method: "GET".into(),
                scheme: "https".into(),
                host: "api.example.com".into(),
                port: 443,
                path: path.into(),
                version: "HTTP/2.0".into(),
                headers: Vec::new(),
                body: body.as_bytes().to_vec(),
                timestamp: Utc::now(),
                client_addr: String::new(),
                process: String::new(),
                process_path: String::new(),
                pid: None,
                provenance: ProcessProvenance::default(),
                guard: GuardAssessment::default(),
            },
            response: None,
            rule_matched: None,
            error: None,
            synthetic: false,
            pinned: false,
            notes: String::new(),
            threat: ThreatAssessment::default(),
            behavior: BehaviorAssessment::default(),
        })
    }

    #[test]
    fn reports_new_endpoints_and_changed_json_values() {
        let before = [session("/users", r#"{"role":"user"}"#)];
        let after = [
            session("/users", r#"{"role":"admin"}"#),
            session("/admin", ""),
        ];
        let report = compare(&before, &after);
        assert!(report.new_endpoints[0].contains("/admin"));
        assert!(report.changed_json[0].contains("user -> admin"));
    }
}
