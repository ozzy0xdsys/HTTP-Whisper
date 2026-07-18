use std::collections::BTreeMap;

use crate::{
    config::AppSettings,
    model::Session,
    rules::{apply_rewrite, pattern_matches},
};

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RuleSimulation {
    pub name: String,
    pub kind: String,
    pub matched: bool,
    pub conditions: Vec<String>,
    pub effect: String,
    pub preview: String,
}

impl RuleSimulation {
    pub fn render(&self, hit_count: usize) -> String {
        let mut lines = vec![format!(
            "{} [{}]  {}  historical hits: {}",
            self.name,
            self.kind,
            if self.matched { "MATCH" } else { "NO MATCH" },
            hit_count
        )];
        lines.extend(self.conditions.iter().map(|value| format!("  {value}")));
        if !self.effect.is_empty() {
            lines.push(format!("  Effect: {}", self.effect));
        }
        if !self.preview.is_empty() {
            lines.push("  Preview:".into());
            lines.extend(
                self.preview
                    .lines()
                    .take(24)
                    .map(|line| format!("    {line}")),
            );
        }
        lines.join("\n")
    }
}

pub fn simulate(session: &Session, settings: &AppSettings) -> Vec<RuleSimulation> {
    let mut simulations = Vec::new();
    if let Session::Http(exchange) = session {
        let request = &exchange.request;
        for rule in &settings.auto_response_rules {
            let method =
                rule.method.is_empty() || pattern_matches(&rule.method, &request.method, false);
            let host = pattern_matches(&rule.host, &request.host, false);
            let path = pattern_matches(
                &rule.path,
                request
                    .path
                    .split_once('?')
                    .map_or(&request.path, |(path, _)| path),
                true,
            );
            let matched = rule.enabled && method && host && path;
            simulations.push(RuleSimulation {
                name: rule.name.clone(),
                kind: "Auto response".into(),
                matched,
                conditions: vec![
                    condition("enabled", rule.enabled),
                    condition("method", method),
                    condition("host", host),
                    condition("path", path),
                ],
                effect: if matched {
                    format!("Return HTTP {} ({})", rule.status_code, rule.content_type)
                } else {
                    String::new()
                },
                preview: if matched {
                    truncate(&rule.body, 1_500)
                } else {
                    String::new()
                },
            });
        }
    }

    let (host, source) = match session {
        Session::Http(exchange) => (
            exchange.request.host.as_str(),
            exchange
                .response
                .as_ref()
                .and_then(|response| std::str::from_utf8(&response.body).ok())
                .unwrap_or(""),
        ),
        Session::WebSocket(message) => (message.host.as_str(), message.payload.as_str()),
    };
    for rule in &settings.response_rewrite_rules {
        let host_matches = pattern_matches(&rule.host, host, false);
        let (rewritten, count) = if host_matches {
            apply_rewrite(source, rule)
        } else {
            (source.into(), 0)
        };
        let matched = host_matches && count > 0;
        simulations.push(RuleSimulation {
            name: rule.name.clone(),
            kind: "Response rewrite".into(),
            matched,
            conditions: vec![
                condition("host", host_matches),
                condition("find expression", count > 0),
            ],
            effect: if matched {
                format!("Replace {count} occurrence(s)")
            } else {
                String::new()
            },
            preview: if matched {
                diff_preview(source, &rewritten)
            } else {
                String::new()
            },
        });
    }
    simulations
}

pub fn hit_counts(sessions: &[Session]) -> BTreeMap<String, usize> {
    let mut counts = BTreeMap::new();
    for value in sessions.iter().filter_map(|session| match session {
        Session::Http(exchange) => exchange.rule_matched.as_deref(),
        Session::WebSocket(message) => message.rule_matched.as_deref(),
    }) {
        for name in value
            .split(',')
            .map(str::trim)
            .filter(|name| !name.is_empty())
        {
            *counts.entry(name.into()).or_default() += 1;
        }
    }
    counts
}

pub fn render_simulations(
    simulations: &[RuleSimulation],
    hits: &BTreeMap<String, usize>,
) -> String {
    if simulations.is_empty() {
        return "No auto-response or response-rewrite rules are configured.".into();
    }
    simulations
        .iter()
        .map(|simulation| {
            simulation.render(hits.get(&simulation.name).copied().unwrap_or_default())
        })
        .collect::<Vec<_>>()
        .join("\n\n")
}

fn condition(name: &str, matched: bool) -> String {
    format!("{} {name}", if matched { "PASS" } else { "FAIL" })
}

fn diff_preview(before: &str, after: &str) -> String {
    format!(
        "Before\n{}\n\nAfter\n{}",
        truncate(before, 700),
        truncate(after, 700)
    )
}

fn truncate(value: &str, limit: usize) -> String {
    let mut output = value.chars().take(limit).collect::<String>();
    if value.chars().count() > limit {
        output.push_str("...");
    }
    output
}

#[cfg(test)]
mod tests {
    use chrono::Utc;
    use uuid::Uuid;

    use super::*;
    use crate::{
        config::{AutoResponseRule, ResponseRewriteRule},
        model::{
            BehaviorAssessment, CapturedExchange, CapturedRequest, CapturedResponse,
            GuardAssessment, ProcessProvenance, ThreatAssessment,
        },
    };

    fn session() -> Session {
        Session::Http(CapturedExchange {
            id: Uuid::new_v4(),
            sequence: 1,
            request: CapturedRequest {
                method: "GET".into(),
                scheme: "https".into(),
                host: "api.example.com".into(),
                port: 443,
                path: "/users/7".into(),
                version: "HTTP/2.0".into(),
                headers: Vec::new(),
                body: Vec::new(),
                timestamp: Utc::now(),
                client_addr: String::new(),
                process: String::new(),
                process_path: String::new(),
                pid: None,
                provenance: ProcessProvenance::default(),
                guard: GuardAssessment::default(),
            },
            response: Some(CapturedResponse {
                status: 200,
                reason: "OK".into(),
                version: "HTTP/2.0".into(),
                headers: Vec::new(),
                body: br#"{"role":"user"}"#.to_vec(),
                duration_ms: 1.0,
            }),
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
    fn explains_each_condition_and_previews_rewrites() {
        let settings = AppSettings {
            auto_response_rules: vec![AutoResponseRule {
                enabled: true,
                method: "GET".into(),
                host: "*.example.com".into(),
                path: "/users/*".into(),
                ..Default::default()
            }],
            response_rewrite_rules: vec![ResponseRewriteRule {
                host: "api.example.com".into(),
                find_text: "user".into(),
                replace_text: "admin".into(),
                ..Default::default()
            }],
            ..Default::default()
        };
        let simulations = simulate(&session(), &settings);
        assert!(simulations.iter().all(|value| value.matched));
        assert!(simulations[1].preview.contains("admin"));
    }
}
