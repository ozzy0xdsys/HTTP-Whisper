use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::Path,
};

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::model::{BehaviorAssessment, CapturedExchange, Session, WebSocketMessage};

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct TrafficBaseline {
    pub profiles: BTreeMap<String, ProcessBaseline>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct ProcessBaseline {
    pub process: String,
    pub process_path: String,
    pub first_seen: Option<DateTime<Utc>>,
    pub last_seen: Option<DateTime<Utc>>,
    pub hosts: BTreeMap<String, HostBaseline>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct HostBaseline {
    pub first_seen: Option<DateTime<Utc>>,
    pub last_seen: Option<DateTime<Utc>>,
    pub request_count: u64,
    pub methods: BTreeSet<String>,
    pub paths: BTreeSet<String>,
    pub content_types: BTreeSet<String>,
    pub websocket_paths: BTreeSet<String>,
    pub websocket_types: BTreeSet<String>,
    pub max_outbound_bytes: usize,
    pub interval_total_ms: i64,
    pub interval_samples: u64,
}

impl TrafficBaseline {
    pub fn load(path: &Path) -> Result<Self> {
        if !path.exists() {
            return Ok(Self::default());
        }
        let bytes = fs::read(path)
            .with_context(|| format!("could not read baseline {}", path.display()))?;
        serde_json::from_slice(&bytes).context("traffic baseline JSON is invalid")
    }

    pub fn save(&self, path: &Path) -> Result<()> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let temporary = path.with_extension("json.tmp");
        fs::write(&temporary, serde_json::to_vec_pretty(self)?)?;
        fs::rename(temporary, path)?;
        Ok(())
    }

    pub fn clear(&mut self) {
        self.profiles.clear();
    }

    pub fn process_count(&self) -> usize {
        self.profiles.len()
    }

    pub fn host_count(&self) -> usize {
        self.profiles
            .values()
            .map(|profile| profile.hosts.len())
            .sum()
    }

    pub fn assess_http(&self, exchange: &CapturedExchange, learning: bool) -> BehaviorAssessment {
        let request = &exchange.request;
        let mut result = BehaviorAssessment {
            baseline_available: !self.profiles.is_empty(),
            learning,
            changes: Vec::new(),
        };
        if learning || self.profiles.is_empty() {
            return result;
        }
        let key = process_key(&request.process_path, &request.process, request.pid);
        let Some(profile) = self.profiles.get(&key) else {
            result.changes.push(format!(
                "Process {} was not present in the learned baseline",
                display_process(&request.process, request.pid)
            ));
            return result;
        };
        let host = request.host.to_ascii_lowercase();
        let Some(host_profile) = profile.hosts.get(&host) else {
            result.changes.push(format!(
                "{} contacted new destination {}",
                display_process(&request.process, request.pid),
                request.host
            ));
            return result;
        };
        if !host_profile.methods.contains(&request.method) {
            result.changes.push(format!(
                "New HTTP method {} for {}",
                request.method, request.host
            ));
        }
        let path = path_without_query(&request.path);
        if !host_profile.paths.contains(path) {
            result
                .changes
                .push(format!("New path {path} on {}", request.host));
        }
        if let Some(content_type) = header_value(&request.headers, "content-type")
            && !host_profile.content_types.contains(content_type)
        {
            result.changes.push(format!(
                "New outbound content type {content_type} for {}",
                request.host
            ));
        }
        let expected = host_profile.max_outbound_bytes;
        if request.body.len() >= 64 * 1024
            && request.body.len() > expected.saturating_mul(4).max(64 * 1024)
        {
            result.changes.push(format!(
                "Outbound body grew from a learned maximum of {} to {} bytes",
                expected,
                request.body.len()
            ));
        }
        result
    }

    pub fn assess_websocket(
        &self,
        message: &WebSocketMessage,
        learning: bool,
    ) -> BehaviorAssessment {
        let mut result = BehaviorAssessment {
            baseline_available: !self.profiles.is_empty(),
            learning,
            changes: Vec::new(),
        };
        if learning || self.profiles.is_empty() {
            return result;
        }
        let key = process_key(&message.process_path, &message.process, message.pid);
        let Some(profile) = self.profiles.get(&key) else {
            result.changes.push(format!(
                "Process {} was not present in the learned baseline",
                display_process(&message.process, message.pid)
            ));
            return result;
        };
        let host = message.host.to_ascii_lowercase();
        let Some(host_profile) = profile.hosts.get(&host) else {
            result.changes.push(format!(
                "{} opened a WebSocket to new destination {}",
                display_process(&message.process, message.pid),
                message.host
            ));
            return result;
        };
        let path = path_without_query(&message.path);
        if !host_profile.websocket_paths.contains(path) {
            result
                .changes
                .push(format!("New WebSocket path {path} on {}", message.host));
        }
        if !message.analysis.message_type.is_empty()
            && !host_profile
                .websocket_types
                .contains(&message.analysis.message_type)
        {
            result.changes.push(format!(
                "New WebSocket message type {}",
                message.analysis.message_type
            ));
        }
        result
    }

    pub fn observe(&mut self, session: &Session) {
        match session {
            Session::Http(exchange) => self.observe_http(exchange),
            Session::WebSocket(message) => self.observe_websocket(message),
        }
    }

    pub fn summary(&self) -> String {
        if self.profiles.is_empty() {
            return "No learned baseline. Enable Learn Normal while running trusted activity."
                .into();
        }
        let mut lines = vec![format!(
            "Learned processes: {}\nLearned process/host pairs: {}",
            self.process_count(),
            self.host_count()
        )];
        for profile in self.profiles.values() {
            lines.push(format!(
                "\n{}\n  Executable: {}",
                if profile.process.is_empty() {
                    "<unknown process>"
                } else {
                    &profile.process
                },
                if profile.process_path.is_empty() {
                    "<unknown>"
                } else {
                    &profile.process_path
                }
            ));
            for (host, value) in &profile.hosts {
                lines.push(format!(
                    "  {}  {} event(s), {} HTTP path(s), {} WebSocket path(s)",
                    host,
                    value.request_count,
                    value.paths.len(),
                    value.websocket_paths.len()
                ));
            }
        }
        lines.join("\n")
    }

    fn observe_http(&mut self, exchange: &CapturedExchange) {
        let request = &exchange.request;
        let profile = self.profile_mut(
            &request.process_path,
            &request.process,
            request.pid,
            request.timestamp,
        );
        let host = profile
            .hosts
            .entry(request.host.to_ascii_lowercase())
            .or_default();
        observe_time(host, request.timestamp);
        host.request_count += 1;
        host.methods.insert(request.method.clone());
        if host.paths.len() < 2_000 {
            host.paths.insert(path_without_query(&request.path).into());
        }
        if host.content_types.len() < 200
            && let Some(content_type) = header_value(&request.headers, "content-type")
        {
            host.content_types.insert(content_type.into());
        }
        host.max_outbound_bytes = host.max_outbound_bytes.max(request.body.len());
    }

    fn observe_websocket(&mut self, message: &WebSocketMessage) {
        let profile = self.profile_mut(
            &message.process_path,
            &message.process,
            message.pid,
            message.timestamp,
        );
        let host = profile
            .hosts
            .entry(message.host.to_ascii_lowercase())
            .or_default();
        observe_time(host, message.timestamp);
        host.request_count += 1;
        if host.websocket_paths.len() < 2_000 {
            host.websocket_paths
                .insert(path_without_query(&message.path).into());
        }
        if host.websocket_types.len() < 2_000 && !message.analysis.message_type.is_empty() {
            host.websocket_types
                .insert(message.analysis.message_type.clone());
        }
        host.max_outbound_bytes = host.max_outbound_bytes.max(message.raw_size);
    }

    fn profile_mut(
        &mut self,
        path: &str,
        process: &str,
        pid: Option<u32>,
        timestamp: DateTime<Utc>,
    ) -> &mut ProcessBaseline {
        let profile = self
            .profiles
            .entry(process_key(path, process, pid))
            .or_insert_with(|| ProcessBaseline {
                process: process.into(),
                process_path: path.into(),
                first_seen: Some(timestamp),
                ..Default::default()
            });
        profile.last_seen = Some(timestamp);
        profile
    }
}

fn observe_time(host: &mut HostBaseline, timestamp: DateTime<Utc>) {
    if host.first_seen.is_none() {
        host.first_seen = Some(timestamp);
    }
    if let Some(previous) = host.last_seen {
        let interval = timestamp.signed_duration_since(previous).num_milliseconds();
        if interval >= 0 {
            host.interval_total_ms += interval;
            host.interval_samples += 1;
        }
    }
    host.last_seen = Some(timestamp);
}

fn process_key(path: &str, process: &str, pid: Option<u32>) -> String {
    if !path.is_empty() {
        return path.to_ascii_lowercase();
    }
    if !process.is_empty() {
        return process.to_ascii_lowercase();
    }
    pid.map(|value| format!("pid:{value}"))
        .unwrap_or_else(|| "<unknown>".into())
}

fn display_process(process: &str, pid: Option<u32>) -> String {
    match (process.is_empty(), pid) {
        (false, Some(pid)) => format!("{process} (PID {pid})"),
        (false, None) => process.into(),
        (true, Some(pid)) => format!("PID {pid}"),
        (true, None) => "<unknown process>".into(),
    }
}

fn path_without_query(path: &str) -> &str {
    path.split_once('?').map_or(path, |(path, _)| path)
}

fn header_value<'a>(headers: &'a [crate::model::Header], name: &str) -> Option<&'a str> {
    headers
        .iter()
        .find(|header| header.name.eq_ignore_ascii_case(name))
        .map(|header| header.value.as_str())
}

#[cfg(test)]
mod tests {
    use chrono::Utc;
    use uuid::Uuid;

    use super::*;
    use crate::model::{
        CapturedRequest, GuardAssessment, Header, ProcessProvenance, ThreatAssessment,
    };

    fn exchange(host: &str, path: &str) -> CapturedExchange {
        CapturedExchange {
            id: Uuid::new_v4(),
            sequence: 1,
            request: CapturedRequest {
                method: "GET".into(),
                scheme: "https".into(),
                host: host.into(),
                port: 443,
                path: path.into(),
                version: "HTTP/2.0".into(),
                headers: Vec::new(),
                body: Vec::new(),
                timestamp: Utc::now(),
                client_addr: String::new(),
                process: "demo.exe".into(),
                process_path: r"C:\demo.exe".into(),
                pid: Some(7),
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
        }
    }

    #[test]
    fn learns_and_flags_new_destinations_and_paths() {
        let mut baseline = TrafficBaseline::default();
        baseline.observe(&Session::Http(exchange("api.example.com", "/v1/users")));

        let known = baseline.assess_http(&exchange("api.example.com", "/v1/users"), false);
        assert!(known.changes.is_empty());

        let new_path = baseline.assess_http(&exchange("api.example.com", "/v2/admin"), false);
        assert!(new_path.changes[0].contains("New path"));

        let new_host = baseline.assess_http(&exchange("other.example.com", "/"), false);
        assert!(new_host.changes[0].contains("new destination"));
    }

    #[test]
    fn flags_a_new_outbound_content_type() {
        let mut baseline = TrafficBaseline::default();
        let mut learned = exchange("api.example.com", "/upload");
        learned.request.headers.push(Header {
            name: "Content-Type".into(),
            value: "application/json".into(),
        });
        baseline.observe(&Session::Http(learned));

        let mut changed = exchange("api.example.com", "/upload");
        changed.request.headers.push(Header {
            name: "content-type".into(),
            value: "application/octet-stream".into(),
        });
        let assessment = baseline.assess_http(&changed, false);
        assert!(assessment.changes[0].contains("content type"));
    }

    #[test]
    fn round_trips_the_baseline_file() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("baseline.json");
        let mut baseline = TrafficBaseline::default();
        baseline.observe(&Session::Http(exchange("api.example.com", "/")));
        baseline.save(&path).unwrap();
        assert_eq!(TrafficBaseline::load(&path).unwrap().process_count(), 1);
    }
}
