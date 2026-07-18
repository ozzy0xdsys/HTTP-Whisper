use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    net::IpAddr,
    path::Path,
    time::Duration,
};

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::model::Session;
use crate::platform::BypassConnection;

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct HostDossierIndex {
    pub hosts: BTreeMap<String, HostDossier>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct HostDossier {
    pub host: String,
    pub first_seen: Option<DateTime<Utc>>,
    pub last_seen: Option<DateTime<Utc>>,
    pub http_requests: u64,
    pub websocket_messages: u64,
    pub bypass_connections: u64,
    pub outbound_bytes: u64,
    pub inbound_bytes: u64,
    pub warning_events: u64,
    pub tls_failures: u64,
    pub processes: BTreeSet<String>,
    pub pids: BTreeSet<u32>,
    pub paths: BTreeSet<String>,
    pub status_codes: BTreeMap<u16, u64>,
    pub schemes: BTreeSet<String>,
    pub intelligence: Option<HostIntelligence>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct HostIntelligence {
    pub resolved_addresses: Vec<String>,
    pub reverse_names: Vec<String>,
    pub network_name: String,
    pub network_handle: String,
    pub country: String,
    pub origin_asns: Vec<u64>,
    pub registered_at: String,
    pub changed_at: String,
    pub expires_at: String,
    pub fetched_at: Option<DateTime<Utc>>,
    pub sources: Vec<String>,
}

impl HostDossierIndex {
    pub fn load(path: &Path) -> Result<Self> {
        if !path.exists() {
            return Ok(Self::default());
        }
        let bytes = fs::read(path)
            .with_context(|| format!("could not read host dossiers {}", path.display()))?;
        serde_json::from_slice(&bytes).context("host dossier JSON is invalid")
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

    pub fn observe(&mut self, session: &Session) {
        let host_key = session.host().to_ascii_lowercase();
        let dossier = self.hosts.entry(host_key).or_insert_with(|| HostDossier {
            host: session.host().into(),
            first_seen: Some(session.timestamp()),
            ..Default::default()
        });
        dossier.last_seen = Some(session.timestamp());
        if !session.process().is_empty() {
            dossier.processes.insert(session.process().into());
        }
        if let Some(pid) = session.pid() {
            dossier.pids.insert(pid);
        }
        dossier.warning_events += u64::from(session.threat().is_warning());
        match session {
            Session::Http(exchange) => {
                dossier.http_requests += 1;
                dossier.outbound_bytes += exchange.request.body.len() as u64;
                dossier.schemes.insert(exchange.request.scheme.clone());
                if dossier.paths.len() < 4_000 {
                    dossier.paths.insert(exchange.request.path.clone());
                }
                if let Some(response) = &exchange.response {
                    dossier.inbound_bytes += response.body.len() as u64;
                    *dossier.status_codes.entry(response.status).or_default() += 1;
                }
                if exchange.error.as_ref().is_some_and(|error| {
                    let lower = error.to_ascii_lowercase();
                    lower.contains("certificate") || lower.contains("tls")
                }) {
                    dossier.tls_failures += 1;
                }
            }
            Session::WebSocket(message) => {
                dossier.websocket_messages += 1;
                dossier.schemes.insert(
                    if message.url.starts_with("wss:") {
                        "wss"
                    } else {
                        "ws"
                    }
                    .into(),
                );
                if dossier.paths.len() < 4_000 {
                    dossier.paths.insert(message.path.clone());
                }
                if message.direction == crate::model::Direction::Out {
                    dossier.outbound_bytes += message.raw_size as u64;
                } else {
                    dossier.inbound_bytes += message.raw_size as u64;
                }
            }
        }
    }

    pub fn set_intelligence(&mut self, host: &str, intelligence: HostIntelligence) {
        self.hosts
            .entry(host.to_ascii_lowercase())
            .or_insert_with(|| HostDossier {
                host: host.into(),
                ..Default::default()
            })
            .intelligence = Some(intelligence);
    }

    pub fn observe_bypass(&mut self, connection: &BypassConnection) {
        let dossier = self
            .hosts
            .entry(connection.remote_addr.to_ascii_lowercase())
            .or_insert_with(|| HostDossier {
                host: connection.remote_addr.clone(),
                first_seen: Some(connection.first_seen),
                ..Default::default()
            });
        dossier.last_seen = Some(connection.last_seen);
        dossier.bypass_connections = dossier.bypass_connections.saturating_add(1);
        if !connection.process.is_empty() {
            dossier.processes.insert(connection.process.clone());
        }
        dossier.pids.insert(connection.pid);
    }

    pub fn report(&self, host: &str) -> String {
        let Some(dossier) = self.hosts.get(&host.to_ascii_lowercase()) else {
            return format!("No observations recorded for {host}.");
        };
        let mut lines = vec![
            format!("Host: {}", dossier.host),
            format!("First seen: {}", date_label(dossier.first_seen.as_ref())),
            format!("Last seen: {}", date_label(dossier.last_seen.as_ref())),
            format!("HTTP requests: {}", dossier.http_requests),
            format!("WebSocket messages: {}", dossier.websocket_messages),
            format!("Bypass observations: {}", dossier.bypass_connections),
            format!("Outbound bytes: {}", dossier.outbound_bytes),
            format!("Inbound bytes: {}", dossier.inbound_bytes),
            format!("Warning events: {}", dossier.warning_events),
            format!("TLS failures: {}", dossier.tls_failures),
            format!(
                "Processes: {}",
                if dossier.processes.is_empty() {
                    "<unknown>".into()
                } else {
                    dossier
                        .processes
                        .iter()
                        .cloned()
                        .collect::<Vec<_>>()
                        .join(", ")
                }
            ),
        ];
        if !dossier.status_codes.is_empty() {
            lines.push(format!(
                "Status codes: {}",
                dossier
                    .status_codes
                    .iter()
                    .map(|(status, count)| format!("{status} x{count}"))
                    .collect::<Vec<_>>()
                    .join(", ")
            ));
        }
        if let Some(intelligence) = &dossier.intelligence {
            lines.push("\nPublic network intelligence".into());
            lines.push(format!(
                "Addresses: {}",
                value_or_unknown(&intelligence.resolved_addresses.join(", "))
            ));
            lines.push(format!(
                "Reverse DNS: {}",
                value_or_unknown(&intelligence.reverse_names.join(", "))
            ));
            lines.push(format!(
                "Network: {} {}",
                value_or_unknown(&intelligence.network_name),
                intelligence.network_handle
            ));
            lines.push(format!(
                "Country: {}",
                value_or_unknown(&intelligence.country)
            ));
            lines.push(format!(
                "Origin ASN: {}",
                if intelligence.origin_asns.is_empty() {
                    "<unknown>".into()
                } else {
                    intelligence
                        .origin_asns
                        .iter()
                        .map(|asn| format!("AS{asn}"))
                        .collect::<Vec<_>>()
                        .join(", ")
                }
            ));
            lines.push(format!(
                "Registered: {}",
                value_or_unknown(&intelligence.registered_at)
            ));
            lines.push(format!(
                "Last changed: {}",
                value_or_unknown(&intelligence.changed_at)
            ));
            lines.push(format!(
                "Expires: {}",
                value_or_unknown(&intelligence.expires_at)
            ));
            lines.push(format!("Sources: {}", intelligence.sources.join(", ")));
        } else {
            lines
                .push("\nPublic network intelligence has not been refreshed for this host.".into());
        }
        lines.push("\nObserved paths".into());
        lines.extend(
            dossier
                .paths
                .iter()
                .take(200)
                .map(|path| format!("  {path}")),
        );
        lines.join("\n")
    }
}

pub async fn lookup_host_intelligence(host: &str) -> Result<HostIntelligence> {
    let host = host.trim().trim_end_matches('.').to_ascii_lowercase();
    anyhow::ensure!(!host.is_empty(), "host is required");
    let mut result = HostIntelligence::default();
    let mut addresses = if let Ok(ip) = host.parse::<IpAddr>() {
        vec![ip]
    } else {
        tokio::net::lookup_host((host.as_str(), 443))
            .await
            .map(|values| values.map(|value| value.ip()).collect::<BTreeSet<_>>())
            .unwrap_or_default()
            .into_iter()
            .collect()
    };
    addresses.truncate(12);
    result.resolved_addresses = addresses.iter().map(ToString::to_string).collect();
    for address in addresses.iter().take(4) {
        let address = *address;
        if let Ok(Ok(name)) =
            tokio::task::spawn_blocking(move || dns_lookup::lookup_addr(&address)).await
            && !result.reverse_names.contains(&name)
        {
            result.reverse_names.push(name);
        }
    }

    let client = reqwest::Client::builder()
        .no_proxy()
        .timeout(Duration::from_secs(12))
        .user_agent("HTTP-Whisper/0.8 host-dossier")
        .build()?;
    if host.parse::<IpAddr>().is_err() {
        let url = format!("https://rdap.org/domain/{host}");
        if let Ok(response) = client.get(&url).send().await
            && response.status().is_success()
            && let Ok(value) = response.json::<Value>().await
        {
            result.registered_at = event_date(&value, "registration");
            result.changed_at = event_date(&value, "last changed");
            result.expires_at = event_date(&value, "expiration");
            result.sources.push("rdap.org domain RDAP".into());
        }
    }
    if let Some(address) = addresses.first() {
        let url = format!("https://rdap.org/ip/{address}");
        if let Ok(response) = client.get(&url).send().await
            && response.status().is_success()
            && let Ok(value) = response.json::<Value>().await
        {
            result.network_name = value
                .get("name")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .into();
            result.network_handle = value
                .get("handle")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .into();
            result.country = value
                .get("country")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .into();
            result.origin_asns = value
                .get("arin_originas0_originautnums")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .filter_map(Value::as_u64)
                .collect();
            result.sources.push("rdap.org IP RDAP".into());
        }
    }
    result.fetched_at = Some(Utc::now());
    Ok(result)
}

fn event_date(value: &Value, action: &str) -> String {
    value
        .get("events")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .find(|event| {
            event
                .get("eventAction")
                .and_then(Value::as_str)
                .is_some_and(|value| value.eq_ignore_ascii_case(action))
        })
        .and_then(|event| event.get("eventDate"))
        .and_then(Value::as_str)
        .unwrap_or_default()
        .into()
}

fn date_label(value: Option<&DateTime<Utc>>) -> String {
    value
        .map(|value| value.to_rfc3339())
        .unwrap_or_else(|| "<unknown>".into())
}

fn value_or_unknown(value: &str) -> &str {
    if value.trim().is_empty() {
        "<unknown>"
    } else {
        value
    }
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

    fn session() -> Session {
        Session::Http(CapturedExchange {
            id: Uuid::new_v4(),
            sequence: 1,
            request: CapturedRequest {
                method: "POST".into(),
                scheme: "https".into(),
                host: "api.example.com".into(),
                port: 443,
                path: "/v1/upload".into(),
                version: "HTTP/2.0".into(),
                headers: Vec::new(),
                body: vec![1, 2, 3],
                timestamp: Utc::now(),
                client_addr: String::new(),
                process: "demo.exe".into(),
                process_path: String::new(),
                pid: Some(42),
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
    fn aggregates_host_activity_and_round_trips() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("dossiers.json");
        let mut index = HostDossierIndex::default();
        index.observe(&session());
        index.save(&path).unwrap();
        let restored = HostDossierIndex::load(&path).unwrap();
        let dossier = &restored.hosts["api.example.com"];
        assert_eq!(dossier.http_requests, 1);
        assert_eq!(dossier.outbound_bytes, 3);
        assert!(restored.report("api.example.com").contains("demo.exe"));
    }
}
