use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct Header {
    pub name: String,
    pub value: String,
}

pub type Headers = Vec<Header>;

#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum ThreatLevel {
    #[default]
    None,
    Notice,
    Suspicious,
    High,
}

impl ThreatLevel {
    pub fn label(self) -> &'static str {
        match self {
            Self::None => "None",
            Self::Notice => "Notice",
            Self::Suspicious => "Suspicious",
            Self::High => "High",
        }
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct ThreatFinding {
    pub title: String,
    pub evidence: String,
    pub score: u16,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct ThreatAssessment {
    pub score: u16,
    pub level: ThreatLevel,
    pub findings: Vec<ThreatFinding>,
}

impl ThreatAssessment {
    pub fn is_warning(&self) -> bool {
        self.level >= ThreatLevel::Suspicious
    }

    pub fn primary_finding(&self) -> Option<&ThreatFinding> {
        self.findings.iter().max_by_key(|finding| finding.score)
    }

    pub fn tooltip(&self) -> String {
        if self.findings.is_empty() {
            return "No suspicious indicators detected".into();
        }
        let details = self
            .findings
            .iter()
            .map(|finding| format!("{}: {}", finding.title, finding.evidence))
            .collect::<Vec<_>>()
            .join("\n");
        format!(
            "{} risk ({}/100)\n{}",
            self.level.label(),
            self.score,
            details
        )
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CapturedRequest {
    pub method: String,
    pub scheme: String,
    pub host: String,
    pub port: u16,
    pub path: String,
    pub version: String,
    pub headers: Headers,
    pub body: Vec<u8>,
    pub timestamp: DateTime<Utc>,
    pub client_addr: String,
    pub process: String,
    #[serde(default)]
    pub process_path: String,
    pub pid: Option<u32>,
}

impl CapturedRequest {
    pub fn url(&self) -> String {
        let default = (self.scheme == "https" && self.port == 443)
            || (self.scheme == "http" && self.port == 80);
        let authority = if default {
            self.host.clone()
        } else {
            format!("{}:{}", self.host, self.port)
        };
        format!("{}://{}{}", self.scheme, authority, self.path)
    }

    pub fn content_type(&self) -> Option<&str> {
        header_value(&self.headers, "content-type")
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CapturedResponse {
    pub status: u16,
    pub reason: String,
    pub version: String,
    pub headers: Headers,
    pub body: Vec<u8>,
    pub duration_ms: f64,
}

impl CapturedResponse {
    pub fn content_type(&self) -> Option<&str> {
        header_value(&self.headers, "content-type")
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CapturedExchange {
    pub id: Uuid,
    pub sequence: u64,
    pub request: CapturedRequest,
    pub response: Option<CapturedResponse>,
    pub rule_matched: Option<String>,
    pub error: Option<String>,
    pub synthetic: bool,
    pub pinned: bool,
    pub notes: String,
    #[serde(default)]
    pub threat: ThreatAssessment,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WebSocketMessage {
    pub id: Uuid,
    pub sequence: u64,
    pub url: String,
    pub host: String,
    pub path: String,
    pub direction: Direction,
    pub opcode: String,
    pub is_text: bool,
    pub payload: String,
    pub raw_size: usize,
    pub decoded_as: String,
    pub rule_matched: Option<String>,
    pub timestamp: DateTime<Utc>,
    #[serde(default)]
    pub process: String,
    #[serde(default)]
    pub process_path: String,
    #[serde(default)]
    pub pid: Option<u32>,
    #[serde(default)]
    pub threat: ThreatAssessment,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum Direction {
    Out,
    In,
}

impl Direction {
    pub fn label(self) -> &'static str {
        match self {
            Self::Out => "OUT",
            Self::In => "IN",
        }
    }
}

#[derive(Clone, Debug)]
#[allow(clippy::large_enum_variant)]
pub enum CaptureEvent {
    Starting,
    Started { host: String, port: u16 },
    Log(String),
    Exchange(CapturedExchange),
    ReplayCompleted(CapturedExchange),
    WebSocket(WebSocketMessage),
    OperationError(String),
    Error(String),
    Stopped(String),
}

#[derive(Clone, Debug)]
#[allow(clippy::large_enum_variant)]
pub enum Session {
    Http(CapturedExchange),
    WebSocket(WebSocketMessage),
}

impl Session {
    pub fn id(&self) -> Uuid {
        match self {
            Self::Http(value) => value.id,
            Self::WebSocket(value) => value.id,
        }
    }

    pub fn sequence(&self) -> u64 {
        match self {
            Self::Http(value) => value.sequence,
            Self::WebSocket(value) => value.sequence,
        }
    }

    pub fn url(&self) -> String {
        match self {
            Self::Http(value) => value.request.url(),
            Self::WebSocket(value) => value.url.clone(),
        }
    }

    pub fn searchable_text(&self) -> String {
        match self {
            Self::Http(value) => format!(
                "http {} {} {} {} {} {} {}",
                value.request.method,
                value.request.host,
                value.request.path,
                value
                    .response
                    .as_ref()
                    .map(|r| r.status)
                    .unwrap_or_default(),
                String::from_utf8_lossy(&value.request.body),
                value.threat.level.label(),
                value
                    .threat
                    .findings
                    .iter()
                    .map(|finding| finding.title.as_str())
                    .collect::<Vec<_>>()
                    .join(" ")
            ),
            Self::WebSocket(value) => format!(
                "ws websocket {} {} {} {} {} {}",
                value.direction.label(),
                value.host,
                value.path,
                value.payload,
                value.threat.level.label(),
                value
                    .threat
                    .findings
                    .iter()
                    .map(|finding| finding.title.as_str())
                    .collect::<Vec<_>>()
                    .join(" ")
            ),
        }
    }

    pub fn threat(&self) -> &ThreatAssessment {
        match self {
            Self::Http(value) => &value.threat,
            Self::WebSocket(value) => &value.threat,
        }
    }
}

pub fn header_value<'a>(headers: &'a Headers, name: &str) -> Option<&'a str> {
    headers
        .iter()
        .find(|header| header.name.eq_ignore_ascii_case(name))
        .map(|header| header.value.as_str())
}

pub fn headers_as_text(headers: &Headers) -> String {
    headers
        .iter()
        .map(|header| format!("{}: {}", header.name, header.value))
        .collect::<Vec<_>>()
        .join("\n")
}

pub fn redact_headers(headers: &Headers) -> Headers {
    headers
        .iter()
        .map(|header| {
            let sensitive = [
                "authorization",
                "proxy-authorization",
                "cookie",
                "set-cookie",
            ]
            .iter()
            .any(|name| header.name.eq_ignore_ascii_case(name));
            Header {
                name: header.name.clone(),
                value: if sensitive {
                    "<redacted>".to_owned()
                } else {
                    header.value.clone()
                },
            }
        })
        .collect()
}
