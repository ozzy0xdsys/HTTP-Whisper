use anyhow::Result;
use serde_json::{Value, json};

use crate::model::{CapturedExchange, headers_as_text, redact_headers};

pub fn as_curl(exchange: &CapturedExchange) -> String {
    let request = &exchange.request;
    let mut parts = vec![
        "curl".to_owned(),
        format!("-X {}", shell_quote(&request.method)),
        shell_quote(&request.url()),
    ];
    for header in redact_headers(&request.headers) {
        parts.push(format!(
            "-H {}",
            shell_quote(&format!("{}: {}", header.name, header.value))
        ));
    }
    if !request.body.is_empty() {
        parts.push(format!(
            "--data-binary {}",
            shell_quote(&String::from_utf8_lossy(&request.body))
        ));
    }
    parts.join(" ")
}

pub fn as_json(exchange: &CapturedExchange) -> Result<String> {
    let mut value = serde_json::to_value(exchange)?;
    if let Value::Object(root) = &mut value {
        if let Some(Value::Object(request)) = root.get_mut("request") {
            request.insert(
                "headers".into(),
                serde_json::to_value(redact_headers(&exchange.request.headers))?,
            );
        }
        if let Some(Value::Object(response)) = root.get_mut("response")
            && let Some(value) = &exchange.response
        {
            response.insert(
                "headers".into(),
                serde_json::to_value(redact_headers(&value.headers))?,
            );
        }
    }
    Ok(serde_json::to_string_pretty(&value)?)
}

pub fn as_har(exchange: &CapturedExchange) -> Result<Value> {
    let response = exchange.response.as_ref();
    Ok(json!({
        "startedDateTime": exchange.request.timestamp.to_rfc3339(),
        "time": response.map(|item| item.duration_ms).unwrap_or_default(),
        "request": {
            "method": exchange.request.method,
            "url": exchange.request.url(),
            "httpVersion": exchange.request.version,
            "headers": redact_headers(&exchange.request.headers),
            "headersText": headers_as_text(&redact_headers(&exchange.request.headers)),
            "bodySize": exchange.request.body.len()
        },
        "response": {
            "status": response.map(|item| item.status).unwrap_or_default(),
            "statusText": response.map(|item| item.reason.as_str()).unwrap_or(""),
            "httpVersion": response.map(|item| item.version.as_str()).unwrap_or(""),
            "headers": response.map(|item| redact_headers(&item.headers)).unwrap_or_default(),
            "bodySize": response.map(|item| item.body.len()).unwrap_or_default()
        }
    }))
}

fn shell_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\"'\"'"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{CapturedRequest, Header, ThreatAssessment};
    use chrono::Utc;
    use uuid::Uuid;

    fn exchange() -> CapturedExchange {
        CapturedExchange {
            id: Uuid::new_v4(),
            sequence: 1,
            request: CapturedRequest {
                method: "GET".into(),
                scheme: "https".into(),
                host: "example.test".into(),
                port: 443,
                path: "/".into(),
                version: "HTTP/2.0".into(),
                headers: vec![Header {
                    name: "Authorization".into(),
                    value: "Bearer secret".into(),
                }],
                body: Vec::new(),
                timestamp: Utc::now(),
                client_addr: String::new(),
                process: String::new(),
                process_path: String::new(),
                pid: None,
                provenance: Default::default(),
                guard: Default::default(),
            },
            response: None,
            rule_matched: None,
            error: None,
            synthetic: false,
            pinned: false,
            notes: String::new(),
            threat: ThreatAssessment::default(),
            behavior: Default::default(),
        }
    }

    #[test]
    fn exports_redact_authorization() {
        let exchange = exchange();
        for output in [
            as_curl(&exchange),
            as_json(&exchange).unwrap(),
            as_har(&exchange).unwrap().to_string(),
        ] {
            assert!(!output.contains("Bearer secret"));
            assert!(output.contains("redacted"));
        }
    }
}
