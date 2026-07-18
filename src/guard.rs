use regex::Regex;

use crate::{
    config::ExfiltrationMode,
    model::{CapturedRequest, GuardAction, GuardAssessment, GuardFinding, Header},
    rules::pattern_matches,
};

pub fn protect_http(
    request: &mut CapturedRequest,
    mode: ExfiltrationMode,
    trusted_hosts: &[String],
) -> GuardAssessment {
    if mode == ExfiltrationMode::Off || host_is_trusted(&request.host, trusted_hosts) {
        return GuardAssessment::default();
    }
    let findings = find_http(request);
    let action = action_for(mode, !findings.is_empty());
    if action == GuardAction::Redacted {
        redact_headers(&mut request.headers);
        request
            .headers
            .retain(|header| !header.name.eq_ignore_ascii_case("content-length"));
        request.body = redact_bytes(&request.body);
    }
    GuardAssessment { action, findings }
}

pub fn protect_websocket_text(
    host: &str,
    text: &str,
    mode: ExfiltrationMode,
    trusted_hosts: &[String],
) -> (String, GuardAssessment) {
    if mode == ExfiltrationMode::Off || host_is_trusted(host, trusted_hosts) {
        return (text.into(), GuardAssessment::default());
    }
    let findings = find_text(text, "WebSocket payload");
    let action = action_for(mode, !findings.is_empty());
    let protected = if action == GuardAction::Redacted {
        redact_text(text)
    } else {
        text.into()
    };
    (protected, GuardAssessment { action, findings })
}

pub fn sanitize_text(text: &str) -> String {
    redact_text(text)
}

pub fn sanitize_body(body: &[u8]) -> Vec<u8> {
    redact_bytes(body)
}

pub fn redact_headers(headers: &mut [Header]) {
    for header in headers {
        if is_sensitive_header(&header.name) {
            header.value = "<redacted by HTTP Whisper>".into();
        }
    }
}

fn find_http(request: &CapturedRequest) -> Vec<GuardFinding> {
    let mut findings = Vec::new();
    let plaintext = request.scheme.eq_ignore_ascii_case("http");
    for header in &request.headers {
        if is_sensitive_header(&header.name) && plaintext {
            findings.push(GuardFinding {
                category: "Credential header".into(),
                location: format!("{} header", header.name),
                evidence: "Sensitive authentication data would be sent over plaintext HTTP".into(),
            });
        }
        if header.name.eq_ignore_ascii_case("content-disposition")
            && header.value.to_ascii_lowercase().contains("filename=")
        {
            findings.push(GuardFinding {
                category: "File upload".into(),
                location: "Content-Disposition header".into(),
                evidence: "An outbound file attachment was detected".into(),
            });
        }
    }
    if let Ok(text) = std::str::from_utf8(&request.body) {
        findings.extend(find_text(text, "Request body"));
        if text.to_ascii_lowercase().contains("content-disposition:")
            && text.to_ascii_lowercase().contains("filename=")
        {
            findings.push(GuardFinding {
                category: "File upload".into(),
                location: "Multipart request body".into(),
                evidence: "An outbound multipart file attachment was detected".into(),
            });
        }
    }
    deduplicate(findings)
}

fn find_text(text: &str, location: &str) -> Vec<GuardFinding> {
    let mut findings = Vec::new();
    let lower = text.to_ascii_lowercase();
    let patterns = [
        (
            "Private key",
            "private key-----",
            "A private-key block was detected",
        ),
        (
            "Credential field",
            "\"password\"",
            "A password field with an outbound value was detected",
        ),
        (
            "Credential field",
            "password=",
            "A password form field with an outbound value was detected",
        ),
        (
            "API secret",
            "\"api_key\"",
            "An API key field with an outbound value was detected",
        ),
        (
            "API secret",
            "\"secret\"",
            "A secret field with an outbound value was detected",
        ),
        (
            "Authentication token",
            "\"token\"",
            "An authentication token field with an outbound value was detected",
        ),
        (
            "System information",
            "\"computername\"",
            "A computer-name field was detected",
        ),
        (
            "System information",
            "\"machine_id\"",
            "A machine identifier field was detected",
        ),
        (
            "Screenshot metadata",
            "screenshot",
            "Screenshot-related outbound data was detected",
        ),
    ];
    for (category, needle, evidence) in patterns {
        if lower.contains(needle) {
            findings.push(GuardFinding {
                category: category.into(),
                location: location.into(),
                evidence: evidence.into(),
            });
        }
    }
    if jwt_regex().is_match(text) {
        findings.push(GuardFinding {
            category: "Bearer token".into(),
            location: location.into(),
            evidence: "A JWT-like token was detected".into(),
        });
    }
    deduplicate(findings)
}

fn redact_bytes(bytes: &[u8]) -> Vec<u8> {
    std::str::from_utf8(bytes)
        .map(redact_text)
        .map(String::into_bytes)
        .unwrap_or_else(|_| bytes.to_vec())
}

fn redact_text(text: &str) -> String {
    let text = private_key_regex()
        .replace_all(text, "[REDACTED PRIVATE KEY]")
        .into_owned();
    let text = jwt_regex()
        .replace_all(&text, "[REDACTED JWT]")
        .into_owned();
    secret_field_regex()
        .replace_all(&text, "$1[REDACTED]")
        .into_owned()
}

fn secret_field_regex() -> Regex {
    Regex::new(
        r#"(?i)((?:password|passwd|token|secret|api[_-]?key|credential)[\s\"']*[:=][\s\"']*)[^\"'&,}\s]{3,}"#,
    )
    .expect("secret field regex is valid")
}

fn jwt_regex() -> Regex {
    Regex::new(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b")
        .expect("JWT regex is valid")
}

fn private_key_regex() -> Regex {
    Regex::new(r"(?s)-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?-----END [A-Z0-9 ]*PRIVATE KEY-----")
        .expect("private-key regex is valid")
}

fn host_is_trusted(host: &str, trusted_hosts: &[String]) -> bool {
    trusted_hosts
        .iter()
        .any(|pattern| pattern_matches(pattern, host, false))
}

fn action_for(mode: ExfiltrationMode, found: bool) -> GuardAction {
    if !found {
        return GuardAction::None;
    }
    match mode {
        ExfiltrationMode::Off => GuardAction::None,
        ExfiltrationMode::Warn => GuardAction::Warned,
        ExfiltrationMode::Redact => GuardAction::Redacted,
        ExfiltrationMode::Block => GuardAction::Blocked,
    }
}

fn is_sensitive_header(name: &str) -> bool {
    [
        "authorization",
        "proxy-authorization",
        "cookie",
        "x-api-key",
        "x-auth-token",
    ]
    .iter()
    .any(|sensitive| name.eq_ignore_ascii_case(sensitive))
}

fn deduplicate(findings: Vec<GuardFinding>) -> Vec<GuardFinding> {
    let mut unique = Vec::new();
    for finding in findings {
        if !unique.iter().any(|existing: &GuardFinding| {
            existing.category == finding.category && existing.location == finding.location
        }) {
            unique.push(finding);
        }
    }
    unique
}

#[cfg(test)]
mod tests {
    use chrono::Utc;

    use super::*;
    use crate::model::{Header, ProcessProvenance};

    fn request(body: &str) -> CapturedRequest {
        CapturedRequest {
            method: "POST".into(),
            scheme: "https".into(),
            host: "upload.example.com".into(),
            port: 443,
            path: "/upload".into(),
            version: "HTTP/1.1".into(),
            headers: vec![Header {
                name: "Authorization".into(),
                value: "Bearer visible-over-https".into(),
            }],
            body: body.as_bytes().to_vec(),
            timestamp: Utc::now(),
            client_addr: String::new(),
            process: String::new(),
            process_path: String::new(),
            pid: None,
            provenance: ProcessProvenance::default(),
            guard: GuardAssessment::default(),
        }
    }

    #[test]
    fn warns_and_redacts_explicit_secrets() {
        let mut value = request(r#"{"password":"hunter22"}"#);
        let assessment = protect_http(&mut value, ExfiltrationMode::Redact, &[]);
        assert_eq!(assessment.action, GuardAction::Redacted);
        assert!(String::from_utf8_lossy(&value.body).contains("[REDACTED]"));
        assert!(!String::from_utf8_lossy(&value.body).contains("hunter22"));
    }

    #[test]
    fn trusted_hosts_are_ignored() {
        let mut value = request(r#"{"password":"hunter22"}"#);
        let assessment = protect_http(
            &mut value,
            ExfiltrationMode::Block,
            &["*.example.com".into()],
        );
        assert_eq!(assessment.action, GuardAction::None);
    }

    #[test]
    fn plaintext_auth_headers_are_detected() {
        let mut value = request("");
        value.scheme = "http".into();
        assert_eq!(
            protect_http(&mut value, ExfiltrationMode::Warn, &[]).action,
            GuardAction::Warned
        );
    }
}
