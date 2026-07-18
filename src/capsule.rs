use std::{
    fs,
    io::{Read, Write},
    path::Path,
};

use aes_gcm::{
    Aes256Gcm, Nonce,
    aead::{Aead, KeyInit},
};
use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use flate2::{Compression, read::GzDecoder, write::GzEncoder};
use pbkdf2::pbkdf2_hmac;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use uuid::Uuid;

use crate::{
    baseline::TrafficBaseline,
    config::{AppSettings, AutoResponseRule, ResponseRewriteRule},
    dossier::HostDossierIndex,
    guard::{redact_headers, sanitize_body, sanitize_text},
    model::Session,
};

const MAGIC: &[u8] = b"HTTPWHISPER-CAPSULE-1\n";
const MODE_PLAIN: &[u8] = b"plain\n";
const MODE_ENCRYPTED: &[u8] = b"aes-256-gcm\n";
const KDF_ROUNDS: u32 = 200_000;
const MAX_CAPSULE_BYTES: u64 = 512 * 1024 * 1024;
const MAX_DECOMPRESSED_BYTES: usize = 512 * 1024 * 1024;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CaptureCapsule {
    pub format_version: u32,
    pub created_at: DateTime<Utc>,
    pub sanitized: bool,
    pub sessions: Vec<Session>,
    pub rules: CapsuleRules,
    pub baseline: TrafficBaseline,
    pub dossiers: HostDossierIndex,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct CapsuleRules {
    pub auto_responses: Vec<AutoResponseRule>,
    pub response_rewrites: Vec<ResponseRewriteRule>,
}

pub fn export_capsule(
    path: &Path,
    sessions: &[Session],
    settings: &AppSettings,
    baseline: &TrafficBaseline,
    dossiers: &HostDossierIndex,
    sanitize: bool,
    passphrase: &str,
) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let sessions = if sanitize {
        sessions.iter().cloned().map(sanitize_session).collect()
    } else {
        sessions.to_vec()
    };
    let mut rules = CapsuleRules {
        auto_responses: settings.auto_response_rules.clone(),
        response_rewrites: settings.response_rewrite_rules.clone(),
    };
    if sanitize {
        for rule in &mut rules.auto_responses {
            rule.body = sanitize_text(&rule.body);
        }
        for rule in &mut rules.response_rewrites {
            rule.replace_text = sanitize_text(&rule.replace_text);
        }
    }
    let capsule = CaptureCapsule {
        format_version: 1,
        created_at: Utc::now(),
        sanitized: sanitize,
        sessions,
        rules,
        baseline: baseline.clone(),
        dossiers: dossiers.clone(),
    };
    let json = serde_json::to_vec(&capsule)?;
    let compressed = compress(&json)?;
    let mut output = Vec::with_capacity(compressed.len() + 96);
    output.extend_from_slice(MAGIC);
    if passphrase.is_empty() {
        output.extend_from_slice(MODE_PLAIN);
        output.extend_from_slice(&compressed);
    } else {
        output.extend_from_slice(MODE_ENCRYPTED);
        let salt = *Uuid::new_v4().as_bytes();
        let nonce_source = *Uuid::new_v4().as_bytes();
        let nonce = &nonce_source[..12];
        let key = derive_key(passphrase, &salt);
        let cipher = Aes256Gcm::new_from_slice(&key).expect("AES-256 accepts a 32-byte key");
        let nonce = Nonce::try_from(nonce).expect("nonce has 12 bytes");
        let encrypted = cipher
            .encrypt(&nonce, compressed.as_ref())
            .map_err(|_| anyhow::anyhow!("could not encrypt capture capsule"))?;
        output.extend_from_slice(&salt);
        output.extend_from_slice(&nonce);
        output.extend_from_slice(&encrypted);
    }
    let temporary = path.with_extension("whispercapsule.tmp");
    fs::write(&temporary, output)?;
    fs::rename(temporary, path)?;
    Ok(())
}

pub fn import_capsule(path: &Path, passphrase: &str) -> Result<CaptureCapsule> {
    let metadata = fs::metadata(path)
        .with_context(|| format!("could not inspect capture capsule {}", path.display()))?;
    anyhow::ensure!(
        metadata.len() <= MAX_CAPSULE_BYTES,
        "capture capsule exceeds the 512 MiB file limit"
    );
    let bytes = fs::read(path)
        .with_context(|| format!("could not read capture capsule {}", path.display()))?;
    anyhow::ensure!(
        bytes.starts_with(MAGIC),
        "not an HTTP Whisper capture capsule"
    );
    let remainder = &bytes[MAGIC.len()..];
    let compressed = if let Some(data) = remainder.strip_prefix(MODE_PLAIN) {
        data.to_vec()
    } else if let Some(data) = remainder.strip_prefix(MODE_ENCRYPTED) {
        anyhow::ensure!(!passphrase.is_empty(), "this capsule requires a passphrase");
        anyhow::ensure!(data.len() > 28, "encrypted capsule is truncated");
        let (salt, data) = data.split_at(16);
        let (nonce, encrypted) = data.split_at(12);
        let key = derive_key(passphrase, salt);
        let cipher = Aes256Gcm::new_from_slice(&key).expect("AES-256 accepts a 32-byte key");
        let nonce = Nonce::try_from(nonce).expect("nonce has 12 bytes");
        cipher
            .decrypt(&nonce, encrypted)
            .map_err(|_| anyhow::anyhow!("capsule passphrase is incorrect or data is damaged"))?
    } else {
        anyhow::bail!("capture capsule mode is unsupported");
    };
    let json = decompress_limited(&compressed, MAX_DECOMPRESSED_BYTES)?;
    let capsule: CaptureCapsule =
        serde_json::from_slice(&json).context("capture capsule content is invalid")?;
    anyhow::ensure!(
        capsule.format_version == 1,
        "capture capsule version {} is unsupported",
        capsule.format_version
    );
    Ok(capsule)
}

fn sanitize_session(mut session: Session) -> Session {
    match &mut session {
        Session::Http(exchange) => {
            redact_headers(&mut exchange.request.headers);
            exchange.request.body = sanitize_body(&exchange.request.body);
            if let Some(response) = &mut exchange.response {
                redact_headers(&mut response.headers);
                response.body = sanitize_body(&response.body);
            }
        }
        Session::WebSocket(message) => {
            message.payload = sanitize_text(&message.payload);
            message.wire_payload.clear();
        }
    }
    session
}

fn derive_key(passphrase: &str, salt: &[u8]) -> [u8; 32] {
    let mut key = [0_u8; 32];
    pbkdf2_hmac::<Sha256>(passphrase.as_bytes(), salt, KDF_ROUNDS, &mut key);
    key
}

fn compress(bytes: &[u8]) -> Result<Vec<u8>> {
    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(bytes)?;
    Ok(encoder.finish()?)
}

fn decompress_limited(bytes: &[u8], limit: usize) -> Result<Vec<u8>> {
    let decoder = GzDecoder::new(bytes);
    let mut output = Vec::new();
    decoder
        .take(limit.saturating_add(1) as u64)
        .read_to_end(&mut output)?;
    anyhow::ensure!(
        output.len() <= limit,
        "capture capsule expands beyond the allowed size"
    );
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{
        BehaviorAssessment, CapturedExchange, CapturedRequest, GuardAssessment, Header,
        ProcessProvenance, ThreatAssessment,
    };

    fn session() -> Session {
        Session::Http(CapturedExchange {
            id: Uuid::new_v4(),
            sequence: 1,
            request: CapturedRequest {
                method: "POST".into(),
                scheme: "https".into(),
                host: "example.test".into(),
                port: 443,
                path: "/login".into(),
                version: "HTTP/1.1".into(),
                headers: vec![Header {
                    name: "Authorization".into(),
                    value: "Bearer secret".into(),
                }],
                body: br#"{"password":"hunter22"}"#.to_vec(),
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
    fn encrypted_sanitized_capsules_round_trip() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("test.whispercapsule");
        export_capsule(
            &path,
            &[session()],
            &AppSettings::default(),
            &TrafficBaseline::default(),
            &HostDossierIndex::default(),
            true,
            "correct horse",
        )
        .unwrap();
        let capsule = import_capsule(&path, "correct horse").unwrap();
        let Session::Http(exchange) = &capsule.sessions[0] else {
            panic!("expected HTTP session");
        };
        assert_eq!(
            exchange.request.headers[0].value,
            "<redacted by HTTP Whisper>"
        );
        assert!(!String::from_utf8_lossy(&exchange.request.body).contains("hunter22"));
        assert!(import_capsule(&path, "wrong").is_err());
    }

    #[test]
    fn decompression_obeys_the_size_limit() {
        let compressed = compress(b"larger than the test limit").unwrap();
        assert!(decompress_limited(&compressed, 8).is_err());
    }
}
