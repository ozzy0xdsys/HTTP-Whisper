use std::{collections::HashMap, fs, path::Path};

use anyhow::{Context, Result};
use prost_reflect::{DescriptorPool, DynamicMessage};
use serde_json::Value;

use crate::model::{Direction, WebSocketAnalysis, WebSocketMessage};

#[derive(Default)]
pub struct ProtocolTracker {
    pending: HashMap<String, u64>,
}

impl ProtocolTracker {
    pub fn reset(&mut self) {
        self.pending.clear();
    }

    pub fn analyze(&mut self, message: &mut WebSocketMessage) {
        let mut analysis = inspect_message(message);
        if !analysis.correlation_id.is_empty() {
            let correlation_key = format!(
                "{}\n{}\n{}",
                message.host, message.path, analysis.correlation_id
            );
            if message.direction == Direction::Out {
                self.pending.insert(correlation_key, message.sequence);
            } else {
                analysis.reply_to_sequence = self.pending.remove(&correlation_key);
            }
        }
        message.analysis = analysis;
    }
}

pub fn inspect_message(message: &WebSocketMessage) -> WebSocketAnalysis {
    if let Ok(value) = serde_json::from_str::<Value>(&message.payload) {
        return inspect_json(&value);
    }
    let protocol = if message.is_text {
        "Text"
    } else if looks_like_messagepack(&message.wire_payload) {
        "MessagePack-like binary"
    } else if looks_like_protobuf(&message.wire_payload) {
        "Protobuf-like binary"
    } else if message.decoded_as.contains("gzip") || message.decoded_as.contains("zlib") {
        "Compressed text"
    } else {
        "Unknown binary"
    };
    WebSocketAnalysis {
        protocol: protocol.into(),
        message_type: first_text_token(&message.payload),
        ..Default::default()
    }
}

pub fn descriptor_messages(path: &Path) -> Result<Vec<String>> {
    let bytes = fs::read(path)
        .with_context(|| format!("could not read descriptor set {}", path.display()))?;
    let pool =
        DescriptorPool::decode(bytes.as_slice()).context("invalid protobuf descriptor set")?;
    Ok(pool
        .all_messages()
        .map(|descriptor| descriptor.full_name().to_owned())
        .collect())
}

pub fn decode_with_descriptors(path: &Path, bytes: &[u8]) -> Result<Vec<String>> {
    let descriptor_bytes = fs::read(path)
        .with_context(|| format!("could not read descriptor set {}", path.display()))?;
    let pool = DescriptorPool::decode(descriptor_bytes.as_slice())
        .context("invalid protobuf descriptor set")?;
    let mut candidates = Vec::new();
    for descriptor in pool.all_messages().take(2_000) {
        let name = descriptor.full_name().to_owned();
        let Ok(message) = DynamicMessage::decode(descriptor, bytes) else {
            continue;
        };
        let known = message.fields().count();
        if known == 0 {
            continue;
        }
        let unknown = message.unknown_fields().count();
        candidates.push((known, unknown, name, message.to_string()));
    }
    candidates.sort_by(|left, right| {
        right
            .0
            .cmp(&left.0)
            .then_with(|| left.1.cmp(&right.1))
            .then_with(|| left.2.cmp(&right.2))
    });
    Ok(candidates
        .into_iter()
        .take(8)
        .map(|(known, unknown, name, value)| {
            format!("{name} ({known} known, {unknown} unknown field(s))\n{value}")
        })
        .collect())
}

pub fn protocol_summary(messages: &[WebSocketMessage]) -> String {
    if messages.is_empty() {
        return "No WebSocket messages captured.".into();
    }
    let mut protocols = std::collections::BTreeMap::<String, usize>::new();
    let mut types = std::collections::BTreeMap::<String, usize>::new();
    let mut pairs = 0;
    let mut sequences = 0;
    for message in messages {
        *protocols
            .entry(empty_label(&message.analysis.protocol, "Unclassified"))
            .or_default() += 1;
        if !message.analysis.message_type.is_empty() {
            *types
                .entry(message.analysis.message_type.clone())
                .or_default() += 1;
        }
        pairs += usize::from(message.analysis.reply_to_sequence.is_some());
        sequences += usize::from(message.analysis.sequence_value.is_some());
    }
    let mut lines = vec![format!(
        "Messages: {}\nCorrelated replies: {}\nSequence-bearing messages: {}",
        messages.len(),
        pairs,
        sequences
    )];
    lines.push("\nProtocols".into());
    lines.extend(
        protocols
            .into_iter()
            .map(|(protocol, count)| format!("  {protocol}: {count}")),
    );
    if !types.is_empty() {
        lines.push("\nMessage types".into());
        lines.extend(
            types
                .into_iter()
                .take(100)
                .map(|(kind, count)| format!("  {kind}: {count}")),
        );
    }
    lines.join("\n")
}

fn inspect_json(value: &Value) -> WebSocketAnalysis {
    let protocol = if value.get("jsonrpc").is_some() {
        "JSON-RPC"
    } else if value.get("query").is_some() || value.get("operationName").is_some() {
        "GraphQL over WebSocket"
    } else if value.get("op").is_some() && (value.get("t").is_some() || value.get("s").is_some()) {
        "JSON event stream"
    } else {
        "JSON"
    };
    let message_type = string_or_number(value, &["type", "event", "method", "action", "t", "op"])
        .unwrap_or_default();
    let correlation_id = string_or_number(value, &["request_id", "correlation_id", "nonce", "id"])
        .unwrap_or_default();
    let sequence_value = numeric(value, &["sequence", "seq", "s"]);
    let mut schema = Vec::new();
    collect_schema("$", value, &mut schema, 0);
    WebSocketAnalysis {
        protocol: protocol.into(),
        message_type,
        correlation_id,
        sequence_value,
        reply_to_sequence: None,
        schema,
    }
}

fn collect_schema(path: &str, value: &Value, output: &mut Vec<String>, depth: usize) {
    if output.len() >= 96 || depth > 6 {
        return;
    }
    match value {
        Value::Object(values) => {
            for (key, value) in values {
                let child = format!("{path}.{key}");
                output.push(format!("{child}: {}", json_type(value)));
                collect_schema(&child, value, output, depth + 1);
            }
        }
        Value::Array(values) => {
            if let Some(value) = values.first() {
                let child = format!("{path}[]");
                output.push(format!("{child}: {}", json_type(value)));
                collect_schema(&child, value, output, depth + 1);
            }
        }
        _ => {}
    }
}

fn json_type(value: &Value) -> &'static str {
    match value {
        Value::Null => "null",
        Value::Bool(_) => "boolean",
        Value::Number(value) if value.is_i64() || value.is_u64() => "integer",
        Value::Number(_) => "number",
        Value::String(_) => "string",
        Value::Array(_) => "array",
        Value::Object(_) => "object",
    }
}

fn string_or_number(value: &Value, keys: &[&str]) -> Option<String> {
    keys.iter().find_map(|key| match value.get(*key) {
        Some(Value::String(value)) => Some(value.clone()),
        Some(Value::Number(value)) => Some(value.to_string()),
        _ => None,
    })
}

fn numeric(value: &Value, keys: &[&str]) -> Option<i64> {
    keys.iter().find_map(|key| match value.get(*key) {
        Some(Value::Number(value)) => value.as_i64(),
        Some(Value::String(value)) => value.parse().ok(),
        _ => None,
    })
}

fn looks_like_messagepack(bytes: &[u8]) -> bool {
    bytes.first().is_some_and(|byte| {
        matches!(
            *byte,
            0x80..=0x8f | 0x90..=0x9f | 0xa0..=0xbf | 0xde | 0xdf | 0xdc | 0xdd
        )
    })
}

fn looks_like_protobuf(bytes: &[u8]) -> bool {
    if bytes.len() < 2 {
        return false;
    }
    let wire_type = bytes[0] & 0x07;
    let field_number = bytes[0] >> 3;
    field_number > 0 && wire_type <= 5 && !looks_like_messagepack(bytes)
}

fn first_text_token(value: &str) -> String {
    value
        .split(|character: char| character.is_whitespace() || character == ':' || character == ',')
        .find(|token| !token.is_empty())
        .unwrap_or_default()
        .chars()
        .take(80)
        .collect()
}

fn empty_label(value: &str, fallback: &str) -> String {
    if value.is_empty() {
        fallback.into()
    } else {
        value.into()
    }
}

#[cfg(test)]
mod tests {
    use chrono::Utc;
    use uuid::Uuid;

    use super::*;
    use crate::model::{BehaviorAssessment, GuardAssessment, ProcessProvenance, ThreatAssessment};

    fn message(direction: Direction, sequence: u64, payload: &str) -> WebSocketMessage {
        WebSocketMessage {
            id: Uuid::new_v4(),
            sequence,
            url: "wss://example.test/ws".into(),
            host: "example.test".into(),
            path: "/ws".into(),
            direction,
            opcode: "TEXT".into(),
            is_text: true,
            payload: payload.into(),
            raw_size: payload.len(),
            decoded_as: "text".into(),
            rule_matched: None,
            timestamp: Utc::now(),
            process: String::new(),
            process_path: String::new(),
            pid: None,
            threat: ThreatAssessment::default(),
            provenance: ProcessProvenance::default(),
            guard: GuardAssessment::default(),
            behavior: BehaviorAssessment::default(),
            analysis: WebSocketAnalysis::default(),
            wire_payload: payload.as_bytes().to_vec(),
            synthetic: false,
        }
    }

    #[test]
    fn infers_json_rpc_schema_and_correlates_replies() {
        let mut tracker = ProtocolTracker::default();
        let mut outgoing = message(
            Direction::Out,
            10,
            r#"{"jsonrpc":"2.0","id":7,"method":"users.get","params":{"id":1}}"#,
        );
        tracker.analyze(&mut outgoing);
        assert_eq!(outgoing.analysis.protocol, "JSON-RPC");
        assert_eq!(outgoing.analysis.message_type, "users.get");
        assert!(
            outgoing
                .analysis
                .schema
                .iter()
                .any(|path| path == "$.params.id: integer")
        );

        let mut incoming = message(
            Direction::In,
            11,
            r#"{"jsonrpc":"2.0","id":7,"result":{"name":"Ada"}}"#,
        );
        tracker.analyze(&mut incoming);
        assert_eq!(incoming.analysis.reply_to_sequence, Some(10));
    }

    #[test]
    fn correlation_ids_are_scoped_to_the_websocket_endpoint() {
        let mut tracker = ProtocolTracker::default();
        let mut outgoing = message(Direction::Out, 10, r#"{"id":7,"type":"request"}"#);
        tracker.analyze(&mut outgoing);

        let mut wrong_endpoint = message(Direction::In, 11, r#"{"id":7,"type":"reply"}"#);
        wrong_endpoint.host = "other.example.test".into();
        tracker.analyze(&mut wrong_endpoint);
        assert_eq!(wrong_endpoint.analysis.reply_to_sequence, None);

        let mut correct_endpoint = message(Direction::In, 12, r#"{"id":7,"type":"reply"}"#);
        tracker.analyze(&mut correct_endpoint);
        assert_eq!(correct_endpoint.analysis.reply_to_sequence, Some(10));
    }

    #[test]
    fn recognizes_messagepack_and_protobuf_shapes() {
        let mut msgpack = message(Direction::Out, 1, "");
        msgpack.is_text = false;
        msgpack.wire_payload = vec![0x81, 0xa1, b'a', 1];
        assert_eq!(
            inspect_message(&msgpack).protocol,
            "MessagePack-like binary"
        );

        let mut protobuf = message(Direction::Out, 1, "");
        protobuf.is_text = false;
        protobuf.wire_payload = vec![0x0a, 0x03, b'a', b'b', b'c'];
        assert_eq!(inspect_message(&protobuf).protocol, "Protobuf-like binary");
    }
}
