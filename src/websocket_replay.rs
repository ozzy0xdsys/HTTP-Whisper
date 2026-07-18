use std::time::Duration;

use anyhow::{Context, Result};
use futures_util::{SinkExt, StreamExt};
use tokio_tungstenite::{connect_async, tungstenite::Message};

use crate::model::WebSocketMessage;

pub async fn replay(message: &WebSocketMessage) -> Result<String> {
    let (mut socket, response) = connect_async(&message.url)
        .await
        .with_context(|| format!("could not open replay WebSocket {}", message.url))?;
    let frame = if message.is_text {
        Message::Text(message.payload.clone().into())
    } else {
        let bytes = if message.wire_payload.is_empty() {
            message.payload.as_bytes().to_vec()
        } else {
            message.wire_payload.clone()
        };
        Message::Binary(bytes.into())
    };
    socket
        .send(frame)
        .await
        .context("could not send replay frame")?;
    let reply = tokio::time::timeout(Duration::from_secs(3), socket.next()).await;
    let summary = match reply {
        Ok(Some(Ok(Message::Text(value)))) => {
            format!("received text reply: {}", truncate(value.as_str(), 180))
        }
        Ok(Some(Ok(Message::Binary(value)))) => {
            format!("received binary reply ({} bytes)", value.len())
        }
        Ok(Some(Ok(other))) => format!("received {} reply", message_name(&other)),
        Ok(Some(Err(error))) => format!("frame sent; reply failed: {error}"),
        Ok(None) => "frame sent; server closed without a reply".into(),
        Err(_) => "frame sent; no reply within 3 seconds".into(),
    };
    let _ = socket.close(None).await;
    Ok(format!(
        "WebSocket replay connected with HTTP {}; {summary}",
        response.status()
    ))
}

fn message_name(message: &Message) -> &'static str {
    match message {
        Message::Text(_) => "text",
        Message::Binary(_) => "binary",
        Message::Ping(_) => "ping",
        Message::Pong(_) => "pong",
        Message::Close(_) => "close",
        Message::Frame(_) => "raw frame",
    }
}

fn truncate(value: &str, limit: usize) -> String {
    let mut output = value.chars().take(limit).collect::<String>();
    if value.chars().count() > limit {
        output.push_str("...");
    }
    output
}
