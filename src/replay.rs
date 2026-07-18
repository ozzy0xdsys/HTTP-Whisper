use anyhow::Result;
use reqwest::Method;

use crate::model::{CapturedExchange, CapturedResponse, Header};

pub async fn replay(exchange: &CapturedExchange) -> Result<CapturedResponse> {
    let request = &exchange.request;
    let client = reqwest::Client::builder().no_proxy().build()?;
    let mut builder = client.request(
        Method::from_bytes(request.method.as_bytes())?,
        request.url(),
    );
    for header in &request.headers {
        if !header.name.eq_ignore_ascii_case("host")
            && !header.name.eq_ignore_ascii_case("content-length")
        {
            builder = builder.header(&header.name, &header.value);
        }
    }
    let started = std::time::Instant::now();
    let response = builder.body(request.body.clone()).send().await?;
    let status = response.status();
    let version = format!("{:?}", response.version());
    let headers = response
        .headers()
        .iter()
        .map(|(name, value)| Header {
            name: name.to_string(),
            value: value.to_str().unwrap_or("<binary>").to_owned(),
        })
        .collect();
    let body = response.bytes().await?.to_vec();
    Ok(CapturedResponse {
        status: status.as_u16(),
        reason: status.canonical_reason().unwrap_or("").to_owned(),
        version,
        headers,
        body,
        duration_ms: started.elapsed().as_secs_f64() * 1000.0,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{CapturedRequest, Header, ThreatAssessment};
    use chrono::Utc;
    use std::{
        io::{Read, Write},
        net::TcpListener,
        thread,
    };
    use uuid::Uuid;

    #[tokio::test]
    async fn replays_method_headers_and_body() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut bytes = Vec::new();
            let mut buffer = [0_u8; 4096];
            let count = stream.read(&mut buffer).unwrap();
            bytes.extend_from_slice(&buffer[..count]);
            let request = String::from_utf8_lossy(&bytes);
            assert!(request.starts_with("POST /replay HTTP/1.1"));
            assert!(request.to_ascii_lowercase().contains("x-test: replay"));
            assert!(request.ends_with("hello"));
            stream
                .write_all(
                    b"HTTP/1.1 201 Created\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
                )
                .unwrap();
        });
        let exchange = CapturedExchange {
            id: Uuid::new_v4(),
            sequence: 1,
            request: CapturedRequest {
                method: "POST".into(),
                scheme: "http".into(),
                host: "127.0.0.1".into(),
                port,
                path: "/replay".into(),
                version: "HTTP/1.1".into(),
                headers: vec![Header {
                    name: "X-Test".into(),
                    value: "replay".into(),
                }],
                body: b"hello".to_vec(),
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
        };
        let response = replay(&exchange).await.unwrap();
        assert_eq!(response.status, 201);
        assert_eq!(response.body, b"ok");
        server.join().unwrap();
    }
}
