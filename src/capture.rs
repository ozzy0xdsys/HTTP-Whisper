use std::{
    collections::HashMap,
    fs,
    io::Read,
    net::{IpAddr, SocketAddr},
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
        mpsc,
    },
    thread,
    time::Instant,
};

use anyhow::{Context, Result};
use chrono::Utc;
use flate2::{
    Compress, Compression, Decompress, FlushCompress, FlushDecompress,
    read::{DeflateDecoder, GzDecoder, ZlibDecoder},
};
use http_body_util::BodyExt;
use hudsucker::{
    Body, HttpContext, HttpHandler, Proxy, RequestOrResponse, WebSocketContext, WebSocketHandler,
    decode_request, decode_response,
    hyper::{Method, Request, Response, StatusCode, header},
    rustls::crypto::aws_lc_rs,
    tokio_tungstenite::tungstenite::Message,
};
use parking_lot::{Mutex, RwLock};
use tokio::sync::oneshot;
use uuid::Uuid;

use crate::{
    certificate::{install_current_user_ca, load_or_create_ca},
    config::{AppPaths, AppSettings},
    model::{
        BreakpointAction, BreakpointDecision, BreakpointPhase, CaptureEvent, CapturedExchange,
        CapturedRequest, CapturedResponse, Direction, Header, Headers, PausedBreakpoint,
        WebSocketMessage,
    },
    rules::{
        apply_rewrite, find_auto_response, find_breakpoint, host_is_hidden, matching_rewrites,
    },
    storage::BodyStore,
    windows_proxy::WindowsProxyManager,
};

const MAX_PREVIEW: usize = 1_000_000;

pub struct CaptureWorker {
    stop: Option<oneshot::Sender<()>>,
    join: Option<thread::JoinHandle<()>>,
    settings: Arc<RwLock<AppSettings>>,
    breakpoints: BreakpointController,
}

impl CaptureWorker {
    pub fn start(settings: AppSettings, events: mpsc::Sender<CaptureEvent>) -> Result<Self> {
        let (stop_tx, stop_rx) = oneshot::channel();
        let shared_settings = Arc::new(RwLock::new(settings));
        let worker_settings = Arc::clone(&shared_settings);
        let breakpoints = BreakpointController::default();
        let worker_breakpoints = breakpoints.clone();
        let join = thread::Builder::new()
            .name("http-whisper-capture".into())
            .spawn(move || {
                if let Err(error) =
                    run_capture(worker_settings, worker_breakpoints, events.clone(), stop_rx)
                {
                    let _ = events.send(CaptureEvent::Error(error.to_string()));
                }
            })?;
        Ok(Self {
            stop: Some(stop_tx),
            join: Some(join),
            settings: shared_settings,
            breakpoints,
        })
    }

    pub fn update_settings(&self, settings: AppSettings) {
        *self.settings.write() = settings;
    }

    pub fn stop(&mut self) {
        self.breakpoints.cancel_all();
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
    }

    pub fn resolve_breakpoint(&self, decision: BreakpointDecision) -> bool {
        self.breakpoints.resolve(decision)
    }

    pub fn is_running(&self) -> bool {
        self.join.as_ref().is_some_and(|join| !join.is_finished())
    }

    pub fn join(&mut self) {
        self.stop();
        if let Some(join) = self.join.take() {
            let _ = join.join();
        }
    }
}

impl Drop for CaptureWorker {
    fn drop(&mut self) {
        self.join();
    }
}

fn run_capture(
    settings: Arc<RwLock<AppSettings>>,
    breakpoints: BreakpointController,
    events: mpsc::Sender<CaptureEvent>,
    stop_rx: oneshot::Receiver<()>,
) -> Result<()> {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .thread_name("http-whisper-net")
        .build()?;
    runtime.block_on(async move {
        let _ = events.send(CaptureEvent::Starting);
        let paths = AppPaths::discover()?;
        paths.ensure()?;
        let current = settings.read().clone();
        let host: IpAddr = current
            .capture_host
            .parse()
            .context("capture host is invalid")?;
        let address = SocketAddr::new(host, current.capture_port);
        let listener = tokio::net::TcpListener::bind(address)
            .await
            .with_context(|| {
                format!("cannot listen on {address}; the port may already be in use")
            })?;

        let certificates = load_or_create_ca(paths.certificates_dir.join("rust-mitm"))?;
        let ca_der = Arc::new(fs::read(&certificates.certificate_der).with_context(|| {
            format!(
                "cannot read the CA certificate at {}",
                certificates.certificate_der.display()
            )
        })?);
        let ca_pem = Arc::new(fs::read(&certificates.certificate_pem).with_context(|| {
            format!(
                "cannot read the PEM CA certificate at {}",
                certificates.certificate_pem.display()
            )
        })?);
        if current.enable_https_interception && current.auto_install_ca {
            let _ = events.send(CaptureEvent::Log(
                "Installing HTTP Whisper CA in current-user Root store".into(),
            ));
            install_current_user_ca(&certificates.certificate_der)?;
            let _ = events.send(CaptureEvent::Log("HTTP Whisper CA trusted".into()));
        }

        let mut windows_proxy = WindowsProxyManager::new(paths.data_dir.join("proxy-restore.json"));
        if windows_proxy.recover_if_needed()? {
            let _ = events.send(CaptureEvent::Log(
                "Recovered Windows proxy settings from an interrupted capture".into(),
            ));
        }
        if current.auto_configure_system_proxy {
            windows_proxy.enable(&current.capture_host, current.capture_port)?;
            let _ = events.send(CaptureEvent::Log(format!(
                "Windows and Firefox proxy configured: {}",
                windows_proxy.summary()?
            )));
        }

        let shared = SharedCapture {
            settings,
            events: events.clone(),
            sequence: Arc::new(AtomicU64::new(0)),
            body_store: BodyStore::new(paths.bodies_dir)?,
            ca_der,
            ca_pem,
            breakpoints,
        };
        let http_handler = TrafficHandler::new(shared.clone());
        let websocket_handler = WebSocketTrafficHandler::new(shared);
        let proxy = Proxy::builder()
            .with_listener(listener)
            .with_ca(certificates.authority)
            .with_rustls_connector(aws_lc_rs::default_provider())
            .with_http_handler(http_handler)
            .with_websocket_handler(websocket_handler)
            .with_graceful_shutdown(async move {
                let _ = stop_rx.await;
            })
            .build()?;
        let _ = events.send(CaptureEvent::Started {
            host: current.capture_host,
            port: current.capture_port,
        });
        let result = proxy.start().await;
        if current.auto_configure_system_proxy {
            windows_proxy.restore()?;
        }
        match result {
            Ok(()) => {
                let _ = events.send(CaptureEvent::Stopped("stopped".into()));
                Ok(())
            }
            Err(error) => {
                let _ = events.send(CaptureEvent::Stopped("proxy stopped unexpectedly".into()));
                Err(anyhow::anyhow!(error))
            }
        }
    })
}

#[derive(Clone)]
struct SharedCapture {
    settings: Arc<RwLock<AppSettings>>,
    events: mpsc::Sender<CaptureEvent>,
    sequence: Arc<AtomicU64>,
    body_store: BodyStore,
    ca_der: Arc<Vec<u8>>,
    ca_pem: Arc<Vec<u8>>,
    breakpoints: BreakpointController,
}

impl SharedCapture {
    fn next_sequence(&self) -> u64 {
        self.sequence.fetch_add(1, Ordering::Relaxed) + 1
    }

    async fn pause_at_breakpoint(
        &self,
        rule_name: String,
        phase: BreakpointPhase,
        request: CapturedRequest,
        response: Option<CapturedResponse>,
    ) -> Option<BreakpointDecision> {
        let id = Uuid::new_v4();
        let (decision_tx, decision_rx) = oneshot::channel();
        self.breakpoints.waiters.lock().insert(id, decision_tx);
        let paused = PausedBreakpoint {
            id,
            rule_name,
            phase,
            request,
            response,
        };
        if self
            .events
            .send(CaptureEvent::BreakpointPaused(paused))
            .is_err()
        {
            self.breakpoints.waiters.lock().remove(&id);
            return None;
        }
        decision_rx.await.ok()
    }
}

#[derive(Clone, Default)]
struct BreakpointController {
    waiters: Arc<Mutex<HashMap<Uuid, oneshot::Sender<BreakpointDecision>>>>,
}

impl BreakpointController {
    fn resolve(&self, decision: BreakpointDecision) -> bool {
        self.waiters
            .lock()
            .remove(&decision.id)
            .is_some_and(|waiter| waiter.send(decision).is_ok())
    }

    fn cancel_all(&self) {
        self.waiters.lock().clear();
    }
}

struct PendingRequest {
    request: CapturedRequest,
    started: Instant,
    synthetic: bool,
    rule_matched: Option<String>,
}

struct TrafficHandler {
    shared: SharedCapture,
    pending: Option<PendingRequest>,
}

impl TrafficHandler {
    fn new(shared: SharedCapture) -> Self {
        Self {
            shared,
            pending: None,
        }
    }
}

impl Clone for TrafficHandler {
    fn clone(&self) -> Self {
        Self::new(self.shared.clone())
    }
}

impl HttpHandler for TrafficHandler {
    async fn handle_request(
        &mut self,
        context: &HttpContext,
        request: Request<Body>,
    ) -> RequestOrResponse {
        if let Some(response) = ca_install_response(&request, &self.shared) {
            return RequestOrResponse::Response(response);
        }

        let request = if has_supported_content_encoding(request.headers()) {
            match decode_request(request) {
                Ok(request) => request,
                Err(error) => {
                    let message = format!("Could not decode request body: {error}");
                    let _ = self
                        .shared
                        .events
                        .send(CaptureEvent::Error(message.clone()));
                    return RequestOrResponse::Response(proxy_error_response(&message));
                }
            }
        } else {
            request
        };
        let (mut parts, body) = request.into_parts();
        let mut body = match body.collect().await {
            Ok(value) => value.to_bytes().to_vec(),
            Err(error) => {
                let _ = self.shared.events.send(CaptureEvent::Error(format!(
                    "Could not read request body: {error}"
                )));
                Vec::new()
            }
        };
        let mut captured = request_from_parts(&parts, body.clone(), context);
        let settings = self.shared.settings.read().clone();
        let hidden = host_is_hidden(&captured.host, &settings.hidden_hosts);
        let rule = find_auto_response(
            &captured.method,
            &captured.host,
            path_without_query(&captured.path),
            &settings.auto_response_rules,
        )
        .cloned();
        if let Some(rule) = rule {
            let mut response_text = rule.body;
            let mut matched_names = vec![rule.name];
            for rewrite in matching_rewrites(&captured.host, &settings.response_rewrite_rules) {
                let (rewritten, count) = apply_rewrite(&response_text, rewrite);
                if count > 0 {
                    response_text = rewritten;
                    matched_names.push(rewrite.name.clone());
                }
            }
            let response_body = response_text.into_bytes();
            if !hidden {
                let status = hudsucker::hyper::StatusCode::from_u16(rule.status_code)
                    .unwrap_or(hudsucker::hyper::StatusCode::OK);
                let response_headers = vec![Header {
                    name: "content-type".into(),
                    value: rule.content_type.clone(),
                }];
                let _ = self.shared.body_store.put(&captured.body);
                let _ = self.shared.body_store.put(&response_body);
                let exchange = CapturedExchange {
                    id: Uuid::new_v4(),
                    sequence: self.shared.next_sequence(),
                    request: captured,
                    response: Some(CapturedResponse {
                        status: rule.status_code,
                        reason: status.canonical_reason().unwrap_or("").into(),
                        version: "HTTP/1.1".into(),
                        headers: response_headers,
                        body: response_body.clone(),
                        duration_ms: 0.0,
                    }),
                    rule_matched: Some(matched_names.join(", ")),
                    error: None,
                    synthetic: true,
                    pinned: false,
                    notes: String::new(),
                };
                let _ = self.shared.events.send(CaptureEvent::Exchange(exchange));
            }
            let response = Response::builder()
                .status(rule.status_code)
                .header(header::CONTENT_TYPE, rule.content_type)
                .body(Body::from(response_body))
                .unwrap_or_else(|_| Response::new(Body::from("invalid automatic response")));
            return RequestOrResponse::Response(response);
        }

        let mut breakpoint_match = None;
        if !hidden
            && let Some(rule) = find_breakpoint(
                BreakpointPhase::Request,
                &captured.method,
                &captured.host,
                path_without_query(&captured.path),
                None,
                &settings.breakpoint_rules,
            )
            .cloned()
        {
            let rule_label = format!("Breakpoint: {}", rule.name);
            let decision = self
                .shared
                .pause_at_breakpoint(
                    rule.name.clone(),
                    BreakpointPhase::Request,
                    captured.clone(),
                    None,
                )
                .await;
            if let Some(decision) = decision {
                match decision.action {
                    BreakpointAction::Forward => {
                        if let Err(error) = apply_edited_request(
                            &mut parts,
                            &mut body,
                            &mut captured,
                            decision.request,
                        ) {
                            let message = format!("Could not apply breakpoint request: {error}");
                            let _ = self
                                .shared
                                .events
                                .send(CaptureEvent::Error(message.clone()));
                            return RequestOrResponse::Response(proxy_error_response(&message));
                        }
                        breakpoint_match = Some(rule_label);
                    }
                    BreakpointAction::Drop => {
                        let response_body = b"Dropped by HTTP Whisper request breakpoint".to_vec();
                        if !hidden {
                            let response = CapturedResponse {
                                status: StatusCode::FORBIDDEN.as_u16(),
                                reason: "Forbidden".into(),
                                version: "HTTP/1.1".into(),
                                headers: vec![Header {
                                    name: "content-type".into(),
                                    value: "text/plain; charset=utf-8".into(),
                                }],
                                body: response_body.clone(),
                                duration_ms: 0.0,
                            };
                            let _ = self.shared.body_store.put(&captured.body);
                            let _ = self.shared.body_store.put(&response_body);
                            let exchange = CapturedExchange {
                                id: Uuid::new_v4(),
                                sequence: self.shared.next_sequence(),
                                request: captured,
                                response: Some(response),
                                rule_matched: Some(rule_label),
                                error: Some("Dropped at request breakpoint".into()),
                                synthetic: true,
                                pinned: false,
                                notes: "Dropped at request breakpoint".into(),
                            };
                            let _ = self.shared.events.send(CaptureEvent::Exchange(exchange));
                        }
                        return RequestOrResponse::Response(breakpoint_drop_response(
                            StatusCode::FORBIDDEN,
                            response_body,
                        ));
                    }
                }
            }
        }
        self.pending = Some(PendingRequest {
            request: captured,
            started: Instant::now(),
            synthetic: false,
            rule_matched: breakpoint_match,
        });
        let request = Request::from_parts(parts, Body::from(body));
        RequestOrResponse::Request(request)
    }

    async fn handle_response(
        &mut self,
        _context: &HttpContext,
        response: Response<Body>,
    ) -> Response<Body> {
        let response = if has_supported_content_encoding(response.headers()) {
            match decode_response(response) {
                Ok(response) => response,
                Err(error) => {
                    let message = format!("Could not decode response body: {error}");
                    let _ = self
                        .shared
                        .events
                        .send(CaptureEvent::Error(message.clone()));
                    return proxy_error_response(&message);
                }
            }
        } else {
            response
        };
        let (mut parts, body) = response.into_parts();
        let mut body = match body.collect().await {
            Ok(value) => value.to_bytes().to_vec(),
            Err(error) => {
                let _ = self.shared.events.send(CaptureEvent::Error(format!(
                    "Could not read response body: {error}"
                )));
                Vec::new()
            }
        };
        let mut matched_names = self
            .pending
            .as_ref()
            .and_then(|pending| pending.rule_matched.clone())
            .into_iter()
            .collect::<Vec<_>>();

        if let Some(pending) = &self.pending {
            let settings = self.shared.settings.read();
            if let Ok(mut text) = String::from_utf8(body.clone()) {
                for rule in
                    matching_rewrites(&pending.request.host, &settings.response_rewrite_rules)
                {
                    let (rewritten, count) = apply_rewrite(&text, rule);
                    if count > 0 {
                        matched_names.push(rule.name.clone());
                        text = rewritten;
                    }
                }
                body = text.into_bytes();
                parts.headers.remove(header::CONTENT_LENGTH);
                parts.headers.remove(header::CONTENT_ENCODING);
            }
        }

        if let Some(pending) = self.pending.take() {
            let settings = self.shared.settings.read().clone();
            let hidden = host_is_hidden(&pending.request.host, &settings.hidden_hosts);
            let duration_ms = pending.started.elapsed().as_secs_f64() * 1000.0;
            let mut captured_response = response_from_parts(&parts, body.clone(), duration_ms);
            let mut dropped = false;

            if !hidden
                && let Some(rule) = find_breakpoint(
                    BreakpointPhase::Response,
                    &pending.request.method,
                    &pending.request.host,
                    path_without_query(&pending.request.path),
                    Some(captured_response.status),
                    &settings.breakpoint_rules,
                )
                .cloned()
            {
                let rule_label = format!("Breakpoint: {}", rule.name);
                let decision = self
                    .shared
                    .pause_at_breakpoint(
                        rule.name,
                        BreakpointPhase::Response,
                        pending.request.clone(),
                        Some(captured_response.clone()),
                    )
                    .await;
                if let Some(decision) = decision {
                    match decision.action {
                        BreakpointAction::Forward => {
                            let Some(edited_response) = decision.response else {
                                let message =
                                    "Response breakpoint did not include a response".to_owned();
                                let _ = self
                                    .shared
                                    .events
                                    .send(CaptureEvent::Error(message.clone()));
                                return proxy_error_response(&message);
                            };
                            if let Err(error) = apply_edited_response(
                                &mut parts,
                                &mut body,
                                &mut captured_response,
                                edited_response,
                            ) {
                                let message =
                                    format!("Could not apply breakpoint response: {error}");
                                let _ = self
                                    .shared
                                    .events
                                    .send(CaptureEvent::Error(message.clone()));
                                return proxy_error_response(&message);
                            }
                            matched_names.push(rule_label);
                        }
                        BreakpointAction::Drop => {
                            body = b"Dropped by HTTP Whisper response breakpoint".to_vec();
                            parts.status = StatusCode::BAD_GATEWAY;
                            parts.headers.clear();
                            parts.headers.insert(
                                header::CONTENT_TYPE,
                                "text/plain; charset=utf-8".parse().expect("static header"),
                            );
                            captured_response =
                                response_from_parts(&parts, body.clone(), duration_ms);
                            matched_names.push(rule_label);
                            dropped = true;
                        }
                    }
                }
            }

            if !hidden {
                let _ = self.shared.body_store.put(&pending.request.body);
                let _ = self.shared.body_store.put(&body);
                let exchange = CapturedExchange {
                    id: Uuid::new_v4(),
                    sequence: self.shared.next_sequence(),
                    request: pending.request,
                    response: Some(captured_response),
                    rule_matched: (!matched_names.is_empty()).then(|| matched_names.join(", ")),
                    error: dropped.then(|| "Dropped at response breakpoint".into()),
                    synthetic: pending.synthetic || dropped,
                    pinned: false,
                    notes: if dropped {
                        "Dropped at response breakpoint".into()
                    } else {
                        String::new()
                    },
                };
                let _ = self.shared.events.send(CaptureEvent::Exchange(exchange));
            }
        }
        Response::from_parts(parts, Body::from(body))
    }

    async fn handle_error(
        &mut self,
        _context: &HttpContext,
        error: hudsucker::hyper_util::client::legacy::Error,
    ) -> Response<Body> {
        let message = format!("Upstream request failed: {error}");
        if let Some(pending) = self.pending.take() {
            let settings = self.shared.settings.read();
            if !host_is_hidden(&pending.request.host, &settings.hidden_hosts) {
                let exchange = CapturedExchange {
                    id: Uuid::new_v4(),
                    sequence: self.shared.next_sequence(),
                    request: pending.request,
                    response: None,
                    rule_matched: pending.rule_matched,
                    error: Some(message.clone()),
                    synthetic: false,
                    pinned: false,
                    notes: String::new(),
                };
                let _ = self.shared.events.send(CaptureEvent::Exchange(exchange));
            }
        }
        proxy_error_response(&message)
    }

    async fn should_intercept(&mut self, _context: &HttpContext, _request: &Request<Body>) -> bool {
        self.shared.settings.read().enable_https_interception
    }
}

#[derive(Clone)]
struct WebSocketTrafficHandler {
    shared: SharedCapture,
    streams: Arc<parking_lot::Mutex<HashMap<Direction, ZlibStream>>>,
}

impl WebSocketTrafficHandler {
    fn new(shared: SharedCapture) -> Self {
        Self {
            shared,
            streams: Arc::new(parking_lot::Mutex::new(HashMap::new())),
        }
    }
}

impl WebSocketHandler for WebSocketTrafficHandler {
    async fn handle_message(
        &mut self,
        context: &WebSocketContext,
        message: Message,
    ) -> Option<Message> {
        let (direction, uri) = websocket_context(context);
        let host = uri.host().unwrap_or("<unknown>").to_owned();
        let path = uri
            .path_and_query()
            .map(|value| value.as_str())
            .unwrap_or("/")
            .to_owned();
        let settings = self.shared.settings.read().clone();
        if host_is_hidden(&host, &settings.hidden_hosts) {
            return Some(message);
        }
        let opcode = websocket_opcode(&message).to_owned();
        let mut decoded = self.decode_message(direction, &message);
        let mut matched_names = Vec::new();
        if let Some(text) = decoded.text.clone() {
            let mut rewritten = text;
            for rule in matching_rewrites(&host, &settings.response_rewrite_rules) {
                let (value, count) = apply_rewrite(&rewritten, rule);
                if count > 0 {
                    matched_names.push(rule.name.clone());
                    rewritten = value;
                }
            }
            if !matched_names.is_empty() {
                decoded.preview = rewritten.clone();
                decoded.text = Some(rewritten);
            }
        }
        let forwarded =
            self.encode_message(direction, message, &decoded, !matched_names.is_empty());
        let scheme = if uri.scheme_str() == Some("https") {
            "wss"
        } else {
            "ws"
        };
        let url = format!("{scheme}://{host}{path}");
        let event = WebSocketMessage {
            id: Uuid::new_v4(),
            sequence: self.shared.next_sequence(),
            url,
            host,
            path,
            direction,
            opcode,
            is_text: decoded.kind == DecodeKind::Text,
            payload: decoded.preview,
            raw_size: decoded.raw_size,
            decoded_as: decoded.label,
            rule_matched: (!matched_names.is_empty()).then(|| matched_names.join(", ")),
            timestamp: Utc::now(),
        };
        let _ = self.shared.events.send(CaptureEvent::WebSocket(event));
        Some(forwarded)
    }
}

impl WebSocketTrafficHandler {
    fn decode_message(&self, direction: Direction, message: &Message) -> DecodedPayload {
        match message {
            Message::Text(text) => DecodedPayload::text(text.as_str().to_owned()),
            Message::Binary(bytes) => {
                if let Some(decoded) = decode_binary_stateless(bytes) {
                    return decoded;
                }
                let mut streams = self.streams.lock();
                let stream = streams.entry(direction).or_insert_with(ZlibStream::new);
                if let Some(text) = stream.decode(bytes) {
                    return DecodedPayload {
                        preview: truncate(&text),
                        text: Some(text),
                        label: "binary zlib-stream".into(),
                        kind: DecodeKind::ZlibStream,
                        raw_size: bytes.len(),
                    };
                }
                DecodedPayload::hex(bytes)
            }
            Message::Ping(bytes) => DecodedPayload::control("ping", bytes),
            Message::Pong(bytes) => DecodedPayload::control("pong", bytes),
            Message::Close(frame) => DecodedPayload::text(
                frame
                    .as_ref()
                    .map(ToString::to_string)
                    .unwrap_or_else(|| "<close>".into()),
            ),
            Message::Frame(_) => DecodedPayload::text("<raw WebSocket frame>".into()),
        }
    }

    fn encode_message(
        &self,
        direction: Direction,
        original: Message,
        decoded: &DecodedPayload,
        rewritten: bool,
    ) -> Message {
        let Some(text) = &decoded.text else {
            return original;
        };
        match decoded.kind {
            DecodeKind::Text if rewritten => Message::Text(text.clone().into()),
            DecodeKind::Utf8 if rewritten => Message::Binary(text.as_bytes().to_vec().into()),
            DecodeKind::Gzip if rewritten => {
                let mut encoder = flate2::write::GzEncoder::new(Vec::new(), Compression::default());
                let _ = std::io::Write::write_all(&mut encoder, text.as_bytes());
                Message::Binary(encoder.finish().unwrap_or_default().into())
            }
            DecodeKind::Zlib if rewritten => {
                use flate2::write::ZlibEncoder;
                let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
                let _ = std::io::Write::write_all(&mut encoder, text.as_bytes());
                Message::Binary(encoder.finish().unwrap_or_default().into())
            }
            DecodeKind::Deflate if rewritten => {
                use flate2::write::DeflateEncoder;
                let mut encoder = DeflateEncoder::new(Vec::new(), Compression::default());
                let _ = std::io::Write::write_all(&mut encoder, text.as_bytes());
                Message::Binary(encoder.finish().unwrap_or_default().into())
            }
            DecodeKind::ZlibStream => {
                let mut streams = self.streams.lock();
                let stream = streams.entry(direction).or_insert_with(ZlibStream::new);
                let encoded = stream.encode(text.as_bytes(), rewritten);
                if stream.reencode_all {
                    Message::Binary(encoded.into())
                } else {
                    original
                }
            }
            _ => original,
        }
    }
}

struct ZlibStream {
    decoder: Decompress,
    encoder: Compress,
    reencode_all: bool,
}

impl ZlibStream {
    fn new() -> Self {
        Self {
            decoder: Decompress::new(true),
            encoder: Compress::new(Compression::default(), true),
            reencode_all: false,
        }
    }

    fn decode(&mut self, bytes: &[u8]) -> Option<String> {
        let mut output = Vec::with_capacity(bytes.len() * 4 + 256);
        self.decoder
            .decompress_vec(bytes, &mut output, FlushDecompress::Sync)
            .ok()?;
        String::from_utf8(output).ok()
    }

    fn encode(&mut self, bytes: &[u8], rewritten: bool) -> Vec<u8> {
        self.reencode_all |= rewritten;
        let mut output = Vec::with_capacity(bytes.len() + 64);
        let _ = self
            .encoder
            .compress_vec(bytes, &mut output, FlushCompress::Sync);
        output
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum DecodeKind {
    Text,
    Utf8,
    Gzip,
    Zlib,
    Deflate,
    ZlibStream,
    Hex,
    Control,
}

struct DecodedPayload {
    preview: String,
    text: Option<String>,
    label: String,
    kind: DecodeKind,
    raw_size: usize,
}

impl DecodedPayload {
    fn text(text: String) -> Self {
        let raw_size = text.len();
        Self {
            preview: truncate(&text),
            text: Some(text),
            label: "text".into(),
            kind: DecodeKind::Text,
            raw_size,
        }
    }

    fn hex(bytes: &[u8]) -> Self {
        Self {
            preview: hex_preview(bytes),
            text: None,
            label: "binary hex".into(),
            kind: DecodeKind::Hex,
            raw_size: bytes.len(),
        }
    }

    fn control(label: &str, bytes: &[u8]) -> Self {
        Self {
            preview: hex_preview(bytes),
            text: None,
            label: label.into(),
            kind: DecodeKind::Control,
            raw_size: bytes.len(),
        }
    }
}

fn decode_binary_stateless(bytes: &[u8]) -> Option<DecodedPayload> {
    if let Ok(text) = String::from_utf8(bytes.to_vec()) {
        return Some(binary_decoded(
            text,
            "binary utf-8",
            DecodeKind::Utf8,
            bytes.len(),
        ));
    }
    let decoders: [(&str, DecodeKind, Box<dyn Read>); 3] = [
        (
            "binary gzip",
            DecodeKind::Gzip,
            Box::new(GzDecoder::new(bytes)),
        ),
        (
            "binary zlib",
            DecodeKind::Zlib,
            Box::new(ZlibDecoder::new(bytes)),
        ),
        (
            "binary raw deflate",
            DecodeKind::Deflate,
            Box::new(DeflateDecoder::new(bytes)),
        ),
    ];
    for (label, kind, mut decoder) in decoders {
        let mut output = Vec::new();
        if decoder.read_to_end(&mut output).is_ok()
            && let Ok(text) = String::from_utf8(output)
        {
            return Some(binary_decoded(text, label, kind, bytes.len()));
        }
    }
    None
}

fn binary_decoded(text: String, label: &str, kind: DecodeKind, raw_size: usize) -> DecodedPayload {
    DecodedPayload {
        preview: truncate(&text),
        text: Some(text),
        label: label.into(),
        kind,
        raw_size,
    }
}

fn websocket_context(context: &WebSocketContext) -> (Direction, hudsucker::hyper::Uri) {
    match context {
        WebSocketContext::ClientToServer { dst, .. } => (Direction::Out, dst.clone()),
        WebSocketContext::ServerToClient { src, .. } => (Direction::In, src.clone()),
    }
}

fn websocket_opcode(message: &Message) -> &'static str {
    match message {
        Message::Text(_) => "TEXT",
        Message::Binary(_) => "BINARY",
        Message::Ping(_) => "PING",
        Message::Pong(_) => "PONG",
        Message::Close(_) => "CLOSE",
        Message::Frame(_) => "FRAME",
    }
}

fn request_from_parts(
    parts: &hudsucker::hyper::http::request::Parts,
    body: Vec<u8>,
    context: &HttpContext,
) -> CapturedRequest {
    let uri = &parts.uri;
    let host_header = parts
        .headers
        .get(header::HOST)
        .and_then(|value| value.to_str().ok());
    let host = uri
        .host()
        .or_else(|| host_header.and_then(|value| value.split(':').next()))
        .unwrap_or("<unknown>")
        .to_owned();
    let scheme = uri.scheme_str().unwrap_or("http").to_owned();
    let port = uri
        .port_u16()
        .unwrap_or(if scheme == "https" { 443 } else { 80 });
    CapturedRequest {
        method: parts.method.to_string(),
        scheme,
        host,
        port,
        path: uri
            .path_and_query()
            .map(|value| value.as_str())
            .unwrap_or("/")
            .to_owned(),
        version: version_label(parts.version),
        headers: convert_headers(&parts.headers),
        body,
        timestamp: Utc::now(),
        client_addr: context.client_addr.to_string(),
        process: String::new(),
        pid: None,
    }
}

fn response_from_parts(
    parts: &hudsucker::hyper::http::response::Parts,
    body: Vec<u8>,
    duration_ms: f64,
) -> CapturedResponse {
    CapturedResponse {
        status: parts.status.as_u16(),
        reason: parts.status.canonical_reason().unwrap_or("").into(),
        version: version_label(parts.version),
        headers: convert_headers(&parts.headers),
        body,
        duration_ms,
    }
}

fn convert_headers(map: &hudsucker::hyper::HeaderMap) -> Headers {
    map.iter()
        .map(|(name, value)| Header {
            name: name.to_string(),
            value: value
                .to_str()
                .map(str::to_owned)
                .unwrap_or_else(|_| format!("0x{}", hex::encode(value.as_bytes()))),
        })
        .collect()
}

fn apply_edited_request(
    parts: &mut hudsucker::hyper::http::request::Parts,
    body: &mut Vec<u8>,
    captured: &mut CapturedRequest,
    mut edited: CapturedRequest,
) -> Result<()> {
    let url_changed = edited.scheme != captured.scheme
        || edited.host != captured.host
        || edited.port != captured.port
        || edited.path != captured.path;
    let headers_changed = edited.headers != captured.headers;
    let body_changed = edited.body != captured.body;
    if headers_changed {
        replace_headers(&mut parts.headers, &edited.headers)?;
    }
    if url_changed {
        let uri: hudsucker::hyper::Uri = edited
            .url()
            .parse()
            .context("edited request URL is invalid")?;
        let authority = uri
            .authority()
            .context("edited request URL has no authority")?
            .as_str();
        parts.headers.insert(
            header::HOST,
            authority
                .parse()
                .context("edited request URL has an invalid authority")?,
        );
        parts.uri = uri;
    }
    if body_changed {
        parts.headers.remove(header::CONTENT_LENGTH);
        parts.headers.remove(header::CONTENT_ENCODING);
        *body = edited.body.clone();
    }
    edited.headers = convert_headers(&parts.headers);
    edited.body = body.clone();
    *captured = edited;
    Ok(())
}

fn apply_edited_response(
    parts: &mut hudsucker::hyper::http::response::Parts,
    body: &mut Vec<u8>,
    captured: &mut CapturedResponse,
    mut edited: CapturedResponse,
) -> Result<()> {
    let status_changed = edited.status != captured.status;
    let headers_changed = edited.headers != captured.headers;
    let body_changed = edited.body != captured.body;
    if status_changed {
        parts.status = StatusCode::from_u16(edited.status)
            .context("edited response status is outside 100-599")?;
    }
    if headers_changed {
        replace_headers(&mut parts.headers, &edited.headers)?;
    }
    if body_changed {
        parts.headers.remove(header::CONTENT_LENGTH);
        parts.headers.remove(header::CONTENT_ENCODING);
        *body = edited.body.clone();
    }
    edited.reason = parts.status.canonical_reason().unwrap_or("").into();
    edited.headers = convert_headers(&parts.headers);
    edited.body = body.clone();
    *captured = edited;
    Ok(())
}

fn replace_headers(target: &mut hudsucker::hyper::HeaderMap, headers: &Headers) -> Result<()> {
    target.clear();
    for item in headers {
        let name = hudsucker::hyper::header::HeaderName::from_bytes(item.name.trim().as_bytes())
            .with_context(|| format!("invalid header name: {}", item.name))?;
        let value = item
            .value
            .parse::<hudsucker::hyper::header::HeaderValue>()
            .with_context(|| format!("invalid value for header {}", item.name))?;
        target.append(name, value);
    }
    Ok(())
}

fn breakpoint_drop_response(status: StatusCode, body: Vec<u8>) -> Response<Body> {
    Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, "text/plain; charset=utf-8")
        .body(Body::from(body))
        .unwrap_or_else(|_| Response::new(Body::from("Dropped by HTTP Whisper breakpoint")))
}

fn has_supported_content_encoding(headers: &hudsucker::hyper::HeaderMap) -> bool {
    let values = headers.get_all(header::CONTENT_ENCODING);
    let mut found = false;
    for value in values.iter() {
        for encoding in value.as_bytes().split(|byte| *byte == b',') {
            let encoding = encoding
                .iter()
                .copied()
                .skip_while(u8::is_ascii_whitespace)
                .collect::<Vec<_>>();
            let encoding = encoding
                .strip_suffix(b" ")
                .unwrap_or(&encoding)
                .to_ascii_lowercase();
            found = true;
            if !matches!(
                encoding.as_slice(),
                b"identity" | b"gzip" | b"x-gzip" | b"deflate" | b"br" | b"zstd"
            ) {
                return false;
            }
        }
    }
    found
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CaInstallAsset {
    Page,
    Der,
    Pem,
    Empty,
    NotFound,
}

fn ca_install_response(request: &Request<Body>, shared: &SharedCapture) -> Option<Response<Body>> {
    let host = request.uri().host().or_else(|| {
        request
            .headers()
            .get(header::HOST)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.split(':').next())
    })?;
    if !is_ca_install_host(host) {
        return None;
    }

    let include_body = request.method() != Method::HEAD;
    if request.method() != Method::GET && request.method() != Method::HEAD {
        return Some(
            Response::builder()
                .status(StatusCode::METHOD_NOT_ALLOWED)
                .header(header::ALLOW, "GET, HEAD")
                .body(Body::from(Vec::new()))
                .unwrap_or_else(|_| Response::new(Body::from(Vec::new()))),
        );
    }

    Some(match ca_install_asset(request.uri().path()) {
        CaInstallAsset::Page => ca_response(
            StatusCode::OK,
            "text/html; charset=utf-8",
            None,
            ca_install_html().as_bytes().to_vec(),
            include_body,
        ),
        CaInstallAsset::Der => ca_response(
            StatusCode::OK,
            "application/x-x509-ca-cert",
            Some("attachment; filename=\"http-whisper-ca.cer\""),
            shared.ca_der.as_ref().clone(),
            include_body,
        ),
        CaInstallAsset::Pem => ca_response(
            StatusCode::OK,
            "application/x-pem-file",
            Some("attachment; filename=\"http-whisper-ca.pem\""),
            shared.ca_pem.as_ref().clone(),
            include_body,
        ),
        CaInstallAsset::Empty => ca_response(
            StatusCode::NO_CONTENT,
            "text/plain; charset=utf-8",
            None,
            Vec::new(),
            include_body,
        ),
        CaInstallAsset::NotFound => ca_response(
            StatusCode::NOT_FOUND,
            "text/plain; charset=utf-8",
            None,
            b"HTTP Whisper certificate endpoint not found".to_vec(),
            include_body,
        ),
    })
}

fn is_ca_install_host(host: &str) -> bool {
    let host = host.trim().trim_end_matches('.');
    host.eq_ignore_ascii_case("mitm.it") || host.eq_ignore_ascii_case("httpwhisper.local")
}

fn ca_install_asset(path: &str) -> CaInstallAsset {
    let normalized = path.trim_end_matches('/');
    match normalized {
        "" | "/" | "/cert" => CaInstallAsset::Page,
        "/cert/cer"
        | "/cert/der"
        | "/cert/firefox"
        | "/cert/windows"
        | "/cert/http-whisper-ca.cer"
        | "/cert/http-whisper-ca.der"
        | "/cert/p12" => CaInstallAsset::Der,
        "/cert/pem" | "/cert/http-whisper-ca.pem" => CaInstallAsset::Pem,
        "/favicon.ico" => CaInstallAsset::Empty,
        _ => CaInstallAsset::NotFound,
    }
}

fn ca_response(
    status: StatusCode,
    content_type: &'static str,
    content_disposition: Option<&'static str>,
    body: Vec<u8>,
    include_body: bool,
) -> Response<Body> {
    let mut builder = Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, content_type)
        .header(header::CACHE_CONTROL, "no-store")
        .header(header::CONTENT_LENGTH, body.len().to_string());
    if let Some(content_disposition) = content_disposition {
        builder = builder.header(header::CONTENT_DISPOSITION, content_disposition);
    }
    let body = if include_body { body } else { Vec::new() };
    builder
        .body(Body::from(body))
        .unwrap_or_else(|_| Response::new(Body::from(Vec::new())))
}

fn ca_install_html() -> &'static str {
    r#"<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>HTTP Whisper CA</title>
  <style>
    body { margin: 0; font: 14px Tahoma, Verdana, sans-serif; background: #ece9d8; color: #111; }
    .window { width: min(720px, calc(100% - 32px)); margin: 32px auto; border: 1px solid #0a246a; background: #fff; box-shadow: 2px 2px 0 #7f9db9; }
    .title { padding: 7px 10px; color: #fff; font-weight: bold; background: linear-gradient(90deg, #0a246a, #3a6ea5); }
    .content { padding: 18px; }
    h1 { font-size: 18px; margin: 0 0 12px; }
    p { line-height: 1.45; margin: 0 0 12px; }
    .actions { display: flex; flex-wrap: wrap; gap: 10px; margin: 18px 0; }
    a.button { color: #000; text-decoration: none; border: 1px solid #003c74; background: #ece9d8; padding: 7px 12px; box-shadow: inset 1px 1px #fff, inset -1px -1px #808080; }
    code { background: #f5f5f5; border: 1px solid #ccc; padding: 1px 4px; }
    .note { border-top: 1px solid #ddd; padding-top: 12px; color: #333; }
  </style>
</head>
<body>
  <div class="window">
    <div class="title">HTTP Whisper Certificate Authority</div>
    <div class="content">
      <h1>The HTTP Whisper proxy is running</h1>
      <p>This local page is served by HTTP Whisper through <code>mitm.it</code>. Install this CA only on devices and browsers you control.</p>
      <div class="actions">
        <a class="button" href="/cert/cer">Download DER certificate for Firefox or Windows</a>
        <a class="button" href="/cert/pem">Download PEM certificate</a>
      </div>
      <p>For Firefox, import the DER certificate and enable trust for identifying websites. If automatic Firefox integration is enabled, restart Firefox after accepting the HTTP Whisper UAC prompt.</p>
      <p class="note">If you see a public proxy warning page, Firefox is not using HTTP Whisper yet.</p>
    </div>
  </div>
</body>
</html>
"#
}

fn proxy_error_response(message: &str) -> Response<Body> {
    Response::builder()
        .status(hudsucker::hyper::StatusCode::BAD_GATEWAY)
        .header(header::CONTENT_TYPE, "text/plain; charset=utf-8")
        .body(Body::from(message.to_owned()))
        .unwrap_or_else(|_| Response::new(Body::from("HTTP Whisper proxy error")))
}

fn version_label(version: hudsucker::hyper::Version) -> String {
    match version {
        hudsucker::hyper::Version::HTTP_09 => "HTTP/0.9",
        hudsucker::hyper::Version::HTTP_10 => "HTTP/1.0",
        hudsucker::hyper::Version::HTTP_11 => "HTTP/1.1",
        hudsucker::hyper::Version::HTTP_2 => "HTTP/2.0",
        hudsucker::hyper::Version::HTTP_3 => "HTTP/3.0",
        _ => "HTTP/?",
    }
    .into()
}

fn path_without_query(path: &str) -> &str {
    path.split('?').next().unwrap_or("/")
}

fn truncate(text: &str) -> String {
    if text.len() <= MAX_PREVIEW {
        return text.to_owned();
    }
    let mut end = MAX_PREVIEW;
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}\n\n<preview truncated>", &text[..end])
}

fn hex_preview(bytes: &[u8]) -> String {
    let shown = &bytes[..bytes.len().min(MAX_PREVIEW / 2)];
    let value = hex::encode(shown);
    if shown.len() < bytes.len() {
        format!("{value}\n\n<preview truncated>")
    } else {
        value
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn free_port() -> u16 {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        listener.local_addr().unwrap().port()
    }

    fn start_test_worker(
        settings: AppSettings,
    ) -> (CaptureWorker, std::sync::mpsc::Receiver<CaptureEvent>) {
        let (tx, rx) = std::sync::mpsc::channel();
        let worker = CaptureWorker::start(settings, tx).unwrap();
        loop {
            match rx.recv_timeout(std::time::Duration::from_secs(20)).unwrap() {
                CaptureEvent::Started { .. } => break,
                CaptureEvent::Error(error) => panic!("proxy failed to start: {error}"),
                _ => {}
            }
        }
        (worker, rx)
    }

    fn proxy_client(port: u16, request: String) -> std::thread::JoinHandle<String> {
        std::thread::spawn(move || {
            use std::io::{Read, Write};

            let mut stream = std::net::TcpStream::connect(("127.0.0.1", port)).unwrap();
            stream.write_all(request.as_bytes()).unwrap();
            stream
                .set_read_timeout(Some(std::time::Duration::from_secs(10)))
                .unwrap();
            let mut response = String::new();
            stream.read_to_string(&mut response).unwrap();
            response
        })
    }

    fn next_paused(rx: &std::sync::mpsc::Receiver<CaptureEvent>) -> PausedBreakpoint {
        loop {
            match rx.recv_timeout(std::time::Duration::from_secs(10)).unwrap() {
                CaptureEvent::BreakpointPaused(paused) => break paused,
                CaptureEvent::Error(error) => panic!("capture failed: {error}"),
                _ => {}
            }
        }
    }

    fn next_exchange(rx: &std::sync::mpsc::Receiver<CaptureEvent>) -> CapturedExchange {
        loop {
            match rx.recv_timeout(std::time::Duration::from_secs(10)).unwrap() {
                CaptureEvent::Exchange(exchange) => break exchange,
                CaptureEvent::Error(error) => panic!("capture failed: {error}"),
                _ => {}
            }
        }
    }

    #[test]
    fn decodes_utf8_binary() {
        let decoded = decode_binary_stateless(b"hello").unwrap();
        assert_eq!(decoded.preview, "hello");
        assert_eq!(decoded.kind, DecodeKind::Utf8);
    }

    #[test]
    fn decodes_zlib_binary() {
        use std::io::Write;
        let mut encoder = flate2::write::ZlibEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(b"user123").unwrap();
        let bytes = encoder.finish().unwrap();
        let decoded = decode_binary_stateless(&bytes).unwrap();
        assert_eq!(decoded.text.as_deref(), Some("user123"));
        assert_eq!(decoded.kind, DecodeKind::Zlib);
    }

    #[test]
    fn decodes_gzip_and_raw_deflate_binary() {
        use std::io::Write;

        let mut gzip = flate2::write::GzEncoder::new(Vec::new(), Compression::default());
        gzip.write_all(b"hello gzip").unwrap();
        let decoded = decode_binary_stateless(&gzip.finish().unwrap()).unwrap();
        assert_eq!(decoded.text.as_deref(), Some("hello gzip"));
        assert_eq!(decoded.kind, DecodeKind::Gzip);

        let mut deflate = flate2::write::DeflateEncoder::new(Vec::new(), Compression::default());
        deflate.write_all(b"hello deflate").unwrap();
        let decoded = decode_binary_stateless(&deflate.finish().unwrap()).unwrap();
        assert_eq!(decoded.text.as_deref(), Some("hello deflate"));
        assert_eq!(decoded.kind, DecodeKind::Deflate);
    }

    #[test]
    fn zlib_stream_can_reencode_rewritten_messages() {
        let mut source = Compress::new(Compression::default(), true);
        let mut compressed = Vec::with_capacity(256);
        source
            .compress_vec(b"user123", &mut compressed, FlushCompress::Sync)
            .unwrap();

        let mut proxy_stream = ZlibStream::new();
        assert_eq!(proxy_stream.decode(&compressed).as_deref(), Some("user123"));
        let rewritten = proxy_stream.encode(b"admin123", true);
        assert!(proxy_stream.reencode_all);

        let mut browser = Decompress::new(true);
        let mut decoded = Vec::with_capacity(256);
        browser
            .decompress_vec(&rewritten, &mut decoded, FlushDecompress::Sync)
            .unwrap();
        assert_eq!(decoded, b"admin123");
    }

    #[test]
    fn recognizes_mitm_it_certificate_endpoints() {
        assert!(is_ca_install_host("mitm.it"));
        assert!(is_ca_install_host("MITM.IT."));
        assert!(is_ca_install_host("httpwhisper.local"));
        assert!(!is_ca_install_host("example.com"));

        assert_eq!(ca_install_asset("/"), CaInstallAsset::Page);
        assert_eq!(ca_install_asset("/cert"), CaInstallAsset::Page);
        assert_eq!(ca_install_asset("/cert/cer"), CaInstallAsset::Der);
        assert_eq!(ca_install_asset("/cert/firefox"), CaInstallAsset::Der);
        assert_eq!(ca_install_asset("/cert/pem"), CaInstallAsset::Pem);
        assert_eq!(ca_install_asset("/favicon.ico"), CaInstallAsset::Empty);
        assert_eq!(ca_install_asset("/other"), CaInstallAsset::NotFound);
    }

    #[test]
    fn native_proxy_serves_and_captures_an_automatic_response() {
        use std::{
            io::{Read, Write},
            net::{TcpListener, TcpStream},
            sync::mpsc,
            time::Duration,
        };

        let probe = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = probe.local_addr().unwrap().port();
        drop(probe);
        let settings = AppSettings {
            capture_port: port,
            enable_https_interception: false,
            auto_configure_system_proxy: false,
            auto_install_ca: false,
            auto_response_rules: vec![crate::config::AutoResponseRule {
                name: "Local mock".into(),
                enabled: true,
                method: "GET".into(),
                host: "example.test".into(),
                path: "/mock".into(),
                status_code: 200,
                content_type: "application/json".into(),
                body: "{\"user\":\"admin123\"}".into(),
            }],
            ..Default::default()
        };
        let (tx, rx) = mpsc::channel();
        let mut worker = CaptureWorker::start(settings, tx).unwrap();
        loop {
            match rx.recv_timeout(Duration::from_secs(20)).unwrap() {
                CaptureEvent::Started { .. } => break,
                CaptureEvent::Error(error) => panic!("proxy failed to start: {error}"),
                _ => {}
            }
        }

        let mut stream = TcpStream::connect(("127.0.0.1", port)).unwrap();
        stream
            .write_all(
                b"GET http://example.test/mock HTTP/1.1\r\nHost: example.test\r\nConnection: close\r\n\r\n",
            )
            .unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        let mut response = String::new();
        stream.read_to_string(&mut response).unwrap();
        assert!(response.starts_with("HTTP/1.1 200"), "{response}");
        assert!(response.contains("admin123"), "{response}");

        let exchange = loop {
            match rx.recv_timeout(Duration::from_secs(10)).unwrap() {
                CaptureEvent::Exchange(exchange) => break exchange,
                CaptureEvent::Error(error) => panic!("capture failed: {error}"),
                _ => {}
            }
        };
        assert!(exchange.synthetic);
        assert_eq!(exchange.rule_matched.as_deref(), Some("Local mock"));
        assert_eq!(exchange.request.host, "example.test");
        worker.join();
    }

    #[test]
    fn native_proxy_serves_local_mitm_it_certificate_page() {
        use std::{
            io::{Read, Write},
            net::{TcpListener, TcpStream},
            sync::mpsc,
            time::Duration,
        };

        let probe = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = probe.local_addr().unwrap().port();
        drop(probe);
        let settings = AppSettings {
            capture_port: port,
            enable_https_interception: false,
            auto_configure_system_proxy: false,
            auto_install_ca: false,
            ..Default::default()
        };
        let (tx, rx) = mpsc::channel();
        let mut worker = CaptureWorker::start(settings, tx).unwrap();
        loop {
            match rx.recv_timeout(Duration::from_secs(20)).unwrap() {
                CaptureEvent::Started { .. } => break,
                CaptureEvent::Error(error) => panic!("proxy failed to start: {error}"),
                _ => {}
            }
        }

        let mut stream = TcpStream::connect(("127.0.0.1", port)).unwrap();
        stream
            .write_all(
                b"GET http://mitm.it/ HTTP/1.1\r\nHost: mitm.it\r\nConnection: close\r\n\r\n",
            )
            .unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        let mut response = String::new();
        stream.read_to_string(&mut response).unwrap();
        assert!(response.starts_with("HTTP/1.1 200"), "{response}");
        assert!(
            response.contains("HTTP Whisper proxy is running"),
            "{response}"
        );
        assert!(response.contains("/cert/cer"), "{response}");
        worker.join();
    }

    #[test]
    fn native_proxy_rewrites_a_real_upstream_response() {
        use std::{
            io::{Read, Write},
            net::{TcpListener, TcpStream},
            sync::mpsc,
            thread,
            time::Duration,
        };

        let upstream = TcpListener::bind("127.0.0.1:0").unwrap();
        let upstream_port = upstream.local_addr().unwrap().port();
        let upstream_thread = thread::spawn(move || {
            let (mut stream, _) = upstream.accept().unwrap();
            let mut request = [0_u8; 2048];
            let _ = stream.read(&mut request);
            stream
                .write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 7\r\nConnection: close\r\n\r\nuser123",
                )
                .unwrap();
        });
        let probe = TcpListener::bind("127.0.0.1:0").unwrap();
        let proxy_port = probe.local_addr().unwrap().port();
        drop(probe);
        let settings = AppSettings {
            capture_port: proxy_port,
            enable_https_interception: false,
            auto_configure_system_proxy: false,
            auto_install_ca: false,
            response_rewrite_rules: vec![crate::config::ResponseRewriteRule {
                name: "Promote user".into(),
                host: "127.0.0.1".into(),
                find_text: "user123".into(),
                replace_text: "admin123".into(),
            }],
            ..Default::default()
        };
        let (tx, rx) = mpsc::channel();
        let mut worker = CaptureWorker::start(settings, tx).unwrap();
        loop {
            match rx.recv_timeout(Duration::from_secs(20)).unwrap() {
                CaptureEvent::Started { .. } => break,
                CaptureEvent::Error(error) => panic!("proxy failed to start: {error}"),
                _ => {}
            }
        }

        let mut stream = TcpStream::connect(("127.0.0.1", proxy_port)).unwrap();
        let request = format!(
            "GET http://127.0.0.1:{upstream_port}/profile HTTP/1.1\r\nHost: 127.0.0.1:{upstream_port}\r\nConnection: close\r\n\r\n"
        );
        stream.write_all(request.as_bytes()).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        let mut response = String::new();
        stream.read_to_string(&mut response).unwrap();
        assert!(response.contains("admin123"), "{response}");
        assert!(!response.contains("user123"), "{response}");

        let exchange = loop {
            match rx.recv_timeout(Duration::from_secs(10)).unwrap() {
                CaptureEvent::Exchange(exchange) => break exchange,
                CaptureEvent::Error(error) => panic!("capture failed: {error}"),
                _ => {}
            }
        };
        assert_eq!(exchange.rule_matched.as_deref(), Some("Promote user"));
        assert_eq!(exchange.response.unwrap().body, b"admin123".to_vec());
        worker.join();
        upstream_thread.join().unwrap();
    }

    #[test]
    fn request_breakpoint_forwards_url_body_and_header_edits() {
        use std::io::{Read, Write};

        let original_upstream = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        original_upstream.set_nonblocking(true).unwrap();
        let original_upstream_port = original_upstream.local_addr().unwrap().port();
        let upstream = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let upstream_port = upstream.local_addr().unwrap().port();
        let (request_tx, request_rx) = std::sync::mpsc::channel();
        let upstream_thread = std::thread::spawn(move || {
            let (mut stream, _) = upstream.accept().unwrap();
            stream
                .set_read_timeout(Some(std::time::Duration::from_secs(10)))
                .unwrap();
            let mut buffer = [0_u8; 8192];
            let size = stream.read(&mut buffer).unwrap();
            request_tx
                .send(String::from_utf8_lossy(&buffer[..size]).into_owned())
                .unwrap();
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
                .unwrap();
        });
        let proxy_port = free_port();
        let settings = AppSettings {
            capture_port: proxy_port,
            enable_https_interception: false,
            auto_configure_system_proxy: false,
            auto_install_ca: false,
            breakpoint_rules: vec![crate::config::BreakpointRule {
                name: "Edit request".into(),
                enabled: true,
                phase: BreakpointPhase::Request,
                method: "POST".into(),
                host: "127.0.0.1".into(),
                path: "/original".into(),
                status: String::new(),
            }],
            ..Default::default()
        };
        let (mut worker, rx) = start_test_worker(settings);
        let request = format!(
            "POST http://127.0.0.1:{original_upstream_port}/original HTTP/1.1\r\nHost: 127.0.0.1:{original_upstream_port}\r\nContent-Length: 8\r\nConnection: close\r\n\r\noriginal"
        );
        let client = proxy_client(proxy_port, request);
        let paused = next_paused(&rx);
        assert_eq!(paused.phase, BreakpointPhase::Request);
        let mut edited = paused.request;
        edited.port = upstream_port;
        edited.path = "/changed?debug=1".into();
        edited.body = b"edited-body".to_vec();
        edited.headers.push(Header {
            name: "X-Breakpoint".into(),
            value: "edited".into(),
        });
        assert!(worker.resolve_breakpoint(BreakpointDecision {
            id: paused.id,
            action: BreakpointAction::Forward,
            request: edited,
            response: None,
        }));

        let response = client.join().unwrap();
        assert!(response.starts_with("HTTP/1.1 200"), "{response}");
        let upstream_request = request_rx
            .recv_timeout(std::time::Duration::from_secs(10))
            .unwrap();
        assert!(
            upstream_request.contains("/changed?debug=1"),
            "{upstream_request}"
        );
        assert!(
            upstream_request
                .to_ascii_lowercase()
                .contains("x-breakpoint: edited"),
            "{upstream_request}"
        );
        assert!(
            upstream_request.contains("edited-body"),
            "{upstream_request}"
        );
        assert_eq!(
            original_upstream.accept().unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock
        );
        let exchange = next_exchange(&rx);
        assert_eq!(exchange.request.port, upstream_port);
        assert_eq!(exchange.request.path, "/changed?debug=1");
        assert_eq!(exchange.request.body, b"edited-body");
        assert_eq!(
            exchange.rule_matched.as_deref(),
            Some("Breakpoint: Edit request")
        );
        worker.join();
        upstream_thread.join().unwrap();
    }

    #[test]
    fn response_breakpoint_forwards_status_body_and_header_edits() {
        use std::io::{Read, Write};

        let upstream = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let upstream_port = upstream.local_addr().unwrap().port();
        let upstream_thread = std::thread::spawn(move || {
            let (mut stream, _) = upstream.accept().unwrap();
            let mut request = [0_u8; 2048];
            let _ = stream.read(&mut request);
            stream
                .write_all(
                    b"HTTP/1.1 201 Created\r\nContent-Type: text/plain\r\nContent-Length: 8\r\nConnection: close\r\n\r\noriginal",
                )
                .unwrap();
        });
        let proxy_port = free_port();
        let settings = AppSettings {
            capture_port: proxy_port,
            enable_https_interception: false,
            auto_configure_system_proxy: false,
            auto_install_ca: false,
            breakpoint_rules: vec![crate::config::BreakpointRule {
                name: "Edit response".into(),
                enabled: true,
                phase: BreakpointPhase::Response,
                method: "GET".into(),
                host: "127.0.0.1".into(),
                path: "/response".into(),
                status: "201".into(),
            }],
            ..Default::default()
        };
        let (mut worker, rx) = start_test_worker(settings);
        let request = format!(
            "GET http://127.0.0.1:{upstream_port}/response HTTP/1.1\r\nHost: 127.0.0.1:{upstream_port}\r\nConnection: close\r\n\r\n"
        );
        let client = proxy_client(proxy_port, request);
        let paused = next_paused(&rx);
        assert_eq!(paused.phase, BreakpointPhase::Response);
        let mut edited_response = paused.response.unwrap();
        edited_response.status = 202;
        edited_response.body = b"edited-response".to_vec();
        edited_response.headers = vec![
            Header {
                name: "Content-Type".into(),
                value: "text/plain".into(),
            },
            Header {
                name: "X-Breakpoint".into(),
                value: "edited".into(),
            },
        ];
        assert!(worker.resolve_breakpoint(BreakpointDecision {
            id: paused.id,
            action: BreakpointAction::Forward,
            request: paused.request,
            response: Some(edited_response),
        }));

        let response = client.join().unwrap();
        assert!(response.starts_with("HTTP/1.1 202"), "{response}");
        assert!(response.contains("edited-response"), "{response}");
        assert!(
            response
                .to_ascii_lowercase()
                .contains("x-breakpoint: edited"),
            "{response}"
        );
        let exchange = next_exchange(&rx);
        let captured = exchange.response.unwrap();
        assert_eq!(captured.status, 202);
        assert_eq!(captured.body, b"edited-response");
        assert_eq!(
            exchange.rule_matched.as_deref(),
            Some("Breakpoint: Edit response")
        );
        worker.join();
        upstream_thread.join().unwrap();
    }

    #[test]
    fn request_breakpoint_drop_blocks_the_upstream_request() {
        let upstream = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        upstream.set_nonblocking(true).unwrap();
        let upstream_port = upstream.local_addr().unwrap().port();
        let proxy_port = free_port();
        let settings = AppSettings {
            capture_port: proxy_port,
            enable_https_interception: false,
            auto_configure_system_proxy: false,
            auto_install_ca: false,
            breakpoint_rules: vec![crate::config::BreakpointRule {
                name: "Block request".into(),
                enabled: true,
                phase: BreakpointPhase::Request,
                method: "GET".into(),
                host: "127.0.0.1".into(),
                path: "/blocked".into(),
                status: String::new(),
            }],
            ..Default::default()
        };
        let (mut worker, rx) = start_test_worker(settings);
        let request = format!(
            "GET http://127.0.0.1:{upstream_port}/blocked HTTP/1.1\r\nHost: 127.0.0.1:{upstream_port}\r\nConnection: close\r\n\r\n"
        );
        let client = proxy_client(proxy_port, request);
        let paused = next_paused(&rx);
        assert!(worker.resolve_breakpoint(BreakpointDecision {
            id: paused.id,
            action: BreakpointAction::Drop,
            request: paused.request,
            response: None,
        }));
        let response = client.join().unwrap();
        assert!(response.starts_with("HTTP/1.1 403"), "{response}");
        assert!(response.contains("Dropped by HTTP Whisper"), "{response}");
        let exchange = next_exchange(&rx);
        assert!(exchange.synthetic);
        assert_eq!(
            exchange.error.as_deref(),
            Some("Dropped at request breakpoint")
        );
        std::thread::sleep(std::time::Duration::from_millis(100));
        assert_eq!(
            upstream.accept().unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock
        );
        worker.join();
    }

    #[test]
    fn response_breakpoint_drop_returns_a_blocked_response() {
        use std::io::{Read, Write};

        let upstream = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let upstream_port = upstream.local_addr().unwrap().port();
        let upstream_thread = std::thread::spawn(move || {
            let (mut stream, _) = upstream.accept().unwrap();
            let mut request = [0_u8; 2048];
            let _ = stream.read(&mut request);
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
                .unwrap();
        });
        let proxy_port = free_port();
        let settings = AppSettings {
            capture_port: proxy_port,
            enable_https_interception: false,
            auto_configure_system_proxy: false,
            auto_install_ca: false,
            breakpoint_rules: vec![crate::config::BreakpointRule {
                name: "Block response".into(),
                enabled: true,
                phase: BreakpointPhase::Response,
                method: "GET".into(),
                host: "127.0.0.1".into(),
                path: "/blocked-response".into(),
                status: "2*".into(),
            }],
            ..Default::default()
        };
        let (mut worker, rx) = start_test_worker(settings);
        let request = format!(
            "GET http://127.0.0.1:{upstream_port}/blocked-response HTTP/1.1\r\nHost: 127.0.0.1:{upstream_port}\r\nConnection: close\r\n\r\n"
        );
        let client = proxy_client(proxy_port, request);
        let paused = next_paused(&rx);
        assert!(worker.resolve_breakpoint(BreakpointDecision {
            id: paused.id,
            action: BreakpointAction::Drop,
            request: paused.request,
            response: paused.response,
        }));
        let response = client.join().unwrap();
        assert!(response.starts_with("HTTP/1.1 502"), "{response}");
        assert!(response.contains("Dropped by HTTP Whisper"), "{response}");
        let exchange = next_exchange(&rx);
        assert_eq!(exchange.response.unwrap().status, 502);
        assert_eq!(
            exchange.error.as_deref(),
            Some("Dropped at response breakpoint")
        );
        worker.join();
        upstream_thread.join().unwrap();
    }
}
