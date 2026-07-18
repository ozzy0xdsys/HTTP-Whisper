use std::{
    fs,
    future::Future,
    path::PathBuf,
    sync::mpsc,
    thread,
    time::{Duration, Instant},
};

use chrono::{TimeDelta, Utc};
use eframe::egui::{
    self, Align, Color32, FontData, FontDefinitions, FontFamily, FontId, Frame, Layout, Margin,
    Rect, RichText, ScrollArea, Stroke, TextEdit, Ui, UiBuilder, Vec2,
};
use egui_extras::{Column, TableBuilder};
use uuid::Uuid;

use crate::{
    baseline::TrafficBaseline,
    capsule::{export_capsule, import_capsule},
    capture::CaptureWorker,
    config::{
        AppPaths, AppSettings, AutoResponseRule, ExfiltrationMode, ResponseRewriteRule,
        TableColorField, TableColorPreset, TableColorRule, TableColorTarget,
    },
    dossier::{HostDossierIndex, HostIntelligence, lookup_host_intelligence},
    experiment,
    filtering::matches_filter,
    investigation::{explain_session, process_timeline},
    model::{
        BehaviorAssessment, CaptureEvent, CapturedExchange, CapturedRequest, CapturedResponse,
        GuardAction, GuardAssessment, Header, Session, ThreatAssessment, ThreatLevel,
        WebSocketMessage, headers_as_text,
    },
    platform::{self, BypassConnection, DnsObservation},
    protocol::{ProtocolTracker, decode_with_descriptors, descriptor_messages, protocol_summary},
    rule_debugger::{hit_counts, simulate},
    rules::pattern_matches,
    storage::SessionRepository,
    threat::ThreatAnalyzer,
    windows_proxy::configure_startup,
};

#[cfg(windows)]
use crate::{
    certificate::{install_current_user_ca, load_or_create_ca},
    windows_proxy::install_firefox_support,
};

const XP_BG: Color32 = Color32::from_rgb(236, 233, 216);
const XP_TOOLBAR: Color32 = Color32::from_rgb(214, 223, 247);
const XP_BUTTON: Color32 = Color32::from_rgb(236, 233, 216);
const XP_BORDER: Color32 = Color32::from_rgb(127, 157, 185);
const XP_BLUE: Color32 = Color32::from_rgb(49, 106, 197);
const XP_WHITE: Color32 = Color32::WHITE;
const XP_TEXT: Color32 = Color32::from_rgb(0, 0, 0);
const XP_WARNING: Color32 = Color32::from_rgb(180, 105, 0);
const XP_DANGER: Color32 = Color32::from_rgb(190, 0, 0);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum DialogKind {
    Settings,
    AutoResponses,
    ResponseRewrites,
    Certificates,
    Workbench,
    About,
}

enum BackgroundResult {
    HostIntelligence {
        host: String,
        result: Box<Result<HostIntelligence, String>>,
    },
    WebSocketReplay {
        result: Result<String, String>,
    },
    BypassSnapshot {
        connections: Vec<BypassConnection>,
        dns: Vec<DnsObservation>,
    },
}

pub struct HttpWhisperApp {
    settings: AppSettings,
    settings_draft: AppSettings,
    hidden_hosts_draft: String,
    guard_trusted_hosts_draft: String,
    auto_draft: Vec<AutoResponseRule>,
    auto_selected: usize,
    rewrite_draft: Vec<ResponseRewriteRule>,
    rewrite_selected: usize,
    events_tx: mpsc::Sender<CaptureEvent>,
    events_rx: mpsc::Receiver<CaptureEvent>,
    background_tx: mpsc::Sender<BackgroundResult>,
    background_rx: mpsc::Receiver<BackgroundResult>,
    repository: Option<SessionRepository>,
    worker: Option<CaptureWorker>,
    auto_connect_pending: bool,
    sessions: Vec<Session>,
    selected: Option<Uuid>,
    filter: String,
    tab: usize,
    settings_tab: usize,
    table_color_selected: usize,
    dialog: Option<DialogKind>,
    state: String,
    ca_state: String,
    activity: String,
    status: String,
    errors: usize,
    threat_analyzer: ThreatAnalyzer,
    baseline: TrafficBaseline,
    dossiers: HostDossierIndex,
    protocol_tracker: ProtocolTracker,
    analysis_dirty: bool,
    last_analysis_save: Instant,
    bypass_connections: Vec<BypassConnection>,
    dns_observations: Vec<DnsObservation>,
    bypass_polling: bool,
    last_bypass_poll: Instant,
    last_dns_poll: Instant,
    workbench_tab: usize,
    dossier_selected: String,
    capsule_path: String,
    capsule_passphrase: String,
    capsule_sanitize: bool,
    experiment_before_start: Option<usize>,
    experiment_before: Vec<Session>,
    experiment_after_start: Option<usize>,
    experiment_report: String,
    descriptor_report: String,
    rule_undo: Option<(Vec<AutoResponseRule>, Vec<ResponseRewriteRule>)>,
}

impl HttpWhisperApp {
    pub fn new(cc: &eframe::CreationContext<'_>, settings: AppSettings) -> Self {
        configure_theme(&cc.egui_ctx);
        let auto_connect_pending = settings.auto_connect;
        let startup_error = configure_startup(settings.start_with_windows).err();
        let hidden_hosts_draft = settings.hidden_hosts.join("\n");
        let guard_trusted_hosts_draft = settings.exfiltration_trusted_hosts.join("\n");
        let (events_tx, events_rx) = mpsc::channel();
        let (background_tx, background_rx) = mpsc::channel();
        let paths = AppPaths::discover().ok();
        let repository = paths
            .as_ref()
            .map(|paths| SessionRepository::new(paths.sessions_dir.join("sessions.db")))
            .and_then(|repository| repository.initialize().ok().map(|()| repository));
        let baseline = paths
            .as_ref()
            .and_then(|paths| TrafficBaseline::load(&paths.baselines_file).ok())
            .unwrap_or_default();
        let dossiers = paths
            .as_ref()
            .and_then(|paths| HostDossierIndex::load(&paths.dossiers_file).ok())
            .unwrap_or_default();
        let dossier_selected = dossiers.hosts.keys().next().cloned().unwrap_or_default();
        let capsule_path = paths
            .as_ref()
            .map(|paths| {
                paths
                    .capsules_dir
                    .join(format!(
                        "capture-{}.whispercapsule",
                        Utc::now().format("%Y%m%d-%H%M%S")
                    ))
                    .display()
                    .to_string()
            })
            .unwrap_or_else(|| "capture.whispercapsule".into());
        Self {
            settings_draft: settings.clone(),
            hidden_hosts_draft,
            guard_trusted_hosts_draft,
            auto_draft: settings.auto_response_rules.clone(),
            rewrite_draft: settings.response_rewrite_rules.clone(),
            settings,
            auto_selected: 0,
            rewrite_selected: 0,
            events_tx,
            events_rx,
            background_tx,
            background_rx,
            repository,
            worker: None,
            auto_connect_pending,
            sessions: sample_sessions(),
            selected: None,
            filter: String::new(),
            tab: 0,
            settings_tab: 0,
            table_color_selected: 0,
            dialog: None,
            state: "Idle".into(),
            ca_state: if cfg!(windows) {
                "Auto install".into()
            } else {
                "Manual install".into()
            },
            activity: "Ready to start native Rust capture".into(),
            status: startup_error.map_or_else(
                || "Ready - local proxy 127.0.0.1:8899".into(),
                |error| format!("Startup setting could not be synchronized: {error}"),
            ),
            errors: 0,
            threat_analyzer: ThreatAnalyzer::default(),
            baseline,
            dossiers,
            protocol_tracker: ProtocolTracker::default(),
            analysis_dirty: false,
            last_analysis_save: Instant::now(),
            bypass_connections: Vec::new(),
            dns_observations: Vec::new(),
            bypass_polling: false,
            last_bypass_poll: Instant::now()
                .checked_sub(Duration::from_secs(10))
                .unwrap_or_else(Instant::now),
            last_dns_poll: Instant::now()
                .checked_sub(Duration::from_secs(30))
                .unwrap_or_else(Instant::now),
            workbench_tab: 0,
            dossier_selected,
            capsule_path,
            capsule_passphrase: String::new(),
            capsule_sanitize: true,
            experiment_before_start: None,
            experiment_before: Vec::new(),
            experiment_after_start: None,
            experiment_report: String::new(),
            descriptor_report: String::new(),
            rule_undo: None,
        }
    }

    fn poll_events(&mut self) {
        while let Ok(event) = self.events_rx.try_recv() {
            match event {
                CaptureEvent::Starting => {
                    self.state = "Starting".into();
                    self.ca_state = "Installing".into();
                    self.activity = "Starting native proxy and preparing system settings".into();
                }
                CaptureEvent::Started { host, port } => {
                    self.state = "Capturing".into();
                    self.ca_state = if self.settings.auto_install_ca {
                        "Trusted".into()
                    } else {
                        "Manual install".into()
                    };
                    self.activity = format!("Native Rust proxy running on {host}:{port}");
                    self.status = "Capturing HTTP, HTTPS, and WebSocket traffic".into();
                }
                CaptureEvent::Log(message) => {
                    if message.contains("trusted") {
                        self.ca_state = "Trusted".into();
                    }
                    self.activity = message;
                }
                CaptureEvent::Exchange(mut exchange) => {
                    self.assess_http(&mut exchange);
                    self.activity = exchange.request.url();
                    if let Some(repository) = &self.repository
                        && let Err(error) = repository.add_exchange(&exchange)
                    {
                        self.errors += 1;
                        self.status = format!("Could not save session: {error}");
                    }
                    self.record_analysis(&Session::Http(exchange.clone()));
                    self.push_session(Session::Http(exchange));
                }
                CaptureEvent::ReplayCompleted(mut exchange) => {
                    self.assess_http(&mut exchange);
                    self.activity = format!("Replay completed: {}", exchange.request.url());
                    self.status = exchange
                        .response
                        .as_ref()
                        .map(|response| {
                            format!(
                                "Replay completed with HTTP {} in {:.0} ms",
                                response.status, response.duration_ms
                            )
                        })
                        .unwrap_or_else(|| "Replay completed".into());
                    self.announce_threat(&exchange.threat);
                    self.selected = Some(exchange.id);
                    if let Some(repository) = &self.repository
                        && let Err(error) = repository.add_exchange(&exchange)
                    {
                        self.errors += 1;
                        self.status = format!("Could not save replay: {error}");
                    }
                    self.record_analysis(&Session::Http(exchange.clone()));
                    self.push_session(Session::Http(exchange));
                }
                CaptureEvent::WebSocket(mut message) => {
                    self.protocol_tracker.analyze(&mut message);
                    self.assess_websocket(&mut message);
                    self.activity =
                        format!("WebSocket {} {}", message.direction.label(), message.url);
                    self.record_analysis(&Session::WebSocket(message.clone()));
                    self.push_session(Session::WebSocket(message));
                }
                CaptureEvent::Error(message) => {
                    self.errors += 1;
                    self.state = "Failed".into();
                    self.activity.clone_from(&message);
                    self.status = message;
                }
                CaptureEvent::OperationError(message) => {
                    self.errors += 1;
                    self.activity.clone_from(&message);
                    self.status = message;
                }
                CaptureEvent::Stopped(reason) => {
                    self.state = "Idle".into();
                    self.activity = format!("Stopped: {reason}");
                    self.status = format!("Capture stopped: {reason}");
                }
            }
        }
        if self
            .worker
            .as_ref()
            .is_some_and(|worker| !worker.is_running())
            && let Some(mut worker) = self.worker.take()
        {
            worker.join();
        }
        self.poll_background_results();
    }

    fn start_capture(&mut self) {
        if self.worker.as_ref().is_some_and(CaptureWorker::is_running) {
            return;
        }
        self.sessions.clear();
        self.selected = None;
        self.errors = 0;
        self.threat_analyzer.reset();
        self.protocol_tracker.reset();
        self.bypass_connections.clear();
        self.state = "Starting".into();
        self.ca_state = "Installing".into();
        self.status = "Starting native Rust capture".into();
        match CaptureWorker::start(self.settings.clone(), self.events_tx.clone()) {
            Ok(worker) => self.worker = Some(worker),
            Err(error) => {
                self.state = "Failed".into();
                self.errors += 1;
                self.status = error.to_string();
            }
        }
    }

    fn push_session(&mut self, session: Session) {
        self.sessions.push(session);
        while self.sessions.len() > self.settings.max_session_count {
            let removable = self
                .sessions
                .iter()
                .position(|session| !matches!(session, Session::Http(exchange) if exchange.pinned))
                .unwrap_or(0);
            let removed = self.sessions.remove(removable);
            if self.selected == Some(removed.id()) {
                self.selected = None;
            }
        }
    }

    fn assess_http(&mut self, exchange: &mut CapturedExchange) {
        if !self.settings.threat_detection_enabled {
            exchange.threat = ThreatAssessment::default();
        } else {
            let threshold = Duration::from_secs(self.settings.idle_warning_minutes * 60);
            exchange.threat =
                self.threat_analyzer
                    .analyze_http(exchange, platform::idle_duration(), threshold);
        }
        exchange.behavior = self
            .baseline
            .assess_http(exchange, self.settings.baseline_learning_enabled);
        add_context_findings(
            &mut exchange.threat,
            &exchange.behavior,
            &exchange.request.guard,
            exchange.request.provenance.signature_valid,
            &exchange.request.process,
        );
        self.announce_threat(&exchange.threat);
    }

    fn assess_websocket(&mut self, message: &mut WebSocketMessage) {
        if !self.settings.threat_detection_enabled {
            message.threat = ThreatAssessment::default();
        } else {
            let threshold = Duration::from_secs(self.settings.idle_warning_minutes * 60);
            message.threat = self.threat_analyzer.analyze_websocket(
                message,
                platform::idle_duration(),
                threshold,
            );
        }
        message.behavior = self
            .baseline
            .assess_websocket(message, self.settings.baseline_learning_enabled);
        add_context_findings(
            &mut message.threat,
            &message.behavior,
            &message.guard,
            message.provenance.signature_valid,
            &message.process,
        );
        self.announce_threat(&message.threat);
    }

    fn announce_threat(&mut self, threat: &ThreatAssessment) {
        if let Some(finding) = threat.primary_finding().filter(|_| threat.is_warning()) {
            self.status = format!("Warning: {} - {}", finding.title, finding.evidence);
        }
    }

    fn record_analysis(&mut self, session: &Session) {
        if self.settings.baseline_learning_enabled {
            self.baseline.observe(session);
        }
        self.dossiers.observe(session);
        if self.dossier_selected.is_empty() {
            self.dossier_selected = session.host().to_ascii_lowercase();
        }
        self.analysis_dirty = true;
    }

    fn persist_analysis_state(&mut self, force: bool) {
        if !self.analysis_dirty
            || (!force && self.last_analysis_save.elapsed() < Duration::from_secs(5))
        {
            return;
        }
        let result = AppPaths::discover().and_then(|paths| {
            paths.ensure()?;
            self.baseline.save(&paths.baselines_file)?;
            self.dossiers.save(&paths.dossiers_file)
        });
        match result {
            Ok(()) => {
                self.analysis_dirty = false;
                self.last_analysis_save = Instant::now();
            }
            Err(error) => {
                self.errors += 1;
                self.status = format!("Could not save investigation data: {error}");
            }
        }
    }

    fn poll_background_results(&mut self) {
        while let Ok(event) = self.background_rx.try_recv() {
            match event {
                BackgroundResult::HostIntelligence { host, result } => match *result {
                    Ok(intelligence) => {
                        self.dossiers.set_intelligence(&host, intelligence);
                        self.analysis_dirty = true;
                        self.status = format!("Host intelligence refreshed for {host}");
                    }
                    Err(error) => {
                        self.errors += 1;
                        self.status = format!("Host intelligence failed for {host}: {error}");
                    }
                },
                BackgroundResult::WebSocketReplay { result } => match result {
                    Ok(message) => self.status = message,
                    Err(error) => {
                        self.errors += 1;
                        self.status = format!("WebSocket replay failed: {error}");
                    }
                },
                BackgroundResult::BypassSnapshot { connections, dns } => {
                    self.bypass_polling = false;
                    self.merge_bypass_snapshot(connections, dns);
                }
            }
        }
    }

    fn poll_bypass_connections(&mut self, force: bool) {
        if !self.settings.bypass_radar_enabled
            || self.bypass_polling
            || (!force && self.last_bypass_poll.elapsed() < Duration::from_secs(2))
        {
            return;
        }
        self.last_bypass_poll = Instant::now();
        let poll_dns = force || self.last_dns_poll.elapsed() >= Duration::from_secs(15);
        if poll_dns {
            self.last_dns_poll = Instant::now();
        }
        self.bypass_polling = true;
        let port = self.settings.capture_port;
        let events = self.background_tx.clone();
        spawn_background("http-whisper-bypass-radar", move || async move {
            let connections = platform::snapshot_bypass_connections(port);
            let dns = if poll_dns {
                platform::snapshot_dns_cache()
            } else {
                Vec::new()
            };
            let _ = events.send(BackgroundResult::BypassSnapshot { connections, dns });
        });
    }

    fn merge_bypass_snapshot(
        &mut self,
        snapshots: Vec<BypassConnection>,
        dns: Vec<DnsObservation>,
    ) {
        for snapshot in snapshots {
            let key = (
                snapshot.pid,
                snapshot.local_addr.clone(),
                snapshot.remote_addr.clone(),
                snapshot.remote_port,
            );
            if let Some(existing) = self.bypass_connections.iter_mut().find(|existing| {
                (
                    existing.pid,
                    existing.local_addr.clone(),
                    existing.remote_addr.clone(),
                    existing.remote_port,
                ) == key
            }) {
                existing.last_seen = snapshot.last_seen;
                existing.observations = existing.observations.saturating_add(1);
            } else {
                self.bypass_connections.push(snapshot.clone());
            }
            self.dossiers.observe_bypass(&snapshot);
            self.analysis_dirty = true;
        }
        let cutoff = Utc::now() - TimeDelta::minutes(30);
        self.bypass_connections
            .retain(|connection| connection.last_seen >= cutoff);
        if self.bypass_connections.len() > 5_000 {
            self.bypass_connections
                .sort_by_key(|connection| connection.last_seen);
            self.bypass_connections
                .drain(..self.bypass_connections.len() - 5_000);
        }
        for observation in dns {
            if let Some(existing) = self.dns_observations.iter_mut().find(|existing| {
                existing.host.eq_ignore_ascii_case(&observation.host)
                    && existing.address == observation.address
            }) {
                existing.observed_at = observation.observed_at;
            } else {
                self.dns_observations.push(observation);
            }
        }
        self.dns_observations
            .retain(|observation| observation.observed_at >= cutoff);
        if self.dns_observations.len() > 5_000 {
            self.dns_observations
                .sort_by_key(|observation| observation.observed_at);
            self.dns_observations
                .drain(..self.dns_observations.len() - 5_000);
        }
    }

    fn refresh_selected_host_intelligence(&mut self) {
        if !self.settings.host_intelligence_enabled {
            self.status = "Enable public host intelligence in Settings first".into();
            return;
        }
        let host = self.dossier_selected.clone();
        if host.is_empty() {
            self.status = "Select a host dossier to refresh".into();
            return;
        }
        let events = self.background_tx.clone();
        self.status = format!("Refreshing public intelligence for {host}");
        spawn_background("http-whisper-host-intel", move || async move {
            let result = lookup_host_intelligence(&host)
                .await
                .map_err(|error| error.to_string());
            let _ = events.send(BackgroundResult::HostIntelligence {
                host,
                result: Box::new(result),
            });
        });
    }

    fn replay_selected_websocket(&mut self) {
        let Some(Session::WebSocket(message)) = self.selected_session().cloned() else {
            self.status = "Select a WebSocket message to replay".into();
            return;
        };
        let events = self.background_tx.clone();
        self.status = format!("Replaying WebSocket message #{}", message.sequence);
        spawn_background("http-whisper-ws-replay", move || async move {
            let result = crate::websocket_replay::replay(&message)
                .await
                .map_err(|error| error.to_string());
            let _ = events.send(BackgroundResult::WebSocketReplay { result });
        });
    }

    fn export_current_capsule(&mut self) {
        let path = PathBuf::from(self.capsule_path.trim());
        match export_capsule(
            &path,
            &self.sessions,
            &self.settings,
            &self.baseline,
            &self.dossiers,
            self.capsule_sanitize,
            &self.capsule_passphrase,
        ) {
            Ok(()) => self.status = format!("Capture capsule saved to {}", path.display()),
            Err(error) => {
                self.errors += 1;
                self.status = format!("Could not export capsule: {error}");
            }
        }
    }

    fn open_capsule(&mut self) {
        let path = PathBuf::from(self.capsule_path.trim());
        match import_capsule(&path, &self.capsule_passphrase) {
            Ok(capsule) => {
                self.sessions = capsule.sessions;
                self.settings.auto_response_rules = capsule.rules.auto_responses;
                self.settings.response_rewrite_rules = capsule.rules.response_rewrites;
                self.baseline = capsule.baseline;
                self.dossiers = capsule.dossiers;
                self.selected = self.sessions.first().map(Session::id);
                self.dossier_selected = self
                    .dossiers
                    .hosts
                    .keys()
                    .next()
                    .cloned()
                    .unwrap_or_default();
                self.analysis_dirty = true;
                self.persist_analysis_state(true);
                if let Err(error) = self.settings.save() {
                    self.errors += 1;
                    self.status = format!("Capsule opened, but rules could not be saved: {error}");
                } else {
                    if let Some(worker) = &self.worker {
                        worker.update_settings(self.settings.clone());
                    }
                    self.status = format!("Opened capsule with {} session(s)", self.sessions.len());
                }
            }
            Err(error) => {
                self.errors += 1;
                self.status = format!("Could not open capsule: {error}");
            }
        }
    }

    fn stop_capture(&mut self) {
        if let Some(worker) = &mut self.worker {
            self.state = "Stopping".into();
            self.activity = "Restoring system proxy settings".into();
            self.status = "Stopping native capture".into();
            worker.stop();
        }
    }

    fn open_dialog(&mut self, kind: DialogKind) {
        match kind {
            DialogKind::Settings => {
                self.settings_draft = self.settings.clone();
                self.hidden_hosts_draft = self.settings.hidden_hosts.join("\n");
                self.guard_trusted_hosts_draft =
                    self.settings.exfiltration_trusted_hosts.join("\n");
                self.table_color_selected = self.table_color_selected.min(
                    self.settings_draft
                        .table_color_rules
                        .len()
                        .saturating_sub(1),
                );
            }
            DialogKind::AutoResponses => {
                self.auto_draft = self.settings.auto_response_rules.clone();
                self.auto_selected = self
                    .auto_selected
                    .min(self.auto_draft.len().saturating_sub(1));
            }
            DialogKind::ResponseRewrites => {
                self.rewrite_draft = self.settings.response_rewrite_rules.clone();
                self.rewrite_selected = self
                    .rewrite_selected
                    .min(self.rewrite_draft.len().saturating_sub(1));
            }
            _ => {}
        }
        self.dialog = Some(kind);
    }

    fn save_settings(&mut self) {
        let mut settings = self.settings_draft.clone();
        settings.hidden_hosts = parse_hidden_hosts(&self.hidden_hosts_draft);
        settings.exfiltration_trusted_hosts = parse_hidden_hosts(&self.guard_trusted_hosts_draft);
        match settings.save() {
            Ok(()) => {
                self.settings = settings;
                if let Some(worker) = &self.worker {
                    worker.update_settings(self.settings.clone());
                }
                match configure_startup(self.settings.start_with_windows) {
                    Ok(()) => {
                        self.activity = "Settings saved".into();
                        self.status = "Settings saved".into();
                        self.dialog = None;
                    }
                    Err(error) => {
                        self.errors += 1;
                        self.status =
                            format!("Settings saved, but startup could not be updated: {error}");
                    }
                }
            }
            Err(error) => {
                self.errors += 1;
                self.status = error.to_string();
            }
        }
    }

    fn save_auto_rules(&mut self) {
        self.rule_undo = Some((
            self.settings.auto_response_rules.clone(),
            self.settings.response_rewrite_rules.clone(),
        ));
        self.settings.auto_response_rules = self.auto_draft.clone();
        let count = self.auto_draft.iter().filter(|rule| rule.enabled).count();
        self.persist_settings(&format!("{count} auto response rule(s) enabled"));
    }

    fn save_rewrite_rules(&mut self) {
        self.rule_undo = Some((
            self.settings.auto_response_rules.clone(),
            self.settings.response_rewrite_rules.clone(),
        ));
        self.settings.response_rewrite_rules = self.rewrite_draft.clone();
        let count = self.rewrite_draft.len();
        self.persist_settings(&format!("{count} response rewrite rule(s) enabled"));
    }

    fn persist_settings(&mut self, message: &str) {
        match self.settings.save() {
            Ok(()) => {
                if let Some(worker) = &self.worker {
                    worker.update_settings(self.settings.clone());
                }
                self.activity = message.into();
                self.status = "Settings saved".into();
                self.dialog = None;
            }
            Err(error) => {
                self.errors += 1;
                self.status = error.to_string();
            }
        }
    }

    fn save_runtime_settings(&mut self, message: &str) {
        match self.settings.save() {
            Ok(()) => {
                if let Some(worker) = &self.worker {
                    worker.update_settings(self.settings.clone());
                }
                self.status = message.into();
            }
            Err(error) => {
                self.errors += 1;
                self.status = error.to_string();
            }
        }
    }

    fn selected_session(&self) -> Option<&Session> {
        self.selected
            .and_then(|id| self.sessions.iter().find(|session| session.id() == id))
    }

    fn replay_selected(&mut self) {
        let Some(Session::Http(exchange)) = self.selected_session().cloned() else {
            self.status = "Select an HTTP session to replay".into();
            return;
        };
        let sequence = self
            .sessions
            .iter()
            .map(Session::sequence)
            .max()
            .unwrap_or_default()
            + 1;
        let events = self.events_tx.clone();
        self.status = format!("Replaying {}", exchange.request.url());
        thread::Builder::new()
            .name("http-whisper-replay".into())
            .spawn(move || {
                let runtime = match tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                {
                    Ok(runtime) => runtime,
                    Err(error) => {
                        let _ = events.send(CaptureEvent::OperationError(format!(
                            "Could not start replay: {error}"
                        )));
                        return;
                    }
                };
                match runtime.block_on(crate::replay::replay(&exchange)) {
                    Ok(response) => {
                        let mut replayed = exchange;
                        replayed.id = Uuid::new_v4();
                        replayed.sequence = sequence;
                        replayed.request.timestamp = Utc::now();
                        replayed.response = Some(response);
                        replayed.synthetic = false;
                        replayed.rule_matched = None;
                        replayed.error = None;
                        replayed.pinned = false;
                        replayed.notes = "Replayed request".into();
                        replayed.threat = ThreatAssessment::default();
                        let _ = events.send(CaptureEvent::ReplayCompleted(replayed));
                    }
                    Err(error) => {
                        let _ = events.send(CaptureEvent::OperationError(format!(
                            "Replay failed: {error}"
                        )));
                    }
                }
            })
            .map(|_| ())
            .unwrap_or_else(|error| {
                let _ = self.events_tx.send(CaptureEvent::OperationError(format!(
                    "Could not create replay worker: {error}"
                )));
            });
    }

    fn top_menu(&mut self, ui: &mut Ui) {
        Frame::new()
            .fill(XP_BG)
            .inner_margin(Margin::symmetric(4, 1))
            .show(ui, |ui| {
                egui::MenuBar::new().ui(ui, |ui| {
                    ui.menu_button("File", |ui| {
                        if ui.button("Settings...").clicked() {
                            self.open_dialog(DialogKind::Settings);
                            ui.close();
                        }
                        ui.separator();
                        if ui.button("Exit").clicked() {
                            ui.ctx().send_viewport_cmd(egui::ViewportCommand::Close);
                        }
                    });
                    ui.menu_button("Tools", |ui| {
                        if ui.button("Investigation Workbench...").clicked() {
                            self.open_dialog(DialogKind::Workbench);
                            ui.close();
                        }
                        ui.separator();
                        if ui.button("Auto Responses...").clicked() {
                            self.open_dialog(DialogKind::AutoResponses);
                            ui.close();
                        }
                        if ui.button("Response Rewrites...").clicked() {
                            self.open_dialog(DialogKind::ResponseRewrites);
                            ui.close();
                        }
                        if ui.button("Certificate Manager...").clicked() {
                            self.open_dialog(DialogKind::Certificates);
                            ui.close();
                        }
                    });
                    ui.menu_button("Help", |ui| {
                        if ui.button("About HTTP Whisper").clicked() {
                            self.open_dialog(DialogKind::About);
                            ui.close();
                        }
                    });
                });
            });
    }

    fn toolbar(&mut self, ui: &mut Ui) {
        Frame::new()
            .fill(XP_TOOLBAR)
            .inner_margin(Margin::symmetric(6, 5))
            .stroke(Stroke::new(1.0, Color32::from_rgb(164, 180, 220)))
            .show(ui, |ui| {
                ui.horizontal(|ui| {
                    ui.spacing_mut().item_spacing.x = 5.0;
                    let running = self.worker.as_ref().is_some_and(CaptureWorker::is_running);
                    if ui
                        .add_enabled(!running, toolbar_button("Start Capture"))
                        .clicked()
                    {
                        self.start_capture();
                    }
                    if ui.add_enabled(running, toolbar_button("Stop")).clicked() {
                        self.stop_capture();
                    }
                    if ui.add(toolbar_button("Replay")).clicked() {
                        self.replay_selected();
                    }
                    if ui.add(toolbar_button("Workbench")).clicked() {
                        self.open_dialog(DialogKind::Workbench);
                    }
                    if ui.add(toolbar_button("Auto Responses")).clicked() {
                        self.open_dialog(DialogKind::AutoResponses);
                    }
                    if ui.add(toolbar_button("Response Rewrites")).clicked() {
                        self.open_dialog(DialogKind::ResponseRewrites);
                    }
                    if ui.add(toolbar_button("Certificates")).clicked() {
                        self.open_dialog(DialogKind::Certificates);
                    }
                });
            });
    }

    fn overview(&mut self, ui: &mut Ui) {
        ui.horizontal(|ui| {
            metric(ui, "State", &self.state, 95.0);
            metric(
                ui,
                "Proxy",
                &format!(
                    "{}:{}",
                    self.settings.capture_host, self.settings.capture_port
                ),
                145.0,
            );
            metric(ui, "HTTPS CA", &self.ca_state, 115.0);
            metric(ui, "Sessions", &self.sessions.len().to_string(), 72.0);
            let warnings = self
                .sessions
                .iter()
                .filter(|session| session.threat().is_warning())
                .count();
            metric(ui, "Warnings", &warnings.to_string(), 72.0);
            metric(ui, "Errors", &self.errors.to_string(), 65.0);
            let remaining = ui.available_width().max(180.0);
            group_box(ui, "Activity", Vec2::new(remaining, 49.0), |ui| {
                ui.add(egui::Label::new(&self.activity).truncate());
            });
        });
    }

    fn filter_bar(&mut self, ui: &mut Ui) {
        ui.horizontal(|ui| {
            ui.label("Filter");
            ui.add_sized(
                [ui.available_width(), 23.0],
                TextEdit::singleline(&mut self.filter),
            );
        });
    }

    fn session_table(&mut self, ui: &mut Ui, height: f32) {
        let rows: Vec<Session> = self
            .sessions
            .iter()
            .filter(|session| matches_filter(session, &self.filter))
            .cloned()
            .collect();
        let mut clicked = None;
        let mut pin = None;
        let mut copy = None;
        let mut replay = None;
        Frame::new()
            .fill(XP_WHITE)
            .stroke(Stroke::new(1.0, XP_BORDER))
            .show(ui, |ui| {
                ui.set_height(height);
                ScrollArea::horizontal()
                    .id_salt("sessions-horizontal")
                    .max_height(height)
                    .show(ui, |ui| {
                        ui.set_min_width(1915.0);
                        let mut table = TableBuilder::new(ui)
                            .id_salt("sessions")
                            .striped(true)
                            .resizable(true)
                            .sense(egui::Sense::click())
                            .min_scrolled_height(60.0)
                            .max_scroll_height(height - 2.0);
                        for width in [
                            45.0, 42.0, 45.0, 70.0, 40.0, 90.0, 48.0, 65.0, 55.0, 145.0, 52.0,
                            260.0, 55.0, 145.0, 70.0, 75.0, 70.0, 115.0, 150.0,
                        ] {
                            table =
                                table.column(Column::initial(width).at_least(38.0).resizable(true));
                        }
                        table
                            .header(22.0, |mut header| {
                                for title in [
                                    "Alert",
                                    "Type",
                                    "Seq",
                                    "Timestamp",
                                    "Dir",
                                    "Process",
                                    "PID",
                                    "Method",
                                    "Scheme",
                                    "Host",
                                    "Port",
                                    "Path",
                                    "Status",
                                    "Content Type",
                                    "Req Size",
                                    "Resp Size",
                                    "Duration",
                                    "Rule",
                                    "Error",
                                ] {
                                    header.col(|ui| {
                                        ui.strong(title);
                                    });
                                }
                            })
                            .body(|body| {
                                body.rows(21.0, rows.len(), |mut row| {
                                    let session = &rows[row.index()];
                                    let id = session.id();
                                    let is_selected = self.selected == Some(id);
                                    let colors =
                                        table_cell_colors(&self.settings, session, is_selected);
                                    row.set_selected(is_selected);
                                    row.col(|ui| {
                                        paint_table_cell(ui, colors.row);
                                        threat_indicator(ui, session.threat());
                                    });
                                    for (index, value) in
                                        row_values(session).into_iter().enumerate()
                                    {
                                        row.col(|ui| {
                                            let background = colors.for_value_column(index);
                                            paint_table_cell(ui, background);
                                            let text = match background {
                                                Some(color) => {
                                                    RichText::new(value).color(inverse_color(color))
                                                }
                                                None => RichText::new(value),
                                            };
                                            ui.add(egui::Label::new(text).truncate());
                                        });
                                    }
                                    let response = row.response();
                                    if response.clicked() {
                                        clicked = Some(id);
                                    }
                                    response.context_menu(|ui| {
                                        if ui.button("Copy URL").clicked() {
                                            copy = Some(session.url());
                                            ui.close();
                                        }
                                        if ui.button("Pin Session").clicked() {
                                            pin = Some(id);
                                            ui.close();
                                        }
                                        if ui.button("Replay").clicked() {
                                            replay = Some(id);
                                            ui.close();
                                        }
                                    });
                                });
                            });
                    });
            });
        if let Some(id) = clicked {
            self.selected = Some(id);
        }
        if let Some(id) = pin
            && let Some(Session::Http(exchange)) =
                self.sessions.iter_mut().find(|item| item.id() == id)
        {
            exchange.pinned = !exchange.pinned;
            self.status = if exchange.pinned {
                "Session pinned"
            } else {
                "Session unpinned"
            }
            .into();
            if let Some(repository) = &self.repository
                && let Err(error) = repository.add_exchange(exchange)
            {
                self.errors += 1;
                self.status = format!("Could not save pin state: {error}");
            }
        }
        if let Some(url) = copy {
            ui.ctx().copy_text(url.clone());
            self.status = url;
        }
        if let Some(id) = replay {
            self.selected = Some(id);
            self.replay_selected();
        }
    }

    fn inspector(&mut self, ui: &mut Ui) {
        let tabs = [
            "Overview", "Warnings", "Report", "Request", "Response", "Headers", "Raw", "Notes",
        ];
        Frame::new()
            .fill(XP_BG)
            .stroke(Stroke::new(1.0, XP_BORDER))
            .show(ui, |ui| {
                ui.horizontal(|ui| {
                    for (index, label) in tabs.iter().enumerate() {
                        let selected = self.tab == index;
                        if ui.selectable_label(selected, *label).clicked() {
                            self.tab = index;
                        }
                    }
                });
                ui.separator();
                let mut text = self.inspector_text();
                ScrollArea::both().id_salt("inspector-text").show(ui, |ui| {
                    ui.add_sized(
                        [ui.available_width(), ui.available_height().max(90.0)],
                        TextEdit::multiline(&mut text)
                            .font(FontId::monospace(12.0))
                            .desired_width(f32::INFINITY)
                            .interactive(false),
                    );
                });
            });
    }

    fn inspector_text(&self) -> String {
        let Some(session) = self.selected_session() else {
            return "Select a session".into();
        };
        if self.tab == 1 {
            return threat_inspector(session.threat());
        }
        if self.tab == 2 {
            return explain_session(session, &self.dossiers);
        }
        let content_tab = if self.tab > 2 { self.tab - 2 } else { self.tab };
        match session {
            Session::Http(exchange) => http_inspector(exchange, content_tab),
            Session::WebSocket(message) => websocket_inspector(message, content_tab),
        }
    }

    fn status_bar(&self, ui: &mut Ui) {
        Frame::new()
            .fill(XP_BG)
            .stroke(Stroke::new(1.0, Color32::from_rgb(128, 128, 128)))
            .inner_margin(Margin::symmetric(5, 3))
            .show(ui, |ui| {
                ui.add(egui::Label::new(&self.status).truncate());
            });
    }

    fn show_dialog(&mut self, ui: &mut Ui) {
        let Some(kind) = self.dialog else { return };
        match kind {
            DialogKind::Settings => self.settings_dialog(ui),
            DialogKind::AutoResponses => self.auto_responses_dialog(ui),
            DialogKind::ResponseRewrites => self.response_rewrites_dialog(ui),
            DialogKind::Certificates => self.certificates_dialog(ui),
            DialogKind::Workbench => self.workbench_dialog(ui),
            DialogKind::About => self.about_dialog(ui),
        }
    }

    fn settings_dialog(&mut self, ui: &mut Ui) {
        egui::Window::new("Settings")
            .collapsible(false)
            .resizable(false)
            .fixed_size([520.0, 330.0])
            .show(ui.ctx(), |ui| {
                ui.horizontal(|ui| {
                    ui.selectable_value(&mut self.settings_tab, 0, "General");
                    ui.selectable_value(&mut self.settings_tab, 1, "Warnings");
                    ui.selectable_value(&mut self.settings_tab, 2, "Data Guard");
                    ui.selectable_value(&mut self.settings_tab, 3, "Colors");
                });
                ui.separator();
                ScrollArea::vertical()
                    .id_salt("settings-page")
                    .auto_shrink([false, false])
                    .scroll_bar_visibility(egui::scroll_area::ScrollBarVisibility::AlwaysVisible)
                    .max_height(230.0)
                    .show(ui, |ui| match self.settings_tab {
                        0 => self.settings_general_tab(ui),
                        1 => self.settings_warnings_tab(ui),
                        2 => self.settings_guard_tab(ui),
                        _ => self.settings_colors_tab(ui),
                    });
                ui.add_space(4.0);
                ui.separator();
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    if ui.button("Close").clicked() {
                        self.dialog = None;
                    }
                    if ui.button("Save").clicked() {
                        self.save_settings();
                    }
                });
            });
    }

    fn settings_general_tab(&mut self, ui: &mut Ui) {
        egui::Grid::new("settings-general-grid")
            .num_columns(2)
            .spacing([12.0, 8.0])
            .show(ui, |ui| {
                ui.label("Capture host");
                ui.text_edit_singleline(&mut self.settings_draft.capture_host);
                ui.end_row();
                ui.label("Capture port");
                ui.add(
                    egui::DragValue::new(&mut self.settings_draft.capture_port).range(1..=65535),
                );
                ui.end_row();
                ui.label("HTTPS interception");
                ui.checkbox(
                    &mut self.settings_draft.enable_https_interception,
                    "Enabled",
                );
                ui.end_row();
                #[cfg(windows)]
                {
                    ui.label("Windows proxy");
                    ui.checkbox(
                        &mut self.settings_draft.auto_configure_system_proxy,
                        "Configure automatically",
                    );
                    ui.end_row();
                    ui.label("Local CA");
                    ui.checkbox(
                        &mut self.settings_draft.auto_install_ca,
                        "Install automatically",
                    );
                    ui.end_row();
                    ui.label("Windows startup");
                    ui.checkbox(
                        &mut self.settings_draft.start_with_windows,
                        "Start HTTP Whisper",
                    );
                    ui.end_row();
                }
                #[cfg(not(windows))]
                {
                    ui.label("System proxy");
                    ui.label("Configure manually");
                    ui.end_row();
                    ui.label("Local CA");
                    ui.label("Install from http://mitm.it/");
                    ui.end_row();
                }
                ui.label("On launch");
                ui.checkbox(&mut self.settings_draft.auto_connect, "Auto-connect");
                ui.end_row();
            });
        ui.separator();
        ui.label("Disallowed domains (one per line)");
        scrollable_text_editor(ui, "hidden-hosts", &mut self.hidden_hosts_draft, 70.0);
    }

    fn settings_warnings_tab(&mut self, ui: &mut Ui) {
        egui::Grid::new("settings-warnings-grid")
            .num_columns(2)
            .spacing([12.0, 8.0])
            .show(ui, |ui| {
                ui.label("Traffic warnings");
                ui.checkbox(
                    &mut self.settings_draft.threat_detection_enabled,
                    "Detect suspicious activity",
                );
                ui.end_row();
                ui.label("Idle threshold");
                ui.add(
                    egui::DragValue::new(&mut self.settings_draft.idle_warning_minutes)
                        .range(1..=120)
                        .suffix(" min"),
                );
                ui.end_row();
                ui.label("Learn Normal");
                ui.checkbox(
                    &mut self.settings_draft.baseline_learning_enabled,
                    "Add trusted traffic to baseline",
                );
                ui.end_row();
                ui.label("Bypass radar");
                ui.add_enabled(
                    cfg!(windows),
                    egui::Checkbox::new(
                        &mut self.settings_draft.bypass_radar_enabled,
                        if cfg!(windows) {
                            "Observe direct outbound TCP"
                        } else {
                            "Windows only"
                        },
                    ),
                );
                ui.end_row();
                ui.label("Host intelligence");
                ui.checkbox(
                    &mut self.settings_draft.host_intelligence_enabled,
                    "Allow public DNS and RDAP lookup",
                );
                ui.end_row();
            });
    }

    fn settings_guard_tab(&mut self, ui: &mut Ui) {
        egui::Grid::new("settings-guard-grid")
            .num_columns(2)
            .spacing([12.0, 8.0])
            .show(ui, |ui| {
                ui.label("Outbound secrets");
                egui::ComboBox::from_id_salt("exfiltration-guard-mode")
                    .selected_text(self.settings_draft.exfiltration_guard_mode.label())
                    .show_ui(ui, |ui| {
                        for mode in ExfiltrationMode::ALL {
                            ui.selectable_value(
                                &mut self.settings_draft.exfiltration_guard_mode,
                                mode,
                                mode.label(),
                            );
                        }
                    });
                ui.end_row();
            });
        ui.separator();
        ui.label("Trusted destinations (one per line)");
        scrollable_text_editor(
            ui,
            "guard-trusted-hosts",
            &mut self.guard_trusted_hosts_draft,
            120.0,
        );
    }

    fn settings_colors_tab(&mut self, ui: &mut Ui) {
        let mut preset = self.settings_draft.table_color_preset;
        egui::Grid::new("settings-color-preset-grid")
            .num_columns(2)
            .spacing([12.0, 8.0])
            .show(ui, |ui| {
                ui.label("Preset");
                egui::ComboBox::from_id_salt("table-color-preset")
                    .selected_text(preset.label())
                    .show_ui(ui, |ui| {
                        for option in TableColorPreset::ALL {
                            ui.selectable_value(&mut preset, option, option.label());
                        }
                    });
                ui.end_row();
            });
        if preset != self.settings_draft.table_color_preset {
            self.settings_draft.apply_table_color_preset(preset);
            self.table_color_selected = 0;
        }

        ui.separator();
        ui.horizontal(|ui| {
            ui.label("Rule");
            let selected_name = self
                .settings_draft
                .table_color_rules
                .get(self.table_color_selected)
                .map(|rule| rule.name.as_str())
                .unwrap_or("No rules");
            egui::ComboBox::from_id_salt("table-color-rule")
                .selected_text(selected_name)
                .show_ui(ui, |ui| {
                    for (index, rule) in self.settings_draft.table_color_rules.iter().enumerate() {
                        ui.selectable_value(&mut self.table_color_selected, index, &rule.name);
                    }
                });
            if ui.button("+").on_hover_text("Add color rule").clicked() {
                let number = self.settings_draft.table_color_rules.len() + 1;
                let rule = TableColorRule {
                    name: format!("Table color {number}"),
                    ..Default::default()
                };
                self.settings_draft.table_color_rules.push(rule);
                self.table_color_selected = number - 1;
                self.settings_draft.table_color_preset = TableColorPreset::Custom;
            }
            let can_remove = !self.settings_draft.table_color_rules.is_empty();
            if ui
                .add_enabled(can_remove, egui::Button::new("-"))
                .on_hover_text("Remove selected color rule")
                .clicked()
            {
                self.settings_draft
                    .table_color_rules
                    .remove(self.table_color_selected);
                self.table_color_selected = self.table_color_selected.min(
                    self.settings_draft
                        .table_color_rules
                        .len()
                        .saturating_sub(1),
                );
                self.settings_draft.table_color_preset = TableColorPreset::Custom;
            }
        });

        let Some(rule) = self
            .settings_draft
            .table_color_rules
            .get_mut(self.table_color_selected)
        else {
            return;
        };
        let mut changed = false;
        egui::Grid::new("settings-color-rule-grid")
            .num_columns(2)
            .spacing([12.0, 8.0])
            .show(ui, |ui| {
                ui.label("Enabled");
                changed |= ui.checkbox(&mut rule.enabled, "Use this rule").changed();
                ui.end_row();
                ui.label("Name");
                changed |= ui.text_edit_singleline(&mut rule.name).changed();
                ui.end_row();
                ui.label("Match field");
                let previous_field = rule.field;
                egui::ComboBox::from_id_salt("table-color-field")
                    .selected_text(rule.field.label())
                    .show_ui(ui, |ui| {
                        for field in TableColorField::ALL {
                            ui.selectable_value(&mut rule.field, field, field.label());
                        }
                    });
                if rule.field != previous_field {
                    rule.pattern = match rule.field {
                        TableColorField::Host => "*.example.com".into(),
                        TableColorField::StatusCode => "4xx".into(),
                    };
                    changed = true;
                }
                ui.end_row();
                ui.label("Match value");
                changed |= ui.text_edit_singleline(&mut rule.pattern).changed();
                ui.end_row();
                ui.label("Apply to");
                let previous_target = rule.target;
                egui::ComboBox::from_id_salt("table-color-target")
                    .selected_text(rule.target.label())
                    .show_ui(ui, |ui| {
                        for target in TableColorTarget::ALL {
                            ui.selectable_value(&mut rule.target, target, target.label());
                        }
                    });
                changed |= rule.target != previous_target;
                ui.end_row();
                ui.label("Color");
                changed |= ui.color_edit_button_srgb(&mut rule.color).changed();
                ui.end_row();
            });
        ui.separator();
        highlight_preview(ui, &rule.name, rule.color);
        if changed {
            self.settings_draft.table_color_preset = TableColorPreset::Custom;
        }
    }

    fn workbench_dialog(&mut self, ui: &mut Ui) {
        let screen = ui.ctx().content_rect().size();
        let (default_size, minimum_size) = workbench_window_sizes(screen);
        egui::Window::new("Investigation Workbench")
            .collapsible(false)
            .resizable(true)
            .default_size(default_size)
            .min_size(minimum_size)
            .show(ui.ctx(), |ui| {
                ui.horizontal_wrapped(|ui| {
                    for (index, label) in [
                        "Timeline",
                        "Baseline",
                        "Bypass",
                        "WebSockets",
                        "Dossiers",
                        "Capsules",
                        "Experiments",
                        "Rules",
                    ]
                    .iter()
                    .enumerate()
                    {
                        ui.selectable_value(&mut self.workbench_tab, index, *label);
                    }
                });
                ui.separator();
                let content_height = (ui.available_height() - 38.0).max(320.0);
                ui.allocate_ui_with_layout(
                    Vec2::new(ui.available_width(), content_height),
                    Layout::top_down(Align::Min),
                    |ui| match self.workbench_tab {
                        0 => self.workbench_timeline(ui),
                        1 => self.workbench_baseline(ui),
                        2 => self.workbench_bypass(ui),
                        3 => self.workbench_websockets(ui),
                        4 => self.workbench_dossiers(ui),
                        5 => self.workbench_capsules(ui),
                        6 => self.workbench_experiments(ui),
                        _ => self.workbench_rules(ui),
                    },
                );
                ui.separator();
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    if ui.button("Close").clicked() {
                        self.dialog = None;
                    }
                });
            });
    }

    fn workbench_timeline(&mut self, ui: &mut Ui) {
        ui.horizontal(|ui| {
            if ui.button("Copy Timeline").clicked() {
                ui.ctx().copy_text(process_timeline(&self.sessions));
                self.status = "Application timeline copied".into();
            }
            ui.label(format!("{} captured event(s)", self.sessions.len()));
        });
        let report = process_timeline(&self.sessions);
        read_only_text(ui, "workbench-timeline", &report, ui.available_height());
    }

    fn workbench_baseline(&mut self, ui: &mut Ui) {
        ui.horizontal(|ui| {
            let changed = ui
                .checkbox(&mut self.settings.baseline_learning_enabled, "Learn Normal")
                .changed();
            if changed {
                self.save_runtime_settings(if self.settings.baseline_learning_enabled {
                    "Learn Normal enabled"
                } else {
                    "Learn Normal stopped"
                });
            }
            if ui.button("Clear Baseline").clicked() {
                self.baseline.clear();
                self.analysis_dirty = true;
                self.persist_analysis_state(true);
                self.status = "Learned traffic baseline cleared".into();
            }
            if ui.button("Save Now").clicked() {
                self.analysis_dirty = true;
                self.persist_analysis_state(true);
                self.status = "Traffic baseline saved".into();
            }
        });
        ui.label(format!(
            "Processes: {}    Process/host pairs: {}    State: {}",
            self.baseline.process_count(),
            self.baseline.host_count(),
            if self.settings.baseline_learning_enabled {
                "Learning"
            } else {
                "Monitoring"
            }
        ));
        let summary = self.baseline.summary();
        read_only_text(ui, "workbench-baseline", &summary, ui.available_height());
    }

    fn workbench_bypass(&mut self, ui: &mut Ui) {
        ui.horizontal(|ui| {
            let changed = ui
                .add_enabled(
                    cfg!(windows),
                    egui::Checkbox::new(&mut self.settings.bypass_radar_enabled, "Bypass Radar"),
                )
                .changed();
            if changed {
                self.save_runtime_settings("Bypass radar setting saved");
            }
            if ui.button("Refresh").clicked() {
                self.poll_bypass_connections(true);
            }
            if ui.button("Clear").clicked() {
                self.bypass_connections.clear();
                self.dns_observations.clear();
            }
            ui.label(format!(
                "{} direct connection(s), {} DNS record(s)",
                self.bypass_connections.len(),
                self.dns_observations.len()
            ));
        });
        ui.label(if cfg!(windows) {
            "Coverage: Windows IPv4 established TCP and DNS client cache"
        } else {
            "Bypass Radar is currently available on Windows only"
        });
        ui.separator();
        ScrollArea::both().id_salt("bypass-table").show(ui, |ui| {
            egui::Grid::new("bypass-grid")
                .striped(true)
                .min_col_width(90.0)
                .show(ui, |ui| {
                    for heading in [
                        "Process",
                        "PID",
                        "Local",
                        "Remote",
                        "Port",
                        "First Seen",
                        "Last Seen",
                        "Samples",
                    ] {
                        ui.strong(heading);
                    }
                    ui.end_row();
                    let mut rows = self.bypass_connections.clone();
                    rows.sort_by_key(|row| std::cmp::Reverse(row.last_seen));
                    for connection in rows {
                        ui.label(if connection.process.is_empty() {
                            "<unknown>"
                        } else {
                            &connection.process
                        });
                        ui.label(connection.pid.to_string());
                        ui.label(connection.local_addr);
                        let dns_names = self
                            .dns_observations
                            .iter()
                            .filter(|value| value.address == connection.remote_addr)
                            .map(|value| value.host.as_str())
                            .take(3)
                            .collect::<Vec<_>>()
                            .join(", ");
                        ui.label(if dns_names.is_empty() {
                            connection.remote_addr
                        } else {
                            format!("{} ({dns_names})", connection.remote_addr)
                        });
                        ui.label(connection.remote_port.to_string());
                        ui.label(connection.first_seen.format("%H:%M:%S").to_string());
                        ui.label(connection.last_seen.format("%H:%M:%S").to_string());
                        ui.label(connection.observations.to_string());
                        ui.end_row();
                    }
                });
            ui.add_space(10.0);
            ui.strong("DNS observations");
            egui::Grid::new("bypass-dns-grid")
                .striped(true)
                .min_col_width(150.0)
                .show(ui, |ui| {
                    ui.strong("Host");
                    ui.strong("Address");
                    ui.strong("Observed");
                    ui.end_row();
                    let mut rows = self.dns_observations.clone();
                    rows.sort_by_key(|row| std::cmp::Reverse(row.observed_at));
                    for observation in rows.into_iter().take(1_000) {
                        ui.label(observation.host);
                        ui.label(observation.address);
                        ui.label(observation.observed_at.format("%H:%M:%S").to_string());
                        ui.end_row();
                    }
                });
        });
    }

    fn workbench_websockets(&mut self, ui: &mut Ui) {
        ui.horizontal(|ui| {
            if ui.button("Replay Selected Message").clicked() {
                self.replay_selected_websocket();
            }
            ui.label("Descriptor set");
            ui.add_sized(
                [280.0, 22.0],
                TextEdit::singleline(&mut self.settings.protobuf_descriptor_file),
            );
            if ui.button("Load").clicked() {
                let path = PathBuf::from(self.settings.protobuf_descriptor_file.trim());
                match descriptor_messages(&path) {
                    Ok(messages) => {
                        let mut report = format!(
                            "Loaded {} protobuf message descriptor(s)\n{}",
                            messages.len(),
                            messages.join("\n")
                        );
                        if let Some(Session::WebSocket(message)) = self.selected_session()
                            && !message.wire_payload.is_empty()
                        {
                            match decode_with_descriptors(&path, &message.wire_payload) {
                                Ok(candidates) if !candidates.is_empty() => {
                                    report.push_str("\n\nSelected binary decode candidates\n");
                                    report.push_str(&candidates.join("\n\n"));
                                }
                                Ok(_) => report.push_str(
                                    "\n\nNo descriptor decoded the selected message with known fields.",
                                ),
                                Err(error) => {
                                    report.push_str(&format!("\n\nDecode failed: {error}"));
                                }
                            }
                        }
                        self.descriptor_report = report;
                        self.save_runtime_settings("Protobuf descriptor set loaded");
                    }
                    Err(error) => {
                        self.errors += 1;
                        self.descriptor_report = error.to_string();
                    }
                }
            }
        });
        let messages = self
            .sessions
            .iter()
            .filter_map(|session| match session {
                Session::WebSocket(message) => Some(message.clone()),
                _ => None,
            })
            .collect::<Vec<_>>();
        let mut summary = protocol_summary(&messages);
        if let Some(Session::WebSocket(message)) = self.selected_session() {
            summary.push_str(&format!(
                "\n\nSelected message #{}\nProtocol: {}\nType: {}\nCorrelation: {}\nSequence value: {}\nReply to capture: {}\nGuard: {}\n\nSchema\n{}",
                message.sequence,
                value_or_unknown(&message.analysis.protocol),
                value_or_unknown(&message.analysis.message_type),
                value_or_unknown(&message.analysis.correlation_id),
                message.analysis.sequence_value.map(|value| value.to_string()).unwrap_or_else(|| "<none>".into()),
                message.analysis.reply_to_sequence.map(|value| value.to_string()).unwrap_or_else(|| "<none>".into()),
                message.guard.action.label(),
                message.analysis.schema.join("\n")
            ));
        }
        if !self.descriptor_report.is_empty() {
            summary.push_str("\n\nProtobuf descriptors\n");
            summary.push_str(&self.descriptor_report);
        }
        read_only_text(ui, "workbench-websocket", &summary, ui.available_height());
    }

    fn workbench_dossiers(&mut self, ui: &mut Ui) {
        ui.horizontal(|ui| {
            ui.label("Host");
            let hosts = self.dossiers.hosts.keys().cloned().collect::<Vec<_>>();
            egui::ComboBox::from_id_salt("dossier-host")
                .selected_text(value_or_unknown(&self.dossier_selected))
                .width(260.0)
                .show_ui(ui, |ui| {
                    for host in hosts {
                        ui.selectable_value(&mut self.dossier_selected, host.clone(), host);
                    }
                });
            if ui.button("Refresh Intelligence").clicked() {
                self.refresh_selected_host_intelligence();
            }
            let changed = ui
                .checkbox(
                    &mut self.settings.host_intelligence_enabled,
                    "Public DNS/RDAP",
                )
                .changed();
            if changed {
                self.save_runtime_settings("Host intelligence setting saved");
            }
        });
        let report = self.dossiers.report(&self.dossier_selected);
        read_only_text(ui, "workbench-dossier", &report, ui.available_height());
    }

    fn workbench_capsules(&mut self, ui: &mut Ui) {
        egui::Grid::new("capsule-controls")
            .num_columns(2)
            .spacing([10.0, 8.0])
            .show(ui, |ui| {
                ui.label("Capsule file");
                ui.add(TextEdit::singleline(&mut self.capsule_path).desired_width(600.0));
                ui.end_row();
                ui.label("Passphrase");
                ui.add(
                    TextEdit::singleline(&mut self.capsule_passphrase)
                        .password(true)
                        .desired_width(320.0),
                );
                ui.end_row();
                ui.label("Sanitization");
                ui.checkbox(
                    &mut self.capsule_sanitize,
                    "Redact secrets and raw WS bytes",
                );
                ui.end_row();
            });
        ui.horizontal(|ui| {
            if ui.button("Export Capture Capsule").clicked() {
                self.export_current_capsule();
            }
            if ui.button("Open Capture Capsule").clicked() {
                self.open_capsule();
            }
        });
        ui.separator();
        let encryption = if self.capsule_passphrase.is_empty() {
            "None"
        } else {
            "AES-256-GCM with PBKDF2-HMAC-SHA256"
        };
        let summary = format!(
            "Sessions: {}\nAuto-response rules: {}\nResponse-rewrite rules: {}\nBaseline processes: {}\nHost dossiers: {}\nEncryption: {}\nSanitized: {}",
            self.sessions.len(),
            self.settings.auto_response_rules.len(),
            self.settings.response_rewrite_rules.len(),
            self.baseline.process_count(),
            self.dossiers.hosts.len(),
            encryption,
            self.capsule_sanitize
        );
        read_only_text(ui, "workbench-capsule", &summary, 180.0);
    }

    fn workbench_experiments(&mut self, ui: &mut Ui) {
        ui.horizontal_wrapped(|ui| {
            if ui.button("Start Before Window").clicked() {
                self.experiment_before_start = Some(self.sessions.len());
                self.experiment_before.clear();
                self.experiment_report.clear();
                self.status = "Before experiment window started".into();
            }
            if ui
                .add_enabled(
                    self.experiment_before_start.is_some(),
                    egui::Button::new("End Before Window"),
                )
                .clicked()
            {
                let start = self.experiment_before_start.take().unwrap_or_default();
                self.experiment_before = self.sessions[start.min(self.sessions.len())..].to_vec();
                self.status = format!(
                    "Before window saved with {} event(s)",
                    self.experiment_before.len()
                );
            }
            if ui
                .add_enabled(
                    !self.experiment_before.is_empty(),
                    egui::Button::new("Start After Window"),
                )
                .clicked()
            {
                self.experiment_after_start = Some(self.sessions.len());
                self.status = "After experiment window started".into();
            }
            if ui
                .add_enabled(
                    self.experiment_after_start.is_some(),
                    egui::Button::new("End and Compare"),
                )
                .clicked()
            {
                let start = self.experiment_after_start.take().unwrap_or_default();
                let after = &self.sessions[start.min(self.sessions.len())..];
                self.experiment_report =
                    experiment::compare(&self.experiment_before, after).render();
                self.status = "Before/after comparison completed".into();
            }
            if ui.button("Reset").clicked() {
                self.experiment_before_start = None;
                self.experiment_before.clear();
                self.experiment_after_start = None;
                self.experiment_report.clear();
            }
        });
        ui.label(format!(
            "Before: {} event(s)    Before active: {}    After active: {}",
            self.experiment_before.len(),
            self.experiment_before_start.is_some(),
            self.experiment_after_start.is_some()
        ));
        let report = if self.experiment_report.is_empty() {
            "No experiment comparison has been generated."
        } else {
            &self.experiment_report
        };
        read_only_text(ui, "workbench-experiment", report, ui.available_height());
    }

    fn workbench_rules(&mut self, ui: &mut Ui) {
        ui.horizontal(|ui| {
            if ui.button("Auto Responses...").clicked() {
                self.open_dialog(DialogKind::AutoResponses);
            }
            if ui.button("Response Rewrites...").clicked() {
                self.open_dialog(DialogKind::ResponseRewrites);
            }
            if ui
                .add_enabled(
                    self.rule_undo.is_some(),
                    egui::Button::new("Undo Rule Changes"),
                )
                .clicked()
                && let Some((auto, rewrites)) = self.rule_undo.take()
            {
                self.settings.auto_response_rules = auto;
                self.settings.response_rewrite_rules = rewrites;
                self.save_runtime_settings("Last rule change undone");
            }
        });
        let Some(session) = self.selected_session() else {
            ui.label("Select an HTTP or WebSocket session to simulate rules.");
            return;
        };
        let simulations = simulate(session, &self.settings);
        let hits = hit_counts(&self.sessions);
        if simulations.is_empty() {
            ui.label("No auto-response or response-rewrite rules are configured.");
            return;
        }
        ScrollArea::vertical()
            .id_salt("workbench-rule-debugger")
            .show(ui, |ui| {
                for (index, simulation) in simulations.iter().enumerate() {
                    ui.horizontal_wrapped(|ui| {
                        ui.label(RichText::new(&simulation.name).strong());
                        ui.label(format!("[{}]", simulation.kind));
                        ui.label(
                            RichText::new(if simulation.matched {
                                "MATCH"
                            } else {
                                "NO MATCH"
                            })
                            .strong()
                            .color(if simulation.matched {
                                Color32::from_rgb(0, 110, 0)
                            } else {
                                Color32::from_rgb(110, 110, 110)
                            }),
                        );
                        ui.label(format!(
                            "Historical hits: {}",
                            hits.get(&simulation.name).copied().unwrap_or_default()
                        ));
                    });
                    ui.horizontal_wrapped(|ui| {
                        for condition in &simulation.conditions {
                            let passed = condition.starts_with("PASS");
                            ui.label(RichText::new(condition).color(if passed {
                                Color32::from_rgb(0, 100, 0)
                            } else {
                                XP_DANGER
                            }));
                        }
                    });
                    if !simulation.effect.is_empty() {
                        ui.label(format!("Effect: {}", simulation.effect));
                    }
                    if !simulation.preview.is_empty() {
                        let mut preview = simulation.preview.clone();
                        ScrollArea::both()
                            .id_salt(("rule-preview", index))
                            .max_height(130.0)
                            .auto_shrink([false, false])
                            .show(ui, |ui| {
                                ui.add_sized(
                                    [ui.available_width(), 125.0],
                                    TextEdit::multiline(&mut preview)
                                        .font(FontId::monospace(12.0))
                                        .desired_width(f32::INFINITY)
                                        .interactive(false),
                                );
                            });
                    }
                    ui.separator();
                }
            });
    }

    fn auto_responses_dialog(&mut self, ui: &mut Ui) {
        egui::Window::new("Auto Responses")
            .collapsible(false)
            .resizable(false)
            .fixed_size([760.0, 480.0])
            .show(ui.ctx(), |ui| {
                let left_width = 225.0;
                let gap = 8.0;
                let right_width = (ui.available_width() - left_width - gap).max(360.0);
                ui.horizontal_top(|ui| {
                    fixed_group_box(ui, "Rules", Vec2::new(left_width, 390.0), |ui| {
                        ScrollArea::vertical().max_height(310.0).show(ui, |ui| {
                            for (index, rule) in self.auto_draft.iter().enumerate() {
                                let state = if rule.enabled { "On" } else { "Off" };
                                if ui
                                    .selectable_label(
                                        self.auto_selected == index,
                                        format!(
                                            "{state}  {}  {}{}",
                                            rule.name, rule.host, rule.path
                                        ),
                                    )
                                    .clicked()
                                {
                                    self.auto_selected = index;
                                }
                            }
                        });
                        if ui.button("New").clicked() {
                            let rule = AutoResponseRule {
                                name: format!("Auto response {}", self.auto_draft.len() + 1),
                                ..Default::default()
                            };
                            self.auto_draft.push(rule);
                            self.auto_selected = self.auto_draft.len() - 1;
                        }
                        if ui.button("Delete").clicked() && !self.auto_draft.is_empty() {
                            self.auto_draft.remove(self.auto_selected);
                            self.auto_selected = self
                                .auto_selected
                                .min(self.auto_draft.len().saturating_sub(1));
                        }
                    });
                    ui.add_space(gap);
                    fixed_group_box(ui, "Selected Rule", Vec2::new(right_width, 390.0), |ui| {
                        let selected = self.auto_selected;
                        if let Some(rule) = self.auto_draft.get_mut(self.auto_selected) {
                            rule_form_row(ui, "Name", |ui| {
                                ui.text_edit_singleline(&mut rule.name);
                            });
                            rule_form_row(ui, "", |ui| {
                                ui.checkbox(&mut rule.enabled, "Enabled");
                            });
                            rule_form_row(ui, "Method", |ui| {
                                ui.text_edit_singleline(&mut rule.method);
                            });
                            rule_form_row(ui, "Host", |ui| {
                                ui.text_edit_singleline(&mut rule.host);
                            });
                            rule_form_row(ui, "Path", |ui| {
                                ui.text_edit_singleline(&mut rule.path);
                            });
                            rule_form_row(ui, "Status", |ui| {
                                ui.add(
                                    egui::DragValue::new(&mut rule.status_code).range(100..=599),
                                );
                            });
                            rule_form_row(ui, "Content-Type", |ui| {
                                ui.text_edit_singleline(&mut rule.content_type);
                            });
                            ui.label("Body");
                            scrollable_text_editor(
                                ui,
                                ("auto-response-body", selected),
                                &mut rule.body,
                                130.0,
                            );
                        } else {
                            ui.label("Create a rule to begin.");
                        }
                    });
                });
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    if ui.button("Close").clicked() {
                        self.dialog = None;
                    }
                    if ui.button("Save").clicked() {
                        self.save_auto_rules();
                    }
                });
            });
    }

    fn response_rewrites_dialog(&mut self, ui: &mut Ui) {
        egui::Window::new("Response Rewrites")
            .collapsible(false)
            .resizable(false)
            .fixed_size([760.0, 480.0])
            .show(ui.ctx(), |ui| {
                let left_width = 225.0;
                let gap = 8.0;
                let right_width = (ui.available_width() - left_width - gap).max(360.0);
                ui.horizontal_top(|ui| {
                    fixed_group_box(ui, "Rules", Vec2::new(left_width, 390.0), |ui| {
                        ScrollArea::vertical().max_height(310.0).show(ui, |ui| {
                            for (index, rule) in self.rewrite_draft.iter().enumerate() {
                                let label = format!(
                                    "{}  {}  {} -> {}",
                                    index + 1,
                                    compact_rule_text(&rule.host),
                                    compact_rule_text(&rule.find_text),
                                    compact_rule_text(&rule.replace_text)
                                );
                                if ui
                                    .selectable_label(self.rewrite_selected == index, label)
                                    .clicked()
                                {
                                    self.rewrite_selected = index;
                                }
                            }
                        });
                        if ui.button("New").clicked() {
                            let rule = ResponseRewriteRule {
                                name: format!("Response rewrite {}", self.rewrite_draft.len() + 1),
                                ..Default::default()
                            };
                            self.rewrite_draft.push(rule);
                            self.rewrite_selected = self.rewrite_draft.len() - 1;
                        }
                        if ui.button("Delete").clicked() && !self.rewrite_draft.is_empty() {
                            self.rewrite_draft.remove(self.rewrite_selected);
                            self.rewrite_selected = self
                                .rewrite_selected
                                .min(self.rewrite_draft.len().saturating_sub(1));
                        }
                    });
                    ui.add_space(gap);
                    fixed_group_box(
                        ui,
                        "Host Find / Replace",
                        Vec2::new(right_width, 390.0),
                        |ui| {
                            let selected = self.rewrite_selected;
                            if let Some(rule) = self.rewrite_draft.get_mut(self.rewrite_selected) {
                                rule_form_row(ui, "Host", |ui| {
                                    ui.text_edit_singleline(&mut rule.host);
                                });
                                rule_form_multiline(
                                    ui,
                                    "Find",
                                    ("rewrite-find", selected),
                                    &mut rule.find_text,
                                    132.0,
                                );
                                rule_form_multiline(
                                    ui,
                                    "Replace",
                                    ("rewrite-replace", selected),
                                    &mut rule.replace_text,
                                    132.0,
                                );
                            } else {
                                ui.label("Create a rule to begin.");
                            }
                        },
                    );
                });
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    if ui.button("Close").clicked() {
                        self.dialog = None;
                    }
                    if ui.button("Save").clicked() {
                        self.save_rewrite_rules();
                    }
                });
            });
    }

    fn certificates_dialog(&mut self, ui: &mut Ui) {
        egui::Window::new("Certificate Manager")
            .collapsible(false).resizable(false).default_size([500.0, 245.0])
            .show(ui.ctx(), |ui| {
                ui.label(RichText::new("HTTP Whisper Local Certificate Authority").strong());
                ui.add_space(5.0);
                match AppPaths::discover() {
                    Ok(paths) => {
                        let cert = paths.certificates_dir.join("rust-mitm").join("http-whisper-ca.cer");
                        ui.label(format!("Certificate: {}", cert.display()));
                        ui.label(format!("Status: {}", self.ca_state));
                        ui.label("Proxy certificate page: http://mitm.it/");
                        ui.add_space(8.0);
                        #[cfg(windows)]
                        if ui.button("Install / Repair Trust").clicked() {
                            let result = load_or_create_ca(paths.certificates_dir.join("rust-mitm"))
                                .and_then(|files| install_current_user_ca(&files.certificate_der))
                                .and_then(|_| install_firefox_support());
                            match result {
                                Ok(()) => { self.ca_state = "Trusted".into(); self.status = "CA trust and Firefox integration installed".into(); }
                                Err(error) => { self.errors += 1; self.status = error.to_string(); }
                            }
                        }
                        #[cfg(not(windows))]
                        ui.label("Start capture and install the CA from http://mitm.it/ in your browser or Linux trust store.");
                    }
                    Err(error) => { ui.label(error.to_string()); }
                }
                ui.add_space(8.0);
                ui.label("Start capture, then open http://mitm.it/ in Firefox to download the CA if manual import is needed.");
                ui.label("The private key stays in your local application data directory. Only inspect traffic you own or are authorized to inspect.");
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    if ui.button("OK").clicked() { self.dialog = None; }
                });
            });
    }

    fn about_dialog(&mut self, ui: &mut Ui) {
        egui::Window::new("About HTTP Whisper")
            .collapsible(false)
            .resizable(false)
            .default_size([410.0, 190.0])
            .show(ui.ctx(), |ui| {
                ui.vertical_centered(|ui| {
                    ui.add_space(10.0);
                    ui.heading("HTTP Whisper");
                    ui.label("Version 0.8.0");
                    ui.add_space(8.0);
                    ui.label("Native Rust HTTP/HTTPS and WebSocket debugging workbench");
                    ui.label("Classic Windows XP interface");
                    ui.add_space(12.0);
                    if ui.button("OK").clicked() {
                        self.dialog = None;
                    }
                });
            });
    }
}

impl eframe::App for HttpWhisperApp {
    fn logic(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        if std::mem::take(&mut self.auto_connect_pending) {
            self.start_capture();
        }
        self.poll_events();
        self.poll_bypass_connections(false);
        self.persist_analysis_state(false);
        if self.worker.as_ref().is_some_and(CaptureWorker::is_running) {
            ctx.request_repaint_after(Duration::from_millis(50));
        } else if self.settings.bypass_radar_enabled {
            ctx.request_repaint_after(Duration::from_millis(500));
        }
    }

    fn ui(&mut self, ui: &mut Ui, _frame: &mut eframe::Frame) {
        let viewport_rect = ui.max_rect();
        Frame::new()
            .fill(XP_BG)
            .inner_margin(Margin::ZERO)
            .show(ui, |ui| {
                self.top_menu(ui);
                self.toolbar(ui);
                ui.add_space(5.0);
                Frame::new()
                    .inner_margin(Margin::symmetric(6, 0))
                    .show(ui, |ui| {
                        self.overview(ui);
                    });
                ui.add_space(4.0);
                Frame::new()
                    .inner_margin(Margin::symmetric(6, 0))
                    .show(ui, |ui| self.filter_bar(ui));
                ui.add_space(5.0);
                let available = Rect::from_min_max(
                    egui::pos2(viewport_rect.left() + 6.0, ui.cursor().top()),
                    egui::pos2(viewport_rect.right() - 6.0, viewport_rect.bottom()),
                );
                let status_height = 24.0;
                let inspector_height = (available.height() * 0.38).clamp(115.0, 190.0);
                let table_bottom = available.bottom() - inspector_height - status_height - 10.0;
                let table_rect =
                    Rect::from_min_max(available.min, egui::pos2(available.right(), table_bottom));
                let inspector_rect = Rect::from_min_max(
                    egui::pos2(available.left(), table_bottom + 5.0),
                    egui::pos2(available.right(), available.bottom() - status_height - 5.0),
                );
                let status_rect = Rect::from_min_max(
                    egui::pos2(available.left(), available.bottom() - status_height),
                    available.max,
                );
                ui.scope_builder(UiBuilder::new().max_rect(table_rect), |ui| {
                    ui.set_clip_rect(table_rect);
                    self.session_table(ui, table_rect.height());
                });
                ui.scope_builder(UiBuilder::new().max_rect(inspector_rect), |ui| {
                    ui.set_clip_rect(inspector_rect);
                    self.inspector(ui);
                });
                ui.scope_builder(UiBuilder::new().max_rect(status_rect), |ui| {
                    ui.set_clip_rect(status_rect);
                    self.status_bar(ui);
                });
                ui.advance_cursor_after_rect(available);
            });
        self.show_dialog(ui);
    }

    fn on_exit(&mut self, _gl: Option<&eframe::glow::Context>) {
        self.persist_analysis_state(true);
        if let Some(mut worker) = self.worker.take() {
            worker.join();
        }
    }

    fn clear_color(&self, _visuals: &egui::Visuals) -> [f32; 4] {
        XP_BG.to_normalized_gamma_f32()
    }
}

fn add_context_findings(
    threat: &mut ThreatAssessment,
    behavior: &BehaviorAssessment,
    guard: &GuardAssessment,
    signature_valid: Option<bool>,
    process: &str,
) {
    if behavior.is_unusual() {
        threat.add_finding(
            30,
            "Learned application behavior changed",
            behavior
                .changes
                .iter()
                .take(3)
                .cloned()
                .collect::<Vec<_>>()
                .join("; "),
        );
    }
    if !guard.findings.is_empty() {
        let score = match guard.action {
            GuardAction::None => 0,
            GuardAction::Warned => 20,
            GuardAction::Redacted => 35,
            GuardAction::Blocked => 50,
        };
        if score > 0 {
            threat.add_finding(
                score,
                format!("Exfiltration guard {} outbound data", guard.action.label()),
                guard
                    .findings
                    .iter()
                    .map(|finding| format!("{} at {}", finding.category, finding.location))
                    .collect::<Vec<_>>()
                    .join("; "),
            );
        }
    }
    if signature_valid == Some(false) && !process.is_empty() {
        threat.add_finding(
            12,
            "Executable signature is missing or invalid",
            format!("{process} did not pass local Authenticode verification"),
        );
    }
}

fn spawn_background<F, Fut>(name: &'static str, task: F)
where
    F: FnOnce() -> Fut + Send + 'static,
    Fut: Future<Output = ()> + Send + 'static,
{
    let _ = thread::Builder::new().name(name.into()).spawn(move || {
        if let Ok(runtime) = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
        {
            runtime.block_on(task());
        }
    });
}

fn read_only_text(
    ui: &mut Ui,
    id: impl std::hash::Hash + std::fmt::Debug,
    text: &str,
    height: f32,
) {
    let mut value = text.to_owned();
    ScrollArea::both().id_salt(id).show(ui, |ui| {
        ui.add_sized(
            [ui.available_width(), height.max(100.0)],
            TextEdit::multiline(&mut value)
                .font(FontId::monospace(12.0))
                .desired_width(f32::INFINITY)
                .interactive(false),
        );
    });
}

fn value_or_unknown(value: &str) -> &str {
    if value.is_empty() { "<unknown>" } else { value }
}

fn workbench_window_sizes(screen: Vec2) -> (Vec2, Vec2) {
    let default_size = Vec2::new(
        (screen.x - 32.0).clamp(620.0, 980.0),
        (screen.y - 72.0).clamp(360.0, 620.0),
    );
    let minimum_size = Vec2::new(default_size.x.min(760.0), default_size.y.min(480.0));
    (default_size, minimum_size)
}

fn configure_theme(ctx: &egui::Context) {
    let mut fonts = FontDefinitions::default();
    if let Ok(bytes) = fs::read(r"C:\Windows\Fonts\tahoma.ttf") {
        fonts
            .font_data
            .insert("Tahoma".into(), FontData::from_owned(bytes).into());
        fonts
            .families
            .entry(FontFamily::Proportional)
            .or_default()
            .insert(0, "Tahoma".into());
    }
    if let Ok(bytes) = fs::read(r"C:\Windows\Fonts\consola.ttf") {
        fonts
            .font_data
            .insert("Consolas".into(), FontData::from_owned(bytes).into());
        fonts
            .families
            .entry(FontFamily::Monospace)
            .or_default()
            .insert(0, "Consolas".into());
    }
    ctx.set_fonts(fonts);
    let mut style = (*ctx.style_of(egui::Theme::Light)).clone();
    style.spacing.item_spacing = Vec2::new(6.0, 4.0);
    style.spacing.button_padding = Vec2::new(8.0, 4.0);
    style.visuals = egui::Visuals::light();
    style.visuals.panel_fill = XP_BG;
    style.visuals.window_fill = XP_BG;
    style.visuals.extreme_bg_color = XP_WHITE;
    style.visuals.selection.bg_fill = XP_BLUE;
    style.visuals.selection.stroke = Stroke::new(1.0, XP_WHITE);
    style.visuals.widgets.inactive.bg_fill = XP_BUTTON;
    style.visuals.widgets.inactive.fg_stroke = Stroke::new(1.0, XP_TEXT);
    style.visuals.widgets.hovered.bg_fill = Color32::from_rgb(225, 233, 250);
    style.visuals.widgets.active.bg_fill = Color32::from_rgb(196, 210, 238);
    style.visuals.widgets.noninteractive.bg_fill = XP_BG;
    style.text_styles.insert(
        egui::TextStyle::Body,
        FontId::new(12.0, FontFamily::Proportional),
    );
    style.text_styles.insert(
        egui::TextStyle::Button,
        FontId::new(12.0, FontFamily::Proportional),
    );
    style.text_styles.insert(
        egui::TextStyle::Small,
        FontId::new(11.0, FontFamily::Proportional),
    );
    ctx.set_style_of(egui::Theme::Light, style);
    ctx.set_theme(egui::ThemePreference::Light);
}

fn toolbar_button(text: &'static str) -> egui::Button<'static> {
    egui::Button::new(RichText::new(text).strong()).min_size(Vec2::new(88.0, 25.0))
}

fn metric(ui: &mut Ui, label: &str, value: &str, width: f32) {
    group_box(ui, label, Vec2::new(width, 49.0), |ui| {
        Frame::new()
            .fill(XP_WHITE)
            .inner_margin(Margin::symmetric(5, 4))
            .show(ui, |ui| {
                ui.set_width(width - 18.0);
                ui.vertical_centered(|ui| {
                    ui.add(egui::Label::new(RichText::new(value).strong()).truncate());
                });
            });
    });
}

fn group_box<R>(ui: &mut Ui, title: &str, size: Vec2, add: impl FnOnce(&mut Ui) -> R) -> R {
    ui.allocate_ui_with_layout(size, Layout::top_down(Align::Min), |ui| {
        ui.set_min_size(size);
        Frame::new()
            .fill(XP_BG)
            .stroke(Stroke::new(1.0, Color32::from_rgb(160, 160, 160)))
            .inner_margin(Margin::symmetric(7, 6))
            .show(ui, |ui| {
                ui.set_min_size(size - Vec2::new(14.0, 12.0));
                ui.label(RichText::new(title).strong().small());
                add(ui)
            })
            .inner
    })
    .inner
}

fn fixed_group_box<R>(ui: &mut Ui, title: &str, size: Vec2, add: impl FnOnce(&mut Ui) -> R) -> R {
    let (rect, _) = ui.allocate_exact_size(size, egui::Sense::hover());
    ui.scope_builder(
        UiBuilder::new()
            .max_rect(rect)
            .layout(Layout::top_down(Align::Min)),
        |ui| {
            ui.set_clip_rect(rect);
            ui.set_max_size(size);
            Frame::new()
                .fill(XP_BG)
                .stroke(Stroke::new(1.0, Color32::from_rgb(160, 160, 160)))
                .inner_margin(Margin::symmetric(7, 6))
                .show(ui, |ui| {
                    ui.set_width((size.x - 14.0).max(1.0));
                    ui.set_max_height((size.y - 12.0).max(1.0));
                    ui.label(RichText::new(title).strong().small());
                    add(ui)
                })
                .inner
        },
    )
    .inner
}

fn rule_form_row(ui: &mut Ui, label: &str, add: impl FnOnce(&mut Ui)) {
    ui.horizontal(|ui| {
        ui.add_sized([82.0, 22.0], egui::Label::new(label));
        ui.allocate_ui_with_layout(
            Vec2::new(ui.available_width(), 22.0),
            Layout::left_to_right(Align::Center),
            add,
        );
    });
}

fn rule_form_multiline(
    ui: &mut Ui,
    label: &str,
    id_salt: impl std::hash::Hash + std::fmt::Debug,
    text: &mut String,
    height: f32,
) {
    ui.horizontal_top(|ui| {
        ui.add_sized([82.0, 22.0], egui::Label::new(label));
        ui.allocate_ui_with_layout(
            Vec2::new(ui.available_width(), height),
            Layout::top_down(Align::Min),
            |ui| {
                scrollable_text_editor(ui, id_salt, text, height);
            },
        );
    });
}

fn scrollable_text_editor(
    ui: &mut Ui,
    id_salt: impl std::hash::Hash + std::fmt::Debug,
    text: &mut String,
    height: f32,
) -> bool {
    ScrollArea::vertical()
        .id_salt(id_salt)
        .max_height(height)
        .min_scrolled_height(height)
        .auto_shrink([false, false])
        .show(ui, |ui| {
            ui.add(
                TextEdit::multiline(text)
                    .font(FontId::monospace(12.0))
                    .desired_width(f32::INFINITY)
                    .desired_rows(4),
            )
        })
        .inner
        .changed()
}

fn compact_rule_text(text: &str) -> String {
    const LIMIT: usize = 24;
    let mut preview: String = text.chars().take(LIMIT).collect();
    if text.chars().count() > LIMIT {
        preview.push_str("...");
    }
    preview.replace(['\r', '\n'], " ")
}

fn parse_hidden_hosts(text: &str) -> Vec<String> {
    text.lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(str::to_owned)
        .collect()
}

fn threat_indicator(ui: &mut Ui, threat: &ThreatAssessment) {
    if !threat.is_warning() {
        return;
    }
    let (fill, border) = if threat.level == ThreatLevel::High {
        (Color32::from_rgb(255, 185, 70), XP_DANGER)
    } else {
        (Color32::from_rgb(255, 225, 70), XP_WARNING)
    };
    let (rect, response) = ui.allocate_exact_size(Vec2::new(17.0, 17.0), egui::Sense::hover());
    let center = rect.center();
    let points = vec![
        egui::pos2(center.x, rect.top() + 1.0),
        egui::pos2(rect.right() - 1.0, rect.bottom() - 1.0),
        egui::pos2(rect.left() + 1.0, rect.bottom() - 1.0),
    ];
    ui.painter().add(egui::Shape::convex_polygon(
        points,
        fill,
        Stroke::new(1.5, border),
    ));
    ui.painter().text(
        center + egui::vec2(0.0, 2.0),
        egui::Align2::CENTER_CENTER,
        "!",
        FontId::proportional(12.0),
        XP_TEXT,
    );
    response.on_hover_text(threat.tooltip());
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct TableCellColors {
    row: Option<Color32>,
    host: Option<Color32>,
    status: Option<Color32>,
}

impl TableCellColors {
    fn for_value_column(self, index: usize) -> Option<Color32> {
        match index {
            8 => self.host.or(self.row),
            11 => self.status.or(self.row),
            _ => self.row,
        }
    }
}

fn table_cell_colors(
    settings: &AppSettings,
    session: &Session,
    is_selected: bool,
) -> TableCellColors {
    if is_selected {
        return TableCellColors::default();
    }
    let mut colors = TableCellColors::default();
    for rule in settings
        .table_color_rules
        .iter()
        .filter(|rule| rule.enabled && table_color_rule_matches(rule, session))
    {
        let color = Color32::from_rgb(rule.color[0], rule.color[1], rule.color[2]);
        match (rule.target, rule.field) {
            (TableColorTarget::EntireRow, _) => colors.row = Some(color),
            (TableColorTarget::MatchedColumn, TableColorField::Host) => {
                colors.host = Some(color);
            }
            (TableColorTarget::MatchedColumn, TableColorField::StatusCode) => {
                colors.status = Some(color);
            }
        }
    }
    colors
}

fn table_color_rule_matches(rule: &TableColorRule, session: &Session) -> bool {
    match rule.field {
        TableColorField::Host => {
            let host = match session {
                Session::Http(exchange) => &exchange.request.host,
                Session::WebSocket(message) => &message.host,
            };
            pattern_matches(rule.pattern.trim(), host, false)
        }
        TableColorField::StatusCode => {
            let Session::Http(exchange) = session else {
                return false;
            };
            exchange.response.as_ref().is_some_and(|response| {
                status_pattern_matches(rule.pattern.trim(), response.status)
            })
        }
    }
}

fn status_pattern_matches(pattern: &str, status: u16) -> bool {
    let bytes = pattern.as_bytes();
    if bytes.len() == 3
        && bytes[0].is_ascii_digit()
        && bytes[1].eq_ignore_ascii_case(&b'x')
        && bytes[2].eq_ignore_ascii_case(&b'x')
    {
        return u16::from(bytes[0] - b'0') == status / 100;
    }
    pattern_matches(pattern, &status.to_string(), false)
}

fn paint_table_cell(ui: &mut Ui, color: Option<Color32>) {
    let Some(color) = color else { return };
    let rect = ui
        .max_rect()
        .expand2(ui.spacing().item_spacing * 0.5)
        .intersect(ui.clip_rect());
    ui.painter()
        .rect_filled(rect, egui::CornerRadius::ZERO, color);
}

fn inverse_color(color: Color32) -> Color32 {
    Color32::from_rgb(255 - color.r(), 255 - color.g(), 255 - color.b())
}

fn highlight_preview(ui: &mut Ui, label: &str, color: [u8; 3]) {
    let (rect, _) =
        ui.allocate_exact_size(Vec2::new(ui.available_width(), 24.0), egui::Sense::hover());
    let fill = Color32::from_rgb(color[0], color[1], color[2]);
    ui.painter()
        .rect_filled(rect, egui::CornerRadius::ZERO, fill);
    ui.painter().rect_stroke(
        rect,
        egui::CornerRadius::ZERO,
        Stroke::new(1.0, XP_BORDER),
        egui::StrokeKind::Inside,
    );
    ui.painter().text(
        rect.left_center() + egui::vec2(6.0, 0.0),
        egui::Align2::LEFT_CENTER,
        label,
        FontId::proportional(12.0),
        inverse_color(fill),
    );
}

fn row_values(session: &Session) -> Vec<String> {
    match session {
        Session::Http(exchange) => {
            let request = &exchange.request;
            let response = exchange.response.as_ref();
            vec![
                "HTTP".into(),
                exchange.sequence.to_string(),
                request.timestamp.format("%H:%M:%S%.3f").to_string(),
                String::new(),
                request.process.clone(),
                request
                    .pid
                    .map(|value| value.to_string())
                    .unwrap_or_default(),
                request.method.clone(),
                request.scheme.clone(),
                request.host.clone(),
                request.port.to_string(),
                request.path.clone(),
                response
                    .map(|value| value.status.to_string())
                    .unwrap_or_default(),
                response
                    .and_then(CapturedResponse::content_type)
                    .unwrap_or("")
                    .into(),
                format_size(request.body.len()),
                response
                    .map(|value| format_size(value.body.len()))
                    .unwrap_or_default(),
                response
                    .map(|value| format!("{:.0} ms", value.duration_ms))
                    .unwrap_or_default(),
                exchange.rule_matched.clone().unwrap_or_default(),
                exchange.error.clone().unwrap_or_default(),
            ]
        }
        Session::WebSocket(message) => vec![
            "WS".into(),
            message.sequence.to_string(),
            message.timestamp.format("%H:%M:%S%.3f").to_string(),
            message.direction.label().into(),
            message.process.clone(),
            message
                .pid
                .map(|value| value.to_string())
                .unwrap_or_default(),
            message.opcode.clone(),
            if message.url.starts_with("wss:") {
                "wss"
            } else {
                "ws"
            }
            .into(),
            message.host.clone(),
            String::new(),
            message.path.clone(),
            String::new(),
            message.decoded_as.clone(),
            String::new(),
            format_size(message.raw_size),
            String::new(),
            message.rule_matched.clone().unwrap_or_default(),
            String::new(),
        ],
    }
}

fn http_inspector(exchange: &CapturedExchange, tab: usize) -> String {
    let request = &exchange.request;
    let response = exchange.response.as_ref();
    let request_body = body_preview(&request.body, request.content_type());
    let response_body = response
        .map(|value| body_preview(&value.body, value.content_type()))
        .unwrap_or_else(|| "<none>".into());
    let request_headers = headers_as_text(&request.headers);
    let response_headers = response
        .map(|value| headers_as_text(&value.headers))
        .unwrap_or_default();
    match tab {
        0 => format!("{} {}\nStatus: {}\nDuration: {:.0} ms\nState: {}\nProcess: {}\nPID: {}\nRisk: {} ({}/100)", request.method, request.url(), response.map(|value| value.status.to_string()).unwrap_or_else(|| "pending".into()), response.map(|value| value.duration_ms).unwrap_or_default(), if exchange.synthetic { "Synthetic" } else { "Completed" }, if request.process.is_empty() { "<unknown>" } else { &request.process }, request.pid.map(|pid| pid.to_string()).unwrap_or_else(|| "<unknown>".into()), exchange.threat.level.label(), exchange.threat.score),
        1 => format!("Method: {}\nURL: {}\nHTTP Version: {}\nClient: {}\nProcess: {}\nExecutable: {}\nPID: {}\nBody Size: {} bytes\n\nBody\n{}", request.method, request.url(), request.version, request.client_addr, if request.process.is_empty() { "<unknown>" } else { &request.process }, if request.process_path.is_empty() { "<unknown>" } else { &request.process_path }, request.pid.map(|pid| pid.to_string()).unwrap_or_else(|| "<unknown>".into()), request.body.len(), request_body),
        2 => response.map(|value| format!("Status: {} {}\nHTTP Version: {}\nDuration: {:.0} ms\nContent-Type: {}\nBody Size: {} bytes\n\nBody\n{}", value.status, value.reason, value.version, value.duration_ms, value.content_type().unwrap_or("<unknown>"), value.body.len(), response_body)).unwrap_or_else(|| "No response captured yet".into()),
        3 => format!("Request headers\n{}\n\nResponse headers\n{}", request_headers, response_headers),
        4 => format!("{} {} {}\n{}\n\n{}\n\nResponse\n{}\n\n{}", request.method, request.path, request.version, request_headers, request_body, response_headers, response_body),
        _ => exchange.notes.clone(),
    }
}

fn websocket_inspector(message: &WebSocketMessage, tab: usize) -> String {
    match tab {
        0 => format!(
            "WebSocket {} {}\nOpcode: {}\nSize: {} bytes\nProcess: {}\nPID: {}\nRisk: {} ({}/100)",
            message.direction.label(),
            message.url,
            message.opcode,
            message.raw_size,
            if message.process.is_empty() {
                "<unknown>"
            } else {
                &message.process
            },
            message
                .pid
                .map(|pid| pid.to_string())
                .unwrap_or_else(|| "<unknown>".into()),
            message.threat.level.label(),
            message.threat.score
        ),
        1 => format!(
            "URL: {}\nHost: {}\nPath: {}\nDirection: {}\nProcess: {}\nExecutable: {}\nPID: {}",
            message.url,
            message.host,
            message.path,
            message.direction.label(),
            if message.process.is_empty() {
                "<unknown>"
            } else {
                &message.process
            },
            if message.process_path.is_empty() {
                "<unknown>"
            } else {
                &message.process_path
            },
            message
                .pid
                .map(|pid| pid.to_string())
                .unwrap_or_else(|| "<unknown>".into())
        ),
        2 => format!(
            "WebSocket Message\nDirection: {}\nOpcode: {}\nDecoded As: {}\nRule: {}\nSize: {} bytes\n\nPayload\n{}",
            message.direction.label(),
            message.opcode,
            message.decoded_as,
            message.rule_matched.as_deref().unwrap_or("<none>"),
            message.raw_size,
            message.payload
        ),
        3 => "WebSocket message rows do not have HTTP headers".into(),
        4 => message.payload.clone(),
        _ => String::new(),
    }
}

fn threat_inspector(threat: &ThreatAssessment) -> String {
    if threat.findings.is_empty() {
        return "Risk: None\nScore: 0/100\n\nNo suspicious indicators detected for this session."
            .into();
    }
    let findings = threat
        .findings
        .iter()
        .map(|finding| {
            format!(
                "+{}  {}\n     {}",
                finding.score, finding.title, finding.evidence
            )
        })
        .collect::<Vec<_>>()
        .join("\n\n");
    format!(
        "Risk: {}\nScore: {}/100\n\nObserved indicators\n{}\n\nWarnings are heuristic evidence, not confirmation that software is malicious.",
        threat.level.label(),
        threat.score,
        findings
    )
}

fn body_preview(body: &[u8], content_type: Option<&str>) -> String {
    if body.is_empty() {
        return "<empty>".into();
    }
    if let Ok(text) = std::str::from_utf8(body) {
        if content_type.is_some_and(|value| value.to_ascii_lowercase().contains("json"))
            && let Ok(value) = serde_json::from_str::<serde_json::Value>(text)
        {
            return serde_json::to_string_pretty(&value).unwrap_or_else(|_| text.into());
        }
        return text.chars().take(1_000_000).collect();
    }
    format!(
        "Binary body ({} bytes)\n{}",
        body.len(),
        hex::encode(&body[..body.len().min(4096)])
    )
}

fn format_size(bytes: usize) -> String {
    if bytes >= 1_048_576 {
        format!("{:.1} MB", bytes as f64 / 1_048_576.0)
    } else if bytes >= 1024 {
        format!("{:.1} KB", bytes as f64 / 1024.0)
    } else {
        format!("{bytes} B")
    }
}

fn sample_sessions() -> Vec<Session> {
    let now = Utc::now();
    let examples = [
        (
            "GET",
            "https",
            "api.example.com",
            443,
            "/api/version",
            200,
            "application/json",
        ),
        (
            "POST",
            "https",
            "api.example.com",
            443,
            "/api/login",
            200,
            "application/json",
        ),
        (
            "GET",
            "http",
            "localhost",
            8080,
            "/health",
            204,
            "text/plain",
        ),
        (
            "PUT",
            "https",
            "storage.example.com",
            443,
            "/v1/files/report.pdf",
            403,
            "application/json",
        ),
    ];
    examples
        .into_iter()
        .enumerate()
        .map(
            |(index, (method, scheme, host, port, path, status, content_type))| {
                Session::Http(CapturedExchange {
                    id: Uuid::new_v4(),
                    sequence: index as u64 + 1,
                    request: CapturedRequest {
                        method: method.into(),
                        scheme: scheme.into(),
                        host: host.into(),
                        port,
                        path: path.into(),
                        version: "HTTP/2.0".into(),
                        headers: vec![
                            Header {
                                name: "Host".into(),
                                value: host.into(),
                            },
                            Header {
                                name: "User-Agent".into(),
                                value: "HTTP Whisper Demo".into(),
                            },
                            Header {
                                name: "Content-Type".into(),
                                value: content_type.into(),
                            },
                            Header {
                                name: "Authorization".into(),
                                value: "Bearer demo-token-value".into(),
                            },
                        ],
                        body: Vec::new(),
                        timestamp: now + TimeDelta::milliseconds((index as i64 + 1) * 120),
                        client_addr: format!("127.0.0.1:{}", 50_001 + index),
                        process: "chrome.exe".into(),
                        process_path: r"C:\Program Files\Google\Chrome\Application\chrome.exe"
                            .into(),
                        pid: Some(4301 + index as u32),
                        provenance: Default::default(),
                        guard: Default::default(),
                    },
                    response: Some(CapturedResponse {
                        status,
                        reason: if status < 400 { "OK" } else { "Forbidden" }.into(),
                        version: "HTTP/2.0".into(),
                        headers: vec![Header {
                            name: "Content-Type".into(),
                            value: content_type.into(),
                        }],
                        body: Vec::new(),
                        duration_ms: 53.0 + index as f64 * 18.0,
                    }),
                    rule_matched: (index == 1).then(|| "Mock login".into()),
                    error: None,
                    synthetic: index == 1,
                    pinned: false,
                    notes: String::new(),
                    threat: ThreatAssessment::default(),
                    behavior: Default::default(),
                })
            },
        )
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn disallowed_domains_are_parsed_only_when_saved() {
        let draft = "one.example.com\n\n  two.example.com  \n";
        assert_eq!(
            parse_hidden_hosts(draft),
            vec!["one.example.com", "two.example.com"]
        );
    }

    #[test]
    fn fixed_rule_dialog_does_not_grow_between_frames() {
        let context = egui::Context::default();
        let mut text = "a very long response body\n".repeat(500);
        let mut sizes = Vec::new();

        for frame in 0..8 {
            let input = egui::RawInput {
                screen_rect: Some(Rect::from_min_size(
                    egui::Pos2::ZERO,
                    Vec2::new(1200.0, 800.0),
                )),
                time: Some(frame as f64 / 60.0),
                ..Default::default()
            };
            let mut size = Vec2::ZERO;
            let _ = context.run_ui(input, |ui| {
                let window = egui::Window::new("Rule Layout Test")
                    .collapsible(false)
                    .resizable(false)
                    .fixed_size([760.0, 480.0])
                    .show(ui.ctx(), |ui| {
                        ui.horizontal_top(|ui| {
                            fixed_group_box(ui, "Rules", Vec2::new(225.0, 390.0), |_| {});
                            ui.add_space(8.0);
                            fixed_group_box(ui, "Selected Rule", Vec2::new(510.0, 390.0), |ui| {
                                scrollable_text_editor(ui, "layout-test-editor", &mut text, 145.0);
                            });
                        });
                    })
                    .expect("rule window should be visible");
                size = window.response.rect.size();
            });
            sizes.push(size);
        }

        let stable_size = sizes[2];
        for size in &sizes[3..] {
            assert_eq!(*size, stable_size);
        }
    }

    #[test]
    fn workbench_size_stays_inside_a_high_dpi_logical_screen() {
        let screen = Vec2::new(864.0, 486.0);
        let (default_size, minimum_size) = workbench_window_sizes(screen);
        assert_eq!(default_size, Vec2::new(832.0, 414.0));
        assert_eq!(minimum_size, Vec2::new(760.0, 414.0));
        assert!(default_size.x + 32.0 <= screen.x);
        assert!(default_size.y + 72.0 <= screen.y);
    }

    #[test]
    fn warning_risk_does_not_color_rows() {
        let mut settings = AppSettings::default();
        let mut session = sample_sessions().remove(0);
        if let Session::Http(exchange) = &mut session {
            exchange.threat.level = ThreatLevel::High;
        }
        settings.table_color_rules.clear();
        assert_eq!(
            table_cell_colors(&settings, &session, false),
            TableCellColors::default()
        );
    }

    #[test]
    fn table_colors_match_status_host_scope_and_selection() {
        let mut session = sample_sessions().remove(3);
        let settings = AppSettings::default();
        let colors = table_cell_colors(&settings, &session, false);
        assert_eq!(colors.row, None);
        assert_eq!(colors.status, Some(Color32::from_rgb(255, 241, 184)));
        assert_eq!(colors.host, None);

        let custom = AppSettings {
            table_color_rules: vec![TableColorRule {
                field: TableColorField::Host,
                pattern: "re:^storage\\.example\\.com$".into(),
                target: TableColorTarget::EntireRow,
                color: [1, 2, 3],
                ..Default::default()
            }],
            ..Default::default()
        };
        assert_eq!(
            table_cell_colors(&custom, &session, false).row,
            Some(Color32::from_rgb(1, 2, 3))
        );
        assert_eq!(
            table_cell_colors(&custom, &session, true),
            TableCellColors::default()
        );

        if let Session::Http(exchange) = &mut session
            && let Some(response) = &mut exchange.response
        {
            response.status = 503;
        }
        let colors = table_cell_colors(&settings, &session, false);
        assert_eq!(colors.row, Some(Color32::from_rgb(255, 218, 218)));
    }

    #[test]
    fn status_patterns_support_classes_wildcards_and_regex() {
        assert!(status_pattern_matches("4xx", 404));
        assert!(status_pattern_matches("5*", 503));
        assert!(status_pattern_matches("re:^20[01]$", 201));
        assert!(!status_pattern_matches("4xx", 500));
    }

    #[test]
    fn table_text_color_is_the_exact_rgb_inverse() {
        assert_eq!(inverse_color(Color32::BLACK), Color32::WHITE);
        assert_eq!(inverse_color(Color32::WHITE), Color32::BLACK);
        assert_eq!(
            inverse_color(Color32::from_rgb(1, 2, 3)),
            Color32::from_rgb(254, 253, 252)
        );
        assert_eq!(
            inverse_color(Color32::from_rgb(255, 218, 218)),
            Color32::from_rgb(0, 37, 37)
        );
    }
}
