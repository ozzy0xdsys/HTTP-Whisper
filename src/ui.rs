use std::{fs, sync::mpsc, thread, time::Duration};

use chrono::{TimeDelta, Utc};
use eframe::egui::{
    self, Align, Color32, CornerRadius, FontData, FontDefinitions, FontFamily, FontId, Frame,
    Layout, Margin, Rect, RichText, ScrollArea, Stroke, TextEdit, Ui, UiBuilder, Vec2,
};
use egui_extras::{Column, TableBuilder};
use uuid::Uuid;

use crate::{
    capture::CaptureWorker,
    certificate::{install_current_user_ca, load_or_create_ca},
    config::{AppPaths, AppSettings, AutoResponseRule, ResponseRewriteRule},
    filtering::matches_filter,
    model::{
        CaptureEvent, CapturedExchange, CapturedRequest, CapturedResponse, Header, Session,
        WebSocketMessage, headers_as_text,
    },
    storage::SessionRepository,
    windows_proxy::{configure_startup, install_firefox_support},
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct UiPalette {
    background: Color32,
    panel: Color32,
    toolbar: Color32,
    surface: Color32,
    button: Color32,
    border: Color32,
    accent: Color32,
    text: Color32,
    hover: Color32,
    active: Color32,
}

fn ui_palette(style: &str) -> UiPalette {
    if style == "classic" {
        UiPalette {
            background: Color32::from_rgb(236, 233, 216),
            panel: Color32::from_rgb(236, 233, 216),
            toolbar: Color32::from_rgb(214, 223, 247),
            surface: Color32::WHITE,
            button: Color32::from_rgb(236, 233, 216),
            border: Color32::from_rgb(127, 157, 185),
            accent: Color32::from_rgb(49, 106, 197),
            text: Color32::BLACK,
            hover: Color32::from_rgb(225, 233, 250),
            active: Color32::from_rgb(196, 210, 238),
        }
    } else {
        UiPalette {
            background: Color32::from_rgb(228, 233, 241),
            panel: Color32::from_rgb(243, 246, 250),
            toolbar: Color32::from_rgb(235, 240, 247),
            surface: Color32::from_rgb(255, 255, 255),
            button: Color32::from_rgb(246, 248, 251),
            border: Color32::from_rgb(143, 156, 175),
            accent: Color32::from_rgb(35, 91, 174),
            text: Color32::from_rgb(29, 36, 48),
            hover: Color32::from_rgb(224, 234, 248),
            active: Color32::from_rgb(63, 112, 184),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum DialogKind {
    Settings,
    AutoResponses,
    ResponseRewrites,
    Certificates,
    About,
}

pub struct HttpWhisperApp {
    settings: AppSettings,
    settings_draft: AppSettings,
    hidden_hosts_draft: String,
    auto_draft: Vec<AutoResponseRule>,
    auto_selected: usize,
    rewrite_draft: Vec<ResponseRewriteRule>,
    rewrite_selected: usize,
    events_tx: mpsc::Sender<CaptureEvent>,
    events_rx: mpsc::Receiver<CaptureEvent>,
    repository: Option<SessionRepository>,
    worker: Option<CaptureWorker>,
    auto_connect_pending: bool,
    applied_interface_style: String,
    sessions: Vec<Session>,
    selected: Option<Uuid>,
    filter: String,
    tab: usize,
    dialog: Option<DialogKind>,
    state: String,
    ca_state: String,
    activity: String,
    status: String,
    errors: usize,
}

impl HttpWhisperApp {
    pub fn new(cc: &eframe::CreationContext<'_>, settings: AppSettings) -> Self {
        configure_theme(&cc.egui_ctx, &settings.interface_style);
        let auto_connect_pending = settings.auto_connect;
        let applied_interface_style = settings.interface_style.clone();
        let startup_error = configure_startup(settings.start_with_windows).err();
        let hidden_hosts_draft = settings.hidden_hosts.join("\n");
        let (events_tx, events_rx) = mpsc::channel();
        let repository = AppPaths::discover()
            .ok()
            .map(|paths| SessionRepository::new(paths.sessions_dir.join("sessions.db")))
            .and_then(|repository| repository.initialize().ok().map(|()| repository));
        Self {
            settings_draft: settings.clone(),
            hidden_hosts_draft,
            auto_draft: settings.auto_response_rules.clone(),
            rewrite_draft: settings.response_rewrite_rules.clone(),
            settings,
            auto_selected: 0,
            rewrite_selected: 0,
            events_tx,
            events_rx,
            repository,
            worker: None,
            auto_connect_pending,
            applied_interface_style,
            sessions: sample_sessions(),
            selected: None,
            filter: String::new(),
            tab: 0,
            dialog: None,
            state: "Idle".into(),
            ca_state: "Auto install".into(),
            activity: "Ready to start native Rust capture".into(),
            status: startup_error.map_or_else(
                || "Ready - local proxy 127.0.0.1:8899".into(),
                |error| format!("Windows startup setting could not be synchronized: {error}"),
            ),
            errors: 0,
        }
    }

    fn poll_events(&mut self) {
        while let Ok(event) = self.events_rx.try_recv() {
            match event {
                CaptureEvent::Starting => {
                    self.state = "Starting".into();
                    self.ca_state = "Installing".into();
                    self.activity = "Starting native proxy and preparing Windows settings".into();
                }
                CaptureEvent::Started { host, port } => {
                    self.state = "Capturing".into();
                    self.ca_state = "Trusted".into();
                    self.activity = format!("Native Rust proxy running on {host}:{port}");
                    self.status = "Capturing HTTP, HTTPS, and WebSocket traffic".into();
                }
                CaptureEvent::Log(message) => {
                    if message.contains("trusted") {
                        self.ca_state = "Trusted".into();
                    }
                    self.activity = message;
                }
                CaptureEvent::Exchange(exchange) => {
                    self.activity = exchange.request.url();
                    if let Some(repository) = &self.repository
                        && let Err(error) = repository.add_exchange(&exchange)
                    {
                        self.errors += 1;
                        self.status = format!("Could not save session: {error}");
                    }
                    self.push_session(Session::Http(exchange));
                }
                CaptureEvent::ReplayCompleted(exchange) => {
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
                    self.selected = Some(exchange.id);
                    if let Some(repository) = &self.repository
                        && let Err(error) = repository.add_exchange(&exchange)
                    {
                        self.errors += 1;
                        self.status = format!("Could not save replay: {error}");
                    }
                    self.push_session(Session::Http(exchange));
                }
                CaptureEvent::WebSocket(message) => {
                    self.activity =
                        format!("WebSocket {} {}", message.direction.label(), message.url);
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
    }

    fn start_capture(&mut self) {
        if self.worker.as_ref().is_some_and(CaptureWorker::is_running) {
            return;
        }
        self.sessions.clear();
        self.selected = None;
        self.errors = 0;
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

    fn stop_capture(&mut self) {
        if let Some(worker) = &mut self.worker {
            self.state = "Stopping".into();
            self.activity = "Restoring Windows and Firefox proxy settings".into();
            self.status = "Stopping native capture".into();
            worker.stop();
        }
    }

    fn open_dialog(&mut self, kind: DialogKind) {
        match kind {
            DialogKind::Settings => {
                self.settings_draft = self.settings.clone();
                self.hidden_hosts_draft = self.settings.hidden_hosts.join("\n");
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
                        self.status = format!(
                            "Settings saved, but Windows startup could not be updated: {error}"
                        );
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
        self.settings.auto_response_rules = self.auto_draft.clone();
        let count = self.auto_draft.iter().filter(|rule| rule.enabled).count();
        self.persist_settings(&format!("{count} auto response rule(s) enabled"));
    }

    fn save_rewrite_rules(&mut self) {
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
        let palette = ui_palette(&self.settings.interface_style);
        Frame::new()
            .fill(palette.panel)
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
        let palette = ui_palette(&self.settings.interface_style);
        let refined = self.settings.interface_style == "refined";
        Frame::new()
            .fill(palette.toolbar)
            .inner_margin(Margin::symmetric(6, 5))
            .stroke(Stroke::new(1.0, palette.border))
            .show(ui, |ui| {
                ui.horizontal(|ui| {
                    ui.spacing_mut().item_spacing.x = 5.0;
                    if refined {
                        ui.add_sized(
                            [112.0, 25.0],
                            egui::Label::new(
                                RichText::new("HTTP Whisper")
                                    .strong()
                                    .size(15.0)
                                    .color(palette.accent),
                            ),
                        );
                        ui.separator();
                    }
                    let running = self.worker.as_ref().is_some_and(CaptureWorker::is_running);
                    let start_button = if refined {
                        primary_toolbar_button("Start Capture", palette)
                    } else {
                        toolbar_button("Start Capture", palette)
                    };
                    if ui.add_enabled(!running, start_button).clicked() {
                        self.start_capture();
                    }
                    if ui
                        .add_enabled(running, toolbar_button("Stop", palette))
                        .clicked()
                    {
                        self.stop_capture();
                    }
                    if ui.add(toolbar_button("Replay", palette)).clicked() {
                        self.replay_selected();
                    }
                    if ui.add(toolbar_button("Auto Responses", palette)).clicked() {
                        self.open_dialog(DialogKind::AutoResponses);
                    }
                    if ui
                        .add(toolbar_button("Response Rewrites", palette))
                        .clicked()
                    {
                        self.open_dialog(DialogKind::ResponseRewrites);
                    }
                    if ui.add(toolbar_button("Certificates", palette)).clicked() {
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
            .fill(ui.visuals().extreme_bg_color)
            .stroke(ui.visuals().widgets.noninteractive.bg_stroke)
            .show(ui, |ui| {
                ui.set_height(height);
                ScrollArea::horizontal()
                    .id_salt("sessions-horizontal")
                    .max_height(height)
                    .show(ui, |ui| {
                        ui.set_min_width(1870.0);
                        let mut table = TableBuilder::new(ui)
                            .id_salt("sessions")
                            .striped(true)
                            .resizable(true)
                            .sense(egui::Sense::click())
                            .min_scrolled_height(60.0)
                            .max_scroll_height(height - 2.0);
                        for width in [
                            42.0, 45.0, 70.0, 40.0, 90.0, 48.0, 65.0, 55.0, 145.0, 52.0, 260.0,
                            55.0, 145.0, 70.0, 75.0, 70.0, 115.0, 150.0,
                        ] {
                            table =
                                table.column(Column::initial(width).at_least(38.0).resizable(true));
                        }
                        table
                            .header(22.0, |mut header| {
                                for title in [
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
                                    row.set_selected(self.selected == Some(id));
                                    for value in row_values(session) {
                                        row.col(|ui| {
                                            ui.add(egui::Label::new(value).truncate());
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
        let tabs = ["Overview", "Request", "Response", "Headers", "Raw", "Notes"];
        Frame::new()
            .fill(ui.visuals().panel_fill)
            .stroke(ui.visuals().widgets.noninteractive.bg_stroke)
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
        match session {
            Session::Http(exchange) => http_inspector(exchange, self.tab),
            Session::WebSocket(message) => websocket_inspector(message, self.tab),
        }
    }

    fn status_bar(&self, ui: &mut Ui) {
        Frame::new()
            .fill(ui.visuals().panel_fill)
            .stroke(ui.visuals().widgets.noninteractive.bg_stroke)
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
            DialogKind::About => self.about_dialog(ui),
        }
    }

    fn settings_dialog(&mut self, ui: &mut Ui) {
        egui::Window::new("Settings")
            .collapsible(false)
            .resizable(false)
            .fixed_size([500.0, 395.0])
            .show(ui.ctx(), |ui| {
                egui::Grid::new("settings-grid")
                    .num_columns(2)
                    .spacing([12.0, 8.0])
                    .show(ui, |ui| {
                        ui.label("Capture host");
                        ui.text_edit_singleline(&mut self.settings_draft.capture_host);
                        ui.end_row();
                        ui.label("Capture port");
                        ui.add(
                            egui::DragValue::new(&mut self.settings_draft.capture_port)
                                .range(1..=65535),
                        );
                        ui.end_row();
                        ui.label("HTTPS interception");
                        ui.checkbox(
                            &mut self.settings_draft.enable_https_interception,
                            "Enabled",
                        );
                        ui.end_row();
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
                        ui.label("On launch");
                        ui.checkbox(&mut self.settings_draft.auto_connect, "Auto-connect");
                        ui.end_row();
                        ui.label("Interface style");
                        ui.horizontal(|ui| {
                            ui.selectable_value(
                                &mut self.settings_draft.interface_style,
                                "refined".into(),
                                "Refined XP",
                            );
                            ui.selectable_value(
                                &mut self.settings_draft.interface_style,
                                "classic".into(),
                                "Classic XP",
                            );
                        });
                        ui.end_row();
                    });
                ui.separator();
                ui.label("Disallowed domains (one per line)");
                scrollable_text_editor(ui, "hidden-hosts", &mut self.hidden_hosts_draft, 70.0);
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
                        if ui.button("Install / Repair Trust").clicked() {
                            let result = load_or_create_ca(paths.certificates_dir.join("rust-mitm"))
                                .and_then(|files| install_current_user_ca(&files.certificate_der))
                                .and_then(|_| install_firefox_support());
                            match result {
                                Ok(()) => { self.ca_state = "Trusted".into(); self.status = "CA trust and Firefox integration installed".into(); }
                                Err(error) => { self.errors += 1; self.status = error.to_string(); }
                            }
                        }
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
                    ui.label("Version 0.5.0");
                    ui.add_space(8.0);
                    ui.label("Native Rust HTTP/HTTPS and WebSocket debugging workbench");
                    ui.label("Refined and Classic Windows XP interface styles");
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
        if self.applied_interface_style != self.settings.interface_style {
            configure_theme(ctx, &self.settings.interface_style);
            self.applied_interface_style = self.settings.interface_style.clone();
        }
        if std::mem::take(&mut self.auto_connect_pending) {
            self.start_capture();
        }
        self.poll_events();
        if self.worker.as_ref().is_some_and(CaptureWorker::is_running) {
            ctx.request_repaint_after(Duration::from_millis(50));
        }
    }

    fn ui(&mut self, ui: &mut Ui, _frame: &mut eframe::Frame) {
        let viewport_rect = ui.max_rect();
        Frame::new()
            .fill(ui.visuals().panel_fill)
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
        if let Some(mut worker) = self.worker.take() {
            worker.join();
        }
    }

    fn clear_color(&self, _visuals: &egui::Visuals) -> [f32; 4] {
        ui_palette(&self.settings.interface_style)
            .background
            .to_normalized_gamma_f32()
    }
}

fn configure_theme(ctx: &egui::Context, interface_style: &str) {
    let refined = interface_style == "refined";
    let palette = ui_palette(interface_style);
    let mut fonts = FontDefinitions::default();
    let (interface_font, interface_font_path) = if refined {
        ("Segoe UI", r"C:\Windows\Fonts\segoeui.ttf")
    } else {
        ("Tahoma", r"C:\Windows\Fonts\tahoma.ttf")
    };
    if let Ok(bytes) = fs::read(interface_font_path) {
        fonts
            .font_data
            .insert(interface_font.into(), FontData::from_owned(bytes).into());
        fonts
            .families
            .entry(FontFamily::Proportional)
            .or_default()
            .insert(0, interface_font.into());
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
    style.spacing.item_spacing = if refined {
        Vec2::new(8.0, 5.0)
    } else {
        Vec2::new(6.0, 4.0)
    };
    style.spacing.button_padding = if refined {
        Vec2::new(10.0, 5.0)
    } else {
        Vec2::new(8.0, 4.0)
    };
    style.visuals = egui::Visuals::light();
    style.visuals.override_text_color = Some(palette.text);
    style.visuals.panel_fill = palette.background;
    style.visuals.window_fill = palette.panel;
    style.visuals.extreme_bg_color = palette.surface;
    style.visuals.faint_bg_color = palette.toolbar;
    style.visuals.code_bg_color = palette.surface;
    style.visuals.hyperlink_color = palette.accent;
    style.visuals.selection.bg_fill = palette.accent;
    style.visuals.selection.stroke = Stroke::new(1.0, Color32::WHITE);
    style.visuals.window_stroke = Stroke::new(1.0, palette.border);
    style.visuals.window_corner_radius = CornerRadius::same(if refined { 5 } else { 1 });
    style.visuals.menu_corner_radius = CornerRadius::same(if refined { 4 } else { 1 });
    style.visuals.widgets.inactive.bg_fill = palette.button;
    style.visuals.widgets.inactive.fg_stroke = Stroke::new(1.0, palette.text);
    style.visuals.widgets.inactive.bg_stroke = Stroke::new(1.0, palette.border);
    style.visuals.widgets.hovered.bg_fill = palette.hover;
    style.visuals.widgets.hovered.fg_stroke = Stroke::new(1.0, palette.text);
    style.visuals.widgets.hovered.bg_stroke = Stroke::new(1.0, palette.accent);
    style.visuals.widgets.active.bg_fill = palette.active;
    style.visuals.widgets.active.fg_stroke = Stroke::new(
        1.0,
        if refined {
            Color32::WHITE
        } else {
            palette.text
        },
    );
    style.visuals.widgets.active.bg_stroke = Stroke::new(1.0, palette.accent);
    style.visuals.widgets.open.bg_fill = palette.hover;
    style.visuals.widgets.open.fg_stroke = Stroke::new(1.0, palette.text);
    style.visuals.widgets.open.bg_stroke = Stroke::new(1.0, palette.accent);
    style.visuals.widgets.noninteractive.bg_fill = palette.panel;
    style.visuals.widgets.noninteractive.fg_stroke = Stroke::new(1.0, palette.text);
    style.visuals.widgets.noninteractive.bg_stroke = Stroke::new(1.0, palette.border);
    let widget_radius = CornerRadius::same(if refined { 4 } else { 1 });
    style.visuals.widgets.inactive.corner_radius = widget_radius;
    style.visuals.widgets.hovered.corner_radius = widget_radius;
    style.visuals.widgets.active.corner_radius = widget_radius;
    style.visuals.widgets.open.corner_radius = widget_radius;
    style.visuals.widgets.noninteractive.corner_radius = widget_radius;
    let body_size = if refined { 13.0 } else { 12.0 };
    style.text_styles.insert(
        egui::TextStyle::Body,
        FontId::new(body_size, FontFamily::Proportional),
    );
    style.text_styles.insert(
        egui::TextStyle::Button,
        FontId::new(if refined { 12.5 } else { 12.0 }, FontFamily::Proportional),
    );
    style.text_styles.insert(
        egui::TextStyle::Small,
        FontId::new(if refined { 11.5 } else { 11.0 }, FontFamily::Proportional),
    );
    ctx.set_style_of(egui::Theme::Light, style);
    ctx.set_theme(egui::ThemePreference::Light);
}

fn toolbar_button(text: &'static str, palette: UiPalette) -> egui::Button<'static> {
    egui::Button::new(RichText::new(text).strong().color(palette.text))
        .min_size(Vec2::new(88.0, 25.0))
}

fn primary_toolbar_button(text: &'static str, palette: UiPalette) -> egui::Button<'static> {
    egui::Button::new(RichText::new(text).strong().color(Color32::WHITE))
        .fill(palette.accent)
        .stroke(Stroke::new(1.0, palette.accent))
        .min_size(Vec2::new(96.0, 25.0))
}

fn metric(ui: &mut Ui, label: &str, value: &str, width: f32) {
    group_box(ui, label, Vec2::new(width, 49.0), |ui| {
        Frame::new()
            .fill(ui.visuals().extreme_bg_color)
            .inner_margin(Margin::symmetric(5, 4))
            .show(ui, |ui| {
                ui.set_width(width - 18.0);
                ui.vertical_centered(|ui| {
                    ui.add(
                        egui::Label::new(
                            RichText::new(value)
                                .strong()
                                .color(ui.visuals().text_color()),
                        )
                        .truncate(),
                    );
                });
            });
    });
}

fn group_box<R>(ui: &mut Ui, title: &str, size: Vec2, add: impl FnOnce(&mut Ui) -> R) -> R {
    ui.allocate_ui_with_layout(size, Layout::top_down(Align::Min), |ui| {
        ui.set_min_size(size);
        Frame::new()
            .fill(ui.visuals().panel_fill)
            .stroke(ui.visuals().widgets.noninteractive.bg_stroke)
            .inner_margin(Margin::symmetric(7, 6))
            .show(ui, |ui| {
                ui.set_min_size(size - Vec2::new(14.0, 12.0));
                ui.label(
                    RichText::new(title)
                        .strong()
                        .small()
                        .color(ui.visuals().text_color()),
                );
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
                .fill(ui.visuals().panel_fill)
                .stroke(ui.visuals().widgets.noninteractive.bg_stroke)
                .inner_margin(Margin::symmetric(7, 6))
                .show(ui, |ui| {
                    ui.set_width((size.x - 14.0).max(1.0));
                    ui.set_max_height((size.y - 12.0).max(1.0));
                    ui.label(
                        RichText::new(title)
                            .strong()
                            .small()
                            .color(ui.visuals().text_color()),
                    );
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
            String::new(),
            String::new(),
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
        0 => format!("{} {}\nStatus: {}\nDuration: {:.0} ms\nState: {}", request.method, request.url(), response.map(|value| value.status.to_string()).unwrap_or_else(|| "pending".into()), response.map(|value| value.duration_ms).unwrap_or_default(), if exchange.synthetic { "Synthetic" } else { "Completed" }),
        1 => format!("Method: {}\nURL: {}\nHTTP Version: {}\nClient: {}\nBody Size: {} bytes\n\nBody\n{}", request.method, request.url(), request.version, request.client_addr, request.body.len(), request_body),
        2 => response.map(|value| format!("Status: {} {}\nHTTP Version: {}\nDuration: {:.0} ms\nContent-Type: {}\nBody Size: {} bytes\n\nBody\n{}", value.status, value.reason, value.version, value.duration_ms, value.content_type().unwrap_or("<unknown>"), value.body.len(), response_body)).unwrap_or_else(|| "No response captured yet".into()),
        3 => format!("Request headers\n{}\n\nResponse headers\n{}", request_headers, response_headers),
        4 => format!("{} {} {}\n{}\n\n{}\n\nResponse\n{}\n\n{}", request.method, request.path, request.version, request_headers, request_body, response_headers, response_body),
        _ => exchange.notes.clone(),
    }
}

fn websocket_inspector(message: &WebSocketMessage, tab: usize) -> String {
    match tab {
        0 => format!(
            "WebSocket {} {}\nOpcode: {}\nSize: {} bytes",
            message.direction.label(),
            message.url,
            message.opcode,
            message.raw_size
        ),
        1 => format!(
            "URL: {}\nHost: {}\nPath: {}\nDirection: {}",
            message.url,
            message.host,
            message.path,
            message.direction.label()
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
                        pid: Some(4301 + index as u32),
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
    fn refined_and_classic_palettes_are_distinct_and_reversible() {
        let refined = ui_palette("refined");
        let classic = ui_palette("classic");
        assert_ne!(refined, classic);
        assert_eq!(ui_palette("classic"), classic);
        assert_eq!(ui_palette("refined"), refined);
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
}
