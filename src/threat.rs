use std::{
    collections::{HashMap, HashSet, VecDeque},
    net::IpAddr,
    time::Duration,
};

use chrono::{DateTime, Utc};

use crate::model::{
    CapturedExchange, CapturedRequest, Direction, Header, ThreatAssessment, ThreatFinding,
    ThreatLevel, WebSocketMessage, header_value,
};

const WARNING_SCORE: u16 = 30;
const HIGH_SCORE: u16 = 60;
const HISTORY_WINDOW_SECONDS: i64 = 120;

#[derive(Default)]
pub struct ThreatAnalyzer {
    host_history: HashMap<String, HostHistory>,
    beacon_history: HashMap<String, VecDeque<DateTime<Utc>>>,
    failed_requests: HashMap<String, VecDeque<(DateTime<Utc>, String)>>,
    destination_history: HashMap<String, VecDeque<(DateTime<Utc>, String, bool)>>,
    encoded_history: HashMap<String, VecDeque<DateTime<Utc>>>,
    outbound_volume: VecDeque<(DateTime<Utc>, usize)>,
    websocket_history: HashMap<String, WebSocketHistory>,
}

#[derive(Clone, Debug)]
struct HostHistory {
    first_seen: DateTime<Utc>,
    count: usize,
}

#[derive(Clone, Debug)]
struct WebSocketHistory {
    first_seen: DateTime<Utc>,
    messages: usize,
}

impl ThreatAnalyzer {
    pub fn reset(&mut self) {
        *self = Self::default();
    }

    pub fn analyze_http(
        &mut self,
        exchange: &CapturedExchange,
        idle_for: Option<Duration>,
        idle_threshold: Duration,
    ) -> ThreatAssessment {
        let request = &exchange.request;
        let host = normalized_host(&request.host);
        let raw_ip = host.parse::<IpAddr>().is_ok();
        let random_domain = looks_random_domain(&host);
        let suspicious_path = suspicious_path(&request.path);
        let mut assessment = ThreatAssessment::default();

        if raw_ip {
            add_finding(
                &mut assessment,
                30,
                "Direct connection to an IP address",
                format!("Destination is {host} instead of a domain name"),
            );
        }
        if random_domain {
            add_finding(
                &mut assessment,
                20,
                "Random-looking domain name",
                format!("Destination host is {host}"),
            );
        }
        if let Some(segment) = suspicious_path {
            add_finding(
                &mut assessment,
                30,
                "Command-and-control style URL path",
                format!("Path contains {segment}"),
            );
        }
        if let Some(category) = suspicious_hosting_category(&host) {
            add_finding(
                &mut assessment,
                20,
                "Traffic to a commonly abused hosting service",
                format!("{host} matches the {category} category"),
            );
        }

        analyze_process(request, &mut assessment);
        analyze_user_agent(request, &mut assessment);
        analyze_headers(request, &mut assessment);
        analyze_plaintext(request, exchange, &mut assessment);
        analyze_tunneling(request, &mut assessment);

        let mut encoded = false;
        if is_upload_method(&request.method) && !request.body.is_empty() {
            if request.body.len() >= 25 * 1024 * 1024 {
                add_finding(
                    &mut assessment,
                    45,
                    "Very large outbound upload",
                    format!(
                        "{} sent {}",
                        request.method,
                        format_bytes(request.body.len())
                    ),
                );
            } else if request.body.len() >= 5 * 1024 * 1024 {
                add_finding(
                    &mut assessment,
                    30,
                    "Large outbound upload",
                    format!(
                        "{} sent {}",
                        request.method,
                        format_bytes(request.body.len())
                    ),
                );
            }
            encoded = looks_encoded(&request.body);
            if encoded {
                let count = self.record_encoded(
                    format!("http|{}|{}", identity_key(request), host),
                    request.timestamp,
                );
                let score = if count >= 3 { 30 } else { 12 };
                add_finding(
                    &mut assessment,
                    score,
                    "Encoded or high-entropy outbound data",
                    format!(
                        "{} encoded upload(s) to {host} observed in the last minute",
                        count
                    ),
                );
            }
        }

        if !request.body.is_empty() {
            let minute_total = self.record_outbound(request.timestamp, request.body.len());
            if minute_total >= 20 * 1024 * 1024 {
                add_finding(
                    &mut assessment,
                    35,
                    "Sudden spike in outbound web traffic",
                    format!(
                        "{} uploaded through HTTP/WebSocket in the last minute",
                        format_bytes(minute_total)
                    ),
                );
            }
        }

        let host_history = self
            .host_history
            .entry(host.clone())
            .or_insert(HostHistory {
                first_seen: request.timestamp,
                count: 0,
            });
        host_history.count += 1;
        if host_history.count >= 5
            && request
                .timestamp
                .signed_duration_since(host_history.first_seen)
                .num_minutes()
                <= 10
            && (raw_ip || random_domain || suspicious_path.is_some())
        {
            add_finding(
                &mut assessment,
                15,
                "Repeated activity to a first-seen destination",
                format!("{} requests to {host} in this capture", host_history.count),
            );
        }

        let beacon_key = format!(
            "http|{}|{}|{}|{}",
            identity_key(request),
            host,
            request.method,
            path_without_query(&request.path)
        );
        if let Some(interval) = self.record_beacon(beacon_key, request.timestamp) {
            add_finding(
                &mut assessment,
                40,
                "Regular beaconing interval",
                format!(
                    "Requests repeat approximately every {}",
                    format_duration(interval)
                ),
            );
        }

        self.analyze_failover(exchange, &mut assessment);
        self.analyze_destinations(request, raw_ip || random_domain, &mut assessment);

        let idle_suspicious = is_upload_method(&request.method)
            || !request.body.is_empty()
            || raw_ip
            || random_domain
            || suspicious_path.is_some()
            || suspicious_process(&request.process)
            || encoded;
        if idle_suspicious && idle_for.is_some_and(|idle| idle >= idle_threshold) {
            add_finding(
                &mut assessment,
                18,
                "Suspicious traffic while the computer is idle",
                format!(
                    "No user input for at least {}",
                    format_duration(idle_for.unwrap_or_default())
                ),
            );
        }

        if let Some(error) = &exchange.error
            && certificate_error(error)
        {
            add_finding(
                &mut assessment,
                45,
                "Upstream TLS certificate validation failed",
                truncate_evidence(error, 180),
            );
        }

        finalize(assessment)
    }

    pub fn analyze_websocket(
        &mut self,
        message: &WebSocketMessage,
        idle_for: Option<Duration>,
        idle_threshold: Duration,
    ) -> ThreatAssessment {
        let host = normalized_host(&message.host);
        let raw_ip = host.parse::<IpAddr>().is_ok();
        let random_domain = looks_random_domain(&host);
        let suspicious_path = suspicious_path(&message.path);
        let mut assessment = ThreatAssessment::default();

        if raw_ip {
            add_finding(
                &mut assessment,
                30,
                "WebSocket connected to an IP address",
                format!("Destination is {host}"),
            );
        }
        if random_domain {
            add_finding(
                &mut assessment,
                20,
                "Random-looking WebSocket domain",
                format!("Destination host is {host}"),
            );
        }
        if let Some(segment) = suspicious_path {
            add_finding(
                &mut assessment,
                30,
                "Command-and-control style WebSocket path",
                format!("Path contains {segment}"),
            );
        }
        if let Some(category) = suspicious_hosting_category(&host) {
            add_finding(
                &mut assessment,
                20,
                "WebSocket to a commonly abused hosting service",
                format!("{host} matches the {category} category"),
            );
        }
        if suspicious_process(&message.process) {
            add_finding(
                &mut assessment,
                35,
                "Unexpected application using WebSocket",
                format!("{} opened web traffic", message.process),
            );
        }

        let identity = websocket_identity_key(message);
        let ws_key = format!("{identity}|{host}|{}", message.path);
        let history = self
            .websocket_history
            .entry(ws_key.clone())
            .or_insert(WebSocketHistory {
                first_seen: message.timestamp,
                messages: 0,
            });
        history.messages += 1;
        let active_for = message
            .timestamp
            .signed_duration_since(history.first_seen)
            .to_std()
            .unwrap_or_default();
        if active_for >= Duration::from_secs(5 * 60) && history.messages >= 5 {
            add_finding(
                &mut assessment,
                20,
                "Long-running WebSocket activity",
                format!(
                    "{} messages observed over {}",
                    history.messages,
                    format_duration(active_for)
                ),
            );
        }

        let mut encoded = false;
        if message.direction == Direction::Out {
            encoded = message.decoded_as.contains("hex")
                || (!message.is_text && message.decoded_as.contains("binary"))
                || looks_encoded(message.payload.as_bytes());
            if encoded && message.raw_size >= 64 {
                let count = self.record_encoded(format!("ws|{identity}|{host}"), message.timestamp);
                add_finding(
                    &mut assessment,
                    if count >= 4 { 30 } else { 8 },
                    "Frequent encoded outbound WebSocket data",
                    format!("{count} encoded message(s) observed in the last minute"),
                );
            }

            let minute_total = self.record_outbound(message.timestamp, message.raw_size);
            if minute_total >= 20 * 1024 * 1024 {
                add_finding(
                    &mut assessment,
                    35,
                    "Sudden spike in outbound web traffic",
                    format!(
                        "{} uploaded through HTTP/WebSocket in the last minute",
                        format_bytes(minute_total)
                    ),
                );
            }
        }

        let beacon_key = format!(
            "ws|{identity}|{host}|{}|{}",
            message.path,
            message.direction.label()
        );
        if let Some(interval) = self.record_beacon(beacon_key, message.timestamp) {
            add_finding(
                &mut assessment,
                40,
                "Regular WebSocket beaconing interval",
                format!(
                    "Messages repeat approximately every {}",
                    format_duration(interval)
                ),
            );
        }

        let idle_suspicious = message.direction == Direction::Out
            && (message.raw_size >= 64 * 1024
                || raw_ip
                || random_domain
                || suspicious_path.is_some()
                || suspicious_process(&message.process)
                || encoded);
        if idle_suspicious && idle_for.is_some_and(|idle| idle >= idle_threshold) {
            add_finding(
                &mut assessment,
                18,
                "Suspicious WebSocket traffic while the computer is idle",
                format!(
                    "No user input for at least {}",
                    format_duration(idle_for.unwrap_or_default())
                ),
            );
        }

        finalize(assessment)
    }

    fn record_beacon(&mut self, key: String, timestamp: DateTime<Utc>) -> Option<Duration> {
        let history = self.beacon_history.entry(key).or_default();
        history.push_back(timestamp);
        while history.len() > 8 {
            history.pop_front();
        }
        fixed_interval(history)
    }

    fn record_encoded(&mut self, key: String, timestamp: DateTime<Utc>) -> usize {
        let history = self.encoded_history.entry(key).or_default();
        history.push_back(timestamp);
        prune_times(history, timestamp, 60);
        history.len()
    }

    fn record_outbound(&mut self, timestamp: DateTime<Utc>, bytes: usize) -> usize {
        self.outbound_volume.push_back((timestamp, bytes));
        while self
            .outbound_volume
            .front()
            .is_some_and(|(time, _)| timestamp.signed_duration_since(*time).num_seconds() > 60)
        {
            self.outbound_volume.pop_front();
        }
        self.outbound_volume.iter().map(|(_, bytes)| *bytes).sum()
    }

    fn analyze_failover(&mut self, exchange: &CapturedExchange, assessment: &mut ThreatAssessment) {
        let identity = stable_identity_key(&exchange.request);
        let Some(identity) = identity else { return };
        let timestamp = exchange.request.timestamp;
        let host = normalized_host(&exchange.request.host);
        let failed = exchange.error.is_some()
            || exchange
                .response
                .as_ref()
                .is_some_and(|response| response.status >= 400);
        let history = self.failed_requests.entry(identity).or_default();
        while history.front().is_some_and(|(time, _)| {
            timestamp.signed_duration_since(*time).num_seconds() > HISTORY_WINDOW_SECONDS
        }) {
            history.pop_front();
        }
        if !failed {
            let alternatives = history
                .iter()
                .filter(|(_, failed_host)| failed_host != &host)
                .count();
            if alternatives >= 3 {
                add_finding(
                    assessment,
                    35,
                    "Fallback after repeated failed requests",
                    format!("Connected to {host} after {alternatives} failures on other hosts"),
                );
                history.clear();
            }
        } else {
            history.push_back((timestamp, host));
        }
    }

    fn analyze_destinations(
        &mut self,
        request: &CapturedRequest,
        destination_suspicious: bool,
        assessment: &mut ThreatAssessment,
    ) {
        let Some(identity) = stable_identity_key(request) else {
            return;
        };
        let history = self.destination_history.entry(identity).or_default();
        history.push_back((
            request.timestamp,
            normalized_host(&request.host),
            destination_suspicious,
        ));
        while history.front().is_some_and(|(time, _, _)| {
            request.timestamp.signed_duration_since(*time).num_seconds() > 60
        }) {
            history.pop_front();
        }
        let unique_hosts = history
            .iter()
            .map(|(_, host, _)| host.as_str())
            .collect::<HashSet<_>>()
            .len();
        let suspicious_hosts = history
            .iter()
            .filter(|(_, _, suspicious)| *suspicious)
            .map(|(_, host, _)| host.as_str())
            .collect::<HashSet<_>>()
            .len();
        if unique_hosts >= 10 && suspicious_hosts >= 3 {
            add_finding(
                assessment,
                30,
                "Rapidly changing suspicious destinations",
                format!("{unique_hosts} hosts contacted in one minute"),
            );
        }
    }
}

fn add_finding(
    assessment: &mut ThreatAssessment,
    score: u16,
    title: impl Into<String>,
    evidence: impl Into<String>,
) {
    let title = title.into();
    if assessment
        .findings
        .iter()
        .any(|finding| finding.title == title)
    {
        return;
    }
    assessment.score = assessment.score.saturating_add(score).min(100);
    assessment.findings.push(ThreatFinding {
        title,
        evidence: evidence.into(),
        score,
    });
}

fn finalize(mut assessment: ThreatAssessment) -> ThreatAssessment {
    assessment.level = match assessment.score {
        0 => ThreatLevel::None,
        1..=29 => ThreatLevel::Notice,
        WARNING_SCORE..=59 => ThreatLevel::Suspicious,
        HIGH_SCORE.. => ThreatLevel::High,
    };
    assessment
        .findings
        .sort_by(|left, right| right.score.cmp(&left.score));
    assessment
}

fn analyze_process(request: &CapturedRequest, assessment: &mut ThreatAssessment) {
    if suspicious_process(&request.process) {
        add_finding(
            assessment,
            35,
            "Unexpected application accessing the web",
            format!(
                "{}{} initiated the request",
                request.process,
                request
                    .pid
                    .map(|pid| format!(" (PID {pid})"))
                    .unwrap_or_default()
            ),
        );
    }
    let path = request.process_path.to_ascii_lowercase();
    if !path.is_empty()
        && (path.contains("\\temp\\")
            || path.contains("/tmp/")
            || path.contains("\\appdata\\local\\temp\\"))
    {
        add_finding(
            assessment,
            20,
            "Web traffic from a temporary executable",
            truncate_evidence(&request.process_path, 180),
        );
    }
}

fn analyze_user_agent(request: &CapturedRequest, assessment: &mut ThreatAssessment) {
    let user_agent = header_value(&request.headers, "user-agent").unwrap_or("");
    if user_agent.is_empty() {
        add_finding(
            assessment,
            5,
            "Missing User-Agent header",
            "The request did not identify its client",
        );
        return;
    }
    if user_agent.len() > 512 || user_agent.chars().any(char::is_control) {
        add_finding(
            assessment,
            30,
            "Malformed or unusually large User-Agent",
            truncate_evidence(user_agent, 180),
        );
    }
    let lower = user_agent.to_ascii_lowercase();
    let unusual = [
        "sqlmap",
        "nikto",
        "masscan",
        "nmap",
        "powershell",
        "python-requests",
        "go-http-client",
        "libwww-perl",
        "curl/",
        "wget/",
    ]
    .iter()
    .find(|value| lower.contains(**value));
    if let Some(tool) = unusual {
        add_finding(
            assessment,
            15,
            "Unusual automated User-Agent",
            format!("User-Agent identifies {tool}"),
        );
    }
    if lower.contains("mozilla/")
        && !request.process.is_empty()
        && !is_browser_process(&request.process)
    {
        add_finding(
            assessment,
            25,
            "Browser-like traffic from a non-browser process",
            format!("{} sent a Mozilla-style User-Agent", request.process),
        );
    }
}

fn analyze_headers(request: &CapturedRequest, assessment: &mut ThreatAssessment) {
    let host_headers = count_header(&request.headers, "host");
    let length_headers = count_header(&request.headers, "content-length");
    if request.version == "HTTP/1.1" && host_headers == 0 {
        add_finding(
            assessment,
            25,
            "Missing required Host header",
            "HTTP/1.1 request has no Host header",
        );
    }
    if host_headers > 1 || length_headers > 1 {
        add_finding(
            assessment,
            35,
            "Ambiguous duplicate HTTP headers",
            format!("Host headers: {host_headers}; Content-Length headers: {length_headers}"),
        );
    }
    if request.headers.len() > 100
        || request.headers.iter().any(|header| {
            header.name.len() > 128
                || header.value.len() > 8_192
                || header.value.contains(['\r', '\n'])
        })
    {
        add_finding(
            assessment,
            30,
            "Highly unusual HTTP header structure",
            format!("Request contains {} headers", request.headers.len()),
        );
    }
}

fn analyze_plaintext(
    request: &CapturedRequest,
    exchange: &CapturedExchange,
    assessment: &mut ThreatAssessment,
) {
    if request.scheme != "http" {
        return;
    }
    let credentials = header_value(&request.headers, "authorization").is_some()
        || header_value(&request.headers, "proxy-authorization").is_some()
        || header_value(&request.headers, "cookie").is_some();
    if credentials {
        add_finding(
            assessment,
            60,
            "Credentials or cookies sent over plaintext HTTP",
            "Authorization, proxy authorization, or cookie data was not protected by TLS",
        );
    }
    let mut content = request.path.to_ascii_lowercase();
    content.push(' ');
    content.push_str(&String::from_utf8_lossy(
        &request.body[..request.body.len().min(1_048_576)],
    ));
    let sensitive_terms = [
        "password",
        "passwd",
        "access_token",
        "api_key",
        "apikey",
        "sessionid",
        "screenshot",
        "hostname",
        "systeminfo",
        "os_version",
        "username",
    ];
    if let Some(term) = sensitive_terms.iter().find(|term| content.contains(**term)) {
        add_finding(
            assessment,
            45,
            "Sensitive information sent over plaintext HTTP",
            format!("Request content contains {term}"),
        );
    }
    let content_type = request.content_type().unwrap_or("").to_ascii_lowercase();
    if !request.body.is_empty()
        && (content_type.contains("multipart/form-data")
            || content_type.contains("application/octet-stream")
            || content_type.starts_with("image/"))
    {
        add_finding(
            assessment,
            40,
            "File or image uploaded over plaintext HTTP",
            format!("Content-Type is {content_type}"),
        );
    }
    if exchange
        .response
        .as_ref()
        .is_some_and(|response| header_value(&response.headers, "set-cookie").is_some())
    {
        add_finding(
            assessment,
            35,
            "Session cookie received over plaintext HTTP",
            "The response contains Set-Cookie without HTTPS",
        );
    }
}

fn analyze_tunneling(request: &CapturedRequest, assessment: &mut ThreatAssessment) {
    if request.method.eq_ignore_ascii_case("CONNECT") {
        add_finding(
            assessment,
            35,
            "HTTP tunneling request",
            format!("CONNECT requested for {}:{}", request.host, request.port),
        );
    }
    let proxy_headers = ["via", "forwarded", "x-forwarded-for", "proxy-authorization"];
    let present = proxy_headers
        .iter()
        .filter(|name| header_value(&request.headers, name).is_some())
        .copied()
        .collect::<Vec<_>>();
    if !present.is_empty() {
        add_finding(
            assessment,
            20,
            "Traffic contains upstream proxy indicators",
            format!("Observed header(s): {}", present.join(", ")),
        );
    }
    if let Some(upgrade) = header_value(&request.headers, "upgrade")
        && !upgrade.eq_ignore_ascii_case("websocket")
    {
        add_finding(
            assessment,
            25,
            "Unusual HTTP protocol upgrade",
            format!("Upgrade requested: {upgrade}"),
        );
    }
}

fn fixed_interval(history: &VecDeque<DateTime<Utc>>) -> Option<Duration> {
    if history.len() < 5 {
        return None;
    }
    let intervals = history
        .iter()
        .zip(history.iter().skip(1))
        .map(|(previous, current)| current.signed_duration_since(*previous).num_milliseconds())
        .collect::<Vec<_>>();
    if intervals.iter().any(|interval| *interval < 1_000) {
        return None;
    }
    let mean = intervals.iter().sum::<i64>() as f64 / intervals.len() as f64;
    let tolerance = (mean * 0.12).max(250.0);
    intervals
        .iter()
        .all(|interval| (*interval as f64 - mean).abs() <= tolerance)
        .then(|| Duration::from_millis(mean as u64))
}

fn prune_times(history: &mut VecDeque<DateTime<Utc>>, now: DateTime<Utc>, seconds: i64) {
    while history
        .front()
        .is_some_and(|time| now.signed_duration_since(*time).num_seconds() > seconds)
    {
        history.pop_front();
    }
}

fn identity_key(request: &CapturedRequest) -> String {
    stable_identity_key(request).unwrap_or_else(|| request.client_addr.clone())
}

fn stable_identity_key(request: &CapturedRequest) -> Option<String> {
    request.pid.map(|pid| format!("pid:{pid}")).or_else(|| {
        (!request.process.is_empty())
            .then(|| format!("process:{}", request.process.to_ascii_lowercase()))
    })
}

fn websocket_identity_key(message: &WebSocketMessage) -> String {
    message
        .pid
        .map(|pid| format!("pid:{pid}"))
        .or_else(|| {
            (!message.process.is_empty())
                .then(|| format!("process:{}", message.process.to_ascii_lowercase()))
        })
        .unwrap_or_else(|| "unknown".into())
}

fn normalized_host(host: &str) -> String {
    host.trim()
        .trim_matches(['[', ']'])
        .trim_end_matches('.')
        .to_ascii_lowercase()
}

fn path_without_query(path: &str) -> &str {
    path.split('?').next().unwrap_or(path)
}

fn suspicious_path(path: &str) -> Option<&'static str> {
    let lower = path_without_query(path).to_ascii_lowercase();
    [
        "/gate", "/panel", "/bot", "/upload", "/cmd", "/command", "/shell", "/beacon", "/checkin",
        "/task", "/payload", "/exfil",
    ]
    .into_iter()
    .find(|segment| {
        lower == *segment
            || lower.starts_with(&format!("{segment}/"))
            || lower.starts_with(&format!("{segment}."))
            || lower.contains(&format!("{segment}/"))
    })
}

fn suspicious_hosting_category(host: &str) -> Option<&'static str> {
    const SERVICES: &[(&str, &str)] = &[
        ("bit.ly", "URL shortener"),
        ("tinyurl.com", "URL shortener"),
        ("t.co", "URL shortener"),
        ("is.gd", "URL shortener"),
        ("pastebin.com", "paste service"),
        ("paste.ee", "paste service"),
        ("hastebin.com", "paste service"),
        ("transfer.sh", "anonymous file transfer"),
        ("file.io", "anonymous file transfer"),
        ("gofile.io", "file sharing"),
        ("anonfiles.com", "anonymous file hosting"),
        ("ngrok.io", "public tunnel"),
        ("trycloudflare.com", "public tunnel"),
        ("loca.lt", "public tunnel"),
    ];
    SERVICES.iter().find_map(|(domain, category)| {
        (host == *domain || host.ends_with(&format!(".{domain}"))).then_some(*category)
    })
}

fn looks_random_domain(host: &str) -> bool {
    if host.parse::<IpAddr>().is_ok() || !host.contains('.') {
        return false;
    }
    let label = host
        .split('.')
        .find(|label| !matches!(*label, "www" | "api" | "cdn" | "static" | "assets"))
        .unwrap_or("");
    if label.len() < 16 {
        return false;
    }
    let alphanumeric = label
        .chars()
        .filter(|character| character.is_ascii_alphanumeric())
        .collect::<String>();
    if alphanumeric.len() < 16 {
        return false;
    }
    let digits = alphanumeric.bytes().filter(u8::is_ascii_digit).count();
    let vowels = alphanumeric
        .bytes()
        .filter(|byte| matches!(byte.to_ascii_lowercase(), b'a' | b'e' | b'i' | b'o' | b'u'))
        .count();
    let all_hex = alphanumeric.bytes().all(|byte| byte.is_ascii_hexdigit());
    all_hex
        || digits * 100 / alphanumeric.len() >= 35
        || (shannon_entropy(alphanumeric.as_bytes()) >= 3.6
            && vowels * 100 / alphanumeric.len() <= 20)
}

fn suspicious_process(process: &str) -> bool {
    let name = process.to_ascii_lowercase();
    [
        "powershell.exe",
        "pwsh.exe",
        "cmd.exe",
        "wscript.exe",
        "cscript.exe",
        "mshta.exe",
        "rundll32.exe",
        "regsvr32.exe",
        "certutil.exe",
        "wmic.exe",
    ]
    .contains(&name.as_str())
}

fn is_browser_process(process: &str) -> bool {
    let name = process.to_ascii_lowercase();
    [
        "firefox.exe",
        "chrome.exe",
        "msedge.exe",
        "brave.exe",
        "opera.exe",
        "vivaldi.exe",
        "chromium.exe",
        "firefox",
        "chrome",
        "chromium",
        "brave",
    ]
    .contains(&name.as_str())
}

fn is_upload_method(method: &str) -> bool {
    method.eq_ignore_ascii_case("POST")
        || method.eq_ignore_ascii_case("PUT")
        || method.eq_ignore_ascii_case("PATCH")
}

fn looks_encoded(body: &[u8]) -> bool {
    let sample = &body[..body.len().min(65_536)];
    if sample.len() < 64 {
        return false;
    }
    let ascii = sample.iter().all(u8::is_ascii);
    if ascii {
        let compact = sample
            .iter()
            .copied()
            .filter(|byte| !byte.is_ascii_whitespace())
            .collect::<Vec<_>>();
        let base64 = compact.len() >= 96
            && compact.len() % 4 == 0
            && compact.iter().all(|byte| {
                byte.is_ascii_alphanumeric() || matches!(*byte, b'+' | b'/' | b'=' | b'-' | b'_')
            });
        let hex = compact.len() >= 128
            && compact.len() % 2 == 0
            && compact.iter().all(u8::is_ascii_hexdigit);
        if base64 || hex {
            return true;
        }
    }
    shannon_entropy(sample) >= 7.4
}

fn shannon_entropy(bytes: &[u8]) -> f64 {
    if bytes.is_empty() {
        return 0.0;
    }
    let mut counts = [0usize; 256];
    for byte in bytes {
        counts[*byte as usize] += 1;
    }
    counts
        .iter()
        .filter(|count| **count > 0)
        .map(|count| {
            let probability = *count as f64 / bytes.len() as f64;
            -probability * probability.log2()
        })
        .sum()
}

fn certificate_error(error: &str) -> bool {
    let lower = error.to_ascii_lowercase();
    [
        "certificate",
        "invalid peer",
        "unknown issuer",
        "not valid for",
        "expired",
        "tls handshake",
        "certverify",
    ]
    .iter()
    .any(|term| lower.contains(term))
}

fn count_header(headers: &[Header], name: &str) -> usize {
    headers
        .iter()
        .filter(|header| header.name.eq_ignore_ascii_case(name))
        .count()
}

fn truncate_evidence(value: &str, limit: usize) -> String {
    let mut truncated = value.chars().take(limit).collect::<String>();
    if value.chars().count() > limit {
        truncated.push_str("...");
    }
    truncated
}

fn format_bytes(bytes: usize) -> String {
    if bytes >= 1024 * 1024 {
        format!("{:.1} MB", bytes as f64 / (1024.0 * 1024.0))
    } else if bytes >= 1024 {
        format!("{:.1} KB", bytes as f64 / 1024.0)
    } else {
        format!("{bytes} bytes")
    }
}

fn format_duration(duration: Duration) -> String {
    if duration.as_secs() >= 60 {
        format!(
            "{} min {} sec",
            duration.as_secs() / 60,
            duration.as_secs() % 60
        )
    } else if duration.as_secs() > 0 {
        format!("{:.1} sec", duration.as_secs_f64())
    } else {
        format!("{} ms", duration.as_millis())
    }
}

#[cfg(test)]
mod tests {
    use chrono::{TimeDelta, Utc};
    use uuid::Uuid;

    use super::*;
    use crate::model::{CapturedResponse, Header};

    fn exchange_at(timestamp: DateTime<Utc>, host: &str, path: &str) -> CapturedExchange {
        CapturedExchange {
            id: Uuid::new_v4(),
            sequence: 1,
            request: CapturedRequest {
                method: "GET".into(),
                scheme: "https".into(),
                host: host.into(),
                port: 443,
                path: path.into(),
                version: "HTTP/2.0".into(),
                headers: vec![Header {
                    name: "user-agent".into(),
                    value: "Mozilla/5.0".into(),
                }],
                body: Vec::new(),
                timestamp,
                client_addr: "127.0.0.1:50000".into(),
                process: "firefox.exe".into(),
                process_path: String::new(),
                pid: Some(10),
                provenance: Default::default(),
                guard: Default::default(),
            },
            response: Some(CapturedResponse {
                status: 200,
                reason: "OK".into(),
                version: "HTTP/2.0".into(),
                headers: Vec::new(),
                body: Vec::new(),
                duration_ms: 10.0,
            }),
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
    fn raw_ip_and_control_path_are_high_risk() {
        let mut analyzer = ThreatAnalyzer::default();
        let exchange = exchange_at(Utc::now(), "173.46.83.202", "/gate");
        let threat = analyzer.analyze_http(&exchange, None, Duration::from_secs(5 * 60));
        assert_eq!(threat.level, ThreatLevel::High);
        assert!(threat.is_warning());
        assert!(
            threat
                .findings
                .iter()
                .any(|finding| finding.title.contains("IP address"))
        );
    }

    #[test]
    fn detects_fixed_interval_beaconing() {
        let mut analyzer = ThreatAnalyzer::default();
        let start = Utc::now();
        let mut latest = ThreatAssessment::default();
        for index in 0..5 {
            let exchange = exchange_at(
                start + TimeDelta::seconds(index * 30),
                "api.example.com",
                "/status",
            );
            latest = analyzer.analyze_http(&exchange, None, Duration::from_secs(5 * 60));
        }
        assert!(latest.is_warning());
        assert!(
            latest
                .findings
                .iter()
                .any(|finding| finding.title.contains("beaconing"))
        );
    }

    #[test]
    fn detects_plaintext_credentials() {
        let mut analyzer = ThreatAnalyzer::default();
        let mut exchange = exchange_at(Utc::now(), "example.com", "/login");
        exchange.request.scheme = "http".into();
        exchange.request.port = 80;
        exchange.request.headers.push(Header {
            name: "Authorization".into(),
            value: "Bearer secret".into(),
        });
        let threat = analyzer.analyze_http(&exchange, None, Duration::from_secs(5 * 60));
        assert_eq!(threat.level, ThreatLevel::High);
    }

    #[test]
    fn ordinary_browser_request_is_not_warned() {
        let mut analyzer = ThreatAnalyzer::default();
        let exchange = exchange_at(Utc::now(), "www.example.com", "/news");
        let threat = analyzer.analyze_http(&exchange, None, Duration::from_secs(5 * 60));
        assert_eq!(threat.level, ThreatLevel::None);
        assert!(!threat.is_warning());
    }

    #[test]
    fn script_host_with_browser_user_agent_is_warned() {
        let mut analyzer = ThreatAnalyzer::default();
        let mut exchange = exchange_at(Utc::now(), "example.com", "/status");
        exchange.request.process = "powershell.exe".into();
        let threat = analyzer.analyze_http(&exchange, None, Duration::from_secs(5 * 60));
        assert_eq!(threat.level, ThreatLevel::High);
        assert!(
            threat
                .findings
                .iter()
                .any(|finding| finding.title.contains("Unexpected application"))
        );
    }

    #[test]
    fn idle_upload_combines_with_encoded_payload_evidence() {
        let mut analyzer = ThreatAnalyzer::default();
        let mut exchange = exchange_at(Utc::now(), "api.example.com", "/submit");
        exchange.request.method = "POST".into();
        exchange.request.body = b"QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo=".repeat(8);
        let threat = analyzer.analyze_http(
            &exchange,
            Some(Duration::from_secs(10 * 60)),
            Duration::from_secs(5 * 60),
        );
        assert!(threat.is_warning());
        assert!(
            threat
                .findings
                .iter()
                .any(|finding| finding.title.contains("idle"))
        );
    }

    #[test]
    fn repeated_encoded_websocket_messages_are_warned() {
        let mut analyzer = ThreatAnalyzer::default();
        let start = Utc::now();
        let mut latest = ThreatAssessment::default();
        for index in 0..4 {
            let message = WebSocketMessage {
                id: Uuid::new_v4(),
                sequence: index as u64 + 1,
                url: "wss://socket.example.com/events".into(),
                host: "socket.example.com".into(),
                path: "/events".into(),
                direction: Direction::Out,
                opcode: "BINARY".into(),
                is_text: false,
                payload: "a1".repeat(128),
                raw_size: 128,
                decoded_as: "binary hex".into(),
                rule_matched: None,
                timestamp: start + TimeDelta::seconds(index * 5),
                process: "chrome.exe".into(),
                process_path: String::new(),
                pid: Some(20),
                threat: ThreatAssessment::default(),
                provenance: Default::default(),
                guard: Default::default(),
                behavior: Default::default(),
                analysis: Default::default(),
                wire_payload: Vec::new(),
                synthetic: false,
            };
            latest = analyzer.analyze_websocket(&message, None, Duration::from_secs(5 * 60));
        }
        assert!(latest.is_warning());
        assert!(
            latest
                .findings
                .iter()
                .any(|finding| finding.title.contains("encoded outbound WebSocket"))
        );
    }
}
