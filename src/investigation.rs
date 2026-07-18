use std::collections::{BTreeMap, BTreeSet};

use crate::{
    dossier::HostDossierIndex,
    model::{GuardAssessment, ProcessProvenance, Session},
};

pub fn explain_session(session: &Session, dossiers: &HostDossierIndex) -> String {
    let mut lines = vec!["HTTP Whisper Investigation Report".into(), String::new()];
    match session {
        Session::Http(exchange) => {
            let request = &exchange.request;
            lines.extend([
                format!("Event: HTTP #{}", exchange.sequence),
                format!("Time: {}", request.timestamp.to_rfc3339()),
                format!("Request: {} {}", request.method, request.url()),
                format!(
                    "Response: {}",
                    exchange
                        .response
                        .as_ref()
                        .map(|response| format!(
                            "HTTP {} in {:.0} ms",
                            response.status, response.duration_ms
                        ))
                        .unwrap_or_else(|| exchange.error.as_deref().unwrap_or("<none>").into())
                ),
                format!("Process: {}", process_label(&request.process, request.pid)),
                format!("Executable: {}", unknown(&request.process_path)),
            ]);
            append_provenance(&mut lines, &request.provenance);
            append_guard(&mut lines, &request.guard);
        }
        Session::WebSocket(message) => {
            lines.extend([
                format!("Event: WebSocket #{}", message.sequence),
                format!("Time: {}", message.timestamp.to_rfc3339()),
                format!(
                    "Message: {} {} ({} bytes)",
                    message.direction.label(),
                    message.url,
                    message.raw_size
                ),
                format!("Process: {}", process_label(&message.process, message.pid)),
                format!("Executable: {}", unknown(&message.process_path)),
            ]);
            append_provenance(&mut lines, &message.provenance);
            append_guard(&mut lines, &message.guard);
            lines.push("\nProtocol analysis".into());
            lines.extend([
                format!("  Protocol: {}", unknown(&message.analysis.protocol)),
                format!(
                    "  Message type: {}",
                    unknown(&message.analysis.message_type)
                ),
                format!(
                    "  Correlation ID: {}",
                    unknown(&message.analysis.correlation_id)
                ),
                format!(
                    "  Sequence value: {}",
                    message
                        .analysis
                        .sequence_value
                        .map(|value| value.to_string())
                        .unwrap_or_else(|| "<none>".into())
                ),
                format!(
                    "  Reply to captured sequence: {}",
                    message
                        .analysis
                        .reply_to_sequence
                        .map(|value| value.to_string())
                        .unwrap_or_else(|| "<none>".into())
                ),
            ]);
        }
    }

    let threat = session.threat();
    lines.push("\nRisk explanation".into());
    lines.push(format!(
        "  Level: {}\n  Score: {}/100",
        threat.level.label(),
        threat.score
    ));
    if threat.findings.is_empty() {
        lines.push("  No suspicious indicators were detected.".into());
    } else {
        for finding in &threat.findings {
            lines.push(format!(
                "  +{} {}\n      {}",
                finding.score, finding.title, finding.evidence
            ));
        }
    }

    let behavior = session.behavior();
    lines.push("\nLearned-baseline comparison".into());
    if behavior.learning {
        lines.push("  Learn Normal was active; this event was added to the baseline.".into());
    } else if !behavior.baseline_available {
        lines.push("  No learned baseline was available.".into());
    } else if behavior.changes.is_empty() {
        lines.push("  This event matched the learned process/host behavior.".into());
    } else {
        lines.extend(
            behavior
                .changes
                .iter()
                .map(|change| format!("  CHANGE {change}")),
        );
    }

    lines.push("\nHost context".into());
    lines.extend(
        dossiers
            .report(session.host())
            .lines()
            .map(|line| format!("  {line}")),
    );
    append_recommendations(&mut lines, session);
    lines.push(
        "\nAssessment note: warnings are explainable heuristic evidence, not a malware verdict."
            .into(),
    );
    lines.join("\n")
}

fn append_recommendations(lines: &mut Vec<String>, session: &Session) {
    let mut checks = BTreeSet::new();
    let guard = session.guard();
    if !guard.findings.is_empty() {
        checks.insert(
            "Confirm that the destination is approved to receive the detected sensitive data.",
        );
        checks
            .insert("Inspect the originating application's configuration and credential handling.");
    }
    if session.behavior().is_unusual() {
        checks.insert(
            "Compare the changed destination, path, or message type with a known-good run.",
        );
    }
    let provenance = match session {
        Session::Http(exchange) => &exchange.request.provenance,
        Session::WebSocket(message) => &message.provenance,
    };
    if provenance.signature_valid == Some(false) {
        checks.insert(
            "Verify the executable SHA-256 and publisher through a trusted software inventory.",
        );
    }
    if session
        .threat()
        .findings
        .iter()
        .any(|finding| finding.title.to_ascii_lowercase().contains("beacon"))
    {
        checks.insert("Review nearby timeline events for the same fixed interval and process.");
    }
    if session.threat().is_warning() {
        checks.insert(
            "Correlate the process and timestamp with endpoint-security and system event logs.",
        );
    }
    if checks.is_empty() {
        checks.insert(
            "No urgent follow-up is suggested; retain this event as comparison evidence if useful.",
        );
    }
    lines.push("\nRecommended checks".into());
    lines.extend(checks.into_iter().map(|check| format!("  - {check}")));
}

pub fn process_timeline(sessions: &[Session]) -> String {
    if sessions.is_empty() {
        return "No captured events.".into();
    }
    let mut counts = BTreeMap::<String, (usize, usize, usize)>::new();
    for session in sessions {
        let key = process_label(session.process(), session.pid());
        let entry = counts.entry(key).or_default();
        entry.0 += 1;
        entry.1 += usize::from(matches!(session, Session::WebSocket(_)));
        entry.2 += usize::from(session.threat().is_warning());
    }
    let mut lines = vec!["Application Network Timeline".into(), String::new()];
    lines.push("Process summary".into());
    lines.extend(
        counts
            .into_iter()
            .map(|(process, (events, websockets, warnings))| {
                format!("  {process}: {events} event(s), {websockets} WS, {warnings} warning(s)")
            }),
    );
    lines.push("\nProcess provenance".into());
    let mut seen = BTreeSet::new();
    for session in sessions {
        let process = process_label(session.process(), session.pid());
        if !seen.insert(process.clone()) {
            continue;
        }
        let (path, provenance) = match session {
            Session::Http(exchange) => {
                (&exchange.request.process_path, &exchange.request.provenance)
            }
            Session::WebSocket(message) => (&message.process_path, &message.provenance),
        };
        lines.push(format!("  {process}"));
        lines.push(format!("    Executable: {}", unknown(path)));
        lines.push(format!(
            "    Parent: {}",
            process_label(&provenance.parent_process, provenance.parent_pid)
        ));
        lines.push(format!("    Publisher: {}", unknown(&provenance.publisher)));
        lines.push(format!(
            "    Started: {}",
            provenance
                .started_at
                .map(|value| value.to_rfc3339())
                .unwrap_or_else(|| "<unknown>".into())
        ));
        lines.push(format!(
            "    Signature: {}",
            provenance
                .signature_valid
                .map(|valid| if valid { "Valid" } else { "Missing or invalid" })
                .unwrap_or("<unknown>")
        ));
        lines.push(format!(
            "    SHA-256: {}",
            unknown(&provenance.executable_sha256)
        ));
    }
    lines.push("\nChronology".into());
    for session in sessions.iter().take(20_000) {
        let warning = if session.threat().is_warning() {
            " !"
        } else {
            ""
        };
        let behavior = if session.behavior().is_unusual() {
            " CHANGE"
        } else {
            ""
        };
        let detail = match session {
            Session::Http(exchange) => format!(
                "{} {}{} {}",
                exchange.request.method,
                exchange.request.host,
                exchange.request.path,
                exchange
                    .response
                    .as_ref()
                    .map(|response| response.status.to_string())
                    .unwrap_or_else(|| "ERR".into())
            ),
            Session::WebSocket(message) => format!(
                "WS {} {}{} {}",
                message.direction.label(),
                message.host,
                message.path,
                unknown(&message.analysis.message_type)
            ),
        };
        lines.push(format!(
            "  {}  {:<28}  {}{}{}",
            session.timestamp().format("%H:%M:%S%.3f"),
            process_label(session.process(), session.pid()),
            detail,
            warning,
            behavior
        ));
    }
    lines.join("\n")
}

fn append_provenance(lines: &mut Vec<String>, provenance: &ProcessProvenance) {
    lines.extend([
        format!(
            "Parent: {}",
            process_label(&provenance.parent_process, provenance.parent_pid)
        ),
        format!("Publisher: {}", unknown(&provenance.publisher)),
        format!(
            "Signature: {}",
            provenance
                .signature_valid
                .map(|valid| if valid { "Valid" } else { "Missing or invalid" })
                .unwrap_or("<unknown>")
        ),
        format!(
            "Process started: {}",
            provenance
                .started_at
                .map(|value| value.to_rfc3339())
                .unwrap_or_else(|| "<unknown>".into())
        ),
        format!("SHA-256: {}", unknown(&provenance.executable_sha256)),
    ]);
}

fn append_guard(lines: &mut Vec<String>, guard: &GuardAssessment) {
    lines.push("\nExfiltration guard".into());
    lines.push(format!("  Action: {}", guard.action.label()));
    if guard.findings.is_empty() {
        lines.push("  No protected outbound data patterns detected.".into());
    } else {
        lines.extend(guard.findings.iter().map(|finding| {
            format!(
                "  {} at {}\n      {}",
                finding.category, finding.location, finding.evidence
            )
        }));
    }
}

fn process_label(process: &str, pid: Option<u32>) -> String {
    match (process.is_empty(), pid) {
        (false, Some(pid)) => format!("{process} (PID {pid})"),
        (false, None) => process.into(),
        (true, Some(pid)) => format!("PID {pid}"),
        (true, None) => "<unknown process>".into(),
    }
}

fn unknown(value: &str) -> &str {
    if value.is_empty() { "<unknown>" } else { value }
}
