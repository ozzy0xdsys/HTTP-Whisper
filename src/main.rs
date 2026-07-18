#![cfg_attr(all(windows, not(debug_assertions)), windows_subsystem = "windows")]

use anyhow::Result;
use http_whisper::{config::AppSettings, ui::HttpWhisperApp, windows_proxy};

fn main() -> Result<()> {
    if windows_proxy::run_helper_from_args()? {
        return Ok(());
    }
    let settings = AppSettings::load_or_default()?;
    let viewport = eframe::egui::ViewportBuilder::default()
        .with_inner_size([1280.0, 800.0])
        .with_min_inner_size([980.0, 620.0])
        .with_title("HTTP Whisper");
    let options = eframe::NativeOptions {
        viewport,
        renderer: eframe::Renderer::Glow,
        ..Default::default()
    };
    eframe::run_native(
        "HTTP Whisper",
        options,
        Box::new(move |cc| Ok(Box::new(HttpWhisperApp::new(cc, settings)))),
    )
    .map_err(|error| anyhow::anyhow!(error.to_string()))
}
