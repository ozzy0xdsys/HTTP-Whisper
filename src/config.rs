use std::{fs, path::PathBuf};

use anyhow::{Context, Result};
use directories::ProjectDirs;
use serde::{Deserialize, Serialize};

use crate::rules::{regex_notation_error, regex_source};

#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ExfiltrationMode {
    Off,
    #[default]
    Warn,
    Redact,
    Block,
}

impl ExfiltrationMode {
    pub const ALL: [Self; 4] = [Self::Off, Self::Warn, Self::Redact, Self::Block];

    pub fn label(self) -> &'static str {
        match self {
            Self::Off => "Off",
            Self::Warn => "Warn only",
            Self::Redact => "Redact before sending",
            Self::Block => "Block transmission",
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct AutoResponseRule {
    pub name: String,
    pub enabled: bool,
    pub method: String,
    pub host: String,
    pub path: String,
    pub status_code: u16,
    pub content_type: String,
    pub body: String,
}

impl AutoResponseRule {
    pub fn validate(&self) -> Result<()> {
        anyhow::ensure!(
            !self.name.trim().is_empty(),
            "auto response name is required"
        );
        anyhow::ensure!(
            !self.host.trim().is_empty(),
            "auto response host is required"
        );
        anyhow::ensure!(
            self.path.starts_with('/') || regex_source(&self.path).is_some(),
            "auto response path must start with / or re:"
        );
        anyhow::ensure!(
            (100..=599).contains(&self.status_code),
            "auto response status must be between 100 and 599"
        );
        anyhow::ensure!(
            !self.content_type.trim().is_empty(),
            "auto response content type is required"
        );
        validate_regex_field("auto response method", &self.method)?;
        validate_regex_field("auto response host", &self.host)?;
        validate_regex_field("auto response path", &self.path)?;
        Ok(())
    }
}

impl Default for AutoResponseRule {
    fn default() -> Self {
        Self {
            name: "Auto response 1".to_owned(),
            enabled: false,
            method: String::new(),
            host: "api.example.com".to_owned(),
            path: "/api/login".to_owned(),
            status_code: 200,
            content_type: "application/json".to_owned(),
            body: "{\n  \"ok\": true\n}".to_owned(),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct ResponseRewriteRule {
    pub name: String,
    pub host: String,
    pub find_text: String,
    pub replace_text: String,
}

impl ResponseRewriteRule {
    pub fn validate(&self) -> Result<()> {
        anyhow::ensure!(
            !self.host.trim().is_empty(),
            "response rewrite host is required"
        );
        anyhow::ensure!(
            !self.find_text.is_empty(),
            "response rewrite find text is required"
        );
        validate_regex_field("response rewrite host", &self.host)?;
        validate_regex_field("response rewrite find text", &self.find_text)?;
        Ok(())
    }
}

impl Default for ResponseRewriteRule {
    fn default() -> Self {
        Self {
            name: "Response rewrite 1".to_owned(),
            host: "*".to_owned(),
            find_text: "user123".to_owned(),
            replace_text: "admin123".to_owned(),
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TableColorPreset {
    #[default]
    HttpStatus,
    NoColors,
    Custom,
}

impl TableColorPreset {
    pub const ALL: [Self; 3] = [Self::HttpStatus, Self::NoColors, Self::Custom];

    pub fn label(self) -> &'static str {
        match self {
            Self::HttpStatus => "HTTP status (default)",
            Self::NoColors => "No table colors",
            Self::Custom => "Custom",
        }
    }

    pub fn rules(self) -> Option<Vec<TableColorRule>> {
        match self {
            Self::HttpStatus => Some(vec![
                TableColorRule {
                    name: "Server errors".into(),
                    field: TableColorField::StatusCode,
                    pattern: "5xx".into(),
                    target: TableColorTarget::EntireRow,
                    color: [255, 218, 218],
                    ..Default::default()
                },
                TableColorRule {
                    name: "Client errors".into(),
                    field: TableColorField::StatusCode,
                    pattern: "4xx".into(),
                    target: TableColorTarget::MatchedColumn,
                    color: [255, 241, 184],
                    ..Default::default()
                },
                TableColorRule {
                    name: "Redirects".into(),
                    field: TableColorField::StatusCode,
                    pattern: "3xx".into(),
                    target: TableColorTarget::MatchedColumn,
                    color: [218, 235, 255],
                    ..Default::default()
                },
            ]),
            Self::NoColors => Some(Vec::new()),
            Self::Custom => None,
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TableColorField {
    #[default]
    Host,
    StatusCode,
}

impl TableColorField {
    pub const ALL: [Self; 2] = [Self::Host, Self::StatusCode];

    pub fn label(self) -> &'static str {
        match self {
            Self::Host => "Host",
            Self::StatusCode => "Status code",
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TableColorTarget {
    #[default]
    EntireRow,
    MatchedColumn,
}

impl TableColorTarget {
    pub const ALL: [Self; 2] = [Self::EntireRow, Self::MatchedColumn];

    pub fn label(self) -> &'static str {
        match self {
            Self::EntireRow => "Entire row",
            Self::MatchedColumn => "Matched column",
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct TableColorRule {
    pub name: String,
    pub enabled: bool,
    pub field: TableColorField,
    pub pattern: String,
    pub target: TableColorTarget,
    pub color: [u8; 3],
}

impl TableColorRule {
    pub fn validate(&self) -> Result<()> {
        anyhow::ensure!(!self.name.trim().is_empty(), "table color name is required");
        anyhow::ensure!(
            !self.pattern.trim().is_empty(),
            "table color match value is required"
        );
        validate_regex_field("table color match", &self.pattern)?;
        if self.field == TableColorField::StatusCode
            && self
                .pattern
                .chars()
                .all(|character| character.is_ascii_digit())
        {
            let status = self.pattern.parse::<u16>().unwrap_or_default();
            anyhow::ensure!(
                (100..=599).contains(&status),
                "exact status color matches must be between 100 and 599"
            );
        }
        Ok(())
    }
}

impl Default for TableColorRule {
    fn default() -> Self {
        Self {
            name: "Host color".into(),
            enabled: true,
            field: TableColorField::Host,
            pattern: "*.example.com".into(),
            target: TableColorTarget::MatchedColumn,
            color: [218, 235, 255],
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct AppSettings {
    pub capture_host: String,
    pub capture_port: u16,
    pub enable_https_interception: bool,
    pub auto_configure_system_proxy: bool,
    pub auto_install_ca: bool,
    pub start_with_windows: bool,
    pub auto_connect: bool,
    pub threat_detection_enabled: bool,
    pub idle_warning_minutes: u64,
    pub baseline_learning_enabled: bool,
    pub bypass_radar_enabled: bool,
    pub exfiltration_guard_mode: ExfiltrationMode,
    pub exfiltration_trusted_hosts: Vec<String>,
    pub host_intelligence_enabled: bool,
    pub protobuf_descriptor_file: String,
    pub table_color_preset: TableColorPreset,
    pub table_color_rules: Vec<TableColorRule>,
    pub theme: String,
    pub autosave_interval_seconds: u64,
    pub body_memory_limit_bytes: usize,
    pub max_session_count: usize,
    pub hidden_hosts: Vec<String>,
    pub auto_response_rules: Vec<AutoResponseRule>,
    pub response_rewrite_rules: Vec<ResponseRewriteRule>,
}

impl Default for AppSettings {
    fn default() -> Self {
        let table_color_preset = TableColorPreset::HttpStatus;
        let table_color_rules = table_color_preset.rules().unwrap();
        Self {
            capture_host: "127.0.0.1".to_owned(),
            capture_port: 8899,
            enable_https_interception: true,
            auto_configure_system_proxy: cfg!(windows),
            auto_install_ca: cfg!(windows),
            start_with_windows: false,
            auto_connect: false,
            threat_detection_enabled: true,
            idle_warning_minutes: 5,
            baseline_learning_enabled: false,
            bypass_radar_enabled: cfg!(windows),
            exfiltration_guard_mode: ExfiltrationMode::Warn,
            exfiltration_trusted_hosts: Vec::new(),
            host_intelligence_enabled: false,
            protobuf_descriptor_file: String::new(),
            table_color_preset,
            table_color_rules,
            theme: "system".to_owned(),
            autosave_interval_seconds: 30,
            body_memory_limit_bytes: 1_048_576,
            max_session_count: 50_000,
            hidden_hosts: vec!["detectportal.firefox.com".to_owned()],
            auto_response_rules: Vec::new(),
            response_rewrite_rules: Vec::new(),
        }
    }
}

impl AppSettings {
    pub fn apply_table_color_preset(&mut self, preset: TableColorPreset) {
        self.table_color_preset = preset;
        if let Some(rules) = preset.rules() {
            self.table_color_rules = rules;
        }
    }

    pub fn load_or_default() -> Result<Self> {
        let paths = AppPaths::discover()?;
        paths.ensure()?;
        if !paths.settings_file.exists() {
            let settings = Self::default();
            settings.save()?;
            return Ok(settings);
        }
        let json = fs::read_to_string(&paths.settings_file)
            .with_context(|| format!("could not read {}", paths.settings_file.display()))?;
        let settings: Self = serde_json::from_str(&json).context("settings.json is invalid")?;
        settings.validate()?;
        Ok(settings)
    }

    pub fn save(&self) -> Result<()> {
        self.validate()?;
        let paths = AppPaths::discover()?;
        paths.ensure()?;
        let temporary = paths.settings_file.with_extension("json.tmp");
        fs::write(&temporary, serde_json::to_vec_pretty(self)?)?;
        fs::rename(&temporary, &paths.settings_file)?;
        Ok(())
    }

    pub fn validate(&self) -> Result<()> {
        anyhow::ensure!(
            !self.capture_host.trim().is_empty(),
            "capture host is required"
        );
        anyhow::ensure!(
            self.capture_port > 0,
            "capture port must be between 1 and 65535"
        );
        anyhow::ensure!(
            matches!(self.theme.as_str(), "system" | "dark" | "light"),
            "theme must be system, dark, or light"
        );
        anyhow::ensure!(
            self.autosave_interval_seconds >= 5,
            "autosave interval must be at least 5 seconds"
        );
        anyhow::ensure!(
            (1..=120).contains(&self.idle_warning_minutes),
            "idle warning threshold must be between 1 and 120 minutes"
        );
        anyhow::ensure!(
            self.max_session_count > 0,
            "maximum session count must be positive"
        );
        anyhow::ensure!(
            self.hidden_hosts.iter().all(|host| !host.trim().is_empty()),
            "hidden host entries cannot be blank"
        );
        for host in &self.hidden_hosts {
            validate_regex_field("hidden host", host)?;
        }
        anyhow::ensure!(
            self.exfiltration_trusted_hosts
                .iter()
                .all(|host| !host.trim().is_empty()),
            "trusted exfiltration host entries cannot be blank"
        );
        for host in &self.exfiltration_trusted_hosts {
            validate_regex_field("trusted exfiltration host", host)?;
        }
        for rule in &self.auto_response_rules {
            rule.validate()?;
        }
        for rule in &self.response_rewrite_rules {
            rule.validate()?;
        }
        for rule in &self.table_color_rules {
            rule.validate()?;
        }
        Ok(())
    }
}

fn validate_regex_field(name: &str, value: &str) -> Result<()> {
    if let Some(error) = regex_notation_error(value) {
        anyhow::bail!("{name} regex is invalid: {error}");
    }
    Ok(())
}

#[derive(Clone, Debug)]
pub struct AppPaths {
    pub data_dir: PathBuf,
    pub settings_file: PathBuf,
    pub certificates_dir: PathBuf,
    pub bodies_dir: PathBuf,
    pub sessions_dir: PathBuf,
    pub baselines_file: PathBuf,
    pub dossiers_file: PathBuf,
    pub capsules_dir: PathBuf,
}

impl AppPaths {
    pub fn discover() -> Result<Self> {
        let dirs = ProjectDirs::from("com", "HTTP Whisper", "HTTP Whisper")
            .context("application data directory is unavailable")?;
        let data_dir = dirs.data_local_dir().to_path_buf();
        Ok(Self {
            settings_file: data_dir.join("settings.json"),
            certificates_dir: data_dir.join("certificates"),
            bodies_dir: data_dir.join("bodies"),
            sessions_dir: data_dir.join("sessions"),
            baselines_file: data_dir.join("baselines.json"),
            dossiers_file: data_dir.join("host-dossiers.json"),
            capsules_dir: data_dir.join("capsules"),
            data_dir,
        })
    }

    pub fn ensure(&self) -> Result<()> {
        for path in [
            &self.data_dir,
            &self.certificates_dir,
            &self.bodies_dir,
            &self.sessions_dir,
            &self.capsules_dir,
        ] {
            fs::create_dir_all(path)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_invalid_rules() {
        let mut settings = AppSettings::default();
        settings.response_rewrite_rules.push(ResponseRewriteRule {
            find_text: String::new(),
            ..Default::default()
        });
        assert!(settings.validate().is_err());
    }

    #[test]
    fn response_rewrite_requires_a_host() {
        let mut settings = AppSettings::default();
        settings.response_rewrite_rules.push(ResponseRewriteRule {
            host: String::new(),
            ..Default::default()
        });
        assert!(settings.validate().is_err());
    }

    #[test]
    fn existing_global_rewrites_migrate_to_all_hosts() {
        let rule: ResponseRewriteRule =
            serde_json::from_str(r#"{"find_text":"user","replace_text":"admin"}"#).unwrap();
        assert_eq!(rule.host, "*");
    }

    #[test]
    fn startup_options_default_to_disabled_for_existing_settings() {
        let settings: AppSettings = serde_json::from_str("{}").unwrap();
        assert!(!settings.start_with_windows);
        assert!(!settings.auto_connect);
        assert!(settings.threat_detection_enabled);
        assert_eq!(settings.idle_warning_minutes, 5);
        assert!(!settings.baseline_learning_enabled);
        assert_eq!(settings.bypass_radar_enabled, cfg!(windows));
        assert_eq!(settings.exfiltration_guard_mode, ExfiltrationMode::Warn);
        assert!(settings.exfiltration_trusted_hosts.is_empty());
        assert!(!settings.host_intelligence_enabled);
        assert!(settings.protobuf_descriptor_file.is_empty());
        assert_eq!(settings.table_color_preset, TableColorPreset::HttpStatus);
        assert_eq!(settings.table_color_rules.len(), 3);
        assert_eq!(settings.table_color_rules[0].pattern, "5xx");
    }

    #[test]
    fn table_color_presets_apply_rules_and_custom_preserves_them() {
        let mut settings = AppSettings::default();
        settings.apply_table_color_preset(TableColorPreset::NoColors);
        assert!(settings.table_color_rules.is_empty());

        settings.table_color_rules.push(TableColorRule {
            color: [1, 2, 3],
            ..Default::default()
        });
        settings.apply_table_color_preset(TableColorPreset::Custom);

        let json = serde_json::to_string(&settings).unwrap();
        let restored: AppSettings = serde_json::from_str(&json).unwrap();
        assert_eq!(restored.table_color_preset, TableColorPreset::Custom);
        assert_eq!(restored.table_color_rules[0].color, [1, 2, 3]);
    }

    #[test]
    fn rejects_invalid_table_color_rules() {
        let mut settings = AppSettings::default();
        settings.table_color_rules.push(TableColorRule {
            pattern: "re:(unclosed".into(),
            ..Default::default()
        });
        assert!(settings.validate().is_err());
    }

    #[cfg(not(windows))]
    #[test]
    fn linux_defaults_to_manual_system_integration() {
        let settings = AppSettings::default();
        assert!(!settings.auto_configure_system_proxy);
        assert!(!settings.auto_install_ca);
        assert!(!settings.start_with_windows);
    }

    #[test]
    fn rejects_invalid_regex_notation() {
        let mut settings = AppSettings::default();
        settings.auto_response_rules.push(AutoResponseRule {
            host: "re:(unclosed".into(),
            ..Default::default()
        });
        assert!(settings.validate().is_err());
    }
}
