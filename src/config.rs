use std::{fs, path::PathBuf};

use anyhow::{Context, Result};
use directories::ProjectDirs;
use serde::{Deserialize, Serialize};

use crate::rules::{regex_notation_error, regex_source};

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
        Self {
            capture_host: "127.0.0.1".to_owned(),
            capture_port: 8899,
            enable_https_interception: true,
            auto_configure_system_proxy: true,
            auto_install_ca: true,
            start_with_windows: false,
            auto_connect: false,
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
        for rule in &self.auto_response_rules {
            rule.validate()?;
        }
        for rule in &self.response_rewrite_rules {
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
}

impl AppPaths {
    pub fn discover() -> Result<Self> {
        let dirs = ProjectDirs::from("com", "HTTP Whisper", "HTTP Whisper")
            .context("Windows application data directory is unavailable")?;
        let data_dir = dirs.data_local_dir().to_path_buf();
        Ok(Self {
            settings_file: data_dir.join("settings.json"),
            certificates_dir: data_dir.join("certificates"),
            bodies_dir: data_dir.join("bodies"),
            sessions_dir: data_dir.join("sessions"),
            data_dir,
        })
    }

    pub fn ensure(&self) -> Result<()> {
        for path in [
            &self.data_dir,
            &self.certificates_dir,
            &self.bodies_dir,
            &self.sessions_dir,
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
