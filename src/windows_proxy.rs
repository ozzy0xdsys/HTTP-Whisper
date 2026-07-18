#[cfg(windows)]
mod platform {
    use std::{
        env, fs,
        os::windows::process::CommandExt,
        path::{Path, PathBuf},
        process::Command,
    };

    use anyhow::{Context, Result, bail};
    use serde::{Deserialize, Serialize};
    use windows::Win32::{
        Foundation::{HWND, LPARAM, WPARAM},
        Networking::WinInet::InternetSetOptionW,
        UI::WindowsAndMessaging::{
            HWND_BROADCAST, SEND_MESSAGE_TIMEOUT_FLAGS, SMTO_ABORTIFHUNG, SendMessageTimeoutW,
            WM_SETTINGCHANGE,
        },
    };
    use winreg::{RegKey, enums::*};

    const INTERNET_SETTINGS: &str = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings";
    const WINDOWS_RUN: &str = r"Software\Microsoft\Windows\CurrentVersion\Run";
    const STARTUP_VALUE: &str = "HTTP Whisper";
    const FIREFOX_PROXY: &str = r"Software\Policies\Mozilla\Firefox\Proxy";
    const FIREFOX_CERTIFICATES: &str = r"Software\Policies\Mozilla\Firefox\Certificates";
    const FIREFOX_HELPER_ARGUMENT: &str = "--install-firefox-integration";
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;
    const SETTINGS_CHANGED: u32 = 39;
    const SETTINGS_REFRESH: u32 = 37;

    #[derive(Clone, Debug, Default, Serialize, Deserialize)]
    struct ProxySnapshot {
        proxy_enable: Option<u32>,
        proxy_server: Option<String>,
        proxy_override: Option<String>,
        auto_config_url: Option<String>,
        auto_detect: Option<u32>,
    }

    pub struct WindowsProxyManager {
        snapshot_file: PathBuf,
        active: bool,
    }

    impl WindowsProxyManager {
        pub fn new(snapshot_file: PathBuf) -> Self {
            Self {
                snapshot_file,
                active: false,
            }
        }

        pub fn recover_if_needed(&mut self) -> Result<bool> {
            if !self.snapshot_file.exists() {
                return Ok(false);
            }
            self.restore()
                .context("could not recover Windows proxy settings from the previous capture")?;
            Ok(true)
        }

        pub fn enable(&mut self, host: &str, port: u16) -> Result<()> {
            if self.active {
                return Ok(());
            }

            ensure_firefox_integration().context(
                "Firefox integration could not be installed; accept the Windows UAC prompt when starting capture",
            )?;

            let hkcu = RegKey::predef(HKEY_CURRENT_USER);
            let internet = hkcu
                .open_subkey_with_flags(INTERNET_SETTINGS, KEY_READ | KEY_WRITE)
                .context("cannot open the current user's Windows proxy settings for writing")?;
            let snapshot = ProxySnapshot {
                proxy_enable: read_dword(&internet, "ProxyEnable"),
                proxy_server: read_string(&internet, "ProxyServer"),
                proxy_override: read_string(&internet, "ProxyOverride"),
                auto_config_url: read_string(&internet, "AutoConfigURL"),
                auto_detect: read_dword(&internet, "AutoDetect"),
            };
            fs::write(&self.snapshot_file, serde_json::to_vec_pretty(&snapshot)?).with_context(
                || {
                    format!(
                        "cannot save the proxy recovery snapshot at {}",
                        self.snapshot_file.display()
                    )
                },
            )?;

            let endpoint = format!("{host}:{port}");
            let configure = || -> Result<()> {
                internet
                    .set_value("ProxyEnable", &1_u32)
                    .context("cannot enable the current user's Windows proxy")?;
                internet
                    .set_value("ProxyServer", &format!("http={endpoint};https={endpoint}"))
                    .context("cannot set the current user's HTTP/HTTPS proxy address")?;
                internet
                    .set_value("ProxyOverride", &"<local>")
                    .context("cannot set the Windows local-address proxy bypass")?;
                internet
                    .set_value("AutoDetect", &0_u32)
                    .context("cannot disable automatic proxy detection during capture")?;
                let _ = internet.delete_value("AutoConfigURL");
                Ok(())
            };
            if let Err(error) = configure() {
                let _ = self.restore_snapshot(&internet);
                return Err(error);
            }

            notify_settings_changed();
            self.active = true;
            Ok(())
        }

        pub fn restore(&mut self) -> Result<()> {
            if !self.snapshot_file.exists() {
                self.active = false;
                return Ok(());
            }
            let hkcu = RegKey::predef(HKEY_CURRENT_USER);
            let internet = hkcu
                .open_subkey_with_flags(INTERNET_SETTINGS, KEY_READ | KEY_WRITE)
                .context("cannot open the current user's Windows proxy settings for restoration")?;
            self.restore_snapshot(&internet)?;
            notify_settings_changed();
            fs::remove_file(&self.snapshot_file).with_context(|| {
                format!(
                    "restored the proxy but could not remove recovery snapshot {}",
                    self.snapshot_file.display()
                )
            })?;
            self.active = false;
            Ok(())
        }

        fn restore_snapshot(&self, internet: &RegKey) -> Result<()> {
            let snapshot: ProxySnapshot =
                serde_json::from_slice(&fs::read(&self.snapshot_file).with_context(|| {
                    format!(
                        "cannot read proxy recovery snapshot {}",
                        self.snapshot_file.display()
                    )
                })?)
                .context("saved proxy snapshot is invalid")?;
            restore_dword(internet, "ProxyEnable", snapshot.proxy_enable)?;
            restore_string(internet, "ProxyServer", snapshot.proxy_server.as_deref())?;
            restore_string(
                internet,
                "ProxyOverride",
                snapshot.proxy_override.as_deref(),
            )?;
            restore_string(
                internet,
                "AutoConfigURL",
                snapshot.auto_config_url.as_deref(),
            )?;
            restore_dword(internet, "AutoDetect", snapshot.auto_detect)?;
            Ok(())
        }

        pub fn summary(&self) -> Result<String> {
            let key = RegKey::predef(HKEY_CURRENT_USER)
                .open_subkey(INTERNET_SETTINGS)
                .context("cannot read the configured Windows proxy")?;
            Ok(format!(
                "ProxyEnable={}, ProxyServer={}, Firefox=system proxy",
                read_dword(&key, "ProxyEnable").unwrap_or_default(),
                read_string(&key, "ProxyServer").unwrap_or_else(|| "<unset>".into())
            ))
        }
    }

    impl Drop for WindowsProxyManager {
        fn drop(&mut self) {
            if self.active {
                let _ = self.restore();
            }
        }
    }

    pub fn run_helper_from_args() -> Result<bool> {
        if env::args().nth(1).as_deref() != Some(FIREFOX_HELPER_ARGUMENT) {
            return Ok(false);
        }
        install_firefox_integration()
            .context("the elevated Firefox integration helper could not update its policy keys")?;
        Ok(true)
    }

    pub fn install_firefox_support() -> Result<()> {
        ensure_firefox_integration().context(
            "Firefox integration could not be installed; accept the Windows UAC prompt when prompted",
        )
    }

    pub fn configure_startup(enabled: bool) -> Result<()> {
        let hkcu = RegKey::predef(HKEY_CURRENT_USER);
        if enabled {
            let executable = env::current_exe()
                .context("cannot locate HTTP Whisper's executable for Windows startup")?;
            let (run, _) = hkcu
                .create_subkey(WINDOWS_RUN)
                .context("cannot open the current user's Windows startup registry key")?;
            run.set_value(STARTUP_VALUE, &startup_command(&executable))
                .context("cannot add HTTP Whisper to Windows startup")?;
        } else {
            match hkcu.open_subkey_with_flags(WINDOWS_RUN, KEY_WRITE) {
                Ok(run) => {
                    if let Err(error) = run.delete_value(STARTUP_VALUE)
                        && error.kind() != std::io::ErrorKind::NotFound
                    {
                        return Err(error)
                            .context("cannot remove HTTP Whisper from Windows startup");
                    }
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => {
                    return Err(error)
                        .context("cannot open the current user's Windows startup registry key");
                }
            }
        }
        Ok(())
    }

    fn startup_command(executable: &Path) -> String {
        format!(r#""{}""#, executable.display())
    }

    fn ensure_firefox_integration() -> Result<()> {
        if firefox_integration_is_installed() {
            return Ok(());
        }

        match install_firefox_integration() {
            Ok(()) => Ok(()),
            Err(error) if is_access_denied(&error) => run_elevated_firefox_helper(),
            Err(error) => Err(error),
        }
    }

    fn firefox_integration_is_installed() -> bool {
        let hkcu = RegKey::predef(HKEY_CURRENT_USER);
        let mode = hkcu
            .open_subkey(FIREFOX_PROXY)
            .ok()
            .and_then(|key| read_string(&key, "Mode"));
        let roots = hkcu
            .open_subkey(FIREFOX_CERTIFICATES)
            .ok()
            .and_then(|key| read_dword(&key, "ImportEnterpriseRoots"));
        mode.as_deref() == Some("system") && roots == Some(1)
    }

    fn install_firefox_integration() -> Result<()> {
        let hkcu = RegKey::predef(HKEY_CURRENT_USER);
        let (firefox_proxy, _) = hkcu
            .create_subkey(FIREFOX_PROXY)
            .context("cannot create the Firefox proxy policy registry key")?;
        let (firefox_certs, _) = hkcu
            .create_subkey(FIREFOX_CERTIFICATES)
            .context("cannot create the Firefox certificate policy registry key")?;
        firefox_proxy
            .set_value("Mode", &"system")
            .context("cannot make Firefox follow the Windows system proxy")?;
        firefox_proxy
            .set_value("Locked", &0_u32)
            .context("cannot leave the Firefox proxy control unlocked")?;
        firefox_certs
            .set_value("ImportEnterpriseRoots", &1_u32)
            .context("cannot enable Windows certificate trust in Firefox")?;
        Ok(())
    }

    fn run_elevated_firefox_helper() -> Result<()> {
        let executable = env::current_exe().context("cannot locate HTTP Whisper's executable")?;
        let executable = powershell_literal(&executable.to_string_lossy());
        let script = format!(
            "$ErrorActionPreference='Stop'; try {{ $p=Start-Process -FilePath {executable} -ArgumentList '{FIREFOX_HELPER_ARGUMENT}' -Verb RunAs -Wait -PassThru; exit $p.ExitCode }} catch {{ Write-Error $_.Exception.Message; exit 1223 }}"
        );
        let output = Command::new("powershell.exe")
            .args([
                "-NoLogo",
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                &script,
            ])
            .creation_flags(CREATE_NO_WINDOW)
            .output()
            .context("could not start the Windows elevation prompt for Firefox integration")?;
        if !output.status.success() {
            let detail = String::from_utf8_lossy(&output.stderr);
            let detail = detail.trim();
            if detail.is_empty() {
                bail!("administrator approval was cancelled or the elevated helper failed")
            }
            bail!("administrator approval failed: {detail}")
        }
        if !firefox_integration_is_installed() {
            bail!("the elevated helper finished, but Firefox policy was not installed")
        }
        Ok(())
    }

    fn is_access_denied(error: &anyhow::Error) -> bool {
        error.chain().any(|cause| {
            cause
                .downcast_ref::<std::io::Error>()
                .is_some_and(|io| io.raw_os_error() == Some(5))
        })
    }

    fn powershell_literal(value: &str) -> String {
        format!("'{}'", value.replace('\'', "''"))
    }

    fn read_dword(key: &RegKey, name: &str) -> Option<u32> {
        key.get_value(name).ok()
    }

    fn read_string(key: &RegKey, name: &str) -> Option<String> {
        key.get_value(name).ok()
    }

    fn restore_dword(key: &RegKey, name: &str, value: Option<u32>) -> Result<()> {
        if let Some(value) = value {
            key.set_value(name, &value)
                .with_context(|| format!("cannot restore Windows proxy value {name}"))?;
        } else {
            let _ = key.delete_value(name);
        }
        Ok(())
    }

    fn restore_string(key: &RegKey, name: &str, value: Option<&str>) -> Result<()> {
        if let Some(value) = value {
            key.set_value(name, &value)
                .with_context(|| format!("cannot restore Windows proxy value {name}"))?;
        } else {
            let _ = key.delete_value(name);
        }
        Ok(())
    }

    fn notify_settings_changed() {
        unsafe {
            let _ = InternetSetOptionW(None, SETTINGS_CHANGED, None, 0);
            let _ = InternetSetOptionW(None, SETTINGS_REFRESH, None, 0);
            let mut result = 0_usize;
            let _ = SendMessageTimeoutW(
                HWND(HWND_BROADCAST.0),
                WM_SETTINGCHANGE,
                WPARAM(0),
                LPARAM(0),
                SEND_MESSAGE_TIMEOUT_FLAGS(SMTO_ABORTIFHUNG.0),
                5_000,
                Some(&mut result),
            );
        }
    }

    pub use WindowsProxyManager as Manager;

    #[cfg(test)]
    mod tests {
        use std::io;

        use anyhow::Context;

        use super::{is_access_denied, powershell_literal, startup_command};

        #[test]
        fn escapes_powershell_paths() {
            assert_eq!(
                powershell_literal(r"C:\User's App\app.exe"),
                r"'C:\User''s App\app.exe'"
            );
        }

        #[test]
        fn detects_access_denied_through_error_context() {
            let error = Err::<(), _>(io::Error::from_raw_os_error(5))
                .context("Firefox policy write failed")
                .unwrap_err();
            assert!(is_access_denied(&error));
        }

        #[test]
        fn quotes_windows_startup_executable_paths() {
            assert_eq!(
                startup_command(std::path::Path::new(
                    r"C:\Program Files\HTTP Whisper\HTTP-Whisper.exe"
                )),
                r#""C:\Program Files\HTTP Whisper\HTTP-Whisper.exe""#
            );
        }
    }
}

#[cfg(not(windows))]
mod platform {
    use anyhow::{Result, bail};
    use std::path::PathBuf;

    pub struct Manager;
    impl Manager {
        pub fn new(_snapshot_file: PathBuf) -> Self {
            Self
        }
        pub fn recover_if_needed(&mut self) -> Result<bool> {
            Ok(false)
        }
        pub fn enable(&mut self, _host: &str, _port: u16) -> Result<()> {
            bail!(
                "automatic system proxy configuration is only available on Windows; disable it and configure your Linux desktop or browser manually"
            )
        }
        pub fn restore(&mut self) -> Result<()> {
            Ok(())
        }
        pub fn summary(&self) -> Result<String> {
            Ok("system proxy unavailable".into())
        }
    }

    pub fn run_helper_from_args() -> Result<bool> {
        Ok(false)
    }

    pub fn install_firefox_support() -> Result<()> {
        bail!(
            "automatic Firefox trust installation is only available on Windows; install the CA from http://mitm.it/"
        )
    }

    pub fn configure_startup(_enabled: bool) -> Result<()> {
        Ok(())
    }

    #[cfg(test)]
    mod tests {
        use super::Manager;

        #[test]
        fn unsupported_linux_integrations_report_an_error() {
            let mut manager = Manager::new(std::path::PathBuf::from("proxy-restore.json"));
            assert!(manager.enable("127.0.0.1", 8899).is_err());
            assert!(super::install_firefox_support().is_err());
        }
    }
}

pub use platform::{
    Manager as WindowsProxyManager, configure_startup, install_firefox_support,
    run_helper_from_args,
};
