use std::{net::SocketAddr, time::Duration};

use chrono::{DateTime, Utc};

#[derive(Clone, Debug, Default)]
pub struct ProcessIdentity {
    pub pid: Option<u32>,
    pub name: String,
    pub path: String,
    pub parent_pid: Option<u32>,
    pub parent_name: String,
    pub executable_sha256: String,
    pub publisher: String,
    pub signature_valid: Option<bool>,
    pub started_at: Option<DateTime<Utc>>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct BypassConnection {
    pub local_addr: String,
    pub remote_addr: String,
    pub remote_port: u16,
    pub pid: u32,
    pub process: String,
    pub process_path: String,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
    pub observations: u64,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct DnsObservation {
    pub host: String,
    pub address: String,
    pub observed_at: DateTime<Utc>,
}

#[cfg(windows)]
mod implementation {
    use std::os::windows::process::CommandExt;
    use std::{
        collections::HashMap,
        ffi::c_void,
        fs::File,
        io::Read,
        mem::size_of,
        net::{Ipv4Addr, SocketAddr},
        path::Path,
        process::Command,
        slice,
        sync::{Mutex, OnceLock},
        time::{Duration, Instant},
    };

    use chrono::Utc;
    use sha2::{Digest, Sha256};

    use windows::{
        Win32::{
            Foundation::{CloseHandle, FILETIME, HANDLE, HWND},
            NetworkManagement::IpHelper::{GetTcpTable2, MIB_TCPTABLE2},
            Security::WinTrust::{
                WINTRUST_ACTION_GENERIC_VERIFY_V2, WINTRUST_DATA, WINTRUST_DATA_0,
                WINTRUST_FILE_INFO, WTD_CACHE_ONLY_URL_RETRIEVAL, WTD_CHOICE_FILE, WTD_REVOKE_NONE,
                WTD_STATEACTION_IGNORE, WTD_UI_NONE, WinVerifyTrust,
            },
            Storage::FileSystem::{GetFileVersionInfoSizeW, GetFileVersionInfoW, VerQueryValueW},
            System::{
                Diagnostics::ToolHelp::{
                    CreateToolhelp32Snapshot, PROCESSENTRY32W, Process32FirstW, Process32NextW,
                    TH32CS_SNAPPROCESS,
                },
                SystemInformation::GetTickCount,
                Threading::{
                    GetProcessTimes, OpenProcess, PROCESS_NAME_WIN32,
                    PROCESS_QUERY_LIMITED_INFORMATION, QueryFullProcessImageNameW,
                },
            },
            UI::Input::KeyboardAndMouse::{GetLastInputInfo, LASTINPUTINFO},
        },
        core::{PCWSTR, PWSTR},
    };

    use super::{BypassConnection, DnsObservation, ProcessIdentity};

    const NO_ERROR: u32 = 0;
    const ERROR_INSUFFICIENT_BUFFER: u32 = 122;
    const CACHE_TTL: Duration = Duration::from_secs(60);
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;

    static PROCESS_CACHE: OnceLock<Mutex<HashMap<SocketAddr, (Instant, ProcessIdentity)>>> =
        OnceLock::new();
    static PID_CACHE: OnceLock<Mutex<HashMap<u32, (Instant, ProcessIdentity)>>> = OnceLock::new();

    pub fn resolve_client(address: SocketAddr) -> ProcessIdentity {
        let cache = PROCESS_CACHE.get_or_init(|| Mutex::new(HashMap::new()));
        if let Ok(cache) = cache.lock()
            && let Some((captured, identity)) = cache.get(&address)
            && captured.elapsed() < CACHE_TTL
        {
            return identity.clone();
        }

        let identity = owning_pid(address.port())
            .map(cached_process_identity)
            .unwrap_or_default();
        if let Ok(mut cache) = cache.lock() {
            if cache.len() >= 1_024 {
                cache.retain(|_, (captured, _)| captured.elapsed() < CACHE_TTL);
            }
            cache.insert(address, (Instant::now(), identity.clone()));
        }
        identity
    }

    fn owning_pid(port: u16) -> Option<u32> {
        tcp_rows().into_iter().find_map(|row| {
            let local_port = u16::from_be((row.dwLocalPort & 0xffff) as u16);
            (local_port == port).then_some(row.dwOwningPid)
        })
    }

    fn tcp_rows() -> Vec<windows::Win32::NetworkManagement::IpHelper::MIB_TCPROW2> {
        let mut bytes = 0u32;
        let first = unsafe { GetTcpTable2(None, &mut bytes, false) };
        if first != ERROR_INSUFFICIENT_BUFFER || bytes == 0 {
            return Vec::new();
        }
        let words = (bytes as usize).div_ceil(size_of::<u32>());
        let mut buffer = vec![0u32; words];
        let table = buffer.as_mut_ptr().cast::<MIB_TCPTABLE2>();
        let result = unsafe { GetTcpTable2(Some(table), &mut bytes, false) };
        if result != NO_ERROR {
            return Vec::new();
        }
        let rows = unsafe {
            slice::from_raw_parts((*table).table.as_ptr(), (*table).dwNumEntries as usize)
        };
        rows.to_vec()
    }

    fn process_identity(pid: u32) -> ProcessIdentity {
        let Ok(handle) = (unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) })
        else {
            return ProcessIdentity {
                pid: Some(pid),
                ..Default::default()
            };
        };
        let mut buffer = vec![0u16; 32_768];
        let mut length = buffer.len() as u32;
        let result = unsafe {
            QueryFullProcessImageNameW(
                handle,
                PROCESS_NAME_WIN32,
                PWSTR(buffer.as_mut_ptr()),
                &mut length,
            )
        };
        let started_at = process_started_at(handle);
        let _ = unsafe { CloseHandle(handle) };
        let path = result
            .ok()
            .map(|_| String::from_utf16_lossy(&buffer[..length as usize]))
            .unwrap_or_default();
        let name = Path::new(&path)
            .file_name()
            .and_then(|value| value.to_str())
            .unwrap_or_default()
            .to_owned();
        let (parent_pid, parent_name) = process_parent(pid).unwrap_or_default();
        ProcessIdentity {
            pid: Some(pid),
            name,
            parent_pid,
            parent_name,
            executable_sha256: file_sha256(&path),
            publisher: file_company(&path),
            signature_valid: (!path.is_empty()).then(|| signature_is_valid(&path)),
            started_at,
            path,
        }
    }

    fn basic_process_identity(pid: u32) -> ProcessIdentity {
        let Ok(handle) = (unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) })
        else {
            return ProcessIdentity {
                pid: Some(pid),
                ..Default::default()
            };
        };
        let mut buffer = vec![0u16; 32_768];
        let mut length = buffer.len() as u32;
        let path = unsafe {
            QueryFullProcessImageNameW(
                handle,
                PROCESS_NAME_WIN32,
                PWSTR(buffer.as_mut_ptr()),
                &mut length,
            )
        }
        .ok()
        .map(|_| String::from_utf16_lossy(&buffer[..length as usize]))
        .unwrap_or_default();
        let _ = unsafe { CloseHandle(handle) };
        let name = Path::new(&path)
            .file_name()
            .and_then(|value| value.to_str())
            .unwrap_or_default()
            .to_owned();
        ProcessIdentity {
            pid: Some(pid),
            name,
            path,
            ..Default::default()
        }
    }

    fn process_started_at(handle: HANDLE) -> Option<chrono::DateTime<Utc>> {
        let mut created = FILETIME::default();
        let mut exited = FILETIME::default();
        let mut kernel = FILETIME::default();
        let mut user = FILETIME::default();
        unsafe { GetProcessTimes(handle, &mut created, &mut exited, &mut kernel, &mut user) }
            .ok()?;
        let ticks = (u64::from(created.dwHighDateTime) << 32) | u64::from(created.dwLowDateTime);
        const UNIX_EPOCH_TICKS: u64 = 116_444_736_000_000_000;
        let unix_ticks = ticks.checked_sub(UNIX_EPOCH_TICKS)?;
        let seconds = (unix_ticks / 10_000_000) as i64;
        let nanos = ((unix_ticks % 10_000_000) * 100) as u32;
        chrono::DateTime::from_timestamp(seconds, nanos)
    }

    fn cached_process_identity(pid: u32) -> ProcessIdentity {
        let cache = PID_CACHE.get_or_init(|| Mutex::new(HashMap::new()));
        if let Ok(cache) = cache.lock()
            && let Some((captured, identity)) = cache.get(&pid)
            && captured.elapsed() < CACHE_TTL
        {
            return identity.clone();
        }
        let identity = process_identity(pid);
        if let Ok(mut cache) = cache.lock() {
            if cache.len() >= 512 {
                cache.retain(|_, (captured, _)| captured.elapsed() < CACHE_TTL);
            }
            cache.insert(pid, (Instant::now(), identity.clone()));
        }
        identity
    }

    fn process_parent(pid: u32) -> Option<(Option<u32>, String)> {
        let snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) }.ok()?;
        let mut entry = PROCESSENTRY32W {
            dwSize: size_of::<PROCESSENTRY32W>() as u32,
            ..Default::default()
        };
        let mut parent_pid = None;
        let mut names = HashMap::new();
        if unsafe { Process32FirstW(snapshot, &mut entry) }.is_ok() {
            loop {
                let length = entry
                    .szExeFile
                    .iter()
                    .position(|value| *value == 0)
                    .unwrap_or(entry.szExeFile.len());
                names.insert(
                    entry.th32ProcessID,
                    String::from_utf16_lossy(&entry.szExeFile[..length]),
                );
                if entry.th32ProcessID == pid {
                    parent_pid =
                        (entry.th32ParentProcessID != 0).then_some(entry.th32ParentProcessID);
                }
                if unsafe { Process32NextW(snapshot, &mut entry) }.is_err() {
                    break;
                }
            }
        }
        let _ = unsafe { CloseHandle(snapshot) };
        let parent_name = parent_pid
            .and_then(|parent| names.get(&parent).cloned())
            .unwrap_or_default();
        Some((parent_pid, parent_name))
    }

    fn file_sha256(path: &str) -> String {
        let Ok(mut file) = File::open(path) else {
            return String::new();
        };
        let mut hasher = Sha256::new();
        let mut buffer = [0_u8; 64 * 1024];
        loop {
            let Ok(read) = file.read(&mut buffer) else {
                return String::new();
            };
            if read == 0 {
                break;
            }
            hasher.update(&buffer[..read]);
        }
        hex::encode(hasher.finalize())
    }

    fn wide(value: &str) -> Vec<u16> {
        value.encode_utf16().chain(std::iter::once(0)).collect()
    }

    fn file_company(path: &str) -> String {
        let path = wide(path);
        let size = unsafe { GetFileVersionInfoSizeW(PCWSTR(path.as_ptr()), None) };
        if size == 0 {
            return String::new();
        }
        let mut data = vec![0_u8; size as usize];
        if unsafe {
            GetFileVersionInfoW(PCWSTR(path.as_ptr()), None, size, data.as_mut_ptr().cast())
        }
        .is_err()
        {
            return String::new();
        }
        let translation = wide("\\VarFileInfo\\Translation");
        let mut translation_ptr: *mut c_void = std::ptr::null_mut();
        let mut translation_len = 0_u32;
        let found = unsafe {
            VerQueryValueW(
                data.as_ptr().cast(),
                PCWSTR(translation.as_ptr()),
                &mut translation_ptr,
                &mut translation_len,
            )
        };
        let (language, codepage) = if found.as_bool() && translation_len >= 4 {
            let values = unsafe { slice::from_raw_parts(translation_ptr.cast::<u16>(), 2) };
            (values[0], values[1])
        } else {
            (0x0409, 0x04b0)
        };
        let query = wide(&format!(
            "\\StringFileInfo\\{language:04x}{codepage:04x}\\CompanyName"
        ));
        let mut value_ptr: *mut c_void = std::ptr::null_mut();
        let mut value_len = 0_u32;
        if !unsafe {
            VerQueryValueW(
                data.as_ptr().cast(),
                PCWSTR(query.as_ptr()),
                &mut value_ptr,
                &mut value_len,
            )
        }
        .as_bool()
            || value_len == 0
        {
            return String::new();
        }
        let value = unsafe {
            slice::from_raw_parts(
                value_ptr.cast::<u16>(),
                value_len.saturating_sub(1) as usize,
            )
        };
        String::from_utf16_lossy(value)
    }

    fn signature_is_valid(path: &str) -> bool {
        let path = wide(path);
        let mut file = WINTRUST_FILE_INFO {
            cbStruct: size_of::<WINTRUST_FILE_INFO>() as u32,
            pcwszFilePath: PCWSTR(path.as_ptr()),
            hFile: HANDLE::default(),
            pgKnownSubject: std::ptr::null_mut(),
        };
        let mut data = WINTRUST_DATA {
            cbStruct: size_of::<WINTRUST_DATA>() as u32,
            dwUIChoice: WTD_UI_NONE,
            fdwRevocationChecks: WTD_REVOKE_NONE,
            dwUnionChoice: WTD_CHOICE_FILE,
            Anonymous: WINTRUST_DATA_0 { pFile: &mut file },
            dwStateAction: WTD_STATEACTION_IGNORE,
            dwProvFlags: WTD_CACHE_ONLY_URL_RETRIEVAL,
            ..Default::default()
        };
        let mut action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
        unsafe {
            WinVerifyTrust(
                HWND::default(),
                &mut action,
                (&mut data as *mut WINTRUST_DATA).cast(),
            ) == 0
        }
    }

    pub fn snapshot_bypass_connections(proxy_port: u16) -> Vec<BypassConnection> {
        let current_pid = std::process::id();
        tcp_rows()
            .into_iter()
            .filter(|row| row.dwState == 5 && row.dwOwningPid != current_pid)
            .filter_map(|row| {
                let local_port = u16::from_be((row.dwLocalPort & 0xffff) as u16);
                let remote_port = u16::from_be((row.dwRemotePort & 0xffff) as u16);
                let local_ip = Ipv4Addr::from(u32::from_be(row.dwLocalAddr));
                let remote_ip = Ipv4Addr::from(u32::from_be(row.dwRemoteAddr));
                if remote_ip.is_loopback()
                    || remote_ip.is_unspecified()
                    || (local_ip.is_loopback() && remote_port == proxy_port)
                {
                    return None;
                }
                let process = basic_process_identity(row.dwOwningPid);
                let now = Utc::now();
                Some(BypassConnection {
                    local_addr: format!("{local_ip}:{local_port}"),
                    remote_addr: remote_ip.to_string(),
                    remote_port,
                    pid: row.dwOwningPid,
                    process: process.name,
                    process_path: process.path,
                    first_seen: now,
                    last_seen: now,
                    observations: 1,
                })
            })
            .collect()
    }

    pub fn snapshot_dns_cache() -> Vec<DnsObservation> {
        let output = Command::new("powershell.exe")
            .args([
                "-NoLogo",
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                "Get-DnsClientCache | Where-Object { $_.Type -in 1,28 -and $_.Data } | Select-Object Entry,Data | ConvertTo-Json -Compress",
            ])
            .creation_flags(CREATE_NO_WINDOW)
            .output();
        let Ok(output) = output else {
            return Vec::new();
        };
        if !output.status.success() {
            return Vec::new();
        }
        let Ok(value) = serde_json::from_slice::<serde_json::Value>(&output.stdout) else {
            return Vec::new();
        };
        let values = match value {
            serde_json::Value::Array(values) => values,
            serde_json::Value::Object(_) => vec![value],
            _ => Vec::new(),
        };
        let now = Utc::now();
        values
            .into_iter()
            .filter_map(|value| {
                let host = value
                    .get("Entry")?
                    .as_str()?
                    .trim_end_matches('.')
                    .to_owned();
                let address = value.get("Data")?.as_str()?.to_owned();
                (!host.is_empty() && !address.is_empty()).then_some(DnsObservation {
                    host,
                    address,
                    observed_at: now,
                })
            })
            .collect()
    }

    pub fn idle_duration() -> Option<Duration> {
        let mut input = LASTINPUTINFO {
            cbSize: size_of::<LASTINPUTINFO>() as u32,
            dwTime: 0,
        };
        if !unsafe { GetLastInputInfo(&mut input) }.as_bool() {
            return None;
        }
        let elapsed_ms = unsafe { GetTickCount() }.wrapping_sub(input.dwTime);
        Some(Duration::from_millis(u64::from(elapsed_ms)))
    }

    #[cfg(test)]
    mod tests {
        use std::{net::TcpListener, thread, time::Duration};

        use super::{owning_pid, process_identity};

        #[test]
        fn resolves_the_process_that_owns_a_loopback_connection() {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let address = listener.local_addr().unwrap();
            let client = std::net::TcpStream::connect(address).unwrap();
            let (_server, client_address) = listener.accept().unwrap();
            let mut pid = None;
            for _ in 0..20 {
                pid = owning_pid(client_address.port());
                if pid.is_some() {
                    break;
                }
                thread::sleep(Duration::from_millis(10));
            }
            drop(client);
            assert_eq!(pid, Some(std::process::id()));
            let identity = process_identity(pid.unwrap());
            assert!(!identity.name.is_empty());
            assert!(!identity.path.is_empty());
            assert_eq!(identity.executable_sha256.len(), 64);
            assert!(identity.signature_valid.is_some());
            assert!(identity.started_at.is_some());
        }
    }
}

#[cfg(not(windows))]
mod implementation {
    use std::{net::SocketAddr, time::Duration};

    use super::ProcessIdentity;

    pub fn resolve_client(_address: SocketAddr) -> ProcessIdentity {
        ProcessIdentity::default()
    }

    pub fn idle_duration() -> Option<Duration> {
        None
    }

    pub fn snapshot_bypass_connections(_proxy_port: u16) -> Vec<super::BypassConnection> {
        Vec::new()
    }

    pub fn snapshot_dns_cache() -> Vec<super::DnsObservation> {
        Vec::new()
    }
}

pub fn resolve_client(address: SocketAddr) -> ProcessIdentity {
    implementation::resolve_client(address)
}

pub fn idle_duration() -> Option<Duration> {
    implementation::idle_duration()
}

pub fn snapshot_bypass_connections(proxy_port: u16) -> Vec<BypassConnection> {
    implementation::snapshot_bypass_connections(proxy_port)
}

pub fn snapshot_dns_cache() -> Vec<DnsObservation> {
    implementation::snapshot_dns_cache()
}
