use std::{net::SocketAddr, time::Duration};

#[derive(Clone, Debug, Default)]
pub struct ProcessIdentity {
    pub pid: Option<u32>,
    pub name: String,
    pub path: String,
}

#[cfg(windows)]
mod implementation {
    use std::{
        collections::HashMap,
        mem::size_of,
        net::SocketAddr,
        path::Path,
        slice,
        sync::{Mutex, OnceLock},
        time::{Duration, Instant},
    };

    use windows::{
        Win32::{
            Foundation::CloseHandle,
            NetworkManagement::IpHelper::{GetTcpTable2, MIB_TCPTABLE2},
            System::{
                SystemInformation::GetTickCount,
                Threading::{
                    OpenProcess, PROCESS_NAME_WIN32, PROCESS_QUERY_LIMITED_INFORMATION,
                    QueryFullProcessImageNameW,
                },
            },
            UI::Input::KeyboardAndMouse::{GetLastInputInfo, LASTINPUTINFO},
        },
        core::PWSTR,
    };

    use super::ProcessIdentity;

    const NO_ERROR: u32 = 0;
    const ERROR_INSUFFICIENT_BUFFER: u32 = 122;
    const CACHE_TTL: Duration = Duration::from_secs(60);

    static PROCESS_CACHE: OnceLock<Mutex<HashMap<SocketAddr, (Instant, ProcessIdentity)>>> =
        OnceLock::new();

    pub fn resolve_client(address: SocketAddr) -> ProcessIdentity {
        let cache = PROCESS_CACHE.get_or_init(|| Mutex::new(HashMap::new()));
        if let Ok(cache) = cache.lock()
            && let Some((captured, identity)) = cache.get(&address)
            && captured.elapsed() < CACHE_TTL
        {
            return identity.clone();
        }

        let identity = owning_pid(address.port())
            .map(process_identity)
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
        let mut bytes = 0u32;
        let first = unsafe { GetTcpTable2(None, &mut bytes, false) };
        if first != ERROR_INSUFFICIENT_BUFFER || bytes == 0 {
            return None;
        }
        let words = (bytes as usize).div_ceil(size_of::<u32>());
        let mut buffer = vec![0u32; words];
        let table = buffer.as_mut_ptr().cast::<MIB_TCPTABLE2>();
        let result = unsafe { GetTcpTable2(Some(table), &mut bytes, false) };
        if result != NO_ERROR {
            return None;
        }
        let rows = unsafe {
            slice::from_raw_parts((*table).table.as_ptr(), (*table).dwNumEntries as usize)
        };
        rows.iter().find_map(|row| {
            let local_port = u16::from_be((row.dwLocalPort & 0xffff) as u16);
            (local_port == port).then_some(row.dwOwningPid)
        })
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
        ProcessIdentity {
            pid: Some(pid),
            name,
            path,
        }
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
}

pub fn resolve_client(address: SocketAddr) -> ProcessIdentity {
    implementation::resolve_client(address)
}

pub fn idle_duration() -> Option<Duration> {
    implementation::idle_duration()
}
