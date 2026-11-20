//! The one machine-wide setting `--vpn` touches. On Windows that is `WinINET`'s
//! Internet Settings: the same proxy Chrome, Edge and most desktop apps read.
//! A snapshot is taken before the first arm and restored on `down`.

use crate::config::{fronts, Ports};
use crate::paths::{read_trim, read_trim_checked, Paths};

pub struct Routes {
    pub socks: Option<u16>,
    pub http: Option<u16>,
}

pub fn routes(list: &str, ports: Ports) -> Routes {
    let mut socks = None;
    let mut http = None;
    for front in fronts(list) {
        match front.as_str() {
            "socks" => socks = Some(ports.socks),
            "http" => http = Some(ports.http),
            "mixed" => {
                if socks.is_none() {
                    socks = Some(ports.mixed);
                }
                if http.is_none() {
                    http = Some(ports.mixed);
                }
            }
            _ => {}
        }
    }
    Routes { socks, http }
}

pub fn preflight(list: &str, ports: Ports) -> Result<(), String> {
    let routes = routes(list, ports);
    if routes.socks.is_none() && routes.http.is_none() {
        return Err(
            "system proxy: --fronts names no socks, http or mixed front; nothing was started."
                .to_owned(),
        );
    }
    #[cfg(windows)]
    {
        let key = win::open().map_err(|error| {
            format!("system proxy: cannot read the current proxy settings ({error}); nothing was started.")
        })?;
        win::close(key);
        Ok(())
    }
    #[cfg(not(windows))]
    {
        Err(format!(
            "ferrox-cli: --vpn sets the Windows system proxy; on {} nothing was started.\n  point the app at the fronts instead: ferrox-cli ports",
            std::env::consts::OS
        ))
    }
}

pub fn arm(paths: &Paths, list: &str, ports: Ports) -> Result<(), String> {
    #[cfg(not(windows))]
    let _ = paths;
    let routes = routes(list, ports);
    if routes.socks.is_none() && routes.http.is_none() {
        return Err("system proxy: the fronts name no proxy; nothing was armed.".to_owned());
    }
    #[cfg(windows)]
    {
        let _lock = lock(paths)?;
        win::arm(paths, routes.socks, routes.http)
    }
    #[cfg(not(windows))]
    {
        Err("system proxy: this launcher only arms the Windows proxy.".to_owned())
    }
}

/// Only the lane that armed the proxy may clear it; a second configuration root sharing the
/// state directory must not restore or delete the first lane's snapshot.
fn owned(paths: &Paths) -> Result<bool, String> {
    let text = match read_trim_checked(&paths.proxy_owner) {
        Ok(text) => text,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(true),
        Err(error) => {
            return Err(format!(
                "system proxy: cannot read {}: {error}; the snapshot was kept.",
                paths.proxy_owner.display()
            ));
        }
    };
    same_owner(&text, paths)
}

fn same_path(owner: &str, path: &std::path::Path) -> bool {
    let path = path.to_string_lossy();
    if cfg!(windows) {
        owner.eq_ignore_ascii_case(&path)
    } else {
        owner == path
    }
}

#[cfg(any(windows, test))]
fn owner_text(paths: &Paths) -> String {
    serde_json::json!({
        "conf_dir": paths.conf_dir.to_string_lossy(),
        "proxy_state": paths.proxy_state.to_string_lossy(),
    })
    .to_string()
}

fn same_owner(text: &str, paths: &Paths) -> Result<bool, String> {
    if let Ok(serde_json::Value::Object(fields)) = serde_json::from_str(text) {
        let conf = fields.get("conf_dir").and_then(serde_json::Value::as_str);
        let state = fields
            .get("proxy_state")
            .and_then(serde_json::Value::as_str);
        return Ok(conf.is_some_and(|conf| same_path(conf, &paths.conf_dir))
            && state.is_some_and(|state| same_path(state, &paths.proxy_state)));
    }
    let owner = serde_json::from_str::<String>(text).unwrap_or_else(|_| text.to_owned());
    if same_path(&owner, &paths.proxy_state) {
        return another_lane_runs(paths).map(|runs| !runs);
    }
    Ok(same_path(&owner, &paths.conf_dir)
        && paths
            .proxy_state
            .file_name()
            .is_some_and(|name| name == std::ffi::OsStr::new("system-proxy.state")))
}

#[cfg(any(windows, test))]
fn arm_owner(paths: &Paths) -> Result<(), String> {
    if owned(paths)? {
        Ok(())
    } else {
        Err(format!(
            "system proxy: another configuration root owns {}; it was not armed again.",
            paths.proxy_state.display()
        ))
    }
}

/// A legacy owner names only the shared snapshot, so it cannot say which root armed it; clearing is safe only when every registered lane can be read and none is alive.
fn another_lane_runs(paths: &Paths) -> Result<bool, String> {
    let text = match read_trim_checked(&paths.lanes_file) {
        Ok(text) => text,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Err(format!(
                "system proxy: cannot find {}; a legacy owner cannot prove no lane is live, so the snapshot was kept.",
                paths.lanes_file.display()
            ));
        }
        Err(error) => {
            return Err(format!(
                "system proxy: cannot read {}: {error}; the snapshot was kept.",
                paths.lanes_file.display()
            ));
        }
    };
    for dir in text.lines().map(str::trim).filter(|line| !line.is_empty()) {
        let entries = std::fs::read_dir(dir).map_err(|error| {
            format!("system proxy: cannot read {dir}: {error}; the snapshot was kept.")
        })?;
        for entry in entries {
            let entry = entry.map_err(|error| {
                format!(
                    "system proxy: cannot read a lane entry in {dir}: {error}; the snapshot was kept."
                )
            })?;
            let name = entry.file_name();
            let Some(name) = name.to_str() else {
                continue;
            };
            if !name.starts_with("lane") {
                continue;
            }
            let pid = std::path::Path::new(name)
                .extension()
                .is_some_and(|extension| extension.eq_ignore_ascii_case("pid"));
            if !pid || entry.path() == paths.pid_file {
                continue;
            }
            let text = match read_trim_checked(&entry.path()) {
                Ok(text) => text,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
                Err(error) => {
                    return Err(format!(
                        "system proxy: cannot read {}: {error}; the snapshot was kept.",
                        entry.path().display()
                    ));
                }
            };
            let Ok(pid) = text.parse() else {
                return Err(format!(
                    "system proxy: cannot parse {}; the snapshot was kept.",
                    entry.path().display()
                ));
            };
            if crate::lane::alive(pid) {
                return Ok(true);
            }
        }
    }
    Ok(false)
}

#[cfg(windows)]
fn lock(paths: &Paths) -> Result<std::fs::File, String> {
    let path = paths.state_dir.join("system-proxy.lock");
    std::fs::create_dir_all(&paths.state_dir).map_err(|error| {
        format!(
            "system proxy: cannot create {}: {error}",
            paths.state_dir.display()
        )
    })?;
    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(&path)
        .map_err(|error| format!("system proxy: cannot open {}: {error}", path.display()))?;
    file.lock()
        .map_err(|error| format!("system proxy: cannot lock {}: {error}", path.display()))?;
    Ok(file)
}

#[allow(clippy::unnecessary_wraps)] // Windows restores the registry and can fail; the other targets only remove files.
pub fn clear(paths: &Paths) -> Result<(), String> {
    #[cfg(windows)]
    {
        let _lock = lock(paths)?;
        if !owned(paths)? {
            return Ok(());
        }
        win::clear(paths)
    }
    #[cfg(not(windows))]
    {
        if !owned(paths)? {
            return Ok(());
        }
        let _ = std::fs::remove_file(&paths.proxy_ports);
        let _ = std::fs::remove_file(&paths.proxy_state);
        let _ = std::fs::remove_file(&paths.proxy_owner);
        Ok(())
    }
}

pub fn armed_endpoint(paths: &Paths) -> Option<String> {
    let ports = read_trim(&paths.proxy_ports)?;
    let mut parts = ports.split_whitespace();
    let socks = parts.next().filter(|value| *value != "-");
    let http = parts.next().filter(|value| *value != "-");
    socks.or(http).map(|port| format!("127.0.0.1:{port}"))
}

#[cfg(windows)]
mod win {
    use std::ffi::c_void;
    use std::ptr;

    use serde_json::{json, Value};
    use windows_sys::Win32::Foundation::{ERROR_FILE_NOT_FOUND, ERROR_SUCCESS};
    use windows_sys::Win32::Networking::WinInet::{
        InternetSetOptionW, INTERNET_OPTION_REFRESH, INTERNET_OPTION_SETTINGS_CHANGED,
    };
    use windows_sys::Win32::System::Registry::{
        RegCloseKey, RegDeleteValueW, RegOpenKeyExW, RegQueryValueExW, RegSetValueExW, HKEY,
        HKEY_CURRENT_USER, KEY_QUERY_VALUE, KEY_SET_VALUE, REG_DWORD, REG_SZ,
    };

    use crate::paths::{read_trim_checked, write_private, Paths};

    const SETTINGS: &str = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings";
    const MAX_VALUE: u32 = 1024 * 1024;
    const NAMES: [&str; 5] = [
        "ProxyEnable",
        "ProxyServer",
        "ProxyOverride",
        "AutoConfigURL",
        "AutoDetect",
    ];

    fn wide(value: &str) -> Vec<u16> {
        value.encode_utf16().chain(std::iter::once(0)).collect()
    }

    pub fn close(key: HKEY) {
        unsafe { RegCloseKey(key) };
    }

    pub fn open() -> Result<HKEY, String> {
        let subkey = wide(SETTINGS);
        let mut key: HKEY = ptr::null_mut();
        let status = unsafe {
            RegOpenKeyExW(
                HKEY_CURRENT_USER,
                subkey.as_ptr(),
                0,
                KEY_QUERY_VALUE | KEY_SET_VALUE,
                &mut key,
            )
        };
        if status == ERROR_SUCCESS {
            Ok(key)
        } else {
            Err(format!("RegOpenKeyEx failed with {status}"))
        }
    }

    fn read(key: HKEY, name: &str) -> Result<Option<(u32, Vec<u8>)>, String> {
        let name = wide(name);
        let mut kind = 0_u32;
        let mut size = 0_u32;
        let status = unsafe {
            RegQueryValueExW(
                key,
                name.as_ptr(),
                ptr::null(),
                &mut kind,
                ptr::null_mut(),
                &mut size,
            )
        };
        if status == ERROR_FILE_NOT_FOUND {
            return Ok(None);
        }
        if status != ERROR_SUCCESS {
            return Err(format!("RegQueryValueEx({name:?}) failed with {status}"));
        }
        if size > MAX_VALUE {
            return Err(format!(
                "registry value {name:?} is larger than {MAX_VALUE} bytes"
            ));
        }
        let mut buffer = vec![0_u8; size as usize];
        let status = unsafe {
            RegQueryValueExW(
                key,
                name.as_ptr(),
                ptr::null(),
                &mut kind,
                buffer.as_mut_ptr(),
                &mut size,
            )
        };
        if status != ERROR_SUCCESS {
            return Err(format!("RegQueryValueEx({name:?}) failed with {status}"));
        }
        let size = (size as usize).min(buffer.len());
        buffer.truncate(size);
        Ok(Some((kind, buffer)))
    }

    fn text_of(bytes: &[u8]) -> String {
        let units: Vec<u16> = bytes
            .chunks_exact(2)
            .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
            .take_while(|unit| *unit != 0)
            .collect();
        String::from_utf16_lossy(&units)
    }

    fn write_raw(key: HKEY, name: &str, kind: u32, data: &[u8]) -> bool {
        let name = wide(name);
        unsafe {
            RegSetValueExW(
                key,
                name.as_ptr(),
                0,
                kind,
                data.as_ptr(),
                data.len() as u32,
            ) == ERROR_SUCCESS
        }
    }

    fn write_sz(key: HKEY, name: &str, value: &str) -> bool {
        let bytes: Vec<u8> = value
            .encode_utf16()
            .chain(std::iter::once(0))
            .flat_map(u16::to_le_bytes)
            .collect();
        write_raw(key, name, REG_SZ, &bytes)
    }

    fn write_dword(key: HKEY, name: &str, value: u32) -> bool {
        write_raw(key, name, REG_DWORD, &value.to_le_bytes())
    }

    fn delete(key: HKEY, name: &str) -> bool {
        let name = wide(name);
        let status = unsafe { RegDeleteValueW(key, name.as_ptr()) };
        status == ERROR_SUCCESS || status == ERROR_FILE_NOT_FOUND
    }

    fn snapshot(key: HKEY) -> Result<Value, String> {
        let mut object = serde_json::Map::new();
        for name in NAMES {
            if let Some((kind, bytes)) = read(key, name)? {
                object.insert(name.to_owned(), json!({"kind": kind, "bytes": bytes}));
            }
        }
        Ok(Value::Object(object))
    }

    fn restore(key: HKEY, snapshot: &Value) -> bool {
        let mut ok = true;
        for name in NAMES {
            match snapshot.get(name) {
                Some(Value::Object(value)) => {
                    let kind = value
                        .get("kind")
                        .and_then(Value::as_u64)
                        .and_then(|kind| u32::try_from(kind).ok());
                    let bytes: Option<Vec<u8>> =
                        value.get("bytes").and_then(Value::as_array).map(|rows| {
                            rows.iter()
                                .filter_map(Value::as_u64)
                                .filter_map(|byte| u8::try_from(byte).ok())
                                .collect()
                        });
                    match (kind, bytes) {
                        (Some(kind), Some(bytes)) => {
                            ok &= write_raw(key, name, kind, &bytes);
                        }
                        _ => ok &= delete(key, name),
                    }
                }
                Some(Value::String(text)) => {
                    ok &= write_sz(key, name, text);
                }
                Some(Value::Number(number)) => {
                    if let Some(value) = number.as_u64() {
                        ok &= write_dword(key, name, value as u32);
                    }
                }
                _ => ok &= delete(key, name),
            }
        }
        ok
    }

    fn notify() -> bool {
        unsafe {
            InternetSetOptionW(
                ptr::null(),
                INTERNET_OPTION_SETTINGS_CHANGED,
                ptr::null::<c_void>(),
                0,
            ) != 0
                && InternetSetOptionW(
                    ptr::null(),
                    INTERNET_OPTION_REFRESH,
                    ptr::null::<c_void>(),
                    0,
                ) != 0
        }
    }

    fn server(socks: Option<u16>, http: Option<u16>) -> String {
        let mut parts = Vec::new();
        if let Some(port) = http {
            parts.push(format!("http=127.0.0.1:{port}"));
            parts.push(format!("https=127.0.0.1:{port}"));
        }
        if let Some(port) = socks {
            parts.push(format!("socks=127.0.0.1:{port}"));
        }
        parts.join(";")
    }

    fn bypass(key: HKEY) -> Result<String, String> {
        let prior = match read(key, "ProxyOverride")? {
            Some((kind, bytes)) if kind == REG_SZ => text_of(&bytes),
            Some(_) | None => String::new(),
        };
        let mut entries: Vec<String> = [
            "localhost",
            "127.0.0.1",
            "::1",
            "<local>",
            "*.local",
            "10.*",
            "172.16.*",
            "192.168.*",
        ]
        .iter()
        .map(|entry| (*entry).to_owned())
        .collect();
        let seen: Vec<String> = entries.clone();
        for entry in prior.split(';') {
            let entry = entry.trim();
            if entry.is_empty() || seen.iter().any(|item| item == entry) {
                continue;
            }
            entries.push(entry.to_owned());
        }
        Ok(entries.join(";"))
    }

    pub fn arm(paths: &Paths, socks: Option<u16>, http: Option<u16>) -> Result<(), String> {
        super::arm_owner(paths)?;
        let key = open().map_err(|error| {
            format!("system proxy: cannot read the current settings ({error}).")
        })?;
        let bypass = match bypass(key) {
            Ok(bypass) => bypass,
            Err(error) => {
                close(key);
                return Err(format!(
                    "system proxy: cannot read the current bypass list: {error}"
                ));
            }
        };
        let fresh = !paths.proxy_state.exists();
        if fresh {
            let snapshot = match snapshot(key) {
                Ok(snapshot) => snapshot,
                Err(error) => {
                    close(key);
                    return Err(format!("system proxy: cannot record the snapshot: {error}"));
                }
            };
            let text = match serde_json::to_string(&snapshot) {
                Ok(text) => text,
                Err(error) => {
                    close(key);
                    return Err(format!("system proxy: cannot record the snapshot: {error}"));
                }
            };
            if text.len() as u64 > crate::paths::MAX_PRIVATE_BYTES {
                close(key);
                return Err(
                    "system proxy: the current settings are too large to snapshot safely; nothing was armed."
                        .to_owned(),
                );
            }
            if let Err(error) = write_private(&paths.proxy_state, &text) {
                close(key);
                return Err(format!("system proxy: cannot record the snapshot: {error}"));
            }
        }
        let owner = super::owner_text(paths);
        if let Err(error) = write_private(&paths.proxy_owner, &owner) {
            close(key);
            if fresh {
                let _ = std::fs::remove_file(&paths.proxy_state);
            }
            return Err(format!(
                "system proxy: cannot publish ownership ({error}); nothing was armed."
            ));
        }
        let server = server(socks, http);
        let ok = write_dword(key, "ProxyEnable", 1)
            && write_sz(key, "ProxyServer", &server)
            && write_sz(key, "ProxyOverride", &bypass)
            && write_dword(key, "AutoDetect", 0);
        let cleared = delete(key, "AutoConfigURL");
        unsafe { RegCloseKey(key) };
        if !ok || !cleared || !notify() {
            let _ = clear(paths);
            return Err("system proxy: the arm did not stick; nothing was armed.".to_owned());
        }
        let _ = write_private(
            &paths.proxy_ports,
            &format!(
                "{} {}\n",
                socks.map_or_else(|| "-".to_owned(), |port| port.to_string()),
                http.map_or_else(|| "-".to_owned(), |port| port.to_string())
            ),
        );
        if let Some(port) = socks {
            println!("system proxy on: SOCKS 127.0.0.1:{port}");
        }
        if let Some(port) = http {
            println!("system proxy on: HTTP and HTTPS 127.0.0.1:{port}");
        }
        println!("scope: apps that honour the Windows proxy. Apps that ignore it (and raw UDP) are not captured: ferrox-cli tun says why.");
        Ok(())
    }

    pub fn clear(paths: &Paths) -> Result<(), String> {
        let text = match read_trim_checked(&paths.proxy_state) {
            Ok(text) => text,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                let _ = std::fs::remove_file(&paths.proxy_ports);
                let _ = std::fs::remove_file(&paths.proxy_owner);
                return Ok(());
            }
            Err(error) => {
                return Err(format!(
                    "system proxy: cannot read {} ({error}); the snapshot was kept.",
                    paths.proxy_state.display()
                ));
            }
        };
        let snapshot: Value = serde_json::from_str(&text).map_err(|error| {
            format!(
                "system proxy: cannot read the saved settings ({error}); the snapshot was kept."
            )
        })?;
        let key = open().map_err(|error| {
            format!(
                "system proxy: cannot open the registry to restore the saved settings ({error}); the snapshot was kept."
            )
        })?;
        let restored = restore(key, &snapshot);
        unsafe { RegCloseKey(key) };
        if !restored || !notify() {
            return Err(
                "system proxy: the saved settings were not fully restored; the snapshot was kept."
                    .to_owned(),
            );
        }
        let _ = std::fs::remove_file(&paths.proxy_ports);
        let _ = std::fs::remove_file(&paths.proxy_state);
        let _ = std::fs::remove_file(&paths.proxy_owner);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn workspace(name: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!(
            "ferrox-proxy-{name}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |since| since.as_nanos())
        ))
    }

    #[test]
    fn only_the_root_that_armed_owns_a_shared_snapshot() {
        let shared = workspace("shared");
        let first = Paths::with_dirs(shared.join("first"), shared.clone(), None);
        let second = Paths::with_dirs(shared.join("second"), shared.clone(), None);
        std::fs::create_dir_all(&shared).expect("state");
        std::fs::write(&first.proxy_state, "{}").expect("snapshot");
        crate::paths::write_private(&first.proxy_owner, &owner_text(&first)).expect("owner file");
        assert_eq!(owned(&first), Ok(true));
        assert_eq!(owned(&second), Ok(false));
        let _ = std::fs::remove_dir_all(&shared);
    }

    #[test]
    fn a_plain_root_owner_still_reads() {
        let dir = workspace("plain");
        let paths = Paths::with_dirs(dir.join("conf"), dir.join("state"), None);
        std::fs::create_dir_all(&paths.state_dir).expect("state");
        crate::paths::write_private(&paths.proxy_owner, &paths.conf_dir.to_string_lossy())
            .expect("owner file");
        assert_eq!(owned(&paths), Ok(true));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_legacy_snapshot_owner_without_a_registry_keeps_the_snapshot() {
        let dir = workspace("legacy-snapshot");
        let paths = Paths::with_dirs(dir.join("conf"), dir.join("state"), None);
        std::fs::create_dir_all(&paths.state_dir).expect("state");
        crate::paths::write_private(
            &paths.proxy_owner,
            &serde_json::to_string(&paths.proxy_state).expect("owner"),
        )
        .expect("owner file");
        let error = owned(&paths).expect_err("a missing registry cannot prove a lane is gone");
        assert!(error.contains("snapshot was kept"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_second_root_does_not_rearm_a_snapshot_it_does_not_own() {
        let shared = workspace("arm-owner");
        let first = Paths::with_dirs(shared.join("first"), shared.clone(), None);
        let second = Paths::with_dirs(shared.join("second"), shared.clone(), None);
        std::fs::create_dir_all(&shared).expect("state");
        std::fs::write(&first.proxy_state, "{}").expect("snapshot");
        crate::paths::write_private(&first.proxy_owner, &owner_text(&first)).expect("owner file");
        assert_eq!(arm_owner(&first), Ok(()));
        let error = arm_owner(&second).expect_err("a second root must not rearm the snapshot");
        assert!(error.contains("another configuration root"));
        let _ = std::fs::remove_dir_all(&shared);
    }

    #[test]
    fn a_legacy_snapshot_owner_does_not_clear_another_roots_live_lane() {
        let shared = workspace("legacy-snapshot-other-root");
        let first = Paths::with_dirs(shared.join("first"), shared.clone(), None);
        let second = Paths::with_dirs(shared.join("second"), shared.clone(), None);
        std::fs::create_dir_all(&first.conf_dir).expect("first conf");
        std::fs::create_dir_all(&second.conf_dir).expect("second conf");
        std::fs::create_dir_all(&shared).expect("state");
        crate::paths::write_private(
            &second.proxy_owner,
            &serde_json::to_string(&second.proxy_state).expect("owner"),
        )
        .expect("owner file");
        crate::paths::write_private(&first.pid_file, &format!("{}\n", std::process::id()))
            .expect("pid file");
        crate::paths::write_private(
            &shared.join("lanes"),
            &format!("{}\n", first.conf_dir.display()),
        )
        .expect("lane registry");
        assert_eq!(owned(&first), Ok(true));
        assert_eq!(owned(&second), Ok(false));
        let _ = std::fs::remove_file(&first.pid_file);
        assert_eq!(owned(&second), Ok(true));
        let _ = std::fs::remove_dir_all(&shared);
    }

    #[test]
    fn a_legacy_snapshot_owner_refuses_an_unreadable_registry() {
        let shared = workspace("legacy-unreadable-registry");
        let paths = Paths::with_dirs(shared.join("conf"), shared.clone(), None);
        std::fs::create_dir_all(&shared).expect("state");
        crate::paths::write_private(
            &paths.proxy_owner,
            &serde_json::to_string(&paths.proxy_state).expect("owner"),
        )
        .expect("owner file");
        let blocker = shared.join("not-a-directory");
        std::fs::write(&blocker, "not a lane directory").expect("blocker");
        crate::paths::write_private(&paths.lanes_file, &format!("{}\n", blocker.display()))
            .expect("lane registry");
        let error = owned(&paths).expect_err("an unreadable registry cannot prove a lane is gone");
        assert!(error.contains("snapshot was kept"));
        let _ = std::fs::remove_dir_all(&shared);
    }

    #[test]
    fn a_legacy_snapshot_owner_keeps_the_snapshot_for_a_missing_registered_dir() {
        let shared = workspace("legacy-missing-lane-dir");
        let paths = Paths::with_dirs(shared.join("conf"), shared.clone(), None);
        std::fs::create_dir_all(&shared).expect("state");
        crate::paths::write_private(
            &paths.proxy_owner,
            &serde_json::to_string(&paths.proxy_state).expect("owner"),
        )
        .expect("owner file");
        let missing = shared.join("gone");
        crate::paths::write_private(&paths.lanes_file, &format!("{}\n", missing.display()))
            .expect("lane registry");
        let error =
            owned(&paths).expect_err("a missing lane directory cannot prove a lane is gone");
        assert!(error.contains("snapshot was kept"));
        let _ = std::fs::remove_dir_all(&shared);
    }

    #[test]
    fn a_legacy_root_owner_does_not_authorize_a_named_lane() {
        let dir = workspace("legacy-root-named");
        let default = Paths::with_dirs(dir.join("conf"), dir.join("state"), None);
        let named = Paths::with_dirs(dir.join("conf"), dir.join("state"), Some("work"));
        std::fs::create_dir_all(&default.state_dir).expect("state");
        crate::paths::write_private(
            &default.proxy_owner,
            &serde_json::to_string(&default.conf_dir).expect("owner"),
        )
        .expect("owner file");
        assert_eq!(owned(&default), Ok(true));
        assert_eq!(owned(&named), Ok(false));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn an_absent_owner_file_is_clearable() {
        let dir = workspace("absent");
        let paths = Paths::with_dirs(dir.join("conf"), dir.join("state"), None);
        assert_eq!(owned(&paths), Ok(true));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
