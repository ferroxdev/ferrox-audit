//! One lane is one child process. The pid file is the truth about whether it is
//! alive; a log beside the config is where the engine says what it is doing.

use std::fs::{File, OpenOptions};
use std::io::Write as _;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpStream, ToSocketAddrs};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Duration;

use crate::args::die;
use crate::config::{front_listeners, fronts, port_of, Ports};
use crate::paths::{read_trim, read_trim_checked, secure_dir, write_private, Paths};

fn bin_name() -> &'static str {
    if cfg!(windows) {
        "ferrox-app.exe"
    } else {
        "ferrox-app"
    }
}

fn project_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .map(Path::to_path_buf)
        .unwrap_or_default()
}

fn candidate_bin() -> PathBuf {
    let root = project_root();
    let cargo_target =
        std::env::var_os("CARGO_TARGET_DIR").map_or_else(|| root.join("target"), PathBuf::from);
    cargo_target.join("release").join(bin_name())
}

fn beside_bin() -> Option<PathBuf> {
    std::env::current_exe()
        .ok()
        .and_then(|path| path.parent().map(|parent| parent.join(bin_name())))
}

fn env_bin() -> Option<PathBuf> {
    std::env::var_os("FERROX_BIN").map(PathBuf::from)
}

fn resolve_bin() -> Option<PathBuf> {
    if let Some(path) = env_bin() {
        return Some(path);
    }
    if let Some(path) = beside_bin().filter(|path| path.exists()) {
        return Some(path);
    }
    let built = candidate_bin();
    built.exists().then_some(built)
}

pub fn require_bin() -> PathBuf {
    if let Some(path) = resolve_bin() {
        return path;
    }
    let built = candidate_bin();
    #[cfg(debug_assertions)]
    if project_root().join("Cargo.toml").exists() {
        eprintln!("building ferrox-app (release, one time)...");
        let status = Command::new("cargo")
            .args(["build", "--locked", "--release", "-p", "ferrox-app"])
            .current_dir(project_root())
            .status();
        if status.is_ok_and(|status| status.success()) && built.exists() {
            return built;
        }
    }
    die(&format!(
        "no binary at {}: unpack a release package beside this launcher, or build one: cargo build --release -p ferrox-app",
        built.display()
    ))
}

pub fn pid(paths: &Paths) -> Option<u32> {
    read_trim(&paths.pid_file).and_then(|text| text.parse().ok())
}

pub fn alive(pid: u32) -> bool {
    #[cfg(unix)]
    {
        let Ok(pid) = i32::try_from(pid) else {
            return false;
        };
        unsafe { libc::kill(pid, 0) == 0 }
    }
    #[cfg(windows)]
    {
        use windows_sys::Win32::Foundation::{CloseHandle, STILL_ACTIVE};
        use windows_sys::Win32::System::Threading::{
            GetExitCodeProcess, OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION,
        };
        let handle = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
        if handle.is_null() {
            return false;
        }
        let mut code = 0_u32;
        let ok = unsafe { GetExitCodeProcess(handle, &mut code) };
        unsafe { CloseHandle(handle) };
        ok != 0 && code == STILL_ACTIVE as u32
    }
}

pub fn running(paths: &Paths) -> bool {
    pid(paths).is_some_and(|pid| alive(pid) && is_ferrox(paths, pid))
}

fn process_exe(pid: u32) -> Option<PathBuf> {
    #[cfg(target_os = "linux")]
    {
        std::fs::read_link(format!("/proc/{pid}/exe")).ok()
    }
    #[cfg(target_os = "macos")]
    {
        let output = Command::new("/bin/ps")
            .args(["-p", &pid.to_string(), "-o", "comm="])
            .stdin(Stdio::null())
            .stderr(Stdio::null())
            .output()
            .ok()?;
        if !output.status.success() {
            return None;
        }
        let path = String::from_utf8_lossy(&output.stdout).trim().to_owned();
        (!path.is_empty()).then(|| PathBuf::from(path))
    }
    #[cfg(windows)]
    {
        use windows_sys::Win32::Foundation::CloseHandle;
        use windows_sys::Win32::System::Threading::{
            OpenProcess, QueryFullProcessImageNameW, PROCESS_QUERY_LIMITED_INFORMATION,
        };
        let handle = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
        if handle.is_null() {
            return None;
        }
        let mut buffer = vec![0_u16; 32_768];
        let mut length = buffer.len() as u32;
        let ok = unsafe { QueryFullProcessImageNameW(handle, 0, buffer.as_mut_ptr(), &mut length) };
        unsafe { CloseHandle(handle) };
        if ok == 0 {
            return None;
        }
        Some(PathBuf::from(String::from_utf16_lossy(
            &buffer[..length as usize],
        )))
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
    {
        let _ = pid;
        None
    }
}

fn recorded_bin(paths: &Paths) -> PathBuf {
    read_trim(&bin_marker(paths))
        .filter(|text| !text.is_empty())
        .map_or_else(
            || resolve_bin().unwrap_or_else(candidate_bin),
            PathBuf::from,
        )
}

fn canonical_exe(path: &Path) -> PathBuf {
    if let Ok(canonical) = std::fs::canonicalize(path) {
        return canonical;
    }
    let text = path.to_string_lossy();
    let Some(stripped) = text.strip_suffix(" (deleted)") else {
        return path.to_path_buf();
    };
    let stripped = PathBuf::from(stripped);
    std::fs::canonicalize(&stripped).unwrap_or(stripped)
}

fn same_exe(actual: &Path, expected: &Path) -> bool {
    let actual = canonical_exe(actual);
    let expected = canonical_exe(expected);
    #[cfg(windows)]
    {
        actual
            .to_string_lossy()
            .eq_ignore_ascii_case(&expected.to_string_lossy())
    }
    #[cfg(not(windows))]
    {
        actual == expected
    }
}

fn recognises(actual: &Path, recorded: &Path, overridden: Option<&Path>) -> bool {
    same_exe(actual, recorded) || overridden.is_some_and(|path| same_exe(actual, path))
}

fn is_ferrox(paths: &Paths, pid: u32) -> bool {
    let Some(actual) = process_exe(pid) else {
        #[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
        return true;
        #[cfg(any(target_os = "linux", target_os = "macos", windows))]
        return false;
    };
    let overridden = env_bin();
    recognises(&actual, &recorded_bin(paths), overridden.as_deref())
}

#[cfg(any(unix, windows))]
fn wait_exit(pid: u32, attempts: u32) -> bool {
    for _ in 0..attempts {
        if !alive(pid) {
            return true;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    !alive(pid)
}

pub fn kill(paths: &Paths, pid: u32) -> Result<(), String> {
    if !is_ferrox(paths, pid) {
        return Err(format!(
            "process {pid} is not ferrox-app; it was not stopped. If the binary was renamed, set FERROX_BIN. Otherwise remove the stale pid file {}.",
            paths.pid_file.display()
        ));
    }
    #[cfg(unix)]
    {
        let process =
            i32::try_from(pid).map_err(|_| "the pid does not fit a process id".to_owned())?;
        if unsafe { libc::kill(process, libc::SIGTERM) } != 0 {
            let error = std::io::Error::last_os_error();
            if error.raw_os_error() != Some(libc::ESRCH) {
                return Err(format!("cannot stop process {pid}: {error}"));
            }
            return Ok(());
        }
        if wait_exit(pid, 10) {
            return Ok(());
        }
        if unsafe { libc::kill(process, libc::SIGKILL) } != 0 {
            let error = std::io::Error::last_os_error();
            if error.raw_os_error() != Some(libc::ESRCH) {
                return Err(format!("cannot stop process {pid}: {error}"));
            }
            return Ok(());
        }
        if !wait_exit(pid, 50) {
            return Err(format!(
                "process {pid} did not exit after SIGKILL; its pid file was kept."
            ));
        }
    }
    #[cfg(windows)]
    {
        use windows_sys::Win32::Foundation::CloseHandle;
        use windows_sys::Win32::System::Threading::{
            OpenProcess, TerminateProcess, PROCESS_TERMINATE,
        };
        let handle = unsafe { OpenProcess(PROCESS_TERMINATE, 0, pid) };
        if handle.is_null() {
            let error = std::io::Error::last_os_error();
            // ERROR_INVALID_PARAMETER: the pid left between `alive` and here, so there is nothing to stop.
            if error.raw_os_error() == Some(87) {
                return Ok(());
            }
            return Err(format!("cannot open process {pid} to stop it: {error}"));
        }
        let stopped = unsafe { TerminateProcess(handle, 1) };
        unsafe { CloseHandle(handle) };
        if stopped == 0 {
            let error = std::io::Error::last_os_error();
            if !wait_exit(pid, 5) {
                return Err(format!("cannot stop process {pid}: {error}"));
            }
        }
        if !wait_exit(pid, 50) {
            return Err(format!(
                "process {pid} did not exit after it was terminated; its pid file was kept."
            ));
        }
    }
    Ok(())
}

/// Hold the per-lane lifecycle lock across config writes, the running check, replacement and pid
/// publication, so two `up` calls cannot race to publish the same pid file.
pub fn lock(paths: &Paths) -> Result<File, String> {
    secure_dir(&paths.conf_dir)
        .map_err(|error| format!("cannot create the config dir: {error}"))?;
    secure_dir(&paths.state_dir)
        .map_err(|error| format!("cannot create the state dir: {error}"))?;
    let path = paths.pid_file.with_extension("lock");
    let file = OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(&path)
        .map_err(|error| format!("cannot open {}: {error}", path.display()))?;
    file.try_lock().map_err(|error| {
        format!("another ferrox-cli up is starting this lane ({error}); nothing was started.")
    })?;
    Ok(file)
}

fn port_lock_path(paths: &Paths) -> PathBuf {
    paths.state_dir.join("ports.lock")
}

/// Serialize the free-port scan and engine start across every lane sharing this state directory: a
/// lane that releases its probe before the next one scans can hand the same port to both.
pub fn port_lock(paths: &Paths) -> Result<File, String> {
    secure_dir(&paths.state_dir)
        .map_err(|error| format!("cannot create the state dir: {error}"))?;
    let path = port_lock_path(paths);
    let file = OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(&path)
        .map_err(|error| format!("cannot open {}: {error}", path.display()))?;
    file.lock()
        .map_err(|error| format!("cannot lock {}: {error}", path.display()))?;
    Ok(file)
}

fn register(paths: &Paths) -> Result<(), String> {
    secure_dir(&paths.state_dir)
        .map_err(|error| format!("cannot create the state dir: {error}"))?;
    let text = match read_trim_checked(&paths.lanes_file) {
        Ok(text) => text,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => String::new(),
        Err(error) => {
            return Err(format!(
                "cannot read {}: {error}",
                paths.lanes_file.display()
            ));
        }
    };
    let conf = paths.conf_dir.to_string_lossy();
    if text.lines().any(|line| line == conf) {
        return Ok(());
    }
    let current = std::fs::metadata(&paths.lanes_file).map_or(0, |meta| meta.len());
    let addition = conf.len() as u64 + 1;
    if current.saturating_add(addition) > crate::paths::MAX_PRIVATE_BYTES {
        return Err(format!(
            "the lane registry {} would exceed {} bytes; nothing was started.",
            paths.lanes_file.display(),
            crate::paths::MAX_PRIVATE_BYTES
        ));
    }
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&paths.lanes_file)
        .map_err(|error| format!("cannot append to {}: {error}", paths.lanes_file.display()))?;
    writeln!(file, "{conf}")
        .map_err(|error| format!("cannot append to {}: {error}", paths.lanes_file.display()))?;
    if file.metadata().map_or(current, |meta| meta.len()) > crate::paths::MAX_PRIVATE_BYTES {
        let _ = file.set_len(current);
        return Err(format!(
            "the lane registry {} exceeded {} bytes; the entry was rolled back.",
            paths.lanes_file.display(),
            crate::paths::MAX_PRIVATE_BYTES
        ));
    }
    Ok(())
}

fn config_marker(paths: &Paths) -> PathBuf {
    let name = paths.pid_file.file_stem().map_or_else(
        || String::from("lane"),
        |stem| stem.to_string_lossy().into_owned(),
    );
    paths.conf_dir.join(format!(".{name}.provenance"))
}

fn bin_marker(paths: &Paths) -> PathBuf {
    let name = paths.pid_file.file_stem().map_or_else(
        || String::from("lane"),
        |stem| stem.to_string_lossy().into_owned(),
    );
    paths.conf_dir.join(format!(".{name}.bin"))
}

pub fn remember_user_config(paths: &Paths) -> Result<(), String> {
    write_private(
        &config_marker(paths),
        &format!("{}\n", paths.cfg.to_string_lossy()),
    )
    .map_err(|error| {
        format!(
            "cannot record the lane config {}: {error}",
            paths.cfg.display()
        )
    })
}

pub fn forget_user_config(paths: &Paths) {
    let _ = std::fs::remove_file(config_marker(paths));
}

pub fn user_config(paths: &Paths) -> Option<PathBuf> {
    read_trim(&config_marker(paths))
        .filter(|text| !text.is_empty())
        .map(PathBuf::from)
}

pub fn adopt_config(paths: &mut Paths) {
    if let Some(cfg) = user_config(paths) {
        paths.cfg = cfg;
    }
}

pub fn start(bin: &Path, paths: &Paths, debug: bool) -> Result<u32, String> {
    secure_dir(&paths.conf_dir)
        .map_err(|error| format!("cannot create the config dir: {error}"))?;
    secure_dir(&paths.state_dir)
        .map_err(|error| format!("cannot create the state dir: {error}"))?;
    let bin = canonical_exe(bin);
    let recorded = bin
        .to_str()
        .filter(|path| !path.contains('\n') && !path.contains('\r'));
    let Some(recorded) = recorded else {
        return Err(format!(
            "cannot record the lane binary {}: its path is not a single valid UTF-8 line",
            bin.display()
        ));
    };
    write_private(&bin_marker(paths), &format!("{recorded}\n"))
        .map_err(|error| format!("cannot record the lane binary {}: {error}", bin.display()))?;
    register(paths)?;
    let out = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(&paths.log)
        .map_err(|error| format!("cannot open {}: {error}", paths.log.display()))?;
    let err = out
        .try_clone()
        .map_err(|error| format!("cannot open {}: {error}", paths.log.display()))?;
    let mut command = Command::new(&bin);
    command
        .arg("run")
        .arg("-c")
        .arg(&paths.cfg)
        .stdin(Stdio::null())
        .stdout(out)
        .stderr(err);
    if debug {
        command.env("FOXY_DEBUG", "1");
    }
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt as _;
        command.creation_flags(0x0800_0000);
    }
    let mut child = command
        .spawn()
        .map_err(|error| format!("cannot start {}: {error}", bin.display()))?;
    let pid = child.id();
    if let Err(error) = write_private(&paths.pid_file, &format!("{pid}\n")) {
        let _ = child.kill();
        let _ = child.wait();
        return Err(format!("cannot write the pid file: {error}"));
    }
    // Reap the engine when it exits, so `serve` sees it leave instead of looping on a zombie.
    std::thread::spawn(move || {
        let _ = child.wait();
    });
    Ok(pid)
}

pub fn stop(paths: &Paths) -> Result<(), String> {
    if let Some(pid) = pid(paths) {
        if alive(pid) {
            kill(paths, pid)?;
        }
    }
    match std::fs::remove_file(&paths.pid_file) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(format!(
            "cannot remove {}: {error}",
            paths.pid_file.display()
        )),
    }
}

enum Listener {
    Ready(Vec<SocketAddr>),
    Pending(std::sync::mpsc::Receiver<Vec<SocketAddr>>),
}

impl Listener {
    fn new(listen: &str, port: u16) -> Self {
        let listen = listen.trim();
        let host = listen
            .strip_prefix('[')
            .and_then(|host| host.strip_suffix(']'))
            .unwrap_or(listen);
        match host.parse::<IpAddr>() {
            Ok(IpAddr::V4(ip)) if ip.is_unspecified() => {
                Self::Ready(vec![SocketAddr::from((Ipv4Addr::LOCALHOST, port))])
            }
            Ok(IpAddr::V4(ip)) => Self::Ready(vec![SocketAddr::from((ip, port))]),
            Ok(IpAddr::V6(ip)) if ip.is_unspecified() => {
                Self::Ready(vec![SocketAddr::from((Ipv6Addr::LOCALHOST, port))])
            }
            Ok(IpAddr::V6(ip)) => Self::Ready(vec![SocketAddr::from((ip, port))]),
            Err(_) if host.is_empty() => Self::Ready(loopback_addresses(port)),
            Err(_) => {
                let (sender, receiver) = std::sync::mpsc::channel();
                let host = host.to_owned();
                let _ = std::thread::spawn(move || {
                    let addresses = (host.as_str(), port)
                        .to_socket_addrs()
                        .map(std::iter::Iterator::collect::<Vec<_>>)
                        .unwrap_or_default();
                    let _ = sender.send(addresses);
                });
                Self::Pending(receiver)
            }
        }
    }

    fn addresses(&mut self) -> Vec<SocketAddr> {
        match self {
            Self::Ready(addresses) => addresses.clone(),
            Self::Pending(receiver) => match receiver.try_recv() {
                Ok(addresses) => {
                    *self = Self::Ready(addresses.clone());
                    addresses
                }
                Err(std::sync::mpsc::TryRecvError::Empty) => Vec::new(),
                Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                    *self = Self::Ready(Vec::new());
                    Vec::new()
                }
            },
        }
    }
}

fn loopback_addresses(port: u16) -> Vec<SocketAddr> {
    vec![
        SocketAddr::from((Ipv4Addr::LOCALHOST, port)),
        SocketAddr::from((Ipv6Addr::LOCALHOST, port)),
    ]
}

pub fn port_open(addresses: &[SocketAddr]) -> bool {
    addresses
        .iter()
        .any(|address| TcpStream::connect_timeout(address, Duration::from_millis(300)).is_ok())
}

pub fn wait_fronts(list: &str, ports: Ports, paths: &Paths) -> bool {
    let listeners = front_listeners(&paths.cfg, list);
    for front in fronts(list) {
        let listen = listeners
            .iter()
            .find(|(name, _)| name == &front)
            .map_or("", |(_, listen)| listen.as_str());
        let port = port_of(&front, ports);
        let mut listener = Listener::new(listen, port);
        let mut opened = false;
        for _ in 0..90 {
            if port_open(&listener.addresses()) {
                opened = true;
                break;
            }
            if !running(paths) {
                return false;
            }
            std::thread::sleep(Duration::from_secs(1));
        }
        if !opened {
            return false;
        }
    }
    true
}

pub fn uptime(paths: &Paths) -> Option<String> {
    let created = std::fs::metadata(&paths.pid_file).ok()?.created().ok()?;
    let elapsed = created.elapsed().ok()?;
    let seconds = elapsed.as_secs();
    let hours = seconds / 3600;
    let minutes = (seconds % 3600) / 60;
    let seconds = seconds % 60;
    Some(if hours > 0 {
        format!("{hours}:{minutes:02}:{seconds:02}")
    } else {
        format!("{minutes}:{seconds:02}")
    })
}

pub fn foxy_configured(paths: &Paths) -> bool {
    read_trim(&paths.cfg)
        .is_some_and(|text| text.contains("\"protocol\"") && text.contains("\"foxy\""))
}

pub fn other_lanes(paths: &Paths) -> Vec<(String, u32)> {
    let mut lanes = Vec::new();
    let Ok(entries) = std::fs::read_dir(&paths.conf_dir) else {
        return lanes;
    };
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        let Some(rest) = name.strip_prefix("lane-") else {
            continue;
        };
        let Some(instance) = rest.strip_suffix(".pid") else {
            continue;
        };
        if let Some(pid) = read_trim(&entry.path()).and_then(|text| text.parse().ok()) {
            let lane_paths = Paths::with_dirs(
                paths.conf_dir.clone(),
                paths.state_dir.clone(),
                Some(instance),
            );
            if alive(pid) && is_ferrox(&lane_paths, pid) {
                lanes.push((instance.to_owned(), pid));
            }
        }
    }
    lanes
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lanes_in_one_root_share_the_port_probe_lock() {
        let root = std::env::temp_dir().join(format!("ferrox-ports-{}", std::process::id()));
        let one = Paths::with_dirs(root.clone(), root.join("state"), Some("one"));
        let two = Paths::with_dirs(root.clone(), root.join("state"), Some("two"));
        let held = port_lock(&one).unwrap();
        let probe = OpenOptions::new()
            .read(true)
            .write(true)
            .open(port_lock_path(&two))
            .unwrap();
        assert!(probe.try_lock().is_err());
        drop(held);
        assert!(probe.try_lock().is_ok());
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn lanes_in_two_roots_sharing_state_share_the_port_probe_lock() {
        let root = std::env::temp_dir().join(format!("ferrox-ports-roots-{}", std::process::id()));
        let one = Paths::with_dirs(root.join("one"), root.join("state"), None);
        let two = Paths::with_dirs(root.join("two"), root.join("state"), None);
        let held = port_lock(&one).unwrap();
        let probe = OpenOptions::new()
            .read(true)
            .write(true)
            .open(port_lock_path(&two))
            .unwrap();
        assert!(probe.try_lock().is_err());
        drop(held);
        assert!(probe.try_lock().is_ok());
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn a_user_config_marker_round_trips_and_can_be_forgotten() {
        let root = std::env::temp_dir().join(format!("ferrox-config-{}", std::process::id()));
        let mut paths = Paths::with_dirs(root.join("conf"), root.join("state"), Some("work"));
        paths.cfg = root.join("custom.json");
        remember_user_config(&paths).unwrap();
        assert_eq!(user_config(&paths), Some(paths.cfg.clone()));
        let mut adopted = Paths::with_dirs(root.join("conf"), root.join("state"), Some("work"));
        adopt_config(&mut adopted);
        assert_eq!(adopted.cfg, paths.cfg);
        forget_user_config(&paths);
        assert_eq!(user_config(&paths), None);
        let _ = std::fs::remove_dir_all(root);
    }

    #[cfg(any(target_os = "linux", target_os = "macos", windows))]
    #[test]
    fn a_live_foreign_pid_is_kept_for_retry() {
        let root = std::env::temp_dir().join(format!("ferrox-foreign-{}", std::process::id()));
        let paths = Paths::with_dirs(root.join("conf"), root.join("state"), None);
        let current = std::process::id();
        assert!(
            !is_ferrox(&paths, current),
            "the test process looks like the lane"
        );
        write_private(&paths.pid_file, &format!("{current}\n")).unwrap();
        assert!(!running(&paths));
        let error = stop(&paths).expect_err("a foreign pid is not stopped");
        assert!(
            error.contains(&paths.pid_file.display().to_string()),
            "the refusal names the pid file: {error}"
        );
        assert_eq!(pid(&paths), Some(current));
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn a_lane_is_recognised_by_its_recorded_or_overridden_binary() {
        let root = std::env::temp_dir().join(format!("ferrox-rename-{}", std::process::id()));
        let paths = Paths::with_dirs(root.join("conf"), root.join("state"), None);
        let recorded = root.join("ferrox-app");
        let overridden = root.join("renamed-ferrox-app");
        write_private(&bin_marker(&paths), &format!("{}\n", recorded.display())).unwrap();
        assert_eq!(recorded_bin(&paths), recorded);
        assert!(recognises(&recorded, &recorded, None));
        assert!(!recognises(&overridden, &recorded, None));
        assert!(recognises(&recorded, &recorded, Some(&overridden)));
        assert!(recognises(&overridden, &recorded, Some(&overridden)));
        assert!(!recognises(
            &root.join("other"),
            &recorded,
            Some(&overridden)
        ));
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn a_configured_listener_address_is_probed_where_it_listens() {
        assert_eq!(
            Listener::new("127.0.0.2", 1080).addresses(),
            [SocketAddr::from(([127, 0, 0, 2], 1080))]
        );
        assert_eq!(
            Listener::new("[::1]", 1080).addresses(),
            [SocketAddr::from((Ipv6Addr::LOCALHOST, 1080))]
        );
        assert_eq!(
            Listener::new("", 1080).addresses(),
            [
                SocketAddr::from((Ipv4Addr::LOCALHOST, 1080)),
                SocketAddr::from((Ipv6Addr::LOCALHOST, 1080))
            ]
        );
        assert_eq!(
            Listener::new("0.0.0.0", 1080).addresses(),
            [SocketAddr::from((Ipv4Addr::LOCALHOST, 1080))]
        );
        assert_eq!(
            Listener::new("[::]", 1080).addresses(),
            [SocketAddr::from((Ipv6Addr::LOCALHOST, 1080))]
        );
    }
}
