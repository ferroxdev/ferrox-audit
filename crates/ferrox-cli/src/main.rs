#![allow(
    clippy::assigning_clones,
    clippy::borrow_as_ptr,
    clippy::chunks_exact_to_as_chunks,
    clippy::match_same_arms,
    clippy::similar_names,
    clippy::struct_excessive_bools,
    clippy::too_many_lines
)]

mod args;
mod config;
mod credentials;
mod lane;
mod locations;
mod paths;
mod probe;
mod proxy;

use std::fs::File;
use std::io::{IsTerminal as _, Read as _, Seek as _, SeekFrom, Write as _};
use std::path::{Path, PathBuf};
use std::process::exit;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use args::{Action, Options, Outbound};
use config::{fronts, port_of, FoxyAccount, Ports};
use paths::{read_trim, read_trim_checked, Paths};

fn main() {
    let mut options = args::parse();
    let mut paths = Paths::new(options.instance.as_deref());
    let code = match options.action {
        Action::Up => up(&mut options, &mut paths, false),
        Action::Serve => up(&mut options, &mut paths, true),
        Action::Down => down(&options, &mut paths),
        Action::Status => status(&mut options, &mut paths),
        Action::Ports => {
            ports(&mut options, &mut paths);
            0
        }
        Action::Tun => {
            tun();
            0
        }
        Action::Login => {
            if let Err(error) = reconcile(&paths) {
                eprintln!("ferrox-cli: {error}");
            }
            credentials::login(&options, &paths).unwrap_or_else(|error| args::die(&error));
            0
        }
        Action::Logout => logout(&paths),
        Action::Locations => {
            locations::list(&paths, &options.loc_filter, options.ping)
                .unwrap_or_else(|error| args::die(&error));
            0
        }
        Action::Location => {
            locations::remember(&paths, &options.loc_country, &options.loc_city)
                .unwrap_or_else(|error| args::die(&error));
            0
        }
        Action::Version => version(&paths),
        Action::Supervise => supervise(&options, &paths),
    };
    exit(code);
}

fn reconcile(paths: &Paths) -> Result<(), String> {
    if !paths.proxy_state.exists() {
        return Ok(());
    }
    // Serialize with `up`/`down` before reading liveness and clearing the proxy.
    let _lifecycle = lane::lock(paths)?;
    if !lane::running(paths) {
        proxy::clear(paths)?;
    }
    Ok(())
}

fn choose_carrier(options: &Options) -> String {
    if options.outbound != Some(Outbound::Foxy)
        || options.carrier_set
        || !std::io::stdin().is_terminal()
    {
        return options.carrier.clone();
    }
    println!("carrier: where the lane sends its flows (name --carrier to skip this):");
    println!("  1) auto  h2, then h1, then h3 — the fastest that answers (default)");
    println!("  2) h2    HTTPS/2 on a session reused across flows");
    println!("  3) h1    one TLS connection per flow");
    println!("  4) h3    QUIC; also carries UDP. Falls back to h2, then h1");
    print!("carrier [auto]: ");
    let _ = std::io::stdout().flush();
    let mut answer = String::new();
    let _ = std::io::stdin().read_line(&mut answer);
    match answer.trim().to_lowercase().as_str() {
        "" | "1" | "auto" => "auto".to_owned(),
        "2" | "h2" => "h2".to_owned(),
        "3" | "h1" => "h1".to_owned(),
        "4" | "h3" => "h3".to_owned(),
        other => {
            println!("carrier: '{other}' is not one of the four; using auto.");
            "auto".to_owned()
        }
    }
}

fn duplicate_fronts(list: &str, ports: Ports) {
    let mut seen: Vec<u16> = Vec::new();
    for front in fronts(list) {
        let port = port_of(&front, ports);
        if seen.contains(&port) {
            args::die(&format!(
                "two fronts cannot share port {port}; nothing was started."
            ));
        }
        seen.push(port);
    }
}

fn ensure_config(options: &Options) {
    if options.outbound == Some(Outbound::Config) && !Path::new(&options.config_file).is_file() {
        args::die(&format!("no such config: {}", options.config_file));
    }
}

fn adopt_lane_config(options: &Options, paths: &mut Paths) {
    if options.outbound == Some(Outbound::Config) && !options.config_file.is_empty() {
        let path = Path::new(&options.config_file);
        paths.cfg = std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
    } else {
        lane::adopt_config(paths);
    }
}

fn load_saved_fronts(options: &mut Options, paths: &Paths) {
    if !paths.cfg.is_file() {
        return;
    }
    let path = paths.cfg.to_string_lossy();
    if let Ok(saved) = config::config_fronts(
        &path,
        options.vpn,
        options.fronts_set,
        options.fronts.as_str(),
    ) {
        options.fronts = saved;
    }
}

fn duplicate_set_ports(options: &Options) -> Option<String> {
    let listed = fronts(&options.fronts);
    let mut seen: Vec<(u16, &str)> = Vec::new();
    for (name, port, set) in [
        ("socks", options.socks, options.socks_set),
        ("http", options.http, options.http_set),
        ("mixed", options.mixed, options.mixed_set),
    ] {
        if !set || !listed.iter().any(|front| front == name) {
            continue;
        }
        if let Some((_, other)) = seen.iter().find(|(taken, _)| *taken == port) {
            return Some(format!(
                "two fronts cannot share port {port} ({other} and {name}); nothing was started."
            ));
        }
        seen.push((port, name));
    }
    None
}

fn reject_duplicate_ports(options: &Options) {
    if options.outbound == Some(Outbound::Config) {
        return;
    }
    if let Some(message) = duplicate_set_ports(options) {
        args::die(&message);
    }
}

fn reject_empty_fronts(options: &Options) -> Result<(), String> {
    if options.outbound != Some(Outbound::Config) && fronts(&options.fronts).is_empty() {
        return Err(
            "--fronts names no front; give socks, http, mixed, or a combination; nothing was started.".to_owned(),
        );
    }
    Ok(())
}

fn prepare(options: &mut Options, paths: &mut Paths) -> (Ports, bool) {
    let user_config = options.outbound == Some(Outbound::Config);
    if user_config {
        ensure_config(options);
        let list = config::config_fronts(
            &options.config_file,
            options.vpn,
            options.fronts_set,
            &options.fronts,
        )
        .unwrap_or_else(|error| args::die(&error));
        options.fronts = list;
        paths.cfg = std::fs::canonicalize(&options.config_file)
            .unwrap_or_else(|_| PathBuf::from(&options.config_file));
        options.socks_set = false;
        options.http_set = false;
        options.mixed_set = false;
        let ports = config::plan_ports(options, paths, false);
        duplicate_fronts(&options.fronts, ports);
        (ports, true)
    } else {
        let ports = config::plan_ports(options, paths, true);
        duplicate_fronts(&options.fronts, ports);
        (ports, false)
    }
}

fn foxy_account(options: &mut Options, paths: &Paths) -> FoxyAccount {
    config::load_foxy_location(options, paths);
    credentials::resolve(options, paths).unwrap_or_else(|error| args::die(&error))
}

fn user_config_at_default(paths: &Paths) -> bool {
    paths.cfg.exists()
        && lane::user_config(paths).is_some_and(|cfg| {
            std::fs::canonicalize(&cfg).ok() == std::fs::canonicalize(&paths.cfg).ok()
        })
}

fn write_lane_config(
    options: &Options,
    paths: &Paths,
    ports: Ports,
    account: Option<&FoxyAccount>,
) {
    if options.outbound == Some(Outbound::Config) {
        lane::remember_user_config(paths).unwrap_or_else(|error| args::die(&error));
        return;
    }
    if user_config_at_default(paths) {
        args::die(&format!(
            "{} is a user config started with --config; refusing to overwrite it. Pass --config again or remove the file.",
            paths.cfg.display()
        ));
    }
    let outbound =
        config::build_outbound(options, paths, account).unwrap_or_else(|error| args::die(&error));
    config::write_config(&paths.cfg, &outbound, &options.fronts, ports)
        .unwrap_or_else(|error| args::die(&error));
    lane::forget_user_config(paths);
    if options.outbound == Some(Outbound::Foxy) {
        config::save_foxy_location(options, paths).unwrap_or_else(|error| args::die(&error));
    }
}

fn up(options: &mut Options, paths: &mut Paths, serve: bool) -> i32 {
    if let Err(error) = reconcile(paths) {
        eprintln!("ferrox-cli: {error}");
        return 1;
    }
    ensure_config(options);
    reject_duplicate_ports(options);
    reject_empty_fronts(options).unwrap_or_else(|error| args::die(&error));
    config::validate_exclusions(options).unwrap_or_else(|error| args::die(&error));
    options.carrier = choose_carrier(options);
    let lifecycle = match lane::lock(paths) {
        Ok(lock) => lock,
        Err(error) => {
            eprintln!("ferrox-cli: {error}");
            return 1;
        }
    };
    let bin = lane::require_bin();
    let account = if options.outbound == Some(Outbound::Foxy) {
        Some(foxy_account(options, paths))
    } else {
        None
    };
    let port_reservation = match lane::port_lock(paths) {
        Ok(lock) => lock,
        Err(error) => {
            eprintln!("ferrox-cli: {error}");
            return 1;
        }
    };
    let (ports, user_config) = prepare(options, paths);
    if options.vpn {
        if let Err(error) = proxy::preflight(&options.fronts, ports) {
            eprintln!("{error}");
            return 1;
        }
    }
    write_lane_config(options, paths, ports, account.as_ref());
    if lane::running(paths) {
        println!(
            "a lane{} is already running (pid {}); stopping it first.",
            options
                .instance
                .as_ref()
                .map_or_else(String::new, |name| format!(" '{name}'")),
            lane::pid(paths).unwrap_or_default()
        );
        if let Err(error) = proxy::clear(paths) {
            eprintln!("ferrox-cli: {error}");
            return 1;
        }
        if let Err(error) = lane::stop(paths) {
            eprintln!("ferrox-cli: {error}");
            return 1;
        }
    }
    let pid = lane::start(&bin, paths, options.debug).unwrap_or_else(|error| args::die(&error));
    let interrupted = Arc::new(AtomicBool::new(false));
    let cancelled = Arc::new(Mutex::new(false));
    let flag = Arc::clone(&interrupted);
    let cancel = Arc::clone(&cancelled);
    let watched = paths.clone();
    let _ = ctrlc::set_handler(move || {
        flag.store(true, Ordering::SeqCst);
        let Ok(mut cancelled) = cancel.try_lock() else {
            return;
        };
        if *cancelled {
            return;
        }
        *cancelled = true;
        let stopped = match lane::stop(&watched) {
            Ok(()) => true,
            Err(error) => {
                eprintln!("ferrox-cli: {error}");
                eprintln!(
                    "ferrox-cli: the lane config and supervisor files were kept so 'ferrox-cli down' can retry."
                );
                false
            }
        };
        if stopped {
            if !user_config {
                let _ = std::fs::remove_file(&watched.cfg);
            }
            if let Err(error) = proxy::clear(&watched) {
                eprintln!("ferrox-cli: {error}");
            }
        }
    });

    let opened =
        fronts(&options.fronts).is_empty() || lane::wait_fronts(&options.fronts, ports, paths);
    if !opened {
        println!(
            "the lane did not open its fronts; last lines of {}:",
            paths.log.display()
        );
        tail(&paths.log, 20);
        let code = stop_with_cancellation(&cancelled, &interrupted, paths, user_config, 3);
        drop(port_reservation);
        return code;
    }
    drop(port_reservation);
    if interrupted.load(Ordering::SeqCst) {
        return stop_with_cancellation(&cancelled, &interrupted, paths, user_config, 3);
    }
    println!(
        "lane{} up (pid {pid}), fronts:",
        options
            .instance
            .as_ref()
            .map_or_else(String::new, |name| format!(" '{name}'"))
    );
    port_map(options, ports);
    if options.outbound == Some(Outbound::Foxy) {
        println!("carrier: {}", options.carrier);
    }
    let mut arm = true;
    if !fronts(&options.fronts).is_empty() {
        match verify_flow(options, ports, paths) {
            Flow::Carry => {}
            Flow::Skip => {
                if options.vpn {
                    println!("not arming the system proxy; the lane keeps its own routing.");
                }
                arm = false;
            }
            Flow::Fail => {
                return stop_with_cancellation(&cancelled, &interrupted, paths, user_config, 3);
            }
        }
    }
    if interrupted.load(Ordering::SeqCst) {
        return stop_with_cancellation(&cancelled, &interrupted, paths, user_config, 3);
    }
    if options.vpn && arm {
        // Hold the cancellation lock across the arm and handoff so a Ctrl-C either owns cleanup or looks at a finished start.
        let mut state = cancelled
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if *state || interrupted.load(Ordering::SeqCst) {
            *state = true;
            stop_and_forget(paths, user_config);
            drop(state);
            return 130;
        }
        if let Err(error) = proxy::arm(paths, &options.fronts, ports) {
            *state = true;
            drop(state);
            eprintln!("{error}");
            stop_and_forget(paths, user_config);
            return 1;
        }
        if !serve {
            spawn_supervisor(paths, pid, options.instance.as_deref());
        }
        if interrupted.load(Ordering::SeqCst) {
            *state = true;
            stop_and_forget(paths, user_config);
            drop(state);
            return 130;
        }
        drop(state);
        if interrupted.load(Ordering::SeqCst) {
            return stop_with_cancellation(&cancelled, &interrupted, paths, user_config, 130);
        }
    }
    println!("log:  {}", paths.log.display());
    drop(lifecycle);
    if serve {
        println!("Ctrl-C stops it.");
        while lane::running(paths) && !interrupted.load(Ordering::SeqCst) {
            std::thread::sleep(Duration::from_secs(1));
        }
        if interrupted.load(Ordering::SeqCst) {
            stop_and_forget(paths, user_config);
            return 130;
        }
        println!("the lane exited; last lines of {}:", paths.log.display());
        tail(&paths.log, 15);
        return stop_and_forget(paths, user_config);
    }
    println!("stop: ferrox-cli down");
    0
}

fn spawn_supervisor(paths: &Paths, pid: u32, instance: Option<&str>) {
    let Ok(exe) = std::env::current_exe() else {
        return;
    };
    let mut command = std::process::Command::new(exe);
    command
        .arg("__supervise")
        .arg(pid.to_string())
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null());
    if let Some(name) = instance {
        command.arg("--instance").arg(name);
    }
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt as _;
        command.creation_flags(0x0800_0000);
    }
    if let Ok(child) = command.spawn() {
        let _ = paths::write_private(&paths.supervisor_pid, &format!("{}\n", child.id()));
    }
}

/// Claim cleanup under the cancellation lock, so a Ctrl-C and a startup failure cannot both stop the lane.
fn stop_with_cancellation(
    cancelled: &Mutex<bool>,
    interrupted: &AtomicBool,
    paths: &Paths,
    user_config: bool,
    failure: i32,
) -> i32 {
    let mut cancelled = cancelled
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if *cancelled {
        return 130;
    }
    *cancelled = true;
    let interrupted = interrupted.load(Ordering::SeqCst);
    stop_and_forget(paths, user_config);
    if interrupted {
        130
    } else {
        failure
    }
}

fn stop_and_forget(paths: &Paths, user_config: bool) -> i32 {
    if let Err(error) = lane::stop(paths) {
        eprintln!("ferrox-cli: {error}");
        eprintln!(
            "ferrox-cli: the lane config and supervisor files were kept so a later 'down' can retry."
        );
        return 1;
    }
    if !user_config {
        lane::forget_user_config(paths);
        let _ = std::fs::remove_file(&paths.cfg);
    }
    let restored = match proxy::clear(paths) {
        Ok(()) => true,
        Err(error) => {
            eprintln!("ferrox-cli: {error}");
            false
        }
    };
    let _ = std::fs::remove_file(&paths.supervisor_file);
    let _ = std::fs::remove_file(&paths.supervisor_pid);
    if user_config {
        println!(
            "the lane was stopped; your config is untouched and the log stays at {}.",
            paths.log.display()
        );
    } else {
        println!(
            "the lane was stopped and its config removed; the log stays at {}.",
            paths.log.display()
        );
    }
    i32::from(!restored)
}

enum Flow {
    Carry,
    Skip,
    Fail,
}

fn verify_flow(options: &Options, ports: Ports, paths: &Paths) -> Flow {
    let front = fronts(&options.fronts)
        .first()
        .cloned()
        .unwrap_or_else(|| "socks".to_owned());
    let port = port_of(&front, ports);
    let answer = probe::probe_front(&front, port, probe::trace_timeout());
    if !probe::carries_trace(&answer) {
        if options.outbound == Some(Outbound::Veepn)
            && probe::probe_plain(&front, port, probe::trace_timeout()).contains("Example Domain")
        {
            println!("exit through {front}: a plain HTTP flow answered.");
            return Flow::Carry;
        }
        if options.outbound == Some(Outbound::Config) {
            println!(
                "the custom config did not answer the probe; leaving the lane to its own routing."
            );
            return Flow::Skip;
        }
        println!("NOT CONNECTED: the fronts are up, but no flow got through them.");
        diagnose(options, paths);
        return Flow::Fail;
    }
    println!("exit through {front}: {}", probe::exit_line(&answer));
    let want = options.country.to_uppercase();
    let got = probe::exit_country(&answer);
    if options.outbound == Some(Outbound::Veepn) {
        let pinned = config::effective_region(options);
        if !pinned.is_empty() && got.to_lowercase() != pinned {
            println!(
                "note: the exit reads {}, not the pinned {pinned}; the plane's pool can route elsewhere, so the front is carrying the flow either way.",
                if got.is_empty() { "unreadable" } else { &got }
            );
        }
    }
    if options.outbound == Some(Outbound::Foxy) && want != "REC" && got != want {
        println!(
            "the exit reads {}, not the pinned {want}: that is either another country's edge or this machine's own address, so the lane is not carrying it.",
            if got.is_empty() { "unreadable" } else { &got }
        );
        diagnose(options, paths);
        return Flow::Fail;
    }
    Flow::Carry
}

fn diagnose(options: &Options, paths: &Paths) {
    let log = read_tail(&paths.log, 64 * 1024).text;
    if log.trim().is_empty() {
        println!(
            "the lane log is empty: it refused the flow without saying why. Re-run with --debug for the dial trace."
        );
        return;
    }
    println!(
        "the lane's own words, last lines of {}:",
        paths.log.display()
    );
    tail(&paths.log, 8);
    if options.outbound == Some(Outbound::Veepn) {
        println!("diagnosis: the plane answered no list this lane can dial; the lines above name the region and the reason.");
    } else if log.contains("handshake with the edge failed") {
        println!("diagnosis: TLS to the edge never completed. That is the network, not the account: chain the dial through a proxy this network does allow:");
        println!("  ferrox-cli up --foxy --upstream socks5://127.0.0.1:PORT");
    } else if log.contains("did not sign in") || log.contains("token was refused") {
        println!("diagnosis: the lane never signed in. Check the account, or pass --code 123456 for two-factor.");
    } else if log.contains("no quota left") || log.contains("answered 429") {
        println!("diagnosis: the plane is refusing this account for quota; wait for the reset, or move the exit with --country.");
    } else {
        println!("diagnosis: none of the known shapes; the lines above are all there is.");
    }
}

fn down(options: &Options, paths: &mut Paths) -> i32 {
    let explicit_config =
        options.outbound == Some(Outbound::Config) && !options.config_file.is_empty();
    if options.all {
        if explicit_config {
            let _lifecycle = match lane::lock(paths) {
                Ok(lock) => lock,
                Err(error) => {
                    eprintln!("ferrox-cli: {error}");
                    return 1;
                }
            };
            adopt_lane_config(options, paths);
            if let Err(error) = lane::remember_user_config(paths) {
                eprintln!("ferrox-cli: {error}");
                return 1;
            }
        }
        let mut rc = stop_all_lanes(paths);
        if rc == 0 {
            if let Err(error) = proxy::clear(paths) {
                eprintln!("ferrox-cli: {error}");
                rc = 1;
            }
        }
        if rc == 0 {
            let _ = std::fs::remove_file(&paths.lanes_file);
            println!("every lane is stopped; generated configs are removed and a user config is kept. The stored foxy session is kept; 'ferrox-cli logout' forgets it.");
        }
        return rc;
    }
    let _lifecycle = match lane::lock(paths) {
        Ok(lock) => lock,
        Err(error) => {
            eprintln!("ferrox-cli: {error}");
            return 1;
        }
    };
    adopt_lane_config(options, paths);
    if explicit_config {
        if let Err(error) = lane::remember_user_config(paths) {
            eprintln!("ferrox-cli: {error}");
        }
    }
    let user_config = lane::user_config(paths).is_some();
    let rc = stop_lane_locked(paths);
    if rc == 0 && !explicit_config {
        forget_config(paths);
    }
    let name = options
        .instance
        .as_ref()
        .map_or_else(String::new, |name| format!(" '{name}'"));
    if rc != 0 {
        eprintln!(
            "the lane was not fully stopped or the system proxy was not cleared; run 'ferrox-cli down' again."
        );
    } else if user_config {
        println!(
            "lane{name} stopped; the user config is kept. The stored foxy session is kept; 'ferrox-cli logout' forgets it."
        );
    } else {
        println!(
            "lane{name} stopped; the lane config is removed. The stored foxy session is kept; 'ferrox-cli logout' forgets it."
        );
    }
    rc
}

fn stop_lane(paths: &Paths) -> i32 {
    let _lifecycle = match lane::lock(paths) {
        Ok(lock) => lock,
        Err(error) => {
            eprintln!("ferrox-cli: {error}");
            return 1;
        }
    };
    stop_lane_locked(paths)
}

fn stop_lane_locked(paths: &Paths) -> i32 {
    let saved_pid = lane::pid(paths);
    if let Err(error) = lane::stop(paths) {
        eprintln!("ferrox-cli: {error}");
        return 1;
    }
    if let Err(error) = proxy::clear(paths) {
        eprintln!("ferrox-cli: {error}");
        if let Some(pid) = saved_pid {
            let _ = paths::write_private(&paths.pid_file, &format!("{pid}\n"));
        }
        return 1;
    }
    0
}

fn forget_config(paths: &Paths) {
    if lane::user_config(paths).is_some() {
        return;
    }
    let name = paths
        .cfg
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_default();
    let is_json = paths
        .cfg
        .extension()
        .is_some_and(|extension| extension.eq_ignore_ascii_case("json"));
    if paths.cfg.parent() == Some(paths.conf_dir.as_path()) && name.starts_with("lane") && is_json {
        let _ = std::fs::remove_file(&paths.cfg);
    }
}

fn prune_lanes(paths: &Paths, missing: &[PathBuf]) {
    let Ok(_lock) = lane::port_lock(paths) else {
        eprintln!(
            "ferrox-cli: cannot lock {}; stale lanes were not pruned.",
            paths.lanes_file.display()
        );
        return;
    };
    let Ok(text) = read_trim_checked(&paths.lanes_file) else {
        return;
    };
    let kept: Vec<&str> = text
        .lines()
        .map(str::trim)
        .filter(|line| {
            !line.is_empty()
                && !missing.iter().any(|dir| {
                    Path::new(*line) == dir.as_path()
                        && matches!(
                            std::fs::metadata(dir),
                            Err(error) if error.kind() == std::io::ErrorKind::NotFound
                        )
                })
        })
        .collect();
    let result = if kept.is_empty() {
        crate::paths::write_private(&paths.lanes_file, "")
    } else {
        crate::paths::write_private(&paths.lanes_file, &format!("{}\n", kept.join("\n")))
    };
    if let Err(error) = result {
        eprintln!(
            "ferrox-cli: cannot prune {}: {error}",
            paths.lanes_file.display()
        );
    }
}

fn stop_all_lanes(paths: &Paths) -> i32 {
    let mut rc = 0;
    let mut dirs: Vec<(PathBuf, bool)> = Vec::new();
    match read_trim_checked(&paths.lanes_file) {
        Ok(text) => {
            for line in text.lines().map(str::trim).filter(|line| !line.is_empty()) {
                dirs.push((PathBuf::from(line), true));
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => {
            eprintln!(
                "ferrox-cli: cannot read {}: {error}; no lane was stopped.",
                paths.lanes_file.display()
            );
            return 1;
        }
    }
    if !dirs.iter().any(|(dir, _)| dir == &paths.conf_dir) {
        dirs.push((paths.conf_dir.clone(), false));
    }
    let mut missing: Vec<PathBuf> = Vec::new();
    for (dir, registered) in dirs {
        let entries = match std::fs::read_dir(&dir) {
            Ok(entries) => entries,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                if registered {
                    eprintln!(
                        "ferrox-cli: the registered lane directory {} is gone; pruning it.",
                        dir.display()
                    );
                    missing.push(dir);
                }
                continue;
            }
            Err(error) => {
                eprintln!(
                    "ferrox-cli: cannot read {}: {error}; its lanes were not stopped.",
                    dir.display()
                );
                rc = 1;
                continue;
            }
        };
        for entry in entries {
            let entry = match entry {
                Ok(entry) => entry,
                Err(error) => {
                    eprintln!(
                        "ferrox-cli: cannot read a lane entry in {}: {error}",
                        dir.display()
                    );
                    rc = 1;
                    continue;
                }
            };
            let name = entry.file_name().to_string_lossy().into_owned();
            let Some(rest) = name.strip_prefix("lane") else {
                continue;
            };
            let Some(rest) = rest.strip_suffix(".pid") else {
                continue;
            };
            let instance = rest.strip_prefix('-');
            let lane_paths = Paths::with_dirs(dir.clone(), paths.state_dir.clone(), instance);
            if stop_lane(&lane_paths) != 0 {
                rc = 1;
            } else {
                forget_config(&lane_paths);
            }
        }
    }
    if !missing.is_empty() {
        prune_lanes(paths, &missing);
    }
    rc
}

fn status(options: &mut Options, paths: &mut Paths) -> i32 {
    adopt_lane_config(options, paths);
    load_saved_fronts(options, paths);
    if let Err(error) = reconcile(paths) {
        eprintln!("ferrox-cli: {error}");
    }
    if !lane::running(paths) {
        println!(
            "lane{} not running.",
            options
                .instance
                .as_ref()
                .map_or_else(String::new, |name| format!(" '{name}'"))
        );
        if let Some(endpoint) = proxy::armed_endpoint(paths) {
            println!("system proxy points at {endpoint} but no lane owns it; run 'ferrox-cli down' to clear it.");
        }
        for (name, pid) in lane::other_lanes(paths) {
            println!("instance {name} is running (pid {pid}).");
        }
        if paths.token_file.exists() {
            println!(
                "foxy session stored in {}: the next up --foxy resumes it without a sign-in mail.",
                paths.token_file.display()
            );
        }
        return 1;
    }
    println!(
        "lane{} pid {}, fronts:",
        options
            .instance
            .as_ref()
            .map_or_else(String::new, |name| format!(" '{name}'")),
        lane::pid(paths).unwrap_or_default()
    );
    let ports = config::plan_ports(options, paths, false);
    port_map(options, ports);
    if let Some(uptime) = lane::uptime(paths) {
        println!("up for {uptime}");
    }
    let tail = read_tail(&paths.log, 64 * 1024);
    let log = &tail.text;
    if let Some(carrier) = log
        .lines()
        .filter_map(|line| line.strip_prefix("foxy: carrier "))
        .next_back()
    {
        println!("carrier: {carrier}");
    } else if tail.truncated && lane::foxy_configured(paths) {
        println!(
            "carrier: not in the retained 64 KiB window; older entries are in {}.",
            paths.log.display()
        );
    }
    if let Some(quota) = log
        .lines()
        .filter_map(|line| line.strip_prefix("foxy: allowance "))
        .next_back()
    {
        println!("quota left: {quota}");
    } else if tail.truncated && lane::foxy_configured(paths) {
        println!(
            "quota: not in the retained 64 KiB window; older entries are in {}.",
            paths.log.display()
        );
    } else if lane::foxy_configured(paths) {
        println!("quota: the plane named no allowance for the pass this lane carries: that is silence, not zero.");
    }
    let front = fronts(&options.fronts)
        .first()
        .cloned()
        .unwrap_or_else(|| "socks".to_owned());
    let port = port_of(&front, ports);
    println!("exit through {front} ({port}):");
    let answer = probe::probe_front(&front, port, 30);
    if probe::carries_trace(&answer) {
        println!("{}", probe::exit_line(&answer));
    } else {
        println!("no answer through the front; see {}", paths.log.display());
    }
    0
}

fn ports(options: &mut Options, paths: &mut Paths) {
    adopt_lane_config(options, paths);
    load_saved_fronts(options, paths);
    let ports = config::plan_ports(options, paths, false);
    let routes = proxy::routes(&options.fronts, ports);
    println!("----------------------------------------------------------------");
    println!("local fronts (127.0.0.1 only):");
    port_map(options, ports);
    if options.instance.is_some() {
        println!("----------------------------------------------------------------");
        if !paths.cfg.exists() {
            println!(
                "instance '{}' has not started: these are the defaults it moves off if they are taken.",
                options.instance.as_deref().unwrap_or_default()
            );
        }
        println!("point the app you want at these fronts: the system proxy is one");
        println!("machine-wide setting, so an instance never arms it (--vpn belongs to the");
        println!("unnamed lane).");
        return;
    }
    if routes.http.is_none() && routes.socks.is_none() {
        return;
    }
    println!("----------------------------------------------------------------");
    println!("Windows, Settings > Network & Internet > Proxy > Manual proxy setup:");
    if let Some(port) = routes.http {
        println!("  Use a proxy server: 127.0.0.1:{port} (HTTP)");
    }
    if let Some(port) = routes.socks {
        println!("  SOCKS proxy:        127.0.0.1:{port}");
    }
    println!("Leave authentication off (the fronts are unauthenticated and loopback-only).");
    println!();
    println!("One app instead of the whole system:");
    if let Some(port) = routes.socks {
        println!("  curl --socks5-hostname 127.0.0.1:{port} https://example.com");
    }
    if let Some(port) = routes.http {
        println!("  curl -x http://127.0.0.1:{port} https://example.com");
        println!("  set HTTPS_PROXY=http://127.0.0.1:{port}");
    }
    if let Some(port) = routes.socks {
        println!("  set ALL_PROXY=socks5h://127.0.0.1:{port}");
    }
}

fn port_map(options: &Options, ports: Ports) {
    for front in fronts(&options.fronts) {
        match front.as_str() {
            "socks" => println!(
                "  SOCKS5        socks5://127.0.0.1:{}   (curl --socks5-hostname, UDP-aware)",
                ports.socks
            ),
            "http" => println!(
                "  HTTP + HTTPS  http://127.0.0.1:{}     (CONNECT tunnels, plain forwards)",
                ports.http
            ),
            "mixed" => println!(
                "  mixed         http://127.0.0.1:{}     (SOCKS5 and HTTP on one port)",
                ports.mixed
            ),
            _ => {}
        }
    }
}

fn tun() {
    println!("TUN mode is refused by this binary, by name, not by silence.");
    println!();
    println!("What TUN would be: a virtual network device that takes every IP packet,");
    println!("so apps that ignore proxies are captured too, UDP included. That needs a");
    println!("device driver, a userspace IP stack, and administrator rights.");
    println!();
    println!("What this binary has: no tun inbound and no tun2socks engine. A config");
    println!("naming one is refused with that reason, and `--tun` here refuses before");
    println!("anything starts.");
    println!();
    println!("What you get instead:");
    println!("  ferrox-cli up --vpn      the Windows proxy: TCP apps that honour it");
    println!("  ferrox-cli up --fronts socks   UDP for apps that speak SOCKS5");
}

fn version(paths: &Paths) -> i32 {
    let bin = lane::require_bin();
    let dir = std::env::current_exe()
        .ok()
        .and_then(|exe| exe.parent().map(Path::to_path_buf))
        .unwrap_or_else(|| paths.conf_dir.clone());
    println!("ferrox-cli at {}", dir.display());
    std::process::Command::new(bin)
        .arg("version")
        .status()
        .map_or(1, |status| status.code().unwrap_or(1))
}

fn remove_private_file(path: &Path) -> Result<(), String> {
    match std::fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(format!("cannot remove {}: {error}", path.display())),
    }
}

fn logout(paths: &Paths) -> i32 {
    let rc = stop_all_lanes(paths);
    if rc != 0 {
        eprintln!(
            "ferrox-cli: not every lane stopped; the stored session, the saved account and the lane configs were kept."
        );
        return rc;
    }
    if let Err(error) = proxy::clear(paths) {
        eprintln!("ferrox-cli: {error}");
        return 1;
    }
    let mut rc = 0;
    for path in [&paths.token_file, &paths.creds] {
        if let Err(error) = remove_private_file(path) {
            eprintln!("ferrox-cli: {error}");
            rc = 1;
        }
    }
    if rc != 0 {
        eprintln!(
            "ferrox-cli: the stored session or saved account could not be removed; it was kept."
        );
        return rc;
    }
    forget_config(paths);
    println!("signed out: every lane is stopped, generated configs are removed and a user config is kept; the stored session and saved account are gone.");
    println!(
        "the remembered exit stays in {}; 'ferrox-cli login' signs in again.",
        paths.location_file.display()
    );
    rc
}

fn supervise(options: &Options, paths: &Paths) -> i32 {
    let Some(watched) = options.supervise_pid else {
        return 0;
    };
    let _ = paths::write_private(&paths.supervisor_file, &format!("{watched}\n"));
    let stop = Arc::new(AtomicBool::new(false));
    let flag = Arc::clone(&stop);
    let pid = watched;
    let lane_paths = (*paths).clone();
    let _ = ctrlc::set_handler(move || {
        match lane::kill(&lane_paths, pid) {
            Ok(()) => flag.store(true, Ordering::SeqCst),
            // A failed kill leaves the lane live: keep polling so its exit still clears the proxy, and a second Ctrl-C retries.
            Err(error) => eprintln!("ferrox-cli: {error}"),
        }
    });
    while lane::alive(watched) && !stop.load(Ordering::SeqCst) {
        std::thread::sleep(Duration::from_secs(1));
    }
    if !lane::alive(watched) || stop.load(Ordering::SeqCst) {
        // Retry the lifecycle lock a status read may hold, then re-check the pid before clearing.
        let mut lifecycle = None;
        for _ in 0..20 {
            match lane::lock(paths) {
                Ok(lock) => {
                    lifecycle = Some(lock);
                    break;
                }
                Err(_) => std::thread::sleep(Duration::from_millis(50)),
            }
        }
        if let Some(_lifecycle) = lifecycle {
            let current = lane::pid(paths);
            if current.is_none() || current == Some(watched) {
                if let Err(error) = proxy::clear(paths) {
                    eprintln!("ferrox-cli: {error}");
                }
                let _ = std::fs::remove_file(&paths.pid_file);
            }
        }
    }
    if read_trim(&paths.supervisor_file).as_deref() == Some(watched.to_string().as_str()) {
        let _ = std::fs::remove_file(&paths.supervisor_file);
        let _ = std::fs::remove_file(&paths.supervisor_pid);
    }
    0
}

struct Tail {
    text: String,
    truncated: bool,
}

fn read_tail(path: &Path, max_bytes: u64) -> Tail {
    let Ok(mut file) = File::open(path) else {
        return Tail {
            text: String::new(),
            truncated: false,
        };
    };
    let Ok(metadata) = file.metadata() else {
        return Tail {
            text: String::new(),
            truncated: false,
        };
    };
    let truncated = metadata.len() > max_bytes;
    let start = metadata.len().saturating_sub(max_bytes);
    if file.seek(SeekFrom::Start(start)).is_err() {
        return Tail {
            text: String::new(),
            truncated,
        };
    }
    let mut bytes = Vec::new();
    if file.take(max_bytes).read_to_end(&mut bytes).is_err() {
        return Tail {
            text: String::new(),
            truncated,
        };
    }
    Tail {
        text: String::from_utf8_lossy(&bytes).into_owned(),
        truncated,
    }
}

fn tail(path: &Path, lines: usize) {
    let text = read_tail(path, 64 * 1024).text;
    let all: Vec<&str> = text.lines().collect();
    let start = all.len().saturating_sub(lines);
    for line in &all[start..] {
        println!("{line}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "ferrox-main-{name}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |span| span.as_nanos())
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn a_user_config_marker_survives_forget_config() {
        let root = scratch("user-config");
        let paths = Paths::with_dirs(root.join("conf"), root.join("state"), None);
        std::fs::create_dir_all(&paths.conf_dir).unwrap();
        std::fs::write(&paths.cfg, "{}").unwrap();
        lane::remember_user_config(&paths).unwrap();
        assert!(user_config_at_default(&paths));
        forget_config(&paths);
        assert!(paths.cfg.exists());
        assert!(lane::user_config(&paths).is_some());
        assert!(user_config_at_default(&paths));
        forget_config(&paths);
        assert!(paths.cfg.exists());
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn only_explicit_ports_are_checked_for_duplicates_before_prepare() {
        let mut options = Options {
            instance: Some("work".to_owned()),
            socks: 8080,
            socks_set: true,
            ..Options::default()
        };
        assert_eq!(duplicate_set_ports(&options), None);
        options.http = 8080;
        options.http_set = true;
        assert!(duplicate_set_ports(&options).is_some());
    }

    #[test]
    fn an_empty_generated_front_list_is_refused() {
        let mut options = Options {
            fronts: String::new(),
            fronts_set: true,
            ..Options::default()
        };
        assert!(reject_empty_fronts(&options).is_err());
        options.outbound = Some(Outbound::Config);
        assert!(reject_empty_fronts(&options).is_ok());
    }

    #[test]
    fn an_unnamed_lane_scans_off_a_port_a_named_lane_already_took() {
        let root = scratch("scan-unnamed");
        let mut paths = Paths::with_dirs(root.join("conf"), root.join("state"), None);
        let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let taken = listener.local_addr().unwrap().port();
        let mut options = Options {
            fronts: "socks".to_owned(),
            socks: taken,
            ..Options::default()
        };
        let (ports, user_config) = prepare(&mut options, &mut paths);
        assert!(!user_config);
        assert_ne!(ports.socks, taken);
        drop(listener);
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn a_registered_missing_lane_directory_is_pruned_not_fatal() {
        let root = scratch("prune");
        let paths = Paths::with_dirs(root.join("conf"), root.join("state"), None);
        std::fs::create_dir_all(&paths.conf_dir).unwrap();
        std::fs::create_dir_all(&paths.state_dir).unwrap();
        let missing = root.join("gone");
        crate::paths::write_private(
            &paths.lanes_file,
            &format!("{}\n{}\n", missing.display(), paths.conf_dir.display()),
        )
        .unwrap();
        assert_eq!(stop_all_lanes(&paths), 0);
        let text = read_trim_checked(&paths.lanes_file).unwrap();
        let conf = paths.conf_dir.to_string_lossy().into_owned();
        assert!(!text.contains("gone"));
        assert!(text.contains(&conf));
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn a_missing_private_file_is_already_gone() {
        let root = scratch("remove");
        assert_eq!(remove_private_file(&root.join("nope")), Ok(()));
        std::fs::create_dir_all(root.join("dir")).unwrap();
        assert!(remove_private_file(&root.join("dir")).is_err());
        let _ = std::fs::remove_dir_all(root);
    }
}
