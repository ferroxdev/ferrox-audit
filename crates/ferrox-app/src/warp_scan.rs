//! The edge sweep behind `warp`: scan modes, the Cloudflare ranges and seeds
//! each one tries, the cooldown a failed edge is held on, and the last edge a
//! quick reconnect offers first.

use std::collections::{HashMap, HashSet};
use std::io::{Read as _, Write as _};
use std::net::{Ipv4Addr, SocketAddr};
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::mpsc;
use std::time::{Duration, Instant};

const WG_PREFIXES_V4: [&str; 7] = [
    "162.159.192.0/24",
    "162.159.195.0/24",
    "188.114.96.0/24",
    "188.114.97.0/24",
    "188.114.98.0/24",
    "188.114.99.0/24",
    "162.159.193.0/24",
];

const WG_SEEDS_V4: [&str; 5] = [
    "162.159.192.1",
    "162.159.195.1",
    "188.114.96.1",
    "188.114.97.1",
    "162.159.193.1",
];

const WG_PORTS: [u16; 54] = [
    2408, 500, 1701, 4500, 854, 859, 864, 878, 880, 890, 891, 894, 903, 908, 928, 934, 939, 942,
    943, 945, 946, 955, 968, 987, 988, 1002, 1010, 1014, 1018, 1070, 1074, 1180, 1387, 1843, 2371,
    2506, 3138, 3476, 3581, 3854, 4177, 4198, 4233, 5279, 5956, 7103, 7152, 7156, 7281, 7559, 8319,
    8742, 8854, 8886,
];

const MASQUE_PREFIXES_V4: [&str; 14] = [
    "162.159.196.0/24",
    "162.159.195.0/24",
    "162.159.192.0/24",
    "162.159.193.0/24",
    "162.159.204.0/24",
    "162.159.197.0/24",
    "162.159.198.0/24",
    "162.159.199.0/24",
    "172.65.251.0/24",
    "188.114.96.0/24",
    "188.114.97.0/24",
    "188.114.98.0/24",
    "188.114.99.0/24",
    "162.159.36.0/24",
];

const MASQUE_SEEDS: [&str; 10] = [
    "162.159.196.1",
    "162.159.195.1",
    "162.159.192.1",
    "162.159.197.3",
    "162.159.197.1",
    "162.159.198.2",
    "162.159.198.1",
    "162.159.193.1",
    "162.159.199.2",
    "162.159.197.2",
];

const MASQUE_PORTS: [u16; 7] = [443, 500, 1701, 4500, 4443, 8443, 8095];

/// One edge sweep's pace. The values follow the reference's presets; `target`
/// zero means the whole candidate list, and `quiet` is how long a scan keeps
/// looking after it has enough answers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ScanMode {
    Turbo,
    Balanced,
    Thorough,
    Verified,
    Ironclad,
}

impl ScanMode {
    pub(crate) fn parse(text: &str) -> Option<Self> {
        match text.trim().to_ascii_lowercase().as_str() {
            "turbo" | "fast" => Some(Self::Turbo),
            "balanced" => Some(Self::Balanced),
            "thorough" | "deep" | "pro" => Some(Self::Thorough),
            "verified" | "proven" | "stealth" | "quiet" => Some(Self::Verified),
            "ironclad" | "real" | "verify" | "guaranteed" => Some(Self::Ironclad),
            _ => None,
        }
    }

    pub(crate) fn label(self) -> &'static str {
        match self {
            Self::Turbo => "turbo",
            Self::Balanced => "balanced",
            Self::Thorough => "thorough",
            Self::Verified => "verified",
            Self::Ironclad => "ironclad",
        }
    }

    fn strategy(self) -> Strategy {
        match self {
            Self::Turbo => Strategy {
                concurrency: 20,
                timeout: Duration::from_secs(6),
                deadline: Duration::from_secs(45),
                sample: 64,
                full_subnet: false,
                port_waves: 1,
                target: 1,
                quiet: Duration::ZERO,
            },
            Self::Balanced => Strategy {
                concurrency: 16,
                timeout: Duration::from_secs(6),
                deadline: Duration::from_secs(120),
                sample: 140,
                full_subnet: false,
                port_waves: 3,
                target: 6,
                quiet: Duration::from_secs(20),
            },
            Self::Thorough => Strategy {
                concurrency: 20,
                timeout: Duration::from_secs(10),
                deadline: Duration::from_secs(300),
                sample: 0,
                full_subnet: true,
                port_waves: 4,
                target: 0,
                quiet: Duration::from_secs(30),
            },
            Self::Verified => Strategy {
                concurrency: 16,
                timeout: Duration::from_secs(5),
                deadline: Duration::from_secs(60),
                sample: 48,
                full_subnet: false,
                port_waves: 4,
                target: 4,
                quiet: Duration::from_secs(8),
            },
            Self::Ironclad => Strategy {
                concurrency: 4,
                timeout: Duration::from_secs(15),
                deadline: Duration::from_secs(180),
                sample: 140,
                full_subnet: false,
                port_waves: 3,
                target: 3,
                quiet: Duration::from_secs(15),
            },
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct Strategy {
    concurrency: usize,
    timeout: Duration,
    deadline: Duration,
    sample: usize,
    full_subnet: bool,
    port_waves: usize,
    target: usize,
    quiet: Duration,
}

pub(crate) fn wg_candidates(mode: ScanMode) -> Vec<SocketAddr> {
    let strategy = mode.strategy();
    let seeds: Vec<Ipv4Addr> = WG_SEEDS_V4
        .iter()
        .filter_map(|text| text.parse().ok())
        .collect();
    let mut ips: Vec<Ipv4Addr> = seeds;
    for ip in sample_prefixes(&WG_PREFIXES_V4, strategy.full_subnet, strategy.sample) {
        if !ips.contains(&ip) {
            ips.push(ip);
        }
    }
    spread(&ips, &WG_PORTS, strategy.port_waves)
}

pub(crate) fn masque_candidates(mode: ScanMode) -> Vec<SocketAddr> {
    let strategy = mode.strategy();
    let seeds: Vec<Ipv4Addr> = MASQUE_SEEDS
        .iter()
        .filter_map(|text| text.parse().ok())
        .collect();
    let mut out = Vec::new();
    let mut seen = HashSet::new();
    let mut push = |ip: Ipv4Addr, port: u16| {
        let edge = SocketAddr::from((ip, port));
        if seen.insert(edge) {
            out.push(edge);
        }
    };
    let sampled = sample_prefixes(&MASQUE_PREFIXES_V4, strategy.full_subnet, strategy.sample);
    for seed in &seeds {
        push(*seed, MASQUE_PORTS[0]);
    }
    for ip in &sampled {
        push(*ip, MASQUE_PORTS[0]);
    }
    for &port in &MASQUE_PORTS[1..] {
        for seed in &seeds {
            push(*seed, port);
        }
    }
    out
}

fn spread(ips: &[Ipv4Addr], ports: &[u16], waves: usize) -> Vec<SocketAddr> {
    let mut out = Vec::new();
    let mut seen = HashSet::new();
    for wave in 0..waves.max(1) {
        for (index, ip) in ips.iter().enumerate() {
            let port = ports[(index + wave) % ports.len()];
            let edge = SocketAddr::from((*ip, port));
            if seen.insert(edge) {
                out.push(edge);
            }
        }
    }
    out
}

fn sample_prefixes(prefixes: &[&str], full: bool, sample: usize) -> Vec<Ipv4Addr> {
    let hosts: Vec<Vec<Ipv4Addr>> = prefixes
        .iter()
        .map(|prefix| {
            if full {
                enumerate_cidr(prefix)
            } else {
                sample_cidr(prefix, sample)
            }
        })
        .collect();
    let width = hosts.iter().map(Vec::len).max().unwrap_or(0);
    let mut out = Vec::new();
    for index in 0..width {
        for hosts in &hosts {
            if let Some(ip) = hosts.get(index) {
                out.push(*ip);
            }
        }
    }
    out
}

fn parse_cidr(cidr: &str) -> Option<(u32, u8)> {
    let (address, prefix) = cidr.split_once('/')?;
    Some((
        u32::from(address.parse::<Ipv4Addr>().ok()?),
        prefix.parse().ok()?,
    ))
}

fn sample_cidr(cidr: &str, count: usize) -> Vec<Ipv4Addr> {
    let Some((base, prefix)) = parse_cidr(cidr) else {
        return Vec::new();
    };
    let host_bits = 32u32.saturating_sub(u32::from(prefix));
    if host_bits >= 32 {
        return Vec::new();
    }
    let size = 1u64 << host_bits;
    if size <= 2 {
        return vec![Ipv4Addr::from(base)];
    }
    let usable = size - 2;
    let want = (count as u64).min(usable);
    let mut out = Vec::with_capacity(want as usize);
    for index in 0..want {
        let offset = 1 + (index * usable / want);
        out.push(Ipv4Addr::from((u64::from(base) + offset) as u32));
    }
    out
}

fn enumerate_cidr(cidr: &str) -> Vec<Ipv4Addr> {
    let Some((base, prefix)) = parse_cidr(cidr) else {
        return Vec::new();
    };
    let host_bits = 32u32.saturating_sub(u32::from(prefix));
    if host_bits == 0 {
        return vec![Ipv4Addr::from(base)];
    }
    if host_bits > 12 {
        return Vec::new();
    }
    let size = 1u64 << host_bits;
    (1..size - 1)
        .map(|offset| Ipv4Addr::from((u64::from(base) + offset) as u32))
        .collect()
}

/// Ask every candidate until the mode has enough answers or its deadline passes,
/// and return the fastest edge on each address.
pub(crate) fn hunt<F>(
    candidates: Vec<SocketAddr>,
    mode: ScanMode,
    excluded: &HashSet<SocketAddr>,
    verify: F,
) -> Vec<(SocketAddr, Duration)>
where
    F: Fn(SocketAddr) -> Option<Duration> + Sync,
{
    hunt_with_early(candidates, Vec::new(), mode, excluded, verify)
}

pub(crate) fn masque_hunt<F>(
    mode: ScanMode,
    excluded: &HashSet<SocketAddr>,
    verify: F,
) -> Vec<(SocketAddr, Duration)>
where
    F: Fn(SocketAddr) -> Option<Duration> + Sync,
{
    let candidates = masque_candidates(mode);
    let fallback = candidates
        .iter()
        .position(|edge| edge.port() != MASQUE_PORTS[0])
        .unwrap_or(candidates.len());
    let (edges, fallbacks) = candidates.split_at(fallback);
    hunt_with_early(edges.to_vec(), fallbacks.to_vec(), mode, excluded, verify)
}

fn hunt_with_early<F>(
    candidates: Vec<SocketAddr>,
    early: Vec<SocketAddr>,
    mode: ScanMode,
    excluded: &HashSet<SocketAddr>,
    verify: F,
) -> Vec<(SocketAddr, Duration)>
where
    F: Fn(SocketAddr) -> Option<Duration> + Sync,
{
    let strategy = mode.strategy();
    let candidates: Vec<SocketAddr> = candidates
        .into_iter()
        .filter(|edge| !excluded.contains(edge))
        .collect();
    let early: Vec<SocketAddr> = early
        .into_iter()
        .filter(|edge| !excluded.contains(edge))
        .collect();
    if candidates.is_empty() && early.is_empty() {
        return Vec::new();
    }
    let index = AtomicUsize::new(0);
    let early_index = AtomicUsize::new(0);
    let done = AtomicBool::new(false);
    let deadline = Instant::now() + strategy.deadline;
    let (sender, receiver) = mpsc::channel();
    let mut found = Vec::new();
    std::thread::scope(|scope| {
        let workers = strategy.concurrency.min(candidates.len() + early.len());
        for worker in 0..workers {
            let sender = sender.clone();
            let index = &index;
            let early_index = &early_index;
            // One worker keeps the seed fallbacks from waiting behind every sampled 443 edge.
            let early_lane = worker == 0 && !early.is_empty();
            let done = &done;
            let candidates = &candidates;
            let early = &early;
            let verify = &verify;
            scope.spawn(move || loop {
                if done.load(Ordering::Relaxed) || Instant::now() >= deadline {
                    break;
                }
                let edge = if early_lane {
                    early
                        .get(early_index.fetch_add(1, Ordering::Relaxed))
                        .copied()
                        .or_else(|| {
                            candidates
                                .get(index.fetch_add(1, Ordering::Relaxed))
                                .copied()
                        })
                } else {
                    candidates
                        .get(index.fetch_add(1, Ordering::Relaxed))
                        .copied()
                        .or_else(|| {
                            early
                                .get(early_index.fetch_add(1, Ordering::Relaxed))
                                .copied()
                        })
                };
                let Some(edge) = edge else {
                    break;
                };
                let result = verify(edge);
                if sender.send((edge, result)).is_err() {
                    break;
                }
            });
        }
        drop(sender);
        let mut quiet_until: Option<Instant> = None;
        loop {
            let until = quiet_until.map_or(deadline, |quiet| quiet.min(deadline));
            let left = until.saturating_duration_since(Instant::now());
            if left.is_zero() {
                break;
            }
            let Ok((edge, result)) = receiver.recv_timeout(left) else {
                break;
            };
            let Some(rtt) = result else {
                continue;
            };
            found.push((edge, rtt));
            if strategy.target > 0 && found.len() >= strategy.target {
                if strategy.quiet.is_zero() {
                    done.store(true, Ordering::Relaxed);
                    break;
                }
                if quiet_until.is_none() {
                    quiet_until = Some(Instant::now() + strategy.quiet);
                }
            }
        }
        done.store(true, Ordering::Relaxed);
    });
    found.sort_by_key(|(_, rtt)| *rtt);
    let mut seen = HashSet::new();
    found
        .into_iter()
        .filter(|(edge, _)| seen.insert(edge.ip()))
        .collect()
}

pub(crate) fn scan_timeout(mode: ScanMode) -> Duration {
    mode.strategy().timeout
}

/// Edges held out of a rescan after a data-plane failure.
#[derive(Debug)]
pub(crate) struct Cooldowns {
    ttl: Duration,
    held: HashMap<SocketAddr, Instant>,
}

impl Cooldowns {
    pub(crate) fn new(ttl: Duration) -> Self {
        Self {
            ttl,
            held: HashMap::new(),
        }
    }

    pub(crate) fn hold(&mut self, edge: SocketAddr, now: Instant) {
        self.held.insert(edge, now);
    }

    pub(crate) fn cooling(&self, edge: SocketAddr, now: Instant) -> bool {
        self.held
            .get(&edge)
            .is_some_and(|held| now.duration_since(*held) < self.ttl)
    }

    pub(crate) fn purge(&mut self, now: Instant) {
        self.held
            .retain(|_, held| now.duration_since(*held) < self.ttl);
    }

    pub(crate) fn excluded(&self, now: Instant) -> HashSet<SocketAddr> {
        self.held
            .keys()
            .filter(|edge| self.cooling(**edge, now))
            .copied()
            .collect()
    }
}

/// The recent edges a quick reconnect may try before it scans. `recent` holds
/// carrier and endpoint pairs, newest first, so a failed carrier can still leave
/// its other half to be reused.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct LastEdge {
    recent: Vec<(String, SocketAddr, Option<String>)>,
}

const RECENT_CAP: usize = 8;
const LAST_EDGE_CAP: usize = 64 * 1024;

impl LastEdge {
    pub(crate) fn load(path: &Path) -> Self {
        let Ok(file) = std::fs::File::open(path) else {
            return Self::default();
        };
        let mut text = String::new();
        if file
            .take(LAST_EDGE_CAP as u64)
            .read_to_string(&mut text)
            .is_err()
        {
            return Self::default();
        }
        let Ok(json) = crate::json::parse(&text) else {
            return Self::default();
        };
        let mut recent = Vec::new();
        for row in json
            .get("recent")
            .and_then(crate::json::Json::as_arr)
            .into_iter()
            .flatten()
        {
            let Some(carrier) = row.get("carrier").and_then(crate::json::Json::as_str) else {
                continue;
            };
            let Some(endpoint) = row
                .get("endpoint")
                .and_then(crate::json::Json::as_str)
                .and_then(|text| text.parse().ok())
            else {
                continue;
            };
            let profile = row
                .get("profile")
                .and_then(crate::json::Json::as_str)
                .map(str::to_owned);
            if recent
                .iter()
                .any(|(name, _, _): &(String, SocketAddr, Option<String>)| name == carrier)
            {
                continue;
            }
            recent.push((carrier.to_owned(), endpoint, profile));
            if recent.len() == RECENT_CAP {
                break;
            }
        }
        Self { recent }
    }

    pub(crate) fn save(&self, path: &Path) -> Result<(), String> {
        let rows = self
            .recent
            .iter()
            .map(|(carrier, endpoint, profile)| {
                let mut row = vec![
                    (
                        "carrier".to_owned(),
                        crate::json::Json::Str(carrier.clone()),
                    ),
                    (
                        "endpoint".to_owned(),
                        crate::json::Json::Str(endpoint.to_string()),
                    ),
                ];
                if let Some(profile) = profile {
                    row.push((
                        "profile".to_owned(),
                        crate::json::Json::Str(profile.clone()),
                    ));
                }
                crate::json::Json::Obj(row)
            })
            .collect();
        let json =
            crate::json::Json::Obj(vec![("recent".to_owned(), crate::json::Json::Arr(rows))]);
        let mut text = String::new();
        crate::json::write(&json, &mut text);
        let dir = path.parent().unwrap_or_else(|| Path::new("."));
        let mut opened = None;
        let mut last_error = std::io::Error::from(std::io::ErrorKind::AlreadyExists);
        for _ in 0..8 {
            let mut raw = [0u8; 8];
            let _ = getrandom::fill(&mut raw);
            let mut name = path.file_name().map_or_else(
                || std::ffi::OsString::from("lastconn"),
                std::ffi::OsStr::to_os_string,
            );
            name.push(format!(
                ".{}.{}.tmp",
                std::process::id(),
                ferrox_core::foxy::account::hex_encode(&raw)
            ));
            let temp = dir.join(name);
            let mut options = std::fs::OpenOptions::new();
            options.write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt as _;
                options.mode(0o600);
            }
            match options.open(&temp) {
                Ok(file) => {
                    opened = Some((file, temp));
                    break;
                }
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(error) => {
                    last_error = error;
                    break;
                }
            }
        }
        let Some((mut file, temp)) = opened else {
            return Err(format!(
                "warp: cannot save `{}`: {last_error}",
                path.display()
            ));
        };
        if let Err(error) = file.write_all(text.as_bytes()) {
            drop(file);
            let _ = std::fs::remove_file(&temp);
            return Err(format!("warp: cannot save `{}`: {error}", path.display()));
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let _ = file.set_permissions(std::fs::Permissions::from_mode(0o600));
        }
        drop(file);
        std::fs::rename(&temp, path).map_err(|error| {
            let _ = std::fs::remove_file(&temp);
            format!("warp: cannot save `{}`: {error}", path.display())
        })
    }

    pub(crate) fn get(&self, carrier: &str) -> Option<(SocketAddr, Option<&str>)> {
        self.recent
            .iter()
            .find(|(name, _, _)| name == carrier)
            .map(|(_, endpoint, profile)| (*endpoint, profile.as_deref()))
    }

    pub(crate) fn record(&mut self, carrier: &str, endpoint: SocketAddr, profile: Option<&str>) {
        self.recent.retain(|(name, _, _)| name != carrier);
        self.recent.insert(
            0,
            (carrier.to_owned(), endpoint, profile.map(str::to_owned)),
        );
        self.recent.truncate(RECENT_CAP);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_reference_alias_names_its_mode() {
        let cases = [
            ("turbo", ScanMode::Turbo),
            ("fast", ScanMode::Turbo),
            ("balanced", ScanMode::Balanced),
            ("thorough", ScanMode::Thorough),
            ("deep", ScanMode::Thorough),
            ("pro", ScanMode::Thorough),
            ("verified", ScanMode::Verified),
            ("proven", ScanMode::Verified),
            ("stealth", ScanMode::Verified),
            ("quiet", ScanMode::Verified),
            ("ironclad", ScanMode::Ironclad),
            ("real", ScanMode::Ironclad),
            ("verify", ScanMode::Ironclad),
            ("guaranteed", ScanMode::Ironclad),
        ];
        for (text, mode) in cases {
            assert_eq!(ScanMode::parse(text), Some(mode), "{text}");
        }
        assert_eq!(ScanMode::parse("nonsense"), None);
    }

    #[test]
    fn the_reference_sweep_counts_are_the_documented_ones() {
        assert_eq!(WG_PREFIXES_V4.len(), 7);
        assert_eq!(WG_SEEDS_V4.len(), 5);
        assert_eq!(WG_PORTS.len(), 54);
        assert_eq!(MASQUE_PREFIXES_V4.len(), 14);
        assert_eq!(MASQUE_SEEDS.len(), 10);
        assert_eq!(MASQUE_PORTS.len(), 7);
        assert_eq!(RECENT_CAP, 8);
    }

    #[test]
    fn the_wireguard_sweep_starts_with_the_seeds_on_separate_ports() {
        let candidates = wg_candidates(ScanMode::Turbo);
        for (index, seed) in WG_SEEDS_V4.iter().enumerate() {
            let ip: Ipv4Addr = seed.parse().expect("a seed");
            assert_eq!(
                candidates[index],
                SocketAddr::from((ip, WG_PORTS[index % WG_PORTS.len()]))
            );
        }
        assert!(candidates.contains(&"162.159.192.1:2408".parse().expect("the default port")));
    }

    #[test]
    fn the_masque_sweep_covers_the_documented_ranges_and_every_port() {
        let candidates = masque_candidates(ScanMode::Turbo);
        for seed in ["162.159.197.3", "162.159.198.2"] {
            let ip: Ipv4Addr = seed.parse().expect("a documented seed");
            for port in MASQUE_PORTS {
                assert!(
                    candidates.contains(&SocketAddr::from((ip, port))),
                    "{ip}:{port} is in the sweep"
                );
            }
        }
        assert_eq!(
            candidates[0],
            "162.159.196.1:443".parse().expect("the first seed")
        );
    }

    #[test]
    fn the_masque_sweep_samples_every_443_edge_before_falling_back() {
        for mode in [ScanMode::Turbo, ScanMode::Ironclad] {
            let strategy = mode.strategy();
            let candidates = masque_candidates(mode);
            let fallback = candidates
                .iter()
                .position(|edge| edge.port() != MASQUE_PORTS[0])
                .expect("a seed fallback port");
            let sampled =
                sample_prefixes(&MASQUE_PREFIXES_V4, strategy.full_subnet, strategy.sample)
                    .into_iter()
                    .map(|ip| SocketAddr::from((ip, MASQUE_PORTS[0])));
            let seeds = MASQUE_SEEDS
                .iter()
                .filter_map(|text| text.parse::<Ipv4Addr>().ok())
                .map(|ip| SocketAddr::from((ip, MASQUE_PORTS[0])));
            let before: HashSet<SocketAddr> = candidates[..fallback].iter().copied().collect();
            for edge in sampled.chain(seeds) {
                assert!(
                    before.contains(&edge),
                    "{mode:?} fell back before trying {edge}"
                );
            }
            assert!(
                candidates[fallback..]
                    .iter()
                    .all(|edge| edge.port() != MASQUE_PORTS[0]),
                "{mode:?} sampled a 443 edge after the first fallback port"
            );
        }
    }

    #[test]
    fn a_sampled_range_stays_inside_its_hosts() {
        let hosts = sample_cidr("162.159.197.0/24", 48);
        assert_eq!(hosts.len(), 48);
        assert!(hosts.windows(2).all(|pair| pair[0] != pair[1]));
        assert!(hosts.iter().all(|ip| {
            let octets = ip.octets();
            octets[..3] == [162, 159, 197] && octets[3] != 0 && octets[3] != 255
        }));
    }

    #[test]
    fn a_thorough_range_is_enumerated_without_its_edges() {
        let hosts: Vec<String> = enumerate_cidr("192.0.2.0/30")
            .iter()
            .map(ToString::to_string)
            .collect();
        assert_eq!(hosts, ["192.0.2.1", "192.0.2.2"]);
        assert_eq!(enumerate_cidr("10.0.0.0/8"), Vec::<Ipv4Addr>::new());
    }

    #[test]
    fn an_idle_worker_picks_up_a_fallback_edge() {
        let first: SocketAddr = "192.0.2.1:500".parse().expect("an early edge");
        let second: SocketAddr = "192.0.2.2:500".parse().expect("an early edge");
        let primary: Vec<SocketAddr> = (1..=19)
            .map(|host| {
                format!("198.51.100.{host}:443")
                    .parse()
                    .expect("a primary edge")
            })
            .collect();
        let started = AtomicBool::new(false);
        let caught = AtomicBool::new(false);
        let assisted = AtomicBool::new(false);
        let found = hunt_with_early(
            primary,
            vec![first, second],
            ScanMode::Turbo,
            &HashSet::new(),
            |edge| {
                if edge == first {
                    started.store(true, Ordering::SeqCst);
                    let wait = Instant::now();
                    let mut saw_helper = caught.load(Ordering::SeqCst);
                    while !saw_helper && wait.elapsed() < Duration::from_secs(2) {
                        std::thread::sleep(Duration::from_millis(1));
                        saw_helper = caught.load(Ordering::SeqCst);
                    }
                    assisted.store(saw_helper, Ordering::SeqCst);
                    None
                } else if edge == second {
                    caught.store(true, Ordering::SeqCst);
                    Some(Duration::from_millis(1))
                } else {
                    let wait = Instant::now();
                    while !started.load(Ordering::SeqCst) && wait.elapsed() < Duration::from_secs(2)
                    {
                        std::thread::sleep(Duration::from_millis(1));
                    }
                    None
                }
            },
        );
        assert_eq!(found, vec![(second, Duration::from_millis(1))]);
        assert!(
            assisted.load(Ordering::SeqCst),
            "the first fallback timed out instead of another worker taking the second"
        );
    }

    #[test]
    fn the_first_answering_edge_wins_a_turbo_hunt() {
        let fast: SocketAddr = "192.0.2.1:2408".parse().expect("an edge");
        let slow: SocketAddr = "192.0.2.2:2408".parse().expect("an edge");
        let found = hunt(vec![fast, slow], ScanMode::Turbo, &HashSet::new(), |edge| {
            (edge == fast).then_some(Duration::from_millis(4))
        });
        assert_eq!(found, vec![(fast, Duration::from_millis(4))]);
    }

    #[test]
    fn an_excluded_edge_is_not_probed() {
        let edge: SocketAddr = "192.0.2.1:2408".parse().expect("an edge");
        let mut excluded = HashSet::new();
        excluded.insert(edge);
        let found = hunt(vec![edge], ScanMode::Turbo, &excluded, |_| {
            Some(Duration::from_millis(1))
        });
        assert_eq!(found, Vec::new());
    }

    #[test]
    fn a_cooled_edge_returns_when_its_time_is_up() {
        let edge: SocketAddr = "192.0.2.1:2408".parse().expect("an edge");
        let now = Instant::now();
        let mut cooldowns = Cooldowns::new(Duration::from_secs(300));
        cooldowns.hold(edge, now);
        assert!(cooldowns.cooling(edge, now));
        assert!(!cooldowns.cooling(edge, now + Duration::from_secs(301)));
        cooldowns.hold(edge, now + Duration::from_secs(301));
        cooldowns.purge(now + Duration::from_secs(602));
        assert!(!cooldowns.cooling(edge, now + Duration::from_secs(602)));
    }

    #[test]
    fn the_last_edge_keeps_one_entry_per_carrier_and_is_bounded() {
        let dir = std::env::temp_dir().join(format!("ferrox-lastconn-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("a temp dir");
        let path = dir.join("lastconn.json");
        let mut recent = LastEdge::default();
        recent.record(
            "wireguard",
            "192.0.2.1:2408".parse().expect("an edge"),
            Some("gfw"),
        );
        recent.record("masque", "192.0.2.2:443".parse().expect("an edge"), None);
        assert_eq!(
            recent.get("wireguard"),
            Some(("192.0.2.1:2408".parse().expect("an edge"), Some("gfw")))
        );
        assert_eq!(
            recent.get("masque"),
            Some(("192.0.2.2:443".parse().expect("an edge"), None))
        );
        recent.save(&path).expect("saves");
        assert_eq!(LastEdge::load(&path), recent);
        for index in 0..RECENT_CAP + 4 {
            recent.record(
                "wireguard",
                SocketAddr::from(([192, 0, 2, index as u8 + 1], 2408)),
                Some("balanced"),
            );
        }
        assert_eq!(recent.recent.len(), 2);
        assert_eq!(
            recent.get("wireguard"),
            Some((
                SocketAddr::from(([192, 0, 2, RECENT_CAP as u8 + 4], 2408)),
                Some("balanced")
            ))
        );
        assert_eq!(
            recent.get("masque"),
            Some(("192.0.2.2:443".parse().expect("an edge"), None))
        );
        for index in 0..=RECENT_CAP {
            recent.record(
                &format!("extra-{index}"),
                SocketAddr::from(([198, 51, 100, index as u8 + 1], 443)),
                None,
            );
        }
        assert_eq!(recent.recent.len(), RECENT_CAP);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn the_last_edge_load_is_bounded_and_a_save_never_truncates_a_link_target() {
        let dir =
            std::env::temp_dir().join(format!("ferrox-lastconn-bound-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("a temp dir");
        let path = dir.join("lastconn.json");
        std::fs::write(&path, "x".repeat(LAST_EDGE_CAP + 1)).expect("an oversized file");
        assert_eq!(
            LastEdge::load(&path),
            LastEdge::default(),
            "an oversized file is not a listing"
        );
        #[cfg(unix)]
        {
            let outside = dir.join("outside.json");
            std::fs::write(&outside, "keep me").expect("an outside file");
            let link = dir.join("link.json");
            std::os::unix::fs::symlink(&outside, &link).expect("a link");
            let mut recent = LastEdge::default();
            recent.record(
                "wireguard",
                "192.0.2.9:2408".parse().expect("an edge"),
                None,
            );
            recent.save(&link).expect("saves over the link");
            assert_eq!(
                std::fs::read_to_string(&outside).expect("reads"),
                "keep me",
                "the link's target is never truncated"
            );
            assert_eq!(
                LastEdge::load(&link),
                recent,
                "the link is replaced by the listing"
            );
        }
        std::fs::remove_dir_all(&dir).ok();
    }
}
