use crate::json::Json;
use crate::policy::{self, SystemStats};
use std::collections::{BTreeMap, HashMap};
use std::sync::atomic::{AtomicBool, AtomicI64, Ordering};
use std::sync::{Arc, LazyLock, Mutex, MutexGuard};

/// One reference counter: a signed 64-bit value that every flow shares.
#[derive(Debug, Default)]
pub(crate) struct Counter(AtomicI64);

impl Counter {
    pub(crate) fn add(&self, bytes: u64) {
        self.0.fetch_add(bytes.cast_signed(), Ordering::Relaxed);
    }

    pub(crate) fn value(&self) -> i64 {
        self.0.load(Ordering::Relaxed)
    }

    fn swap(&self, value: i64) -> i64 {
        self.0.swap(value, Ordering::Relaxed)
    }
}

#[derive(Debug, Clone, Copy)]
struct OnlineIp {
    refs: u64,
    last_seen: i64,
}

#[derive(Debug, Default)]
struct Registry {
    counters: HashMap<String, Arc<Counter>>,
    online: HashMap<String, HashMap<String, OnlineIp>>,
}

impl Registry {
    fn counter(&mut self, name: &str) -> Arc<Counter> {
        Arc::clone(
            self.counters
                .entry(name.to_owned())
                .or_insert_with(|| Arc::new(Counter::default())),
        )
    }

    fn online_add(&mut self, name: &str, ip: &str, now: i64) {
        let entries = self.online.entry(name.to_owned()).or_default();
        let entry = entries.entry(ip.to_owned()).or_insert(OnlineIp {
            refs: 0,
            last_seen: now,
        });
        entry.refs += 1;
        entry.last_seen = now;
    }

    fn online_remove(&mut self, name: &str, ip: &str) {
        let Some(entries) = self.online.get_mut(name) else {
            return;
        };
        let Some(entry) = entries.get_mut(ip) else {
            return;
        };
        entry.refs = entry.refs.saturating_sub(1);
        if entry.refs == 0 {
            entries.remove(ip);
        }
        if entries.is_empty() {
            self.online.remove(name);
        }
    }
}

static REGISTRY: LazyLock<Mutex<Registry>> = LazyLock::new(|| Mutex::new(Registry::default()));
static ENABLED: AtomicBool = AtomicBool::new(false);
static SYSTEM: Mutex<SystemStats> = Mutex::new(SystemStats {
    inbound_uplink: false,
    inbound_downlink: false,
    outbound_uplink: false,
    outbound_downlink: false,
});

fn registry() -> MutexGuard<'static, Registry> {
    REGISTRY
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

fn system() -> SystemStats {
    *SYSTEM
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// The metering one flow carries: counters in the reference's directions, the level policy,
/// and the online lease a user flow holds until its last handle drops.
#[derive(Debug, Clone, Default)]
pub(crate) struct Meter {
    read: Vec<Arc<Counter>>,
    write: Vec<Arc<Counter>>,
    online: Option<Arc<OnlineLease>>,
}

impl Meter {
    pub(crate) fn is_empty(&self) -> bool {
        self.read.is_empty() && self.write.is_empty() && self.online.is_none()
    }

    /// Whether this meter already owns the flow's online lease.
    pub(crate) fn has_online(&self) -> bool {
        self.online.is_some()
    }

    /// Whether this meter observes bytes, which is what forbids a descriptor-level fast path.
    pub(crate) fn counts(&self) -> bool {
        !self.read.is_empty() || !self.write.is_empty()
    }

    pub(crate) fn read(&self, bytes: usize) {
        for counter in &self.read {
            counter.add(bytes as u64);
        }
    }

    pub(crate) fn write(&self, bytes: usize) {
        for counter in &self.write {
            counter.add(bytes as u64);
        }
    }

    /// The same counters seen from the far side of a relay: reads there are downlink and writes
    /// are uplink.
    pub(crate) fn reversed(self) -> Self {
        Self {
            read: self.write,
            write: self.read,
            online: self.online,
        }
    }

    /// A newer meter for the same flow keeps the counters the older one carried and adds the
    /// ones it names, so wrapping a decoded user never stops the inbound's own count.
    pub(crate) fn merged(mut self, newer: Self) -> Self {
        self.read.extend(newer.read);
        self.write.extend(newer.write);
        if newer.online.is_some() {
            self.online = newer.online;
        }
        self
    }
}

#[derive(Debug)]
pub(crate) struct OnlineLease {
    name: String,
    ip: String,
}

impl Drop for OnlineLease {
    fn drop(&mut self) {
        registry().online_remove(&self.name, &self.ip);
    }
}

fn counter(name: &str) -> Arc<Counter> {
    registry().counter(name)
}

fn traffic(kind: &str, name: &str, direction: &str) -> String {
    format!("{kind}>>>{name}>>>traffic>>>{direction}")
}

/// Whether the config asked for the stats manager at all.
pub(crate) fn enabled() -> bool {
    ENABLED.load(Ordering::Relaxed)
}

/// Install the stats manager and register every counter the reference would have at startup.
pub(crate) fn install(root: &Json) -> Result<bool, String> {
    let Some(section) = root.get("stats") else {
        ENABLED.store(false, Ordering::Relaxed);
        return Ok(false);
    };
    if !matches!(section, Json::Obj(_)) {
        return Err("`stats` is not an object".to_owned());
    }
    ENABLED.store(true, Ordering::Relaxed);
    let system = policy::system();
    *SYSTEM
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner) = system;
    register_system(root, system);
    register_users(root);
    Ok(true)
}

fn register_system(root: &Json, system: SystemStats) {
    if system.inbound_uplink || system.inbound_downlink {
        for inbound in root.get("inbounds").and_then(Json::as_arr).unwrap_or(&[]) {
            let Some(tag) = inbound
                .get("tag")
                .and_then(Json::as_str)
                .filter(|tag| !tag.is_empty())
            else {
                continue;
            };
            if system.inbound_uplink {
                counter(&traffic("inbound", tag, "uplink"));
            }
            if system.inbound_downlink {
                counter(&traffic("inbound", tag, "downlink"));
            }
        }
    }
    if system.outbound_uplink || system.outbound_downlink {
        for outbound in root.get("outbounds").and_then(Json::as_arr).unwrap_or(&[]) {
            let Some(tag) = outbound
                .get("tag")
                .and_then(Json::as_str)
                .filter(|tag| !tag.is_empty())
            else {
                continue;
            };
            if system.outbound_uplink {
                counter(&traffic("outbound", tag, "uplink"));
            }
            if system.outbound_downlink {
                counter(&traffic("outbound", tag, "downlink"));
            }
        }
    }
}

fn register_users(root: &Json) {
    for inbound in root.get("inbounds").and_then(Json::as_arr).unwrap_or(&[]) {
        let settings = inbound.get("settings");
        for list in ["clients", "accounts", "users"] {
            let Some(rows) = settings
                .and_then(|settings| settings.get(list))
                .and_then(Json::as_arr)
            else {
                continue;
            };
            for row in rows {
                let Some(email) = row
                    .get("email")
                    .and_then(Json::as_str)
                    .filter(|email| !email.is_empty())
                else {
                    continue;
                };
                let level = row.get("level").and_then(Json::as_u32).unwrap_or(0);
                let Some(policy) = policy::configured()
                    .and_then(|config| config.levels.get(&level).map(|level| level.stats))
                else {
                    continue;
                };
                if policy.user_uplink {
                    counter(&traffic("user", email, "uplink"));
                }
                if policy.user_downlink {
                    counter(&traffic("user", email, "downlink"));
                }
            }
        }
    }
}

/// The inbound meter: reads are uplink, writes are downlink, exactly the reference's raw-conn wrap.
pub(crate) fn inbound(tag: Option<&str>) -> Meter {
    if !enabled() {
        return Meter::default();
    }
    let system = system();
    let name = tag.filter(|tag| !tag.is_empty());
    let read = name
        .filter(|_| system.inbound_uplink)
        .map(|tag| counter(&traffic("inbound", tag, "uplink")))
        .into_iter()
        .collect();
    let write = name
        .filter(|_| system.inbound_downlink)
        .map(|tag| counter(&traffic("inbound", tag, "downlink")))
        .into_iter()
        .collect();
    Meter {
        read,
        write,
        online: None,
    }
}

/// The outbound meter: writes are uplink and reads are downlink, the reference's own direction
/// swap at the outbound handler.
pub(crate) fn outbound(tag: Option<&str>) -> Meter {
    if !enabled() {
        return Meter::default();
    }
    let system = system();
    let name = tag.filter(|tag| !tag.is_empty());
    let read = name
        .filter(|_| system.outbound_downlink)
        .map(|tag| counter(&traffic("outbound", tag, "downlink")))
        .into_iter()
        .collect();
    let write = name
        .filter(|_| system.outbound_uplink)
        .map(|tag| counter(&traffic("outbound", tag, "uplink")))
        .into_iter()
        .collect();
    Meter {
        read,
        write,
        online: None,
    }
}

/// The counters a decoded account adds. The online lease belongs to the flow, not the stream,
/// because the reference tracks one source IP per session.
pub(crate) fn user_traffic(email: &str, level: u32) -> Meter {
    if !enabled() || email.is_empty() {
        return Meter::default();
    }
    let Some(policy) =
        policy::configured().and_then(|config| config.levels.get(&level).map(|level| level.stats))
    else {
        return Meter::default();
    };
    let read = policy
        .user_uplink
        .then(|| counter(&traffic("user", email, "uplink")))
        .into_iter()
        .collect();
    let write = policy
        .user_downlink
        .then(|| counter(&traffic("user", email, "downlink")))
        .into_iter()
        .collect();
    Meter {
        read,
        write,
        online: None,
    }
}

/// The online lease an authenticated account holds: the reference tracks it once the protocol
/// names the user, so an unauthenticated probe never enters the map. A flow with no source
/// address keeps an empty key so its count still moves; the IP list hides that key.
pub(crate) fn online(
    email: &str,
    level: u32,
    source: Option<std::net::IpAddr>,
) -> Option<Arc<OnlineLease>> {
    if !enabled() || email.is_empty() {
        return None;
    }
    let policy = policy::configured()
        .and_then(|config| config.levels.get(&level).map(|level| level.stats))?;
    if !policy.user_online {
        return None;
    }
    let ip = match source {
        Some(std::net::IpAddr::V4(ip)) if ip == std::net::Ipv4Addr::LOCALHOST => return None,
        Some(std::net::IpAddr::V6(ip)) if ip == std::net::Ipv6Addr::LOCALHOST => return None,
        Some(ip) => match ip {
            std::net::IpAddr::V4(_) => ip.to_string(),
            std::net::IpAddr::V6(_) => format!("[{ip}]"),
        },
        None => String::new(),
    };
    let name = format!("user>>>{email}>>>online");
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |since| since.as_secs().cast_signed());
    registry().online_add(&name, &ip, now);
    Some(Arc::new(OnlineLease { name, ip }))
}

/// The user meter a decoded account adds: payload counters and the online lease the reference
/// holds for the flow's source until the last relay handle drops.
pub(crate) fn user(email: &str, level: u32) -> Meter {
    let mut meter = user_traffic(email, level);
    meter.online = online(email, level, crate::accesslog::source_ip());
    meter
}

/// The online lease alone, for a relay that already carries the front's traffic meter.
pub(crate) fn online_flow() -> Meter {
    let (email, level) = crate::accesslog::identity();
    Meter {
        online: online(&email, level, crate::accesslog::source_ip()),
        ..Meter::default()
    }
}

/// A meter that counts on every flow, so a gate can observe the descriptor-level fast path a
/// configured user stats policy forbids. The handles are the counters the meter adds to.
#[cfg(test)]
pub(crate) fn counting() -> (Meter, Arc<Counter>, Arc<Counter>) {
    let read = Arc::new(Counter::default());
    let write = Arc::new(Counter::default());
    (
        Meter {
            read: vec![Arc::clone(&read)],
            write: vec![Arc::clone(&write)],
            online: None,
        },
        read,
        write,
    )
}

/// One tag's traffic, as the metrics app prints it.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct Traffic {
    pub(crate) uplink: i64,
    pub(crate) downlink: i64,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct Snapshot {
    pub(crate) inbound: BTreeMap<String, Traffic>,
    pub(crate) outbound: BTreeMap<String, Traffic>,
    pub(crate) user: BTreeMap<String, Traffic>,
    pub(crate) online: BTreeMap<String, u64>,
}

impl Snapshot {
    fn traffic(&mut self, name: &str, value: i64) {
        let Some((kind, rest)) = name.split_once(">>>") else {
            return;
        };
        let Some((tag, direction)) = rest.rsplit_once(">>>traffic>>>") else {
            return;
        };
        let map = match kind {
            "inbound" => &mut self.inbound,
            "outbound" => &mut self.outbound,
            "user" => &mut self.user,
            _ => return,
        };
        let row = map.entry(tag.to_owned()).or_default();
        match direction {
            "uplink" => row.uplink = value,
            "downlink" => row.downlink = value,
            _ => {}
        }
    }
}

/// One counter by the name the reference registered, optionally reset by the read.
pub(crate) fn get(name: &str, reset: bool) -> Option<i64> {
    let registry = registry();
    let counter = registry.counters.get(name)?;
    Some(if reset {
        counter.swap(0)
    } else {
        counter.value()
    })
}

/// One online user as the reference's stats service reports it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct OnlineUser {
    pub(crate) email: String,
    pub(crate) ips: Vec<(String, i64)>,
}

/// The reference's online-map count by its full name.
pub(crate) fn online_count(name: &str) -> Option<u64> {
    registry()
        .online
        .get(name)
        .map(|ips| ips.len().try_into().unwrap_or(u64::MAX))
}

/// The IP list an online map names, without the empty key a source-less flow keeps.
pub(crate) fn online_ips(name: &str) -> Option<Vec<(String, i64)>> {
    let registry = registry();
    let entries = registry.online.get(name)?;
    let mut ips: Vec<(String, i64)> = entries
        .iter()
        .filter(|(ip, _)| !ip.is_empty())
        .map(|(ip, entry)| (ip.clone(), entry.last_seen))
        .collect();
    ips.sort_by(|left, right| left.0.cmp(&right.0));
    Some(ips)
}

/// Every online map with a live entry, by the reference's name.
pub(crate) fn online_users() -> Vec<String> {
    let registry = registry();
    let mut users: Vec<String> = registry
        .online
        .iter()
        .filter(|(_, ips)| !ips.is_empty())
        .map(|(name, _)| name.clone())
        .collect();
    users.sort();
    users
}

/// The online users that name at least one IP, in email order.
pub(crate) fn online_user_stats() -> Vec<OnlineUser> {
    let registry = registry();
    let mut users: Vec<OnlineUser> = registry
        .online
        .iter()
        .filter_map(|(name, ips)| {
            let email = name.strip_prefix("user>>>")?.strip_suffix(">>>online")?;
            let mut rows: Vec<(String, i64)> = ips
                .iter()
                .filter(|(ip, _)| !ip.is_empty())
                .map(|(ip, entry)| (ip.clone(), entry.last_seen))
                .collect();
            if rows.is_empty() {
                return None;
            }
            rows.sort_by(|left, right| left.0.cmp(&right.0));
            Some(OnlineUser {
                email: email.to_owned(),
                ips: rows,
            })
        })
        .collect();
    users.sort_by(|left, right| left.email.cmp(&right.email));
    users
}

/// Every counter whose name contains the pattern, optionally reset by the read.
pub(crate) fn query(pattern: &str, reset: bool) -> Vec<(String, i64)> {
    let registry = registry();
    let mut found: Vec<(String, i64)> = registry
        .counters
        .iter()
        .filter(|(name, _)| name.contains(pattern))
        .map(|(name, counter)| {
            let value = if reset {
                counter.swap(0)
            } else {
                counter.value()
            };
            (name.clone(), value)
        })
        .collect();
    found.sort_by(|left, right| left.0.cmp(&right.0));
    found
}

/// A consistent read of every counter and online map the manager holds.
pub(crate) fn snapshot() -> Snapshot {
    let registry = registry();
    let mut snapshot = Snapshot {
        online: registry
            .online
            .iter()
            .filter_map(|(name, ips)| {
                let email = name.strip_prefix("user>>>")?.strip_suffix(">>>online")?;
                Some((email.to_owned(), ips.len() as u64))
            })
            .collect(),
        ..Snapshot::default()
    };
    for (name, counter) in &registry.counters {
        snapshot.traffic(name, counter.value());
    }
    snapshot
}

#[cfg(test)]
pub(crate) fn clear() {
    let mut registry = registry();
    registry.counters.clear();
    registry.online.clear();
    ENABLED.store(false, Ordering::Relaxed);
    *SYSTEM
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner) = SystemStats::default();
    policy::clear();
}

#[cfg(test)]
static TEST_LOCK: LazyLock<Mutex<()>> = LazyLock::new(|| Mutex::new(()));

#[cfg(test)]
pub(crate) fn test_lock() -> MutexGuard<'static, ()> {
    TEST_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_reference_names_are_registered_and_their_bytes_add_up() {
        let _guard = test_lock();
        clear();
        let root = crate::json::parse(
            r#"{"stats":{},"policy":{"system":{"statsInboundUplink":true,
                "statsOutboundDownlink":true}},"inbounds":[{"tag":"in"}],
                "outbounds":[{"tag":"out"}]}"#,
        )
        .expect("parses");
        crate::policy::install(&root).expect("policy installs");
        install(&root).expect("stats installs");
        let inbound = inbound(Some("in"));
        inbound.read(12);
        inbound.write(99);
        let outbound = outbound(Some("out"));
        outbound.read(7);
        outbound.write(99);
        let snapshot = snapshot();
        assert_eq!(
            snapshot.inbound.get("in"),
            Some(&Traffic {
                uplink: 12,
                downlink: 0
            })
        );
        assert_eq!(
            snapshot.outbound.get("out"),
            Some(&Traffic {
                uplink: 0,
                downlink: 7
            })
        );
        clear();
    }

    #[test]
    fn a_user_meter_keeps_the_inbound_counters_it_was_added_to() {
        let _guard = test_lock();
        clear();
        let root = crate::json::parse(
            r#"{"stats":{},"policy":{"levels":{"1":{"statsUserUplink":true}},
                "system":{"statsInboundUplink":true}},"inbounds":[{"tag":"in"}]}"#,
        )
        .expect("parses");
        crate::policy::install(&root).expect("policy installs");
        install(&root).expect("stats installs");
        let meter = inbound(Some("in")).merged(user("alice@example", 1));
        meter.read(9);
        let snapshot = snapshot();
        assert_eq!(snapshot.inbound["in"].uplink, 9);
        assert_eq!(snapshot.user["alice@example"].uplink, 9);
        clear();
    }

    #[test]
    fn a_reversed_user_meter_counts_the_far_side_directions() {
        let _guard = test_lock();
        clear();
        let root = crate::json::parse(
            r#"{"stats":{},"policy":{"levels":{"1":{"statsUserUplink":true,
                "statsUserDownlink":true}}}}"#,
        )
        .expect("parses");
        crate::policy::install(&root).expect("policy installs");
        install(&root).expect("stats installs");
        let meter = user("alice@example", 1).reversed();
        meter.write(11);
        meter.read(7);
        let snapshot = snapshot();
        assert_eq!(snapshot.user["alice@example"].uplink, 11);
        assert_eq!(snapshot.user["alice@example"].downlink, 7);
        clear();
    }

    #[test]
    fn a_user_meter_holds_its_online_lease_until_its_last_handle_drops() {
        let _guard = test_lock();
        clear();
        let root = crate::json::parse(
            r#"{"stats":{},"policy":{"levels":{"1":{"statsUserUplink":true,
                "statsUserOnline":true}}}}"#,
        )
        .expect("parses");
        crate::policy::install(&root).expect("policy installs");
        install(&root).expect("stats installs");
        let meter = user("alice@example", 1);
        let clone = meter.clone();
        meter.read(5);
        assert_eq!(snapshot().online.get("alice@example"), Some(&1));
        drop(meter);
        assert_eq!(snapshot().online.get("alice@example"), Some(&1));
        drop(clone);
        assert_eq!(snapshot().online.get("alice@example"), None);
        assert_eq!(
            snapshot().user.get("alice@example").expect("user").uplink,
            5
        );
        clear();
    }

    #[test]
    fn a_loopback_source_is_not_online() {
        let _guard = test_lock();
        clear();
        let root = crate::json::parse(
            r#"{"stats":{},"policy":{"levels":{"1":{"statsUserOnline":true}}}}"#,
        )
        .expect("parses");
        crate::policy::install(&root).expect("policy installs");
        install(&root).expect("stats installs");
        assert!(online("alice@example", 1, Some("127.0.0.1".parse().expect("ip"))).is_none());
        assert!(online("alice@example", 1, Some("::1".parse().expect("ip"))).is_none());
        assert_eq!(snapshot().online.get("alice@example"), None);
        let other = online("alice@example", 1, Some("127.0.0.2".parse().expect("ip")))
            .expect("the reference skips only the two localhost spellings");
        drop(other);
        assert_eq!(snapshot().online.get("alice@example"), None);
        clear();
    }

    #[test]
    fn an_online_map_names_its_sources_until_the_last_lease_drops() {
        let _guard = test_lock();
        clear();
        let root = crate::json::parse(
            r#"{"stats":{},"policy":{"levels":{"1":{"statsUserOnline":true}}}}"#,
        )
        .expect("parses");
        crate::policy::install(&root).expect("policy installs");
        install(&root).expect("stats installs");
        let name = "user>>>alice@example>>>online";
        let first = online("alice@example", 1, Some("192.0.2.10".parse().expect("ip")))
            .expect("the level tracks online users");
        let second = online("alice@example", 1, Some("192.0.2.10".parse().expect("ip")))
            .expect("a second flow on the same source");
        assert_eq!(online_count(name), Some(1));
        assert_eq!(online_ips(name).expect("the map").len(), 1);
        assert!(
            online_ips(name).expect("the map")[0].1 > 0,
            "last seen is set"
        );
        assert_eq!(
            online_users(),
            vec![name.to_owned()],
            "the map is named as the reference names it"
        );
        let stats = online_user_stats();
        assert_eq!(stats.len(), 1);
        assert_eq!(stats[0].email, "alice@example");
        assert_eq!(stats[0].ips[0].0, "192.0.2.10");
        drop(first);
        assert_eq!(
            online_count(name),
            Some(1),
            "the second flow still holds it"
        );
        drop(second);
        assert_eq!(online_count(name), None);
        clear();
    }

    #[test]
    fn a_source_less_lease_counts_without_naming_an_ip() {
        let _guard = test_lock();
        clear();
        let root = crate::json::parse(
            r#"{"stats":{},"policy":{"levels":{"1":{"statsUserOnline":true}}}}"#,
        )
        .expect("parses");
        crate::policy::install(&root).expect("policy installs");
        install(&root).expect("stats installs");
        let lease = online("alice@example", 1, None).expect("tracked");
        let name = "user>>>alice@example>>>online";
        assert_eq!(online_count(name), Some(1));
        assert_eq!(online_ips(name), Some(Vec::new()));
        assert_eq!(online_user_stats(), Vec::<OnlineUser>::new());
        drop(lease);
        clear();
    }

    #[test]
    fn a_stats_section_that_is_not_an_object_is_refused() {
        let root = crate::json::parse(r#"{"stats":true}"#).expect("parses");
        assert!(install(&root).expect_err("not an object").contains("stats"));
    }
}
