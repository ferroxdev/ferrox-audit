use std::time::Duration;

use crate::json::Json;

#[derive(Debug, Clone, Default)]
pub(crate) struct NoizeSettings {
    profile: Option<String>,
    no_retry: bool,
    wireguard_override: Option<String>,
}

impl NoizeSettings {
    pub(crate) fn from_settings(settings: &Json) -> Result<Self, String> {
        let profile = match settings.get("noize") {
            None | Some(Json::Null) => None,
            Some(Json::Str(text)) => Some(text.trim().to_owned()).filter(|text| !text.is_empty()),
            Some(_) => return Err("warp: `noize` must be a profile name".to_owned()),
        }
        .or_else(|| {
            std::env::var("AETHER_NOIZE")
                .ok()
                .map(|text| text.trim().to_owned())
                .filter(|text| !text.is_empty())
        });
        let no_retry = settings
            .get("noProfileRetry")
            .and_then(Json::as_bool)
            .unwrap_or_else(|| std::env::var_os("AETHER_WG_NO_PROFILE_RETRY").is_some());
        Ok(Self {
            profile,
            no_retry,
            wireguard_override: None,
        })
    }

    pub(crate) fn from_cli(profile: Option<&str>, no_retry: bool) -> Self {
        Self {
            profile: profile
                .map(str::trim)
                .filter(|profile| !profile.is_empty())
                .map(str::to_owned),
            no_retry,
            wireguard_override: None,
        }
    }

    pub(crate) fn wireguard(&self) -> WireGuardNoize {
        WireGuardNoize::from_profile(Some(self.wireguard_name()))
    }

    pub(crate) fn wireguard_name(&self) -> &str {
        self.wireguard_override
            .as_deref()
            .or(self.profile.as_deref())
            .unwrap_or("balanced")
    }

    pub(crate) fn masque_profile(&self) -> &str {
        self.profile.as_deref().unwrap_or("firewall")
    }

    pub(crate) fn wireguard_candidates(&self) -> Vec<String> {
        let primary = self
            .wireguard_override
            .clone()
            .or_else(|| self.profile.clone())
            .unwrap_or_else(|| "balanced".to_owned());
        let mut names = vec![primary];
        if !self.no_retry {
            for fallback in ["balanced", "aggressive", "light", "off"] {
                if !names.iter().any(|name| name.eq_ignore_ascii_case(fallback)) {
                    names.push(fallback.to_owned());
                }
            }
        }
        names
    }

    pub(crate) fn select_wireguard(&mut self, name: &str) {
        self.wireguard_override = Some(name.to_owned());
    }
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct MasqueNoize {
    before: usize,
    after_i1: usize,
    jmin: usize,
    jmax: usize,
    i1: Option<&'static str>,
    i2: Option<&'static str>,
    interval: Duration,
}

impl MasqueNoize {
    pub(crate) fn off() -> Self {
        Self {
            before: 0,
            after_i1: 0,
            jmin: 0,
            jmax: 0,
            i1: None,
            i2: None,
            interval: Duration::ZERO,
        }
    }

    pub(crate) fn light() -> Self {
        Self {
            before: 1,
            after_i1: 0,
            jmin: 32,
            jmax: 96,
            i1: Some("<b 0d0a0d0a><t><r 16>"),
            i2: None,
            interval: Duration::from_millis(3),
        }
    }

    pub(crate) fn firewall() -> Self {
        Self {
            before: 2,
            after_i1: 2,
            jmin: 48,
            jmax: 190,
            i1: Some("<b 0d0a0d0a><t><r 24>"),
            i2: Some("<r 48>"),
            interval: Duration::from_millis(4),
        }
    }

    pub(crate) fn gfw() -> Self {
        Self {
            before: 2,
            after_i1: 1,
            jmin: 64,
            jmax: 256,
            i1: Some("<b 0d0a0d0a><t><r 24>"),
            i2: Some("<r 32>"),
            interval: Duration::from_millis(5),
        }
    }

    pub(crate) fn from_profile(name: &str) -> Self {
        match name.trim().to_ascii_lowercase().as_str() {
            "off" | "none" => Self::off(),
            "light" => Self::light(),
            "gfw" | "aggressive" | "heavy" => Self::gfw(),
            _ => Self::firewall(),
        }
    }

    pub(crate) fn is_enabled(&self) -> bool {
        self.before > 0 || self.after_i1 > 0 || self.i1.is_some()
    }

    pub(crate) fn send_before(&self, mut send: impl FnMut(&[u8])) {
        if !self.is_enabled() {
            return;
        }
        for _ in 0..self.before {
            send(&self.junk());
            sleep(self.interval);
        }
        if let Some(i1) = self.i1 {
            let packet = crate::psiphon_quic::noise_expand(i1);
            if !packet.is_empty() {
                send(&packet);
                sleep(Duration::from_millis(2));
            }
        }
        for _ in 0..self.after_i1 {
            send(&self.junk());
            sleep(self.interval);
        }
        if let Some(i2) = self.i2 {
            let packet = crate::psiphon_quic::noise_expand(i2);
            if !packet.is_empty() {
                send(&packet);
            }
        }
    }

    fn junk(&self) -> Vec<u8> {
        let (low, high) = if self.jmax > self.jmin && self.jmin > 0 {
            (self.jmin, self.jmax)
        } else {
            (40, 90)
        };
        crate::psiphon_quic::noise_bytes(crate::psiphon_quic::noise_range(low, high))
    }
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct WireGuardNoize {
    i1: Option<&'static str>,
    i2: Option<&'static str>,
    i3: Option<&'static str>,
    i4: Option<&'static str>,
    i5: Option<&'static str>,
    after_i1: usize,
    before_hs: usize,
    after_hs: usize,
    jmin: usize,
    jmax: usize,
    interval: Duration,
    delay: Duration,
}

impl WireGuardNoize {
    pub(crate) fn off() -> Self {
        Self {
            i1: None,
            i2: None,
            i3: None,
            i4: None,
            i5: None,
            after_i1: 0,
            before_hs: 0,
            after_hs: 0,
            jmin: 0,
            jmax: 0,
            interval: Duration::ZERO,
            delay: Duration::ZERO,
        }
    }

    pub(crate) fn light() -> Self {
        Self {
            i1: Some("<b 0d0a0d0a><t><r 20-32>"),
            i2: Some("<rc 24-48>"),
            i3: None,
            i4: None,
            i5: None,
            after_i1: 1,
            before_hs: 2,
            after_hs: 1,
            jmin: 48,
            jmax: 190,
            interval: Duration::from_millis(3),
            delay: Duration::from_millis(5),
        }
    }

    pub(crate) fn balanced() -> Self {
        Self {
            i1: Some("<b 0d0a0d0a><t><rc 20-40>"),
            i2: Some("<b 504f5354><rd 10-20><rc 20-30>"),
            i3: Some("<r 30-50>"),
            i4: None,
            i5: None,
            after_i1: 2,
            before_hs: 3,
            after_hs: 1,
            jmin: 64,
            jmax: 256,
            interval: Duration::from_millis(2),
            delay: Duration::from_millis(8),
        }
    }

    pub(crate) fn aggressive() -> Self {
        Self {
            i1: Some("<b 0d0a0d0a><t><rc 40-64>"),
            i2: Some("<b 504f5354><t><rd 15-30><rc 30-50>"),
            i3: Some("<b 474554><rc 40-60>"),
            i4: Some("<r 60-100>"),
            i5: Some("<c><rd 20-40>"),
            after_i1: 3,
            before_hs: 4,
            after_hs: 3,
            jmin: 80,
            jmax: 384,
            interval: Duration::from_millis(1),
            delay: Duration::from_millis(12),
        }
    }

    pub(crate) fn firewall() -> Self {
        Self {
            i1: Some("<b 0d0a0d0a><t><rc 24-44>"),
            i2: Some("<b 504f5354><c><rd 12-24><rc 24-36>"),
            i3: Some("<b 474554><r 30-50>"),
            i4: None,
            i5: None,
            after_i1: 2,
            before_hs: 3,
            after_hs: 2,
            jmin: 64,
            jmax: 300,
            interval: Duration::from_millis(2),
            delay: Duration::from_millis(10),
        }
    }

    pub(crate) fn gfw() -> Self {
        Self {
            i1: Some("<b 16030100><c><rc 48-72>"),
            i2: Some("<b 0d0a0d0a><t><rd 20-40><rc 36-60>"),
            i3: Some("<b 474554202f20485454502f312e31><rc 40-64>"),
            i4: Some("<b 504f5354><c><r 64-110>"),
            i5: Some("<rd 24-48><rc 32-56>"),
            after_i1: 3,
            before_hs: 5,
            after_hs: 4,
            jmin: 96,
            jmax: 420,
            interval: Duration::from_millis(1),
            delay: Duration::from_millis(16),
        }
    }

    pub(crate) fn from_profile(name: Option<&str>) -> Self {
        match name
            .unwrap_or("balanced")
            .trim()
            .to_ascii_lowercase()
            .as_str()
        {
            "off" | "none" => Self::off(),
            "light" => Self::light(),
            "firewall" => Self::firewall(),
            "gfw" => Self::gfw(),
            "aggressive" | "heavy" => Self::aggressive(),
            _ => Self::balanced(),
        }
    }

    pub(crate) fn is_enabled(&self) -> bool {
        self.before_hs > 0 || self.after_i1 > 0 || self.i1.is_some()
    }

    pub(crate) fn send_before(&self, mut send: impl FnMut(&[u8])) {
        if !self.is_enabled() {
            return;
        }
        if let Some(i1) = self.i1 {
            let payload = crate::psiphon_quic::noise_expand(i1);
            if !payload.is_empty() {
                send(&wrap_ikev2(&payload));
                sleep(Duration::from_millis(2));
            }
        }
        for _ in 0..self.after_i1 {
            send(&self.junk());
            sleep(self.interval);
        }
        for _ in 0..self.before_hs {
            send(&self.junk());
            sleep(self.interval);
        }
        for signature in [self.i2, self.i3, self.i4, self.i5].into_iter().flatten() {
            let packet = crate::psiphon_quic::noise_expand(signature);
            if !packet.is_empty() {
                send(&packet);
                sleep(Duration::from_millis(1));
            }
        }
        sleep(self.delay);
    }

    pub(crate) fn send_after(&self, mut send: impl FnMut(&[u8])) {
        for _ in 0..self.after_hs {
            send(&self.junk());
            sleep(self.interval);
        }
    }

    pub(crate) fn send_keepalive(&self, mut send: impl FnMut(&[u8])) {
        if !self.is_enabled() {
            return;
        }
        let base = self.before_hs.max(1);
        let extra = crate::psiphon_quic::noise_range(0, base);
        for _ in 0..base + extra {
            let mut junk = self.junk();
            if let Some(first) = junk.first_mut() {
                if (1..=4).contains(first) {
                    *first = first.wrapping_add(0x40);
                }
            }
            let jitter = u64::try_from(crate::psiphon_quic::noise_range(0, 8)).unwrap_or(0);
            send(&junk);
            sleep(self.interval + Duration::from_millis(jitter));
        }
    }

    fn junk(&self) -> Vec<u8> {
        if self.jmin == 0 && self.jmax == 0 {
            return vec![0];
        }
        let low = self.jmin.max(1);
        let high = self.jmax.max(low);
        crate::psiphon_quic::noise_bytes(crate::psiphon_quic::noise_range(low, high))
    }
}

fn wrap_ikev2(payload: &[u8]) -> Vec<u8> {
    let mut initiator_spi = [0u8; 8];
    if payload.len() >= 8 {
        initiator_spi.copy_from_slice(&payload[..8]);
    } else {
        let _ = getrandom::fill(&mut initiator_spi);
    }
    let mut responder_spi = [0u8; 8];
    let _ = getrandom::fill(&mut responder_spi);
    let payload_length = u16::try_from(payload.len()).unwrap_or(u16::MAX);
    let total_length = 28u32
        .saturating_add(24)
        .saturating_add(u32::from(payload_length));
    let mut header = Vec::with_capacity(52 + payload.len());
    header.extend_from_slice(&initiator_spi);
    header.extend_from_slice(&responder_spi);
    header.extend_from_slice(&[0x21, 0x20, 0x22, 0x08, 0x00, 0x00, 0x00, 0x00]);
    header.extend_from_slice(&total_length.to_be_bytes());
    header.extend_from_slice(&[0x00, 0x00]);
    header.extend_from_slice(&payload_length.saturating_add(24).to_be_bytes());
    header.extend_from_slice(&[
        0x00, 0x00, 0x00, 0x14, 0x01, 0x01, 0x00, 0x04, 0x03, 0x00, 0x00, 0x08, 0x01, 0x00, 0x00,
        0x0c, 0x00, 0x00, 0x00, 0x00,
    ]);
    header.extend_from_slice(payload);
    header
}

fn sleep(duration: Duration) {
    if !duration.is_zero() {
        std::thread::sleep(duration);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_wireguard_profile_is_balanced_by_default() {
        assert_eq!(WireGuardNoize::from_profile(None).jmin, 64);
        assert_eq!(WireGuardNoize::from_profile(Some("balanced")).jmax, 256);
        assert_eq!(
            WireGuardNoize::from_profile(Some("something-else")).jmax,
            256
        );
        assert!(!WireGuardNoize::from_profile(Some("off")).is_enabled());
    }

    #[test]
    fn the_masque_profile_is_firewall_by_default() {
        assert_eq!(MasqueNoize::from_profile("firewall").jmax, 190);
        assert_eq!(MasqueNoize::from_profile("balanced").jmax, 190);
        assert_eq!(MasqueNoize::from_profile("aggressive").jmax, 256);
        assert!(!MasqueNoize::from_profile("off").is_enabled());
        assert_eq!(MasqueNoize::from_profile("  GFW  ").jmax, 256);
    }

    #[test]
    fn six_wireguard_profiles_keep_six_shapes() {
        let shapes: std::collections::HashSet<(usize, usize)> = [
            WireGuardNoize::off(),
            WireGuardNoize::light(),
            WireGuardNoize::balanced(),
            WireGuardNoize::aggressive(),
            WireGuardNoize::firewall(),
            WireGuardNoize::gfw(),
        ]
        .into_iter()
        .map(|profile| (profile.jmin, profile.jmax))
        .collect();
        assert_eq!(shapes.len(), 6);
    }

    #[test]
    fn four_masque_profiles_keep_four_shapes() {
        let shapes: std::collections::HashSet<(usize, usize)> = [
            MasqueNoize::off(),
            MasqueNoize::light(),
            MasqueNoize::firewall(),
            MasqueNoize::gfw(),
        ]
        .into_iter()
        .map(|profile| (profile.jmin, profile.jmax))
        .collect();
        assert_eq!(shapes.len(), 4);
    }

    #[test]
    fn the_legacy_names_keep_their_own_shapes() {
        assert_eq!(WireGuardNoize::from_profile(Some("firewall")).jmax, 300);
        assert_eq!(WireGuardNoize::from_profile(Some("gfw")).jmax, 420);
        assert_eq!(WireGuardNoize::from_profile(Some("heavy")).jmax, 384);
        assert_eq!(WireGuardNoize::from_profile(Some("none")).jmax, 0);
    }

    #[test]
    fn a_scan_retries_the_fallback_profiles_once_each() {
        let mut settings = NoizeSettings::default();
        let names = settings.wireguard_candidates();
        assert_eq!(names, vec!["balanced", "aggressive", "light", "off"]);
        settings.no_retry = true;
        let names = settings.wireguard_candidates();
        assert_eq!(names, vec!["balanced"]);
        settings.profile = Some("off".to_owned());
        settings.no_retry = false;
        let names = settings.wireguard_candidates();
        assert_eq!(names, vec!["off", "balanced", "aggressive", "light"]);
    }

    #[test]
    fn a_selected_profile_becomes_the_primary() {
        let mut settings = NoizeSettings::default();
        settings.select_wireguard("light");
        assert_eq!(settings.wireguard().jmax, 190);
        let names = settings.wireguard_candidates();
        assert_eq!(names, vec!["light", "balanced", "aggressive", "off"]);
    }

    #[test]
    fn wireguard_signatures_are_sent_in_the_reference_order() {
        let mut packets = Vec::new();
        WireGuardNoize::light().send_before(|packet| packets.push(packet.to_vec()));
        assert_eq!(packets.len(), 5);
        let signature = &packets[0];
        assert!(signature.len() >= 52 + 4 + 1 + 20);
        assert_eq!(&signature[16..20], &[0x21, 0x20, 0x22, 0x08]);
        assert_eq!(
            u32::from_be_bytes(signature[24..28].try_into().expect("total length")) as usize,
            signature.len()
        );
        assert_eq!(
            u16::from_be_bytes(signature[30..32].try_into().expect("payload length")),
            u16::try_from(signature.len() - 28).expect("payload length")
        );
    }

    #[test]
    fn masque_signatures_follow_the_reference_order() {
        let mut packets = Vec::new();
        MasqueNoize::firewall().send_before(|packet| packets.push(packet.to_vec()));
        assert_eq!(packets.len(), 6);
        assert_eq!(&packets[2][..4], &[0x0d, 0x0a, 0x0d, 0x0a]);
        assert_eq!(packets[5].len(), 48);
    }

    #[test]
    fn an_off_profile_sends_nothing() {
        let mut packets = Vec::new();
        MasqueNoize::off().send_before(|packet| packets.push(packet.to_vec()));
        WireGuardNoize::off().send_before(|packet| packets.push(packet.to_vec()));
        assert_eq!(packets, Vec::<Vec<u8>>::new());
    }
}
