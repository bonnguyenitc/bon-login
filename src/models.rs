use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PlatformType {
    MacOS,
    Windows,
    Linux,
}

impl PlatformType {
    pub fn as_cli_str(&self) -> &'static str {
        match self {
            Self::MacOS => "macos",
            Self::Windows => "windows",
            Self::Linux => "linux",
        }
    }

    pub fn label(&self) -> &'static str {
        match self {
            Self::MacOS => "macOS",
            Self::Windows => "Windows",
            Self::Linux => "Linux",
        }
    }

    /// Matches `GetPlatformVersion()` in `adryfish/fingerprint-chromium` 148 (`002-user-agent-fingerprint.patch`).
    pub fn os_version_for_seed(&self, seed: u32) -> &'static str {
        const MACOS_VERSIONS: [&str; 25] = [
            "15.0.0", "15.0.1", "15.1.0", "15.1.1", "15.2.0", "15.3.0", "15.3.1", "15.3.2",
            "15.4.0", "15.4.1", "15.5.0", "15.6.0", "15.6.1", "15.7.0", "15.7.1", "15.7.2",
            "26.0.0", "26.0.1", "26.1.0", "26.2.0", "26.3.0", "26.3.1", "26.3.2", "26.4.0",
            "26.4.1",
        ];
        match self {
            Self::Windows => "19.0.0",
            Self::MacOS => MACOS_VERSIONS[(seed as usize) % MACOS_VERSIONS.len()],
            Self::Linux => ["6.8.0", "6.14.0"][(seed as usize) % 2],
        }
    }

    /// Hardware-coherent CPU core count matching the exact GPU model for `seed` in `adryfish` 148 (`Apple M4` = 10C, `Apple M2` = 8C, Windows Intel/NVIDIA/AMD = 8/12/16C).
    pub fn optimal_cores_for_seed(&self, seed: u32) -> u8 {
        match self {
            Self::MacOS => {
                if seed.is_multiple_of(2) {
                    10
                } else {
                    8
                }
            }
            Self::Windows | Self::Linux => [8, 12, 16][(seed as usize) % 3],
        }
    }

    pub fn default_window_size(&self) -> &'static str {
        match self {
            Self::MacOS => "1440,900",
            Self::Windows | Self::Linux => "1920,1080",
        }
    }

    /// Matches `kWindowsWebGLConfigs` & `kMacOSWebGLConfigs` in `adryfish/fingerprint-chromium` 148 (`011-gpu-info.patch`).
    pub fn webgl_for_seed(
        &self,
        seed: u32,
        gpu_mode: GpuSpoofMode,
    ) -> (&'static str, &'static str) {
        const WIN_CONFIGS: [(&str, &str); 13] = [
            (
                "Google Inc. (Intel)",
                "ANGLE (Intel, Intel(R) Iris(R) Xe Graphics (0x00009A49) Direct3D11 vs_5_0 ps_5_0, D3D11)",
            ),
            (
                "Google Inc. (Intel)",
                "ANGLE (Intel, Intel(R) Iris(R) Xe Graphics (0x000046A6) Direct3D11 vs_5_0 ps_5_0, D3D11)",
            ),
            (
                "Google Inc. (NVIDIA)",
                "ANGLE (NVIDIA, NVIDIA GeForce RTX 3060 Laptop GPU (0x00002560) Direct3D11 vs_5_0 ps_5_0, D3D11)",
            ),
            (
                "Google Inc. (Intel)",
                "ANGLE (Intel, Intel(R) Iris(R) Xe Graphics (0x0000A7A0) Direct3D11 vs_5_0 ps_5_0, D3D11)",
            ),
            (
                "Google Inc. (Intel)",
                "ANGLE (Intel, Intel(R) Iris(R) Xe Graphics (0x0000A7A0) Direct3D11 vs_5_0 ps_5_0, D3D11)",
            ),
            (
                "Google Inc. (AMD)",
                "ANGLE (AMD, AMD Radeon(TM) Graphics (0x00001638) Direct3D11 vs_5_0 ps_5_0, D3D11)",
            ),
            (
                "Google Inc. (Intel)",
                "ANGLE (Intel, Intel(R) UHD Graphics (0x00009B41) Direct3D11 vs_5_0 ps_5_0, D3D11)",
            ),
            (
                "Google Inc. (Intel)",
                "ANGLE (Intel, Intel(R) Iris(R) Xe Graphics (0x000046A6) Direct3D11 vs_5_0 ps_5_0, D3D11)",
            ),
            (
                "Google Inc. (Intel)",
                "ANGLE (Intel, Intel(R) Arc(TM) Graphics (0x00007D55) Direct3D11 vs_5_0 ps_5_0, D3D11)",
            ),
            (
                "Google Inc. (Intel)",
                "ANGLE (Intel, Intel(R) Iris(R) Xe Graphics (0x00009A49) Direct3D11 vs_5_0 ps_5_0, D3D11)",
            ),
            (
                "Google Inc. (Intel)",
                "ANGLE (Intel, Intel(R) UHD Graphics 620 (0x00003EA0) Direct3D11 vs_5_0 ps_5_0, D3D11)",
            ),
            (
                "Google Inc. (NVIDIA)",
                "ANGLE (NVIDIA, NVIDIA GeForce RTX 4060 Laptop GPU (0x000028E0) Direct3D11 vs_5_0 ps_5_0, D3D11)",
            ),
            (
                "Google Inc. (Intel)",
                "ANGLE (Intel, Intel(R) UHD Graphics (0x0000A78B) Direct3D11 vs_5_0 ps_5_0, D3D11)",
            ),
        ];
        const MAC_CONFIGS: [(&str, &str); 2] = [
            (
                "Google Inc. (Apple)",
                "ANGLE (Apple, ANGLE Metal Renderer: Apple M4, Unspecified Version)",
            ),
            (
                "Google Inc. (Apple)",
                "ANGLE (Apple, ANGLE Metal Renderer: Apple M2, Unspecified Version)",
            ),
        ];
        if gpu_mode == GpuSpoofMode::NativePassthrough {
            return (
                "Google Inc. (Apple)",
                "ANGLE (Apple, ANGLE Metal Renderer: Apple Silicon, Native Passthrough)",
            );
        }
        match self {
            Self::Windows => WIN_CONFIGS[(seed as usize) % WIN_CONFIGS.len()],
            Self::MacOS | Self::Linux => MAC_CONFIGS[(seed as usize) % MAC_CONFIGS.len()],
        }
    }

    pub fn from_str_lossy(s: &str) -> Self {
        match s.to_ascii_lowercase().as_str() {
            "windows" | "win" => Self::Windows,
            "linux" => Self::Linux,
            _ => Self::MacOS,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum BrowserBrand {
    Chrome,
    Edge,
    Opera,
    Vivaldi,
}

impl BrowserBrand {
    /// `adryfish/fingerprint-chromium` 148 (`002-user-agent-fingerprint.patch`) supports Chrome and Edge in Client Hints.
    pub const ALL: [BrowserBrand; 2] = [BrowserBrand::Chrome, BrowserBrand::Edge];

    pub fn as_cli_str(&self) -> &'static str {
        match self {
            Self::Chrome | Self::Opera | Self::Vivaldi => "Chrome",
            Self::Edge => "Edge",
        }
    }

    /// Matches `kChromiumVersions` & `kEdgeVersions` in `adryfish/fingerprint-chromium` 148 (`002-user-agent-fingerprint.patch`).
    pub fn version_for_seed(&self, seed: u32) -> &'static str {
        const CHROME_VERSIONS: [&str; 4] = [
            "148.0.7778.217",
            "148.0.7778.179",
            "148.0.7778.168",
            "148.0.7778.97",
        ];
        const EDGE_VERSIONS: [&str; 4] = [
            "148.0.3967.54",
            "148.0.3967.96",
            "148.0.3967.83",
            "148.0.3967.70",
        ];
        match self {
            Self::Edge => EDGE_VERSIONS[(seed as usize) % EDGE_VERSIONS.len()],
            _ => CHROME_VERSIONS[(seed as usize) % CHROME_VERSIONS.len()],
        }
    }

    /// Matches `GetUserAgentInternal()` in `adryfish/fingerprint-chromium` 148 (`002-user-agent-fingerprint.patch`).
    pub fn user_agent_for(&self, os: PlatformType) -> String {
        let plat = match os {
            PlatformType::Windows => "Windows NT 10.0; Win64; x64",
            PlatformType::MacOS => "Macintosh; Intel Mac OS X 10_15_7",
            PlatformType::Linux => "X11; Linux x86_64",
        };
        let suffix = match self {
            Self::Edge => " Edg/148.0.0.0",
            _ => "",
        };
        format!(
            "Mozilla/5.0 ({plat}) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/148.0.0.0 Safari/537.36{suffix}"
        )
    }

    pub fn from_str_lossy(s: &str) -> Self {
        match s.to_ascii_lowercase().as_str() {
            "edge" => Self::Edge,
            _ => Self::Chrome,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum GpuSpoofMode {
    /// Passes `gpu` inside `--disable-spoofing=...` so real Apple Silicon/Intel Metal GPU passes BrowserScan 100%
    NativePassthrough,
    /// Lets adryfish spoof GPU from `--fingerprint=<seed>` (recommended when spoofing Windows on Mac)
    SeedGenerated,
}

impl GpuSpoofMode {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::NativePassthrough => "native",
            Self::SeedGenerated => "seed",
        }
    }

    pub fn label(&self) -> &'static str {
        match self {
            Self::NativePassthrough => "Native GPU",
            Self::SeedGenerated => "Seed GPU",
        }
    }

    pub fn from_str_lossy(s: &str) -> Self {
        if s.eq_ignore_ascii_case("seed") {
            Self::SeedGenerated
        } else {
            Self::NativePassthrough
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProxyProtocol {
    Http,
    Socks5,
}

impl ProxyProtocol {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Http => "http",
            Self::Socks5 => "socks5",
        }
    }

    pub fn from_str_lossy(s: &str) -> Self {
        if s.to_ascii_lowercase().starts_with("socks") {
            Self::Socks5
        } else {
            Self::Http
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProxyConfig {
    pub protocol: ProxyProtocol,
    pub host: String,
    pub port: u16,
    pub username: Option<String>,
    pub password: Option<String>,
}

impl ProxyConfig {
    pub fn parse_flexible(raw: &str) -> anyhow::Result<Option<Self>> {
        Self::parse_with_default_protocol(raw, ProxyProtocol::Http)
    }

    pub fn parse_with_default_protocol(
        raw: &str,
        default_protocol: ProxyProtocol,
    ) -> anyhow::Result<Option<Self>> {
        Ok(Self::parse_with_optional_name(raw, default_protocol)?.map(|(cfg, _)| cfg))
    }

    /// Parses GenLogin 3.0 proxy format (`type:host:port:login:password:name`, `protocol://host:port:user:pass`, `user:pass@host:port`, `host:port`).
    pub fn parse_with_optional_name(
        raw: &str,
        default_protocol: ProxyProtocol,
    ) -> anyhow::Result<Option<(Self, Option<String>)>> {
        // shortcut: strip GenLogin's trailing '|changeIpUrl' metadata if pasted
        let s = raw.split('|').next().unwrap_or(raw).trim();
        if s.is_empty() {
            return Ok(None);
        }

        let lower = s.to_ascii_lowercase();
        let (protocol, rest) = if let Some(len) = [
            "socks5h://",
            "socks5://",
            "socks4://",
            "socks://",
            "socks5:",
            "socks4:",
            "socks:",
        ]
        .into_iter()
        .find_map(|p| lower.starts_with(p).then_some(p.len()))
        {
            (ProxyProtocol::Socks5, &s[len..])
        } else if let Some(len) = ["http://", "https://", "http:", "https:"]
            .into_iter()
            .find_map(|p| lower.starts_with(p).then_some(p.len()))
        {
            (ProxyProtocol::Http, &s[len..])
        } else {
            (default_protocol, s)
        };
        let rest = rest.trim_end_matches('/');

        if let Some((auth, host_port)) = rest.rsplit_once('@') {
            let (host, port_str) = host_port
                .rsplit_once(':')
                .ok_or_else(|| anyhow::anyhow!("Invalid proxy host:port in '{raw}'"))?;
            let port: u16 = port_str.parse()?;
            let (username, password) = match auth.split_once(':') {
                Some((u, p)) => (
                    Some(u.to_string()).filter(|v| !v.is_empty()),
                    Some(p.to_string()).filter(|v| !v.is_empty()),
                ),
                None => (Some(auth.to_string()).filter(|v| !v.is_empty()), None),
            };
            return Ok(Some((
                Self {
                    protocol,
                    host: host.to_string(),
                    port,
                    username,
                    password,
                },
                None,
            )));
        }

        let parts: Vec<&str> = rest.splitn(5, ':').collect();
        match parts.as_slice() {
            [host, port_str] => Ok(Some((
                Self {
                    protocol,
                    host: (*host).to_string(),
                    port: port_str.parse()?,
                    username: None,
                    password: None,
                },
                None,
            ))),
            [host, port_str, name] => Ok(Some((
                Self {
                    protocol,
                    host: (*host).to_string(),
                    port: port_str.parse()?,
                    username: None,
                    password: None,
                },
                Some(name.trim().to_string()).filter(|v| !v.is_empty()),
            ))),
            [host, port_str, user, pass] => Ok(Some((
                Self {
                    protocol,
                    host: (*host).to_string(),
                    port: port_str.parse()?,
                    username: Some((*user).to_string()).filter(|v| !v.is_empty()),
                    password: Some((*pass).to_string()).filter(|v| !v.is_empty()),
                },
                None,
            ))),
            [host, port_str, user, pass, name] => Ok(Some((
                Self {
                    protocol,
                    host: (*host).to_string(),
                    port: port_str.parse()?,
                    username: Some((*user).to_string()).filter(|v| !v.is_empty()),
                    password: Some((*pass).to_string()).filter(|v| !v.is_empty()),
                },
                Some(name.trim().to_string()).filter(|v| !v.is_empty()),
            ))),
            _ => anyhow::bail!(
                "Unsupported proxy format '{raw}'. Use type:host:port:login:password:name or host:port"
            ),
        }
    }

    pub fn display_short(&self) -> String {
        format!("{}:{}", self.host, self.port)
    }

    pub fn to_editable_string(&self) -> String {
        let prefix = match self.protocol {
            ProxyProtocol::Http => "",
            ProxyProtocol::Socks5 => "socks5:",
        };
        match (&self.username, &self.password) {
            (Some(u), Some(p)) => format!("{prefix}{}:{}:{u}:{p}", self.host, self.port),
            (Some(u), None) => format!("{prefix}{}:{}:{u}:", self.host, self.port),
            _ => format!("{prefix}{}:{}", self.host, self.port),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GeoInfo {
    pub ip: String,
    pub country_code: String,
    pub timezone: String,
    pub locale: String,
    pub accept_lang: String,
    #[serde(default)]
    pub latency_ms: Option<u32>,
}

impl GeoInfo {
    pub fn locale_for_country(country_code: &str) -> (String, String) {
        match country_code.to_ascii_uppercase().as_str() {
            "VN" => ("vi-VN".into(), "vi-VN,vi,en-US;q=0.9,en;q=0.8".into()),
            "JP" => ("ja-JP".into(), "ja-JP,ja,en-US;q=0.9,en;q=0.8".into()),
            "KR" => ("ko-KR".into(), "ko-KR,ko,en-US;q=0.9,en;q=0.8".into()),
            "CN" => ("zh-CN".into(), "zh-CN,zh,en-US;q=0.9,en;q=0.8".into()),
            "TW" | "HK" => ("zh-TW".into(), "zh-TW,zh,en-US;q=0.9,en;q=0.8".into()),
            "DE" | "AT" | "CH" => ("de-DE".into(), "de-DE,de,en-US;q=0.9,en;q=0.8".into()),
            "FR" => ("fr-FR".into(), "fr-FR,fr,en-US;q=0.9,en;q=0.8".into()),
            "ES" | "MX" | "AR" => ("es-ES".into(), "es-ES,es,en-US;q=0.9,en;q=0.8".into()),
            "BR" | "PT" => ("pt-BR".into(), "pt-BR,pt,en-US;q=0.9,en;q=0.8".into()),
            "RU" => ("ru-RU".into(), "ru-RU,ru,en-US;q=0.9,en;q=0.8".into()),
            "GB" => ("en-GB".into(), "en-GB,en-US;q=0.9,en;q=0.8".into()),
            _ => ("en-US".into(), "en-US,en;q=0.9".into()),
        }
    }

    pub fn country_flag(country_code: &str) -> &'static str {
        match country_code.to_ascii_uppercase().as_str() {
            "VN" => "🇻🇳",
            "US" => "🇺🇸",
            "GB" | "UK" => "🇬🇧",
            "JP" => "🇯🇵",
            "KR" => "🇰🇷",
            "SG" => "🇸🇬",
            "DE" => "🇩🇪",
            "FR" => "🇫🇷",
            "NL" => "🇳🇱",
            "CA" => "🇨🇦",
            "AU" => "🇦🇺",
            "HK" => "🇭🇰",
            "TW" => "🇹🇼",
            "TH" => "🇹🇭",
            "ID" => "🇮🇩",
            "MY" => "🇲🇾",
            "PH" => "🇵🇭",
            "IN" => "🇮🇳",
            "BR" => "🇧🇷",
            "RU" => "🇷🇺",
            _ => "🌐",
        }
    }

    pub fn compact_ip(&self) -> String {
        if self.ip.len() > 16 && self.ip.contains(':') {
            let parts: Vec<&str> = self.ip.split(':').collect();
            if parts.len() >= 4 {
                return format!("{}:{}..{}", parts[0], parts[1], parts[parts.len() - 1]);
            }
        }
        self.ip.clone()
    }

    pub fn summary_badge(&self) -> String {
        let ip = self.compact_ip();
        let short_tz = self.timezone.rsplit('/').next().unwrap_or(&self.timezone);
        match self.latency_ms {
            Some(ms) => format!("{ip} • {} • {ms}ms", self.country_code),
            None => format!("{ip} • {} • {short_tz}", self.country_code),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SavedProxy {
    pub id: String,
    pub name: String,
    pub group_tag: String,
    pub config: ProxyConfig,
    pub resolved_geo: Option<GeoInfo>,
    pub last_error: Option<String>,
    pub created_at: i64,
    #[serde(default)]
    pub expired_at: Option<i64>,
}

impl SavedProxy {
    pub fn new(
        name: impl Into<String>,
        group_tag: impl Into<String>,
        config: ProxyConfig,
    ) -> Self {
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            name: name.into(),
            group_tag: group_tag.into(),
            config,
            resolved_geo: None,
            last_error: None,
            created_at: unix_now(),
            expired_at: None,
        }
    }

    pub fn format_started_at(&self) -> String {
        format_unix_dd_mm_yyyy(self.created_at)
    }

    pub fn format_expired_at(&self) -> String {
        let Some(exp) = self.expired_at else {
            return "-".to_string();
        };
        let date_s = format_unix_dd_mm_yyyy(exp);
        let diff = exp - unix_now();
        if diff < 0 {
            format!("{date_s} (Expired)")
        } else {
            let days_left = (diff + 86_399) / 86_400;
            format!("{date_s} ({days_left}d)")
        }
    }

    pub fn is_expired(&self) -> bool {
        self.expired_at.is_some_and(|exp| unix_now() > exp)
    }

    pub fn is_expiring_soon(&self) -> bool {
        self.expired_at.is_some_and(|exp| {
            let diff = exp - unix_now();
            (0..=3 * 86_400).contains(&diff)
        })
    }

    /// Parses user expiration input (`DD/MM/YYYY`, `YYYY-MM-DD`, or number of days like `30`, `+30`, `30d`).
    pub fn parse_expiration_input(raw: &str) -> Option<i64> {
        let s = raw.trim();
        if s.is_empty() {
            return None;
        }
        let day_token = s.trim_start_matches('+').trim_end_matches(['d', 'D']).trim();
        if let Ok(days) = day_token.parse::<i64>() {
            if days > 0 {
                return Some(unix_now() + days * 86_400);
            }
            return None;
        }
        if let [d_s, m_s, y_s] = s.split('/').collect::<Vec<_>>().as_slice()
            && let (Ok(d), Ok(m), Ok(y)) = (
                d_s.trim().parse::<u32>(),
                m_s.trim().parse::<u32>(),
                y_s.trim().parse::<i32>(),
            )
            && (1..=31).contains(&d)
            && (1..=12).contains(&m)
            && y >= 2000
        {
            return Some(days_from_civil(y, m, d) * 86_400 + 86_399);
        }
        if let [y_s, m_s, d_s] = s.split('-').collect::<Vec<_>>().as_slice()
            && let (Ok(y), Ok(m), Ok(d)) = (
                y_s.trim().parse::<i32>(),
                m_s.trim().parse::<u32>(),
                d_s.trim().parse::<u32>(),
            )
            && (1..=31).contains(&d)
            && (1..=12).contains(&m)
            && y >= 2000
        {
            return Some(days_from_civil(y, m, d) * 86_400 + 86_399);
        }
        None
    }
}

pub fn format_unix_dd_mm_yyyy(ts: i64) -> String {
    let z = ts.div_euclid(86_400) + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u32;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = if m <= 2 { y + 1 } else { y };
    format!("{d:02}/{m:02}/{year:04}")
}

fn days_from_civil(y: i32, m: u32, d: u32) -> i64 {
    let y = i64::from(y) - if m <= 2 { 1 } else { 0 };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = (y - era * 400) as u32;
    let m_adj = if m > 2 { m - 3 } else { m + 9 };
    let doy = (153 * m_adj + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + i64::from(doe) - 719_468
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Profile {
    pub id: String,
    pub name: String,
    pub group_tag: String,
    pub seed: u32,
    pub os_platform: PlatformType,
    pub os_version: String,
    pub brand: BrowserBrand,
    pub brand_version: String,
    pub hardware_concurrency: u8,
    pub gpu_spoofing: GpuSpoofMode,
    pub spoof_canvas: bool,
    pub spoof_audio: bool,
    pub spoof_font: bool,
    pub spoof_client_rects: bool,
    pub window_size: String,
    pub custom_timezone: Option<String>,
    pub custom_locale: Option<String>,
    pub proxy: Option<ProxyConfig>,
    pub resolved_geo: Option<GeoInfo>,
    pub startup_url: String,
    pub notes: String,
    pub created_at: i64,
    pub last_launched_at: Option<i64>,
}

impl Profile {
    pub const DEFAULT_WINDOW_SIZE: &'static str = "1440,900";

    pub fn new_default(name: impl Into<String>, os_platform: PlatformType) -> Self {
        let now = unix_now();
        let seed: u32 = rand::random::<u32>().max(1000);
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            name: name.into(),
            group_tag: String::new(),
            seed,
            os_platform,
            os_version: os_platform.os_version_for_seed(seed).to_string(),
            brand: BrowserBrand::Chrome,
            brand_version: BrowserBrand::Chrome.version_for_seed(seed).to_string(),
            hardware_concurrency: os_platform.optimal_cores_for_seed(seed),
            gpu_spoofing: GpuSpoofMode::SeedGenerated,
            spoof_canvas: true,
            spoof_audio: true,
            spoof_font: true,
            spoof_client_rects: true,
            window_size: os_platform.default_window_size().to_string(),
            custom_timezone: None,
            custom_locale: None,
            proxy: None,
            resolved_geo: None,
            startup_url: "https://browserscan.net".to_string(),
            notes: String::new(),
            created_at: now,
            last_launched_at: None,
        }
    }

    pub fn cloned_with_new_seed(&self) -> Self {
        let mut copy = self.clone();
        let new_seed = rand::random::<u32>().max(1000);
        copy.id = uuid::Uuid::new_v4().to_string();
        copy.name = format!("{} (Copy)", self.name);
        copy.seed = new_seed;
        copy.os_version = copy.os_platform.os_version_for_seed(new_seed).to_string();
        copy.brand_version = copy.brand.version_for_seed(new_seed).to_string();
        copy.hardware_concurrency = copy.os_platform.optimal_cores_for_seed(new_seed);
        copy.created_at = unix_now();
        copy.last_launched_at = None;
        copy
    }

    /// Matches `021-device-memory-cap.patch` (`[8, 16, 32][seed % 3]` GB).
    pub fn device_memory_for_seed(seed: u32) -> u8 {
        [8, 16, 32][(seed as usize) % 3]
    }

    pub fn disabled_spoofing_csv(&self) -> Option<String> {
        let mut disabled = Vec::new();
        if !self.spoof_font {
            disabled.push("font");
        }
        if !self.spoof_audio {
            disabled.push("audio");
        }
        if !self.spoof_canvas {
            disabled.push("canvas");
        }
        if !self.spoof_client_rects {
            disabled.push("clientrects");
        }
        if self.gpu_spoofing == GpuSpoofMode::NativePassthrough {
            disabled.push("gpu");
        }
        if disabled.is_empty() {
            None
        } else {
            Some(disabled.join(","))
        }
    }

    pub fn matches_filter(&self, query: &str, group_filter: Option<&str>) -> bool {
        if let Some(group) = group_filter
            && !group.is_empty()
            && !group.eq_ignore_ascii_case("All")
            && !self.group_tag.eq_ignore_ascii_case(group)
        {
            return false;
        }

        let q = query.trim().to_ascii_lowercase();
        if q.is_empty() {
            return true;
        }

        self.name.to_ascii_lowercase().contains(&q)
            || self.group_tag.to_ascii_lowercase().contains(&q)
            || self.notes.to_ascii_lowercase().contains(&q)
            || self.seed.to_string().contains(&q)
            || self
                .proxy
                .as_ref()
                .is_some_and(|p| p.host.to_ascii_lowercase().contains(&q))
            || self.resolved_geo.as_ref().is_some_and(|g| {
                g.ip.to_ascii_lowercase().contains(&q)
                    || g.country_code.to_ascii_lowercase().contains(&q)
            })
    }

    pub fn short_id(&self) -> String {
        self.id
            .chars()
            .filter(|c| c.is_ascii_alphanumeric())
            .take(8)
            .collect()
    }

    pub fn format_last_launched(&self) -> String {
        let Some(ts) = self.last_launched_at else {
            return "Never run".to_string();
        };
        let diff = unix_now().saturating_sub(ts);
        if diff < 60 {
            "Just now".to_string()
        } else if diff < 3600 {
            format!("{}m ago", diff / 60)
        } else if diff < 86_400 {
            format!("{}h ago", diff / 3600)
        } else {
            format!("{}d ago", diff / 86_400)
        }
    }

    pub fn short_note(&self, max_chars: usize) -> Option<String> {
        let trimmed = self.notes.trim();
        if trimmed.is_empty() {
            return None;
        }
        let single_line = trimmed.lines().next().unwrap_or(trimmed).trim();
        if single_line.chars().count() > max_chars {
            let cut: String = single_line.chars().take(max_chars.saturating_sub(1)).collect();
            Some(format!("{cut}…"))
        } else {
            Some(single_line.to_string())
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimeInfo {
    pub pid: u32,
    pub cdp_port: u16,
    pub ws_url: String,
    pub local_proxy_port: Option<u16>,
}

impl RuntimeInfo {
    pub fn agent_browser_cli(&self, profile_short_id: &str) -> String {
        format!(
            "agent-browser --session bon_{} --input-mode human connect \"{}\"",
            profile_short_id, self.ws_url
        )
    }

    pub fn pinned_tab_cli(&self, profile_short_id: &str, tab_tag: &str) -> String {
        let clean_tag: String = tab_tag
            .chars()
            .filter(|c| c.is_ascii_alphanumeric() || *c == '_' || *c == '-')
            .collect();
        let suffix = if clean_tag.is_empty() { "tab1" } else { &clean_tag };
        format!(
            "agent-browser --session bon_{}_{} --input-mode human --pin-tab connect \"{}\"",
            profile_short_id, suffix, self.ws_url
        )
    }
}

#[derive(Debug, Clone)]
pub enum ProfileStatus {
    Stopped,
    Starting(String),
    Running(RuntimeInfo),
    Error(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BrowserExtension {
    pub id: String,
    pub name: String,
    pub icon_label: String,
    pub icon_bg: u32,
    pub is_default: bool,
    pub enabled: bool,
    pub source_url: String,
    pub folder_path: String,
    pub created_at: i64,
}

impl BrowserExtension {
    /// Extracts a 32-character Chrome Web Store extension ID (`[a-p]{32}`) from a store URL or raw ID.
    pub fn extract_chrome_store_id(raw: &str) -> Option<String> {
        let trimmed = raw.trim();
        let without_query = trimmed.split(['?', '#']).next().unwrap_or(trimmed);
        for segment in without_query.trim_end_matches('/').rsplit('/') {
            let cand = segment.trim().to_ascii_lowercase();
            if cand.len() == 32 && cand.bytes().all(|b| (b'a'..=b'p').contains(&b)) {
                return Some(cand);
            }
        }
        None
    }

}

pub fn unix_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_flexible_proxy() {
        let p1 = ProxyConfig::parse_flexible("1.2.3.4:8080:myuser:mypass")
            .unwrap()
            .unwrap();
        assert_eq!(p1.protocol, ProxyProtocol::Http);
        assert_eq!(p1.host, "1.2.3.4");
        assert_eq!(p1.port, 8080);
        assert_eq!(p1.username.as_deref(), Some("myuser"));
        assert_eq!(p1.password.as_deref(), Some("mypass"));

        let p2 = ProxyConfig::parse_flexible("socks5://alice:s3cr:t@proxy.example.com:1080")
            .unwrap()
            .unwrap();
        assert_eq!(p2.protocol, ProxyProtocol::Socks5);
        assert_eq!(p2.host, "proxy.example.com");
        assert_eq!(p2.port, 1080);
        assert_eq!(p2.username.as_deref(), Some("alice"));
        assert_eq!(p2.password.as_deref(), Some("s3cr:t"));

        assert!(ProxyConfig::parse_flexible("   ").unwrap().is_none());

        let p3 = ProxyConfig::parse_with_default_protocol(
            "160.250.60.55:45042:admin:pass|http://rotate.local/ip",
            ProxyProtocol::Socks5,
        )
        .unwrap()
        .unwrap();
        assert_eq!(p3.protocol, ProxyProtocol::Socks5);
        assert_eq!(p3.host, "160.250.60.55");
        assert_eq!(p3.port, 45042);
        assert_eq!(p3.username.as_deref(), Some("admin"));
        assert_eq!(p3.password.as_deref(), Some("pass"));

        let (p4, name4) = ProxyConfig::parse_with_optional_name(
            "http:160.250.60.55:45042:user1:pass1:Vina Proxy Data Center",
            ProxyProtocol::Http,
        )
        .unwrap()
        .unwrap();
        assert_eq!(p4.protocol, ProxyProtocol::Http);
        assert_eq!(p4.host, "160.250.60.55");
        assert_eq!(p4.port, 45042);
        assert_eq!(p4.username.as_deref(), Some("user1"));
        assert_eq!(p4.password.as_deref(), Some("pass1"));
        assert_eq!(name4.as_deref(), Some("Vina Proxy Data Center"));

        let (p5, name5) = ProxyConfig::parse_with_optional_name(
            "socks://192.168.1.1:3000:MySocks",
            ProxyProtocol::Http,
        )
        .unwrap()
        .unwrap();
        assert_eq!(p5.protocol, ProxyProtocol::Socks5);
        assert_eq!(p5.host, "192.168.1.1");
        assert_eq!(p5.port, 3000);
        assert_eq!(name5.as_deref(), Some("MySocks"));
    }

    #[test]
    fn test_disabled_spoofing_csv() {
        let mut p = Profile::new_default("Test Mac", PlatformType::MacOS);
        assert_eq!(p.disabled_spoofing_csv(), None);
        p.spoof_font = false;
        p.gpu_spoofing = GpuSpoofMode::NativePassthrough;
        assert_eq!(p.disabled_spoofing_csv().as_deref(), Some("font,gpu"));
    }

    #[test]
    fn test_short_note_last_launched_and_prelaunch_cookies() {
        let mut p = Profile::new_default("Note Test", PlatformType::MacOS);
        assert_eq!(p.format_last_launched(), "Never run");
        assert_eq!(p.short_note(10), None);

        p.last_launched_at = Some(unix_now());
        assert_eq!(p.format_last_launched(), "Just now");

        p.notes = "2FA enabled - FB Ads Campaign Alpha\nLine 2".to_string();
        assert_eq!(p.short_note(12).as_deref(), Some("2FA enabled…"));

        let sid = "testck01";
        crate::launcher::save_prelaunch_cookies(sid, "[{\"name\":\"c_user\",\"value\":\"1\"}]")
            .unwrap();
        assert!(crate::launcher::read_prelaunch_cookies(sid).contains("c_user"));
        crate::launcher::save_prelaunch_cookies(sid, "   ").unwrap();
        assert!(crate::launcher::read_prelaunch_cookies(sid).is_empty());
    }
}
