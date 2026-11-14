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
            Self::MacOS => "1360,850",
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
}

impl BrowserBrand {
    /// `adryfish/fingerprint-chromium` 148 (`002-user-agent-fingerprint.patch`) supports Chrome and Edge in Client Hints.
    pub const ALL: [BrowserBrand; 2] = [BrowserBrand::Chrome, BrowserBrand::Edge];

    pub fn as_cli_str(&self) -> &'static str {
        match self {
            Self::Chrome => "Chrome",
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

    pub fn from_str_lossy(s: &str) -> Self {
        if s.eq_ignore_ascii_case("seed") {
            Self::SeedGenerated
        } else {
            Self::NativePassthrough
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
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
    #[serde(default)]
    pub change_ip_url: Option<String>,
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
        let (s_part, tail_part) = raw.split_once('|').unwrap_or((raw, ""));
        let s = s_part.trim();
        if s.is_empty() {
            return Ok(None);
        }
        let change_ip_url = {
            let u = tail_part.trim();
            (u.starts_with("http://") || u.starts_with("https://")).then(|| u.to_string())
        };

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
                    change_ip_url,
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
                    change_ip_url,
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
                    change_ip_url,
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
                    change_ip_url,
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
                    change_ip_url,
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
        let base = match (&self.username, &self.password) {
            (Some(u), Some(p)) => format!("{prefix}{}:{}:{u}:{p}", self.host, self.port),
            (Some(u), None) => format!("{prefix}{}:{}:{u}:", self.host, self.port),
            _ => format!("{prefix}{}:{}", self.host, self.port),
        };
        match &self.change_ip_url {
            Some(url) if !url.trim().is_empty() => format!("{base}|{}", url.trim()),
            _ => base,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum IpKind {
    #[default]
    Unknown,
    Residential,
    Business,
    Mobile,
    Hosting,
}

impl IpKind {
    pub fn label(self) -> &'static str {
        match self {
            Self::Unknown => "Unknown",
            Self::Residential => "Residential",
            Self::Business => "Business",
            Self::Mobile => "Mobile",
            Self::Hosting => "Hosting",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum IpPolicy {
    #[default]
    #[serde(rename = "any")]
    Any,
    #[serde(rename = "no-hosting")]
    NoHosting,
    #[serde(rename = "residential")]
    ResidentialOrMobile,
}

impl IpPolicy {
    pub fn as_cli_str(self) -> &'static str {
        match self {
            Self::Any => "any",
            Self::NoHosting => "no-hosting",
            Self::ResidentialOrMobile => "residential",
        }
    }

    pub fn from_cli(raw: &str) -> Option<Self> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "any" => Some(Self::Any),
            "no-hosting" => Some(Self::NoHosting),
            "residential" => Some(Self::ResidentialOrMobile),
            _ => None,
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
    #[serde(default)]
    pub city: String,
    #[serde(default)]
    pub region: String,
    #[serde(default)]
    pub asn: String,
    #[serde(default)]
    pub isp: String,
    #[serde(default)]
    pub ip_kind: IpKind,
    #[serde(default)]
    pub is_hosting: Option<bool>,
    #[serde(default)]
    pub is_mobile: Option<bool>,
}

impl GeoInfo {
    pub fn core(
        ip: String,
        country_code: String,
        timezone: String,
        locale: String,
        accept_lang: String,
        latency_ms: Option<u32>,
    ) -> Self {
        Self {
            ip,
            country_code,
            timezone,
            locale,
            accept_lang,
            latency_ms,
            city: String::new(),
            region: String::new(),
            asn: String::new(),
            isp: String::new(),
            ip_kind: IpKind::Unknown,
            is_hosting: None,
            is_mobile: None,
        }
    }

    pub fn classify(is_hosting: Option<bool>, is_mobile: Option<bool>, is_proxy: Option<bool>) -> IpKind {
        if is_hosting == Some(true) {
            IpKind::Hosting
        } else if is_mobile == Some(true) {
            IpKind::Mobile
        } else if is_hosting == Some(false) && is_mobile == Some(false) && is_proxy != Some(true) {
            IpKind::Residential
        } else {
            IpKind::Unknown
        }
    }

    pub fn quality_json(&self) -> String {
        serde_json::json!({
            "city": self.city,
            "region": self.region,
            "asn": self.asn,
            "isp": self.isp,
            "ip_kind": self.ip_kind,
            "is_hosting": self.is_hosting,
            "is_mobile": self.is_mobile,
        })
        .to_string()
    }

    pub fn apply_quality_json(&mut self, raw: &str) {
        let Ok(v) = serde_json::from_str::<serde_json::Value>(raw) else {
            return;
        };
        if let Some(s) = v.get("city").and_then(|x| x.as_str()) {
            self.city = s.to_string();
        }
        if let Some(s) = v.get("region").and_then(|x| x.as_str()) {
            self.region = s.to_string();
        }
        if let Some(s) = v.get("asn").and_then(|x| x.as_str()) {
            self.asn = s.to_string();
        }
        if let Some(s) = v.get("isp").and_then(|x| x.as_str()) {
            self.isp = s.to_string();
        }
        if let Some(kind) = v.get("ip_kind").and_then(|x| serde_json::from_value(x.clone()).ok()) {
            self.ip_kind = kind;
        }
        self.is_hosting = v.get("is_hosting").and_then(|x| x.as_bool());
        self.is_mobile = v.get("is_mobile").and_then(|x| x.as_bool());
    }

    /// `None` when the launch may proceed. Missing hosting bit never blocks.
    pub fn launch_block_reason(&self, policy: IpPolicy) -> Option<String> {
        if policy == IpPolicy::Any || self.is_hosting.is_none() {
            return None;
        }
        let blocked = match policy {
            IpPolicy::Any => false,
            IpPolicy::NoHosting => self.is_hosting == Some(true),
            IpPolicy::ResidentialOrMobile => {
                self.is_hosting == Some(true)
                    || matches!(self.ip_kind, IpKind::Hosting | IpKind::Business)
            }
        };
        if !blocked {
            return None;
        }
        let kind = if self.ip_kind == IpKind::Unknown && self.is_hosting == Some(true) {
            "Hosting"
        } else {
            self.ip_kind.label()
        };
        Some(format!(
            "exit IP {} is {kind}{}, policy requires {}",
            self.ip,
            self.org_paren(),
            policy.as_cli_str()
        ))
    }

    fn org_paren(&self) -> String {
        let asn = self.asn.trim();
        let isp = self.isp.trim();
        if asn.is_empty() && isp.is_empty() {
            String::new()
        } else if isp.is_empty() || asn.contains(isp) {
            format!(" ({asn})")
        } else if asn.is_empty() {
            format!(" ({isp})")
        } else {
            format!(" ({asn} {isp})")
        }
    }

    /// `Residential · Hangzhou` when the probe had a city or a known kind.
    pub fn quality_label(&self) -> Option<String> {
        let kind = (self.ip_kind != IpKind::Unknown).then_some(self.ip_kind.label());
        let city = (!self.city.trim().is_empty()).then_some(self.city.trim());
        match (kind, city) {
            (Some(k), Some(c)) => Some(format!("{k} · {c}")),
            (Some(k), None) => Some(k.to_string()),
            (None, Some(c)) => Some(c.to_string()),
            (None, None) => None,
        }
    }

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
            && valid_civil_date(y, m, d)
        {
            return Some(days_from_civil(y, m, d) * 86_400 + 86_399);
        }
        if let [y_s, m_s, d_s] = s.split('-').collect::<Vec<_>>().as_slice()
            && let (Ok(y), Ok(m), Ok(d)) = (
                y_s.trim().parse::<i32>(),
                m_s.trim().parse::<u32>(),
                d_s.trim().parse::<u32>(),
            )
            && valid_civil_date(y, m, d)
        {
            return Some(days_from_civil(y, m, d) * 86_400 + 86_399);
        }
        None
    }

    pub fn parse_expiration_strict(raw: &str) -> Result<Option<i64>, &'static str> {
        let s = raw.trim();
        if s.is_empty()
            || s.eq_ignore_ascii_case("none")
            || s.eq_ignore_ascii_case("clear")
            || s == "0"
        {
            return Ok(None);
        }
        Self::parse_expiration_input(s).map(Some).ok_or(
            "Invalid expiration date (expected DD/MM/YYYY, YYYY-MM-DD, days like 30d, or 'clear')",
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FreeProxyCandidate {
    pub config: ProxyConfig,
    pub country_code: String,
    pub city: String,
    pub timezone: String,
    pub isp: String,
    pub anonymity: String,
    pub source: String,
    pub reported_latency_ms: Option<u32>,
    pub uptime_pct: Option<u8>,
    pub ssl: bool,
    pub verified_geo: Option<GeoInfo>,
    pub last_error: Option<String>,
}

impl FreeProxyCandidate {
    pub fn endpoint_key(&self) -> String {
        format!(
            "{}://{}:{}",
            self.config.protocol.as_str(),
            self.config.host,
            self.config.port
        )
    }

    pub fn effective_country(&self) -> &str {
        self.verified_geo
            .as_ref()
            .map(|g| g.country_code.as_str())
            .filter(|s| !s.is_empty())
            .unwrap_or(self.country_code.as_str())
    }

    pub fn effective_latency_ms(&self) -> Option<u32> {
        self.verified_geo
            .as_ref()
            .and_then(|g| g.latency_ms)
            .or(self.reported_latency_ms)
    }

    pub fn matches_filter(
        &self,
        query: &str,
        protocol: Option<ProxyProtocol>,
        country: &str,
        only_live: bool,
    ) -> bool {
        if only_live && self.verified_geo.is_none() {
            return false;
        }
        if let Some(proto) = protocol
            && self.config.protocol != proto
        {
            return false;
        }
        let cc = self.effective_country();
        if !country.is_empty()
            && !country.eq_ignore_ascii_case("All")
            && !cc.eq_ignore_ascii_case(country)
        {
            return false;
        }
        let q = query.trim();
        if q.is_empty() {
            return true;
        }
        let port_str = self.config.port.to_string();
        contains_ignore_ascii_case(&self.config.host, q)
            || port_str.contains(q)
            || contains_ignore_ascii_case(cc, q)
            || contains_ignore_ascii_case(&self.city, q)
            || contains_ignore_ascii_case(&self.isp, q)
            || contains_ignore_ascii_case(&self.source, q)
            || contains_ignore_ascii_case(&self.anonymity, q)
            || contains_ignore_ascii_case(self.config.protocol.as_str(), q)
            || self
                .verified_geo
                .as_ref()
                .is_some_and(|g| contains_ignore_ascii_case(&g.ip, q) || contains_ignore_ascii_case(&g.timezone, q))
    }

    pub fn to_saved_proxy(&self, tag: &str) -> SavedProxy {
        let cc = self.effective_country();
        let label_cc = if cc.is_empty() {
            self.config.protocol.as_str().to_ascii_uppercase()
        } else {
            cc.to_ascii_uppercase()
        };
        let name = if self.city.is_empty() {
            format!("Free {label_cc} ({}:{})", self.config.host, self.config.port)
        } else {
            format!(
                "Free {label_cc} - {} ({}:{})",
                self.city, self.config.host, self.config.port
            )
        };
        let group_tag = if tag.trim().is_empty() {
            "free".to_string()
        } else {
            tag.trim().trim_start_matches('#').to_string()
        };
        let mut sp = SavedProxy::new(name, group_tag, self.config.clone());
        if let Some(geo) = &self.verified_geo {
            sp.resolved_geo = Some(geo.clone());
        } else if !cc.is_empty() && !self.timezone.is_empty() {
            let (locale, accept_lang) = GeoInfo::locale_for_country(cc);
            sp.resolved_geo = Some(GeoInfo::core(
                self.config.host.clone(),
                cc.to_ascii_uppercase(),
                self.timezone.clone(),
                locale,
                accept_lang,
                self.reported_latency_ms,
            ));
        }
        sp
    }
}

fn valid_civil_date(y: i32, m: u32, d: u32) -> bool {
    if !(2000..=2200).contains(&y) || !(1..=12).contains(&m) || d == 0 {
        return false;
    }
    let max_d = match m {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if (y % 4 == 0 && y % 100 != 0) || (y % 400 == 0) => 29,
        2 => 28,
        _ => return false,
    };
    d <= max_d
}

pub fn seed_urls_for_locale(locale: &str) -> &'static [&'static str] {
    let loc = locale.trim().to_ascii_lowercase();
    if loc.starts_with("zh") {
        &[
            "https://www.baidu.com",
            "https://weibo.com",
            "https://www.zhihu.com",
            "https://www.taobao.com",
        ]
    } else if loc.starts_with("vi") {
        &[
            "https://vnexpress.net",
            "https://dantri.com.vn",
            "https://tuoitre.vn",
            "https://www.wikipedia.org",
        ]
    } else {
        &[
            "https://www.wikipedia.org",
            "https://www.bbc.com",
            "https://www.reddit.com",
            "https://www.amazon.com",
        ]
    }
}

fn locale_lang(locale: &str) -> String {
    locale
        .split([',', ';', '-', '_'])
        .next()
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase()
}

pub fn utc_day_key(ts: i64) -> String {
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
    format!("{year:04}-{m:02}-{d:02}")
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum TrustStage {
    #[default]
    New,
    Warming,
    Mature,
    Restricted,
    Banned,
}

impl TrustStage {
    pub fn from_cli(raw: &str) -> Self {
        match raw.trim().to_ascii_lowercase().as_str() {
            "warming" => Self::Warming,
            "mature" => Self::Mature,
            "restricted" => Self::Restricted,
            "banned" => Self::Banned,
            _ => Self::New,
        }
    }

    pub fn as_cli_str(self) -> &'static str {
        match self {
            Self::New => "new",
            Self::Warming => "warming",
            Self::Mature => "mature",
            Self::Restricted => "restricted",
            Self::Banned => "banned",
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::New => "New",
            Self::Warming => "Warming",
            Self::Mature => "Mature",
            Self::Restricted => "Restricted",
            Self::Banned => "Banned",
        }
    }

    /// Restricted and Banned stick. Otherwise 20 minutes across 2 days is Mature.
    pub fn from_activity(self, seconds: i64, days: i64) -> Self {
        match self {
            Self::Restricted | Self::Banned => self,
            _ if seconds >= 20 * 60 && days >= 2 => Self::Mature,
            _ if seconds > 0 => Self::Warming,
            _ => Self::New,
        }
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
    #[serde(default)]
    pub tags: Vec<String>,
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
    #[serde(default)]
    pub ip_policy: IpPolicy,
    #[serde(default)]
    pub trust_stage: TrustStage,
    #[serde(default)]
    pub seeded_at: Option<i64>,
    pub startup_url: String,
    pub notes: String,
    #[serde(default)]
    pub totp_secret: String,
    pub created_at: i64,
    pub last_launched_at: Option<i64>,
    #[serde(default)]
    pub deleted_at: Option<i64>,
}

impl Profile {
    pub const DEFAULT_WINDOW_SIZE: &'static str = "1360,850";

    /// Generates a random fingerprint seed whose `seed % 13` is `2` (`NVIDIA RTX 3060 0x00002560`)
    /// or `5` (`AMD Radeon 0x00001638`) so WebGL renderer strings avoid hex-letter `A-F` gibberish
    /// penalties on CreepJS (`grade: A`, `confidence: high`, `0 trash`).
    pub fn random_seed() -> u32 {
        let q = (rand::random::<u32>() % 200_000_000).max(100);
        let rem = if rand::random::<bool>() { 2 } else { 5 };
        q.saturating_mul(13).saturating_add(rem)
    }

    pub fn new_default(name: impl Into<String>, os_platform: PlatformType) -> Self {
        let now = unix_now();
        let seed: u32 = Self::random_seed();
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            name: name.into(),
            group_tag: String::new(),
            tags: Vec::new(),
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
            ip_policy: IpPolicy::Any,
            trust_stage: TrustStage::New,
            seeded_at: None,
            startup_url: "https://browserscan.net".to_string(),
            notes: String::new(),
            totp_secret: String::new(),
            created_at: now,
            last_launched_at: None,
            deleted_at: None,
        }
    }

    pub fn set_seed(&mut self, new_seed: u32) {
        self.seed = new_seed;
        self.os_version = self.os_platform.os_version_for_seed(new_seed).to_string();
        self.brand_version = self.brand.version_for_seed(new_seed).to_string();
        self.hardware_concurrency = self.os_platform.optimal_cores_for_seed(new_seed);
    }

    pub fn reseed(&mut self) -> u32 {
        let new_seed = Self::random_seed();
        self.set_seed(new_seed);
        new_seed
    }

    pub fn set_platform(&mut self, os: PlatformType) {
        self.os_platform = os;
        self.os_version = os.os_version_for_seed(self.seed).to_string();
        self.brand_version = self.brand.version_for_seed(self.seed).to_string();
        self.hardware_concurrency = os.optimal_cores_for_seed(self.seed);
        self.window_size = os.default_window_size().to_string();
        if os != PlatformType::MacOS && self.gpu_spoofing == GpuSpoofMode::NativePassthrough {
            self.gpu_spoofing = GpuSpoofMode::SeedGenerated;
        }
    }

    pub fn set_brand(&mut self, brand: BrowserBrand) {
        self.brand = brand;
        self.brand_version = brand.version_for_seed(self.seed).to_string();
    }

    pub fn assign_saved_proxy(&mut self, sp: &SavedProxy) {
        self.proxy = Some(sp.config.clone());
        self.resolved_geo = sp.resolved_geo.clone();
    }

    pub fn clear_proxy(&mut self) {
        self.proxy = None;
        self.resolved_geo = None;
    }

    pub fn cloned_with_new_seed(&self) -> Self {
        let mut copy = self.clone();
        copy.id = uuid::Uuid::new_v4().to_string();
        copy.name = format!("{} (Copy)", self.name);
        copy.reseed();
        copy.created_at = unix_now();
        copy.last_launched_at = None;
        copy.deleted_at = None;
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
        // Apple Metal passthrough on a Windows/Linux fingerprint reports the Mac GPU.
        if self.os_platform == PlatformType::MacOS
            && self.gpu_spoofing == GpuSpoofMode::NativePassthrough
        {
            disabled.push("gpu");
        }
        if disabled.is_empty() {
            None
        } else {
            Some(disabled.join(","))
        }
    }

    pub fn gpu_coherence_warning(&self) -> Option<&'static str> {
        (self.os_platform != PlatformType::MacOS)
            .then_some("Native GPU passthrough only matches macOS profiles")
    }

    pub fn seed_locale(&self) -> &str {
        self.custom_locale
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .or_else(|| {
                self.resolved_geo
                    .as_ref()
                    .map(|g| g.locale.as_str())
                    .filter(|s| !s.is_empty())
            })
            .unwrap_or("en-US")
    }

    pub fn seed_urls(&self) -> Vec<String> {
        seed_urls_for_locale(self.seed_locale())
            .iter()
            .map(|u| (*u).to_string())
            .collect()
    }

    pub fn timezone_coherent(&self) -> bool {
        let Some(geo_tz) = self
            .resolved_geo
            .as_ref()
            .map(|g| g.timezone.as_str())
            .filter(|s| !s.is_empty())
        else {
            return true;
        };
        match self
            .custom_timezone
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
        {
            None => true,
            Some(custom) => custom.eq_ignore_ascii_case(geo_tz),
        }
    }

    pub fn locale_coherent(&self) -> bool {
        let Some(geo_loc) = self
            .resolved_geo
            .as_ref()
            .map(|g| g.locale.as_str())
            .filter(|s| !s.is_empty())
        else {
            return true;
        };
        match self
            .custom_locale
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
        {
            None => true,
            Some(custom) => locale_lang(custom) == locale_lang(geo_loc),
        }
    }

    pub fn audit_report(&self) -> serde_json::Value {
        let geo = self.resolved_geo.as_ref();
        serde_json::json!({
            "short_id": self.short_id(),
            "name": self.name,
            "seeded_at": self.seeded_at,
            "trust_stage": self.trust_stage.as_cli_str(),
            "ip": geo.map(|g| g.ip.as_str()).unwrap_or(""),
            "ip_kind": geo.map(|g| g.ip_kind.label()).unwrap_or("Unknown"),
            "asn": geo.map(|g| g.asn.as_str()).unwrap_or(""),
            "isp": geo.map(|g| g.isp.as_str()).unwrap_or(""),
            "city": geo.map(|g| g.city.as_str()).unwrap_or(""),
            "timezone": self.custom_timezone.as_deref().filter(|s| !s.trim().is_empty()).unwrap_or_else(|| geo.map(|g| g.timezone.as_str()).unwrap_or("")),
            "locale": self.seed_locale(),
            "timezone_coherent": self.timezone_coherent(),
            "locale_coherent": self.locale_coherent(),
            "webrtc": "disable_non_proxied_udp",
        })
    }

    pub fn shared_exit_label(profiles: &[Profile], profile: &Profile) -> Option<String> {
        if let Some(ip) = profile.resolved_geo.as_ref().map(|g| g.ip.as_str()) {
            let n = profiles
                .iter()
                .filter(|p| {
                    p.id != profile.id
                        && p.deleted_at.is_none()
                        && p.resolved_geo.as_ref().is_some_and(|g| g.ip == ip)
                })
                .count();
            if n > 0 {
                return Some(format!("exit IP shared with {n} profiles"));
            }
        }
        let Some(px) = &profile.proxy else {
            return None;
        };
        let n = profiles
            .iter()
            .filter(|p| {
                p.id != profile.id
                    && p.deleted_at.is_none()
                    && p.proxy.as_ref().is_some_and(|o| {
                        o.host == px.host && o.port == px.port && o.username == px.username
                    })
            })
            .count();
        (n > 0).then(|| format!("proxy shared with {n} profiles"))
    }

    pub fn matches_filter(&self, query: &str, group_filter: Option<&str>) -> bool {
        if let Some(group) = group_filter
            && !group.is_empty()
            && !group.eq_ignore_ascii_case("All")
            && !self.group_tag.eq_ignore_ascii_case(group)
        {
            return false;
        }

        let q = query.trim();
        if q.is_empty() {
            return true;
        }

        contains_ignore_ascii_case(&self.name, q)
            || contains_ignore_ascii_case(&self.id, q)
            || contains_ignore_ascii_case(&self.group_tag, q)
            || self.tags.iter().any(|t| contains_ignore_ascii_case(t, q))
            || contains_ignore_ascii_case(&self.notes, q)
            || self
                .proxy
                .as_ref()
                .is_some_and(|p| contains_ignore_ascii_case(&p.host, q))
            || self.resolved_geo.as_ref().is_some_and(|g| {
                contains_ignore_ascii_case(&g.ip, q)
                    || contains_ignore_ascii_case(&g.country_code, q)
            })
            || (q.bytes().all(|b| b.is_ascii_digit()) && u32_contains_digits(self.seed, q))
    }

    pub fn short_id(&self) -> String {
        self.id
            .chars()
            .filter(|c| c.is_ascii_alphanumeric())
            .take(8)
            .collect()
    }

    /// Deterministic 8-color accent palette (`(border_rgb, bg_rgba, skcolor_argb_i64)`) from `seed`
    /// so each profile row dot in BonLogin matches its Chromium toolbar/avatar color.
    pub fn accent_color_for_seed(seed: u32) -> (u32, u32, i64) {
        const PALETTE: [(u32, u32); 8] = [
            (0x38bdf8, 0x0284c740), // Sky Blue
            (0x34d399, 0x10b98140), // Emerald
            (0xfbbf24, 0xf59e0b40), // Amber
            (0xf87171, 0xef444440), // Rose Red
            (0xc084fc, 0xa855f740), // Purple
            (0xf472b6, 0xec489940), // Pink
            (0x2dd4bf, 0x14b8a640), // Teal
            (0xfb923c, 0xf9731640), // Orange
        ];
        let (rgb_hex, rgba_hex) = PALETTE[(seed as usize) % PALETTE.len()];
        let skcolor = (0xFF00_0000u32 | rgb_hex) as i32 as i64;
        (rgb_hex, rgba_hex, skcolor)
    }

    /// Window/Profile badge label (`"[#id4] Profile Name"`).
    pub fn window_badge_label(&self) -> String {
        let sid = self.short_id();
        let id4 = &sid[..sid.len().min(4)];
        format!("[#{id4}] {}", self.name.trim())
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

    pub const PRESET_TAGS: [&'static str; 8] = [
        "Live",
        "Warmup",
        "Ads",
        "VIP",
        "Ready",
        "2FA",
        "Checkpoint",
        "Die",
    ];

    pub fn parse_tags_csv(raw: &str) -> Vec<String> {
        let mut out = Vec::new();
        for part in raw.split(',') {
            let t = part.trim();
            if !t.is_empty() && !out.iter().any(|x: &String| x.eq_ignore_ascii_case(t)) {
                out.push(t.to_string());
            }
        }
        out
    }

    pub fn tags_csv(&self) -> String {
        self.tags.join(",")
    }

    /// Returns `(text_rgb_hex, bg_rgba_hex)` for a profile status/category tag.
    pub fn tag_badge_colors(tag: &str) -> (u32, u32) {
        let t = tag.trim();
        if contains_ignore_ascii_case(t, "live")
            || contains_ignore_ascii_case(t, "ready")
            || contains_ignore_ascii_case(t, "ok")
            || contains_ignore_ascii_case(t, "active")
        {
            (0x34d399, 0x10b98126)
        } else if contains_ignore_ascii_case(t, "die")
            || contains_ignore_ascii_case(t, "ban")
            || contains_ignore_ascii_case(t, "block")
            || contains_ignore_ascii_case(t, "err")
        {
            (0xf87171, 0xef444426)
        } else if contains_ignore_ascii_case(t, "warm")
            || contains_ignore_ascii_case(t, "check")
            || contains_ignore_ascii_case(t, "pend")
            || contains_ignore_ascii_case(t, "hold")
        {
            (0xfbbf24, 0xf59e0b26)
        } else if contains_ignore_ascii_case(t, "vip")
            || contains_ignore_ascii_case(t, "2fa")
            || contains_ignore_ascii_case(t, "pro")
        {
            (0xc084fc, 0xa855f726)
        } else {
            (0x60a5fa, 0x3b82f626)
        }
    }

    /// Splits `startup_url` by newline, comma, or whitespace into individual URLs for multi-tab launch.
    pub fn startup_urls(&self) -> Vec<String> {
        self.startup_url
            .split(['\n', '\r', ',', ' ', '\t'])
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(ToString::to_string)
            .collect()
    }

    pub fn current_totp(&self) -> Option<(String, u8)> {
        generate_totp_code(&self.totp_secret, unix_now().max(0) as u64)
    }

    pub fn format_deleted_at(&self) -> String {
        let Some(ts) = self.deleted_at else {
            return String::new();
        };
        let diff = unix_now().saturating_sub(ts);
        if diff < 60 {
            "Deleted just now".to_string()
        } else if diff < 3600 {
            format!("Deleted {}m ago", diff / 60)
        } else if diff < 86_400 {
            format!("Deleted {}h ago", diff / 3600)
        } else {
            format!("Deleted {}d ago", diff / 86_400)
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
    Starting,
    Running(RuntimeInfo),
    Error,
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

#[derive(Debug, Clone)]
pub struct ProfileEditorDraft {
    pub profile: Profile,
    pub is_edit: bool,
    pub cores_pinned: bool,
}

impl ProfileEditorDraft {
    pub fn from_profile(template: &Profile, is_edit: bool) -> Self {
        let mut profile = template.clone();
        if !is_edit {
            profile.id = uuid::Uuid::new_v4().to_string();
        }
        let cores_pinned = is_edit
            && profile.hardware_concurrency
                != profile.os_platform.optimal_cores_for_seed(profile.seed);
        Self {
            profile,
            is_edit,
            cores_pinned,
        }
    }

    pub fn select_platform(&mut self, os: PlatformType) {
        self.profile.set_platform(os);
        self.cores_pinned = false;
    }

    pub fn select_brand(&mut self, brand: BrowserBrand) {
        self.profile.set_brand(brand);
    }

    pub fn select_gpu_spoofing(&mut self, mode: GpuSpoofMode) {
        if self.profile.os_platform != PlatformType::MacOS
            && mode == GpuSpoofMode::NativePassthrough
        {
            self.profile.gpu_spoofing = GpuSpoofMode::SeedGenerated;
        } else {
            self.profile.gpu_spoofing = mode;
        }
    }

    pub fn select_cores(&mut self, cores: u8) {
        self.profile.hardware_concurrency = cores;
        self.cores_pinned = true;
    }

    pub fn randomize_to_seed(&mut self, new_seed: u32) {
        self.profile.set_seed(new_seed);
        self.cores_pinned = false;
    }

    #[allow(clippy::too_many_arguments)]
    pub fn finalize(
        &self,
        name: &str,
        seed_str: &str,
        require_proxy: bool,
        auto_geo: bool,
        custom_tz: &str,
        custom_locale: &str,
        startup_url: &str,
        notes: &str,
        totp_secret: &str,
    ) -> Result<Profile, String> {
        let clean_name = name.trim().to_string();
        if clean_name.is_empty() {
            return Err("Profile name cannot be empty".to_string());
        }
        let seed: u32 = seed_str
            .trim()
            .parse()
            .map_err(|_| "Seed must be a valid 32-bit unsigned integer".to_string())?;

        let mut out = self.profile.clone();
        out.name = clean_name;
        out.group_tag = out.group_tag.trim().to_string();

        if seed != out.seed {
            let pinned = self.cores_pinned.then_some(out.hardware_concurrency);
            out.set_seed(seed);
            if let Some(c) = pinned {
                out.hardware_concurrency = c;
            }
        }
        if out.os_platform != PlatformType::MacOS
            && out.gpu_spoofing == GpuSpoofMode::NativePassthrough
        {
            out.gpu_spoofing = GpuSpoofMode::SeedGenerated;
        }

        if !require_proxy {
            out.clear_proxy();
        } else if out.proxy.is_none() {
            return Err(
                "Select a proxy from Proxy manager or switch to 'Without proxy'".to_string(),
            );
        }

        if auto_geo {
            out.custom_timezone = None;
            out.custom_locale = None;
        } else {
            let tz = custom_tz.trim();
            let loc = custom_locale.trim();
            out.custom_timezone = (!tz.is_empty()).then(|| tz.to_string());
            out.custom_locale = (!loc.is_empty()).then(|| loc.to_string());
        }

        let url_trimmed = startup_url.trim();
        out.startup_url = if url_trimmed.is_empty() {
            "https://browserscan.net".to_string()
        } else {
            url_trimmed.to_string()
        };
        out.notes = notes.trim().to_string();
        out.totp_secret = totp_secret.trim().to_string();
        Ok(out)
    }
}

pub fn unix_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

#[inline]
pub fn contains_ignore_ascii_case(haystack: &str, needle: &str) -> bool {
    let n = needle.as_bytes();
    n.is_empty()
        || haystack
            .as_bytes()
            .windows(n.len())
            .any(|w| w.eq_ignore_ascii_case(n))
}

#[inline]
fn u32_contains_digits(mut n: u32, needle: &str) -> bool {
    let mut buf = [0u8; 10];
    let mut i = 10;
    loop {
        i -= 1;
        buf[i] = b'0' + (n % 10) as u8;
        n /= 10;
        if n == 0 {
            break;
        }
    }
    buf[i..]
        .windows(needle.len())
        .any(|w| w == needle.as_bytes())
}

/// Generates a 6-digit RFC 6238 TOTP code and remaining seconds in the 30s window from a Base32 secret or `otpauth://` URI.
pub fn generate_totp_code(raw_secret: &str, unix_secs: u64) -> Option<(String, u8)> {
    let trimmed = raw_secret.trim();
    if trimmed.is_empty() {
        return None;
    }
    let raw_part = if let Some(idx) = trimmed.to_ascii_lowercase().find("secret=") {
        let after = &trimmed[idx + 7..];
        after.split(['&', '#', ' ']).next().unwrap_or(after)
    } else {
        trimmed
    };
    let cleaned_secret = raw_part
        .replace("%20", "")
        .replace("%3D", "")
        .replace("%3d", "");
    let key = decode_base32(&cleaned_secret)?;
    if key.is_empty() {
        return None;
    }
    let counter = (unix_secs / 30).to_be_bytes();
    let mac = hmac_sha1(&key, &counter);
    let offset = (mac[19] & 0x0f) as usize;
    let bin_code = u32::from_be_bytes([
        mac[offset] & 0x7f,
        mac[offset + 1],
        mac[offset + 2],
        mac[offset + 3],
    ]);
    let otp = bin_code % 1_000_000;
    let rem = (30 - (unix_secs % 30)) as u8;
    Some((format!("{otp:06}"), rem))
}

fn decode_base32(input: &str) -> Option<Vec<u8>> {
    let mut bits: u32 = 0;
    let mut bit_count: u8 = 0;
    let mut out = Vec::new();
    for b in input.bytes() {
        if b == b'=' || b == b' ' || b == b'-' || b == b'\t' || b == b'\n' || b == b'\r' {
            continue;
        }
        let val: u8 = match b {
            b'A'..=b'Z' => b - b'A',
            b'a'..=b'z' => b - b'a',
            b'2'..=b'7' => b - b'2' + 26,
            _ => return None,
        };
        bits = (bits << 5) | u32::from(val);
        bit_count += 5;
        if bit_count >= 8 {
            bit_count -= 8;
            out.push(((bits >> bit_count) & 0xff) as u8);
        }
    }
    Some(out)
}

fn hmac_sha1(key: &[u8], message: &[u8]) -> [u8; 20] {
    unsafe extern "C" {
        fn CCHmac(
            algorithm: u32,
            key: *const core::ffi::c_void,
            key_length: usize,
            data: *const core::ffi::c_void,
            data_length: usize,
            mac_out: *mut core::ffi::c_void,
        );
    }
    const K_CC_HMAC_ALG_SHA1: u32 = 0;
    let mut out = [0u8; 20];
    unsafe {
        CCHmac(
            K_CC_HMAC_ALG_SHA1,
            key.as_ptr().cast(),
            key.len(),
            message.as_ptr().cast(),
            message.len(),
            out.as_mut_ptr().cast(),
        );
    }
    out
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
        assert_eq!(p3.change_ip_url.as_deref(), Some("http://rotate.local/ip"));
        assert_eq!(
            p3.to_editable_string(),
            "socks5:160.250.60.55:45042:admin:pass|http://rotate.local/ip"
        );

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
        let sid = p.short_id();
        assert!(p.matches_filter(&sid.to_ascii_uppercase(), None));
        assert!(p.matches_filter("test mac", None));
        assert!(!p.matches_filter("nonexistent", None));
        p.seed = 987654321;
        assert!(p.matches_filter("7654", None));
        assert!(!p.matches_filter("1111", None));
    }

    #[test]
    fn test_windows_native_gpu_is_not_passthrough() {
        let mut p = Profile::new_default("Win", PlatformType::Windows);
        p.gpu_spoofing = GpuSpoofMode::NativePassthrough;
        assert_eq!(p.disabled_spoofing_csv(), None);
        assert_eq!(
            p.gpu_coherence_warning(),
            Some("Native GPU passthrough only matches macOS profiles")
        );
        p.os_platform = PlatformType::MacOS;
        assert_eq!(p.disabled_spoofing_csv().as_deref(), Some("gpu"));
        assert_eq!(p.gpu_coherence_warning(), None);
    }

    #[test]
    fn test_ip_policy_blocks_only_known_hosting() {
        let mut geo = GeoInfo::core(
            "1.2.3.4".into(),
            "US".into(),
            "America/New_York".into(),
            "en-US".into(),
            "en-US,en;q=0.9".into(),
            None,
        );
        assert!(geo.launch_block_reason(IpPolicy::NoHosting).is_none());
        assert!(geo.launch_block_reason(IpPolicy::ResidentialOrMobile).is_none());

        geo.is_hosting = Some(true);
        geo.ip_kind = IpKind::Hosting;
        geo.asn = "AS16509".into();
        geo.isp = "Amazon".into();
        let reason = geo.launch_block_reason(IpPolicy::ResidentialOrMobile).unwrap();
        assert!(reason.contains("exit IP 1.2.3.4 is Hosting (AS16509 Amazon)"));
        assert!(reason.contains("policy requires residential"));
        assert!(geo.launch_block_reason(IpPolicy::NoHosting).unwrap().contains("no-hosting"));
        assert!(geo.launch_block_reason(IpPolicy::Any).is_none());

        geo.is_hosting = Some(false);
        geo.is_mobile = Some(true);
        geo.ip_kind = IpKind::Mobile;
        geo.city = "Hangzhou".into();
        assert!(geo.launch_block_reason(IpPolicy::ResidentialOrMobile).is_none());
        assert_eq!(geo.quality_label().as_deref(), Some("Mobile · Hangzhou"));

        let mut a = Profile::new_default("A", PlatformType::Windows);
        let mut b = Profile::new_default("B", PlatformType::Windows);
        a.resolved_geo = Some(geo.clone());
        b.resolved_geo = Some(geo);
        let note = Profile::shared_exit_label(&[a.clone(), b.clone()], &a).unwrap();
        assert_eq!(note, "exit IP shared with 1 profiles");
    }

    #[test]
    fn test_seed_urls_and_audit_coherence() {
        let zh = seed_urls_for_locale("zh-CN");
        assert!(zh.iter().any(|u| u.contains("baidu.com")));
        let vi = seed_urls_for_locale("vi-VN");
        assert!(vi.iter().any(|u| u.contains("vnexpress.net")));
        assert!(seed_urls_for_locale("en-US").iter().any(|u| u.contains("wikipedia.org")));

        let mut p = Profile::new_default("Audit", PlatformType::Windows);
        p.custom_timezone = Some("Asia/Shanghai".into());
        p.custom_locale = Some("zh-CN".into());
        p.resolved_geo = Some(GeoInfo::core(
            "1.2.3.4".into(),
            "US".into(),
            "America/New_York".into(),
            "en-US".into(),
            "en-US,en".into(),
            None,
        ));
        assert!(!p.timezone_coherent());
        assert!(!p.locale_coherent());
        assert!(!p.seed_urls().is_empty());
        assert!(p.seed_urls()[0].contains("baidu"));
        let report = p.audit_report();
        assert_eq!(report["webrtc"], "disable_non_proxied_udp");
        assert_eq!(report["timezone_coherent"], false);
        assert_eq!(report["ip_kind"], "Unknown");
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

        assert!(SavedProxy::parse_expiration_input("31/02/2026").is_none());
        assert!(SavedProxy::parse_expiration_input("2026-04-31").is_none());
        assert!(SavedProxy::parse_expiration_input("29/02/2028").is_some());

        let tmp = std::env::temp_dir().join(format!(
            "bonlogin-model-ck-{}-{}",
            std::process::id(),
            rand::random::<u32>()
        ));
        let sid = "testck01";
        crate::launcher::save_prelaunch_cookies_in(
            &tmp,
            sid,
            "[{\"name\":\"c_user\",\"value\":\"1\"}]",
        )
        .unwrap();
        assert!(crate::launcher::read_prelaunch_cookies_in(&tmp, sid).contains("c_user"));
        crate::launcher::save_prelaunch_cookies_in(&tmp, sid, "   ").unwrap();
        assert!(crate::launcher::read_prelaunch_cookies_in(&tmp, sid).is_empty());
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn test_universal_cookie_parser_all_formats() {
        // 1. Cookie-Editor JSON array (`expirationDate`, `sameSite: "no_restriction"` / `"unspecified"`, `hostOnly`)
        let cookie_editor = r#"[
            {
                "name": "c_user",
                "value": "1000888999",
                "domain": ".facebook.com",
                "hostOnly": false,
                "path": "/",
                "secure": true,
                "httpOnly": false,
                "sameSite": "no_restriction",
                "session": false,
                "expirationDate": 1825502626.5
            },
            {
                "name": "__Host-csrf",
                "value": "tok123",
                "domain": ".facebook.com",
                "path": "/login",
                "sameSite": "unspecified",
                "session": true
            }
        ]"#;
        let b1 = crate::launcher::parse_and_normalize_cookies(cookie_editor, None).unwrap();
        assert_eq!(b1.format_label, "Cookie-Editor JSON");
        assert_eq!(b1.cookies.len(), 2);
        assert_eq!(b1.cookies[0]["sameSite"], "None");
        assert_eq!(b1.cookies[0]["secure"], true);
        assert_eq!(b1.cookies[0]["expires"], 1825502626.5);
        // __Host- cookie must strip leading dot, force path "/", force secure: true, and omit unspecified sameSite
        assert_eq!(b1.cookies[1]["domain"], "facebook.com");
        assert_eq!(b1.cookies[1]["path"], "/");
        assert_eq!(b1.cookies[1]["secure"], true);
        assert!(b1.cookies[1].get("sameSite").is_none());

        // 2. J2Team JSON (`{"url": ..., "cookies": [...]}`)
        let j2team = r#"{
            "url": "https://shopee.vn",
            "cookies": [
                {"name": "SPC_EC", "value": "abc", "expirationDate": 1890000000000}
            ]
        }"#;
        let b2 = crate::launcher::parse_and_normalize_cookies(j2team, None).unwrap();
        assert_eq!(b2.format_label, "J2Team Cookie JSON");
        assert_eq!(b2.cookies.len(), 1);
        assert_eq!(b2.cookies[0]["domain"], "shopee.vn");
        assert_eq!(b2.cookies[0]["expires"], 1890000000.0);

        // 3. Cookie & Token Grabber JSON (`url` + `cookie` string + `localStorage`)
        let grabber = r#"{
            "url": "https://app.example.com/dashboard",
            "cookie": "sid=xyz987; theme=dark",
            "localStorage": {"auth_jwt": "eyJhbG..."}
        }"#;
        let b3 = crate::launcher::parse_and_normalize_cookies(grabber, None).unwrap();
        assert_eq!(b3.cookies.len(), 2);
        assert_eq!(b3.origins.len(), 1);
        assert_eq!(b3.origins[0]["origin"], "https://app.example.com");

        // 4. Netscape HTTP Cookie File (including `#HttpOnly_`)
        let netscape = "\
# Netscape HTTP Cookie File
#HttpOnly_.facebook.com\tTRUE\t/\tTRUE\t1800000000\txs\t44%3Asecret
.facebook.com\tTRUE\t/\tTRUE\t1800000000\tc_user\t1000111222
";
        let b4 = crate::launcher::parse_and_normalize_cookies(netscape, None).unwrap();
        assert_eq!(b4.format_label, "Netscape Cookie File");
        assert_eq!(b4.cookies.len(), 2);
        assert_eq!(b4.cookies[0]["httpOnly"], true);
        assert_eq!(b4.cookies[0]["name"], "xs");

        // 5. cURL command
        let curl_cmd = "curl 'https://x.com/home' -H 'Cookie: auth_token=tok_abc; ct0=csrf_123'";
        let b5 = crate::launcher::parse_and_normalize_cookies(curl_cmd, None).unwrap();
        assert_eq!(b5.format_label, "cURL Command");
        assert_eq!(b5.cookies.len(), 2);
        assert_eq!(b5.domains, vec!["x.com"]);

        // 6. MMO Pipe account string (`UID|Pass|2FA|c_user=...; xs=...`)
        let mmo_line = "1000998877|Pass123!|JBSWY3DPEHPK3PXP|c_user=1000998877; xs=28%3Aabcd; datr=xyz";
        let b6 = crate::launcher::parse_and_normalize_cookies(mmo_line, None).unwrap();
        assert_eq!(b6.format_label, "Raw Cookie String");
        assert_eq!(b6.cookies.len(), 3);
        assert_eq!(b6.domains, vec!["facebook.com"]);
    }

    #[test]
    fn test_totp_tags_and_startup_urls() {
        // RFC 6238 SHA1 test secret: "12345678901234567890" -> Base32 "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
        let secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
        let (code59, rem59) = generate_totp_code(secret, 59).unwrap();
        assert_eq!(code59, "287082");
        assert_eq!(rem59, 1);

        let otpauth = "otpauth://totp/BonLogin:user@example.com?secret=JBSW%20Y3DP%20EHPK%203PXP%3D%3D&issuer=BonLogin";
        assert!(generate_totp_code(otpauth, 1_700_000_000).is_some());
        let mut p = Profile::new_default("Tag & Multi-Tab", PlatformType::MacOS);
        p.tags = Profile::parse_tags_csv("Live, Warmup, live, Ads");
        assert_eq!(p.tags, vec!["Live", "Warmup", "Ads"]);
        assert!(p.matches_filter("warmup", None));

        p.startup_url = "https://browserscan.net\nhttps://x.com, https://youtube.com".to_string();
        assert_eq!(
            p.startup_urls(),
            vec![
                "https://browserscan.net",
                "https://x.com",
                "https://youtube.com"
            ]
        );

        // Case-insensitive ASCII & non-letter 0x20 bitmask boundary checks
        for pad in [0usize, 1, 14, 15, 16, 17, 31, 32, 33] {
            let hay = format!("{}TikTokShop-Account", "x".repeat(pad));
            assert!(contains_ignore_ascii_case(&hay, "tiktokshop"));
            assert!(!contains_ignore_ascii_case(&hay, "tiktokshopz"));
        }
        assert!(!contains_ignore_ascii_case("@@@@@@@@@@@@@@@@@@@@", "`"));
        assert!(contains_ignore_ascii_case("@@@@@@@@@@@@@@@@@@@`", "`"));
    }

    #[test]
    fn test_profile_coherence_invariants_preserve_macos_gpu_and_guard_windows_mismatch() {
        let mut p = Profile::new_default("Mac Pro", PlatformType::MacOS);
        p.gpu_spoofing = GpuSpoofMode::NativePassthrough;
        let old_seed = p.seed;
        let new_seed = p.reseed();
        assert_ne!(new_seed, 0);
        let _ = old_seed;
        // Reseeding on macOS MUST preserve user-configured NativePassthrough GPU mode
        assert_eq!(p.gpu_spoofing, GpuSpoofMode::NativePassthrough);
        assert_eq!(p.os_version, PlatformType::MacOS.os_version_for_seed(new_seed));

        // Switching platform to Windows MUST switch GPU spoofing to SeedGenerated (avoiding Apple GPU leak on Windows UA)
        p.set_platform(PlatformType::Windows);
        assert_eq!(p.os_platform, PlatformType::Windows);
        assert_eq!(p.gpu_spoofing, GpuSpoofMode::SeedGenerated);
        assert_eq!(p.os_version, PlatformType::Windows.os_version_for_seed(new_seed));

        p.set_brand(BrowserBrand::Edge);
        assert_eq!(p.brand, BrowserBrand::Edge);
        assert_eq!(p.brand_version, BrowserBrand::Edge.version_for_seed(new_seed));
    }

    #[test]
    fn test_profile_editor_draft_coherence_macos_gpu_manual_seed_and_cores_override() {
        let mut orig = Profile::new_default("Mac Studio", PlatformType::MacOS);
        orig.seed = 1302;
        orig.set_seed(1302);
        orig.gpu_spoofing = GpuSpoofMode::NativePassthrough;

        let mut draft = ProfileEditorDraft::from_profile(&orig, true);

        // 1. Selecting macOS in the editor MUST NOT clobber NativePassthrough GPU spoofing
        draft.select_platform(PlatformType::MacOS);
        assert_eq!(draft.profile.gpu_spoofing, GpuSpoofMode::NativePassthrough);

        // 2. Selecting Windows switches GPU to SeedGenerated AND blocks NativePassthrough while on Windows
        draft.select_platform(PlatformType::Windows);
        assert_eq!(draft.profile.gpu_spoofing, GpuSpoofMode::SeedGenerated);
        draft.select_gpu_spoofing(GpuSpoofMode::NativePassthrough);
        assert_eq!(draft.profile.gpu_spoofing, GpuSpoofMode::SeedGenerated);

        // 3. Typing a new seed manually in the input box recomputes optimal CPU cores + OS/Brand versions
        let seed_pick_8 = (1000u32..2000)
            .find(|&s| PlatformType::Windows.optimal_cores_for_seed(s) == 8)
            .unwrap();
        let seed_pick_16 = (2000u32..3000)
            .find(|&s| PlatformType::Windows.optimal_cores_for_seed(s) == 16)
            .unwrap();
        draft.randomize_to_seed(seed_pick_8);
        assert_eq!(draft.profile.hardware_concurrency, 8);

        let finalized = draft
            .finalize(
                "Mac Studio Edited",
                &seed_pick_16.to_string(),
                false,
                true,
                "",
                "",
                "",
                "note",
                "",
            )
            .unwrap();
        assert_eq!(finalized.id, orig.id);
        assert_eq!(finalized.seed, seed_pick_16);
        assert_eq!(
            finalized.hardware_concurrency,
            16,
            "manual seed text edit must update hardware_concurrency when cores were not manually pinned"
        );
        assert_eq!(
            finalized.os_version,
            PlatformType::Windows.os_version_for_seed(seed_pick_16)
        );

        // 4. Explicit manual CPU core selection is respected even across seed text edits
        draft.select_cores(12);
        let pinned = draft
            .finalize(
                "Pinned Cores",
                &seed_pick_16.to_string(),
                false,
                true,
                "",
                "",
                "",
                "",
                "",
            )
            .unwrap();
        assert_eq!(pinned.hardware_concurrency, 12);
    }

    #[test]
    fn test_seed_edit_then_select_platform_updates_brand_version() {
        let mut orig = Profile::new_default("SeedOS", PlatformType::MacOS);
        orig.set_seed(1300);
        let mut draft = ProfileEditorDraft::from_profile(&orig, true);

        // Simulate typing `1301` in seed_input then clicking an OS pill before saving
        draft.profile.seed = 1301;
        draft.select_platform(PlatformType::Windows);
        let saved = draft
            .finalize("SeedOS", "1301", false, true, "", "", "", "", "")
            .unwrap();
        assert_eq!(
            saved.brand_version,
            BrowserBrand::Chrome.version_for_seed(1301),
            "switching OS after editing seed must not leave brand_version on the old seed"
        );
    }
}
