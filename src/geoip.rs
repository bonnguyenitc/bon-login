use crate::models::{FreeProxyCandidate, GeoInfo, ProxyConfig, ProxyProtocol};
use anyhow::{Context, Result, bail};
use serde::Deserialize;
use std::sync::LazyLock;
use std::time::{Duration, Instant};
use tokio::task::JoinSet;

const GEO_CONNECT_TIMEOUT: Duration = Duration::from_secs(4);
const GEO_TIMEOUT: Duration = Duration::from_secs(6);

static DIRECT_CLIENT: LazyLock<reqwest::Client> = LazyLock::new(|| {
    reqwest::Client::builder()
        .connect_timeout(GEO_CONNECT_TIMEOUT)
        .read_timeout(GEO_TIMEOUT)
        .timeout(GEO_TIMEOUT)
        .tcp_nodelay(true)
        .user_agent("curl/8.7.1")
        .build()
        .expect("Failed to initialize direct GeoIP HTTP client")
});

static PROXY_CLIENT_CACHE: LazyLock<
    std::sync::Mutex<std::collections::HashMap<u16, reqwest::Client>>,
> = LazyLock::new(|| std::sync::Mutex::new(std::collections::HashMap::new()));

fn geo_client_for_port(port: u16) -> Result<reqwest::Client> {
    if let Ok(guard) = PROXY_CLIENT_CACHE.lock()
        && let Some(c) = guard.get(&port)
    {
        return Ok(c.clone());
    }
    let proxy_url = format!("http://127.0.0.1:{port}");
    let client = reqwest::Client::builder()
        .connect_timeout(GEO_CONNECT_TIMEOUT)
        .read_timeout(GEO_TIMEOUT)
        .timeout(GEO_TIMEOUT)
        .pool_max_idle_per_host(0)
        .tcp_nodelay(true)
        .user_agent("curl/8.7.1")
        .proxy(
            reqwest::Proxy::all(&proxy_url)
                .with_context(|| format!("Invalid local proxy URL {proxy_url}"))?,
        )
        .build()
        .context("Failed to build GeoIP HTTP client")?;
    if let Ok(mut guard) = PROXY_CLIENT_CACHE.lock() {
        if guard.len() >= 64 {
            guard.clear();
        }
        guard.insert(port, client.clone());
    }
    Ok(client)
}
// shortcut: cap concurrent GeoIP checks at 5 across UI + bulk launches + CLI to avoid 429 rate-limits
static GEO_SEM: LazyLock<tokio::sync::Semaphore> =
    LazyLock::new(|| tokio::sync::Semaphore::new(5));

#[derive(Debug, Deserialize)]
struct IpWhoResponse {
    success: bool,
    ip: Option<String>,
    country_code: Option<String>,
    timezone: Option<IpWhoTimezone>,
}

#[derive(Debug, Deserialize)]
struct IpWhoTimezone {
    id: Option<String>,
}

#[derive(Debug, Deserialize)]
struct IpInfoResponse {
    ip: Option<String>,
    country: Option<String>,
    timezone: Option<String>,
}

#[derive(Debug, Deserialize)]
struct IpApiResponse {
    status: String,
    message: Option<String>,
    #[serde(rename = "countryCode")]
    country_code: Option<String>,
    query: Option<String>,
    timezone: Option<String>,
}

fn build_geo_info(
    ip: String,
    country_code: String,
    timezone: String,
    latency_ms: Option<u32>,
) -> Result<GeoInfo> {
    let ip = ip.trim().to_string();
    let country_code = country_code.trim().to_ascii_uppercase();
    let timezone = timezone.trim().to_string();
    if ip.is_empty() || country_code.is_empty() || timezone.is_empty() {
        bail!("Incomplete GeoIP fields (ip='{ip}', country='{country_code}', tz='{timezone}')");
    }
    let (locale, accept_lang) = GeoInfo::locale_for_country(&country_code);
    Ok(GeoInfo {
        ip,
        country_code,
        timezone,
        locale,
        accept_lang,
        latency_ms,
    })
}

fn parse_ipwho_json(body: &str, latency_ms: Option<u32>) -> Result<GeoInfo> {
    let parsed: IpWhoResponse = serde_json::from_str(body)?;
    if !parsed.success {
        bail!("ipwho.is returned success=false");
    }
    let ip = parsed.ip.context("ipwho.is missing ip")?;
    let country_code = parsed.country_code.context("ipwho.is missing country_code")?;
    let timezone = parsed
        .timezone
        .and_then(|t| t.id)
        .context("ipwho.is missing timezone.id")?;
    build_geo_info(ip, country_code, timezone, latency_ms)
}

fn parse_ipinfo_json(body: &str, latency_ms: Option<u32>) -> Result<GeoInfo> {
    let parsed: IpInfoResponse = serde_json::from_str(body)?;
    let ip = parsed.ip.context("ipinfo.io missing ip")?;
    let country_code = parsed.country.context("ipinfo.io missing country")?;
    let timezone = parsed.timezone.context("ipinfo.io missing timezone")?;
    build_geo_info(ip, country_code, timezone, latency_ms)
}

fn parse_ipapi_json(body: &str, latency_ms: Option<u32>) -> Result<GeoInfo> {
    let parsed: IpApiResponse = serde_json::from_str(body)?;
    if parsed.status != "success" {
        bail!(
            "ip-api.com returned status='{}' ({})",
            parsed.status,
            parsed.message.unwrap_or_default()
        );
    }
    let ip = parsed.query.context("ip-api.com missing query")?;
    let country_code = parsed.country_code.context("ip-api.com missing countryCode")?;
    let timezone = parsed.timezone.context("ip-api.com missing timezone")?;
    build_geo_info(ip, country_code, timezone, latency_ms)
}

pub async fn resolve_geo_via_port(local_proxy_port: Option<u16>) -> Result<GeoInfo> {
    let _permit = GEO_SEM.acquire().await;
    let client = if let Some(port) = local_proxy_port {
        geo_client_for_port(port)?
    } else {
        DIRECT_CLIENT.clone()
    };

    type ParserFn = fn(&str, Option<u32>) -> Result<GeoInfo>;
    let providers: [(&'static str, &'static str, ParserFn); 3] = [
        ("ipwho.is", "https://ipwho.is/", parse_ipwho_json),
        ("ipinfo.io", "https://ipinfo.io/json", parse_ipinfo_json),
        (
            "ip-api.com",
            "http://ip-api.com/json/?fields=status,message,countryCode,query,timezone",
            parse_ipapi_json,
        ),
    ];

    let mut set = JoinSet::new();
    for (name, url, parser) in providers {
        let c = client.clone();
        set.spawn(async move {
            let t0 = Instant::now();
            let resp = c
                .get(url)
                .send()
                .await
                .map_err(|e| format!("{name} req: {e}"))?;
            let text = resp
                .text()
                .await
                .map_err(|e| format!("{name} body: {e}"))?;
            let ms = t0.elapsed().as_millis() as u32;
            parser(&text, Some(ms)).map_err(|e| format!("{name}: {e}"))
        });
    }

    let mut errors = Vec::with_capacity(3);
    while let Some(joined) = set.join_next().await {
        match joined {
            Ok(Ok(geo)) => {
                set.abort_all();
                return Ok(geo);
            }
            Ok(Err(err)) => errors.push(err),
            Err(join_err) => errors.push(format!("task join: {join_err}")),
        }
    }

    bail!(
        "Fail-closed: all GeoIP providers failed ({})",
        errors.join(" | ")
    )
}

/// Calls a proxy provider's IP rotation webhook (`change_ip_url`) directly and returns a short status summary.
pub async fn trigger_proxy_rotation(change_ip_url: &str) -> Result<String> {
    let url = change_ip_url.trim();
    if !url.starts_with("http://") && !url.starts_with("https://") {
        bail!("Rotation URL must start with http:// or https://");
    }
    let resp = DIRECT_CLIENT
        .get(url)
        .send()
        .await
        .with_context(|| format!("Rotation webhook failed: {url}"))?;
    let status = resp.status();
    let body = resp.text().await.unwrap_or_default();
    if !status.is_success() {
        bail!("Rotation webhook returned HTTP {status}");
    }
    let summary: String = body
        .lines()
        .next()
        .unwrap_or("OK")
        .trim()
        .chars()
        .take(80)
        .collect();
    Ok(if summary.is_empty() {
        format!("HTTP {}", status.as_u16())
    } else {
        summary
    })
}

// shortcut: separate 12-permit semaphore for bulk free-proxy scanning so it doesn't starve profile launches
static FREE_SCAN_SEM: LazyLock<tokio::sync::Semaphore> =
    LazyLock::new(|| tokio::sync::Semaphore::new(12));

pub async fn resolve_geo_via_port_fast(local_proxy_port: u16) -> Result<GeoInfo> {
    let _permit = FREE_SCAN_SEM.acquire().await;
    let proxy_url = format!("http://127.0.0.1:{local_proxy_port}");
    let client = reqwest::Client::builder()
        .connect_timeout(Duration::from_millis(3200))
        .read_timeout(Duration::from_millis(4200))
        .timeout(Duration::from_millis(4500))
        .pool_max_idle_per_host(0)
        .tcp_nodelay(true)
        .user_agent("curl/8.7.1")
        .proxy(
            reqwest::Proxy::all(&proxy_url)
                .with_context(|| format!("Invalid local proxy URL {proxy_url}"))?,
        )
        .build()
        .context("Failed to build fast GeoIP client")?;

    type ParserFn = fn(&str, Option<u32>) -> Result<GeoInfo>;
    let providers: [(&'static str, &'static str, ParserFn); 2] = [
        ("ipinfo.io", "https://ipinfo.io/json", parse_ipinfo_json),
        ("ipwho.is", "https://ipwho.is/", parse_ipwho_json),
    ];
    let mut set = JoinSet::new();
    for (name, url, parser) in providers {
        let c = client.clone();
        set.spawn(async move {
            let t0 = Instant::now();
            let resp = c
                .get(url)
                .send()
                .await
                .map_err(|e| format!("{name}: {e}"))?;
            let text = resp
                .text()
                .await
                .map_err(|e| format!("{name} body: {e}"))?;
            let ms = t0.elapsed().as_millis() as u32;
            parser(&text, Some(ms)).map_err(|e| format!("{name}: {e}"))
        });
    }
    let mut last_err = String::from("timeout");
    while let Some(joined) = set.join_next().await {
        match joined {
            Ok(Ok(geo)) => {
                set.abort_all();
                return Ok(geo);
            }
            Ok(Err(e)) => last_err = e,
            Err(e) => last_err = e.to_string(),
        }
    }
    bail!("Proxy check failed ({last_err})")
}

#[derive(Debug, Deserialize)]
struct ProxyScrapeFeed {
    #[serde(default)]
    proxies: Vec<ProxyScrapeItem>,
}

#[derive(Debug, Deserialize)]
struct ProxyScrapeItem {
    #[serde(default)]
    alive: bool,
    #[serde(default)]
    protocol: String,
    #[serde(default)]
    ip: String,
    #[serde(default)]
    port: u16,
    #[serde(default)]
    ssl: bool,
    #[serde(default)]
    anonymity: String,
    timeout: Option<f64>,
    uptime: Option<f64>,
    ip_data: Option<ProxyScrapeIpData>,
}

#[derive(Debug, Deserialize)]
struct ProxyScrapeIpData {
    #[serde(rename = "countryCode", default)]
    country_code: String,
    #[serde(default)]
    city: String,
    #[serde(default)]
    timezone: String,
    #[serde(default)]
    isp: String,
}

#[derive(Debug, Deserialize)]
struct ProxiflyItem {
    #[serde(default)]
    protocol: String,
    #[serde(default)]
    ip: String,
    #[serde(default)]
    port: u16,
    #[serde(default)]
    https: bool,
    #[serde(default)]
    anonymity: String,
    geolocation: Option<ProxiflyGeo>,
}

#[derive(Debug, Deserialize)]
struct ProxiflyGeo {
    #[serde(default)]
    country: String,
    #[serde(default)]
    city: String,
}

pub fn parse_proxyscrape_free_json(body: &str) -> Vec<FreeProxyCandidate> {
    let Ok(feed) = serde_json::from_str::<ProxyScrapeFeed>(body) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for item in feed.proxies {
        if !item.alive || item.ip.trim().is_empty() || item.port == 0 {
            continue;
        }
        let protocol = match item.protocol.trim().to_ascii_lowercase().as_str() {
            "socks5" => ProxyProtocol::Socks5,
            "http" | "https" => ProxyProtocol::Http,
            _ => continue,
        };
        // Skip plain HTTP proxies that don't support SSL/CONNECT
        if protocol == ProxyProtocol::Http && !item.ssl {
            continue;
        }
        let ip_data = item.ip_data.unwrap_or(ProxyScrapeIpData {
            country_code: String::new(),
            city: String::new(),
            timezone: String::new(),
            isp: String::new(),
        });
        let cc = ip_data.country_code.trim().to_ascii_uppercase();
        let reported_latency_ms = item
            .timeout
            .filter(|v| v.is_finite() && *v > 0.0)
            .map(|v| v.round() as u32);
        let uptime_pct = item
            .uptime
            .filter(|v| v.is_finite() && *v >= 0.0)
            .map(|v| v.round().clamp(0.0, 100.0) as u8);
        out.push(FreeProxyCandidate {
            config: ProxyConfig {
                protocol,
                host: item.ip.trim().to_string(),
                port: item.port,
                username: None,
                password: None,
                change_ip_url: None,
            },
            country_code: if cc == "ZZ" || cc == "UNKNOWN" {
                String::new()
            } else {
                cc
            },
            city: ip_data.city.trim().to_string(),
            timezone: ip_data.timezone.trim().to_string(),
            isp: ip_data.isp.trim().to_string(),
            anonymity: if item.anonymity.trim().is_empty() {
                "elite".to_string()
            } else {
                item.anonymity.trim().to_ascii_lowercase()
            },
            source: "ProxyScrape".to_string(),
            reported_latency_ms,
            uptime_pct,
            ssl: item.ssl || protocol == ProxyProtocol::Socks5,
            verified_geo: None,
            last_error: None,
        });
    }
    out
}

pub fn parse_proxifly_free_json(body: &str) -> Vec<FreeProxyCandidate> {
    let Ok(items) = serde_json::from_str::<Vec<ProxiflyItem>>(body) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for item in items {
        if item.ip.trim().is_empty() || item.port == 0 {
            continue;
        }
        let protocol = match item.protocol.trim().to_ascii_lowercase().as_str() {
            "socks5" => ProxyProtocol::Socks5,
            "http" | "https" => ProxyProtocol::Http,
            _ => continue,
        };
        if protocol == ProxyProtocol::Http && !item.https {
            continue;
        }
        let (cc, city) = item
            .geolocation
            .map(|g| {
                let c = g.country.trim().to_ascii_uppercase();
                (
                    if c == "ZZ" || c == "UNKNOWN" {
                        String::new()
                    } else {
                        c
                    },
                    g.city.trim().to_string(),
                )
            })
            .unwrap_or_default();
        out.push(FreeProxyCandidate {
            config: ProxyConfig {
                protocol,
                host: item.ip.trim().to_string(),
                port: item.port,
                username: None,
                password: None,
                change_ip_url: None,
            },
            country_code: cc,
            city,
            timezone: String::new(),
            isp: String::new(),
            anonymity: if item.anonymity.trim().is_empty() {
                "anonymous".to_string()
            } else {
                item.anonymity.trim().to_ascii_lowercase()
            },
            source: "Proxifly".to_string(),
            reported_latency_ms: None,
            uptime_pct: None,
            ssl: item.https || protocol == ProxyProtocol::Socks5,
            verified_geo: None,
            last_error: None,
        });
    }
    out
}

pub fn parse_plain_free_proxy_lines(
    body: &str,
    default_proto: ProxyProtocol,
    source_name: &str,
    max_lines: usize,
) -> Vec<FreeProxyCandidate> {
    let mut out = Vec::new();
    for line in body.lines() {
        if out.len() >= max_lines {
            break;
        }
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        if let Ok(Some((cfg, _))) = ProxyConfig::parse_with_optional_name(trimmed, default_proto) {
            out.push(FreeProxyCandidate {
                config: cfg,
                country_code: String::new(),
                city: String::new(),
                timezone: String::new(),
                isp: String::new(),
                anonymity: "elite".to_string(),
                source: source_name.to_string(),
                reported_latency_ms: None,
                uptime_pct: None,
                ssl: true,
                verified_geo: None,
                last_error: None,
            });
        }
    }
    out
}

pub async fn fetch_free_proxy_candidates() -> Result<Vec<FreeProxyCandidate>> {
    let mut set = JoinSet::new();

    // Source 1: ProxyScrape v4 (rich metadata: country, city, ISP, latency, uptime)
    {
        let c = DIRECT_CLIENT.clone();
        set.spawn(async move {
            let url = "https://api.proxyscrape.com/v4/free-proxy-list/get?request=display_proxies&proxy_format=protocolipport&format=json&timeout=3500";
            let text = c.get(url).send().await.ok()?.text().await.ok()?;
            Some(parse_proxyscrape_free_json(&text))
        });
    }
    // Source 2: Fyvri Fresh SOCKS5 (high live rate for SOCKS5)
    {
        let c = DIRECT_CLIENT.clone();
        set.spawn(async move {
            let url = "https://raw.githubusercontent.com/fyvri/fresh-proxy-list/archive/storage/classic/socks5.txt";
            let text = c.get(url).send().await.ok()?.text().await.ok()?;
            Some(parse_plain_free_proxy_lines(
                &text,
                ProxyProtocol::Socks5,
                "Fyvri",
                120,
            ))
        });
    }
    // Source 3: Proxifly All JSON (updated every 5m, includes country & city)
    {
        let c = DIRECT_CLIENT.clone();
        set.spawn(async move {
            let url = "https://raw.githubusercontent.com/proxifly/free-proxy-list/main/proxies/all/data.json";
            let text = c.get(url).send().await.ok()?.text().await.ok()?;
            Some(parse_proxifly_free_json(&text))
        });
    }

    let mut combined = Vec::new();
    while let Some(res) = set.join_next().await {
        if let Ok(Some(batch)) = res {
            combined.extend(batch);
        }
    }
    if combined.is_empty() {
        bail!("Failed to fetch free proxy lists from public sources");
    }

    // Deduplicate by (protocol, host, port), preferring entries with country_code / latency metadata
    let mut seen: std::collections::HashMap<(ProxyProtocol, String, u16), usize> =
        std::collections::HashMap::new();
    let mut deduped: Vec<FreeProxyCandidate> = Vec::new();
    for item in combined {
        let key = (
            item.config.protocol,
            item.config.host.clone(),
            item.config.port,
        );
        if let Some(&idx) = seen.get(&key) {
            let existing = &mut deduped[idx];
            if existing.country_code.is_empty() && !item.country_code.is_empty() {
                existing.country_code = item.country_code;
                existing.city = item.city;
                existing.timezone = item.timezone;
                existing.isp = item.isp;
            }
            if existing.reported_latency_ms.is_none() && item.reported_latency_ms.is_some() {
                existing.reported_latency_ms = item.reported_latency_ms;
            }
        } else {
            seen.insert(key, deduped.len());
            deduped.push(item);
        }
    }

    // Sort: SOCKS5 & elite & known country & low latency first
    deduped.sort_by(|a, b| {
        let proto_rank = |p: &FreeProxyCandidate| match p.config.protocol {
            ProxyProtocol::Socks5 => 0u8,
            ProxyProtocol::Http => 1u8,
        };
        let has_meta = |p: &FreeProxyCandidate| -> u8 {
            if !p.country_code.is_empty() && p.reported_latency_ms.is_some() {
                0
            } else if !p.country_code.is_empty() {
                1
            } else {
                2
            }
        };
        let anon_rank = |p: &FreeProxyCandidate| match p.anonymity.as_str() {
            "elite" => 0u8,
            "anonymous" => 1u8,
            _ => 2u8,
        };
        proto_rank(a)
            .cmp(&proto_rank(b))
            .then_with(|| has_meta(a).cmp(&has_meta(b)))
            .then_with(|| anon_rank(a).cmp(&anon_rank(b)))
            .then_with(|| {
                a.reported_latency_ms
                    .unwrap_or(9999)
                    .cmp(&b.reported_latency_ms.unwrap_or(9999))
            })
    });
    deduped.truncate(400);
    Ok(deduped)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;

    #[test]
    fn test_parse_three_provider_shapes() {
        let g1 = parse_ipwho_json(
            r#"{
                "success": true,
                "ip": "203.113.10.2",
                "country_code": "VN",
                "timezone": { "id": "Asia/Ho_Chi_Minh" }
            }"#,
            Some(120),
        )
        .unwrap();
        assert_eq!(g1.ip, "203.113.10.2");
        assert_eq!(g1.country_code, "VN");
        assert_eq!(g1.latency_ms, Some(120));

        let g2 = parse_ipinfo_json(
            r#"{
                "ip": "8.8.4.4",
                "country": "US",
                "timezone": "America/Los_Angeles"
            }"#,
            Some(85),
        )
        .unwrap();
        assert_eq!(g2.country_code, "US");
        assert_eq!(g2.latency_ms, Some(85));

        let g3 = parse_ipapi_json(
            r#"{
                "status": "success",
                "countryCode": "JP",
                "query": "133.242.0.1",
                "timezone": "Asia/Tokyo"
            }"#,
            None,
        )
        .unwrap();
        assert_eq!(g3.country_code, "JP");
        assert_eq!(g3.locale, "ja-JP");
    }

    #[tokio::test]
    async fn test_fail_closed_on_closed_local_port() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let closed_port = listener.local_addr().unwrap().port();
        drop(listener);

        let res = resolve_geo_via_port(Some(closed_port)).await;
        assert!(res.is_err());
    }

    #[tokio::test]
    async fn test_trigger_proxy_rotation_and_parser_rejection_edges() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        // 1. Rejects non-HTTP(S) schemes immediately
        assert!(trigger_proxy_rotation("ftp://example.com/rotate").await.is_err());
        assert!(trigger_proxy_rotation("   ").await.is_err());

        // 2. Loopback HTTP rotation server (200 with multiline body, 200 with empty body, 503 error)
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            for step in 0..4 {
                if let Ok((mut s, _)) = listener.accept().await {
                    let mut buf = [0u8; 512];
                    let _ = s.read(&mut buf).await;
                    let resp = match step {
                        0 => "HTTP/1.1 200 OK\r\nContent-Length: 31\r\nConnection: close\r\n\r\n  Rotated to 198.51.100.42  \nOK",
                        1 => "HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                        2 => "HTTP/1.1 200 OK\r\nContent-Length: 3\r\nConnection: close\r\n\r\n   ",
                        _ => "HTTP/1.1 503 Service Unavailable\r\nContent-Length: 9\r\nConnection: close\r\n\r\nRateLimit",
                    };
                    let _ = s.write_all(resp.as_bytes()).await;
                }
            }
        });

        let url = format!("http://127.0.0.1:{port}/rotate");
        let msg1 = trigger_proxy_rotation(&url).await.unwrap();
        assert_eq!(msg1, "Rotated to 198.51.100.42");
        let msg2 = trigger_proxy_rotation(&url).await.unwrap();
        assert_eq!(msg2, "OK");
        let msg3 = trigger_proxy_rotation(&url).await.unwrap();
        assert_eq!(msg3, "HTTP 200");
        let err4 = trigger_proxy_rotation(&url).await.unwrap_err().to_string();
        assert!(err4.contains("503"));

        // 3. Fail-closed parser rejections on provider error payloads or blank fields
        assert!(parse_ipwho_json(r#"{"success":false,"ip":"1.1.1.1"}"#, None).is_err());
        assert!(
            parse_ipwho_json(
                r#"{"success":true,"ip":"   ","country_code":"US","timezone":{"id":"UTC"}}"#,
                None
            )
            .is_err()
        );
        assert!(
            parse_ipapi_json(
                r#"{"status":"fail","message":"reserved range","query":"127.0.0.1"}"#,
                None
            )
            .is_err()
        );
        assert!(parse_ipinfo_json(r#"{"ip":"8.8.8.8","country":"US"}"#, None).is_err());
    }

    #[test]
    fn test_parse_free_proxy_sources_and_filter() {
        let ps_json = r#"{
            "proxies": [
                {
                    "alive": true,
                    "protocol": "socks5",
                    "ip": "45.194.33.12",
                    "port": 30002,
                    "ssl": true,
                    "anonymity": "elite",
                    "timeout": 182.4,
                    "uptime": 98.7,
                    "ip_data": {
                        "countryCode": "HK",
                        "city": "Hong Kong",
                        "timezone": "Asia/Hong_Kong",
                        "isp": "HK Broadband"
                    }
                },
                {
                    "alive": true,
                    "protocol": "http",
                    "ip": "1.2.3.4",
                    "port": 80,
                    "ssl": false
                }
            ]
        }"#;
        let list = parse_proxyscrape_free_json(ps_json);
        assert_eq!(list.len(), 1);
        let item = &list[0];
        assert_eq!(item.config.protocol, ProxyProtocol::Socks5);
        assert_eq!(item.country_code, "HK");
        assert_eq!(item.reported_latency_ms, Some(182));
        assert_eq!(item.uptime_pct, Some(99));
        assert!(item.matches_filter("hong", Some(ProxyProtocol::Socks5), "HK", false));
        assert!(!item.matches_filter("hong", Some(ProxyProtocol::Http), "HK", false));
        assert!(!item.matches_filter("", None, "All", true));
        let saved = item.to_saved_proxy("free");
        assert_eq!(saved.group_tag, "free");
        assert!(saved.name.contains("Free HK"));
        assert_eq!(saved.resolved_geo.as_ref().unwrap().country_code, "HK");
    }
}
