use crate::models::GeoInfo;
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
        .timeout(GEO_TIMEOUT)
        .tcp_nodelay(true)
        .user_agent("curl/8.7.1")
        .build()
        .expect("Failed to initialize direct GeoIP HTTP client")
});

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
        let proxy_url = format!("http://127.0.0.1:{port}");
        reqwest::Client::builder()
            .connect_timeout(GEO_CONNECT_TIMEOUT)
            .timeout(GEO_TIMEOUT)
            .tcp_nodelay(true)
            .user_agent("curl/8.7.1")
            .proxy(
                reqwest::Proxy::all(&proxy_url)
                    .with_context(|| format!("Invalid local proxy URL {proxy_url}"))?,
            )
            .build()
            .context("Failed to build GeoIP HTTP client")?
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
}
