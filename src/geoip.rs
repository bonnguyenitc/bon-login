use crate::models::GeoInfo;
use anyhow::{Context, Result, bail};
use serde::Deserialize;
use std::time::{Duration, Instant};

const GEO_TIMEOUT: Duration = Duration::from_secs(8);

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
    let mut builder = reqwest::Client::builder()
        .timeout(GEO_TIMEOUT)
        .user_agent("curl/8.7.1");

    if let Some(port) = local_proxy_port {
        let proxy_url = format!("http://127.0.0.1:{port}");
        builder = builder.proxy(
            reqwest::Proxy::all(&proxy_url)
                .with_context(|| format!("Invalid local proxy URL {proxy_url}"))?,
        );
    }

    let client = builder.build().context("Failed to build GeoIP HTTP client")?;
    let mut errors = Vec::with_capacity(3);

    // 1. https://ipwho.is/
    let t0 = Instant::now();
    match client.get("https://ipwho.is/").send().await {
        Ok(resp) => match resp.text().await {
            Ok(text) => {
                let ms = t0.elapsed().as_millis() as u32;
                match parse_ipwho_json(&text, Some(ms)) {
                    Ok(geo) => return Ok(geo),
                    Err(e) => errors.push(format!("ipwho.is: {e}")),
                }
            }
            Err(e) => errors.push(format!("ipwho.is body: {e}")),
        },
        Err(e) => errors.push(format!("ipwho.is req: {e}")),
    }

    // 2. https://ipinfo.io/json
    let t1 = Instant::now();
    match client.get("https://ipinfo.io/json").send().await {
        Ok(resp) => match resp.text().await {
            Ok(text) => {
                let ms = t1.elapsed().as_millis() as u32;
                match parse_ipinfo_json(&text, Some(ms)) {
                    Ok(geo) => return Ok(geo),
                    Err(e) => errors.push(format!("ipinfo.io: {e}")),
                }
            }
            Err(e) => errors.push(format!("ipinfo.io body: {e}")),
        },
        Err(e) => errors.push(format!("ipinfo.io req: {e}")),
    }

    // 3. http://ip-api.com/json/?fields=status,message,countryCode,query,timezone
    let t2 = Instant::now();
    match client
        .get("http://ip-api.com/json/?fields=status,message,countryCode,query,timezone")
        .send()
        .await
    {
        Ok(resp) => match resp.text().await {
            Ok(text) => {
                let ms = t2.elapsed().as_millis() as u32;
                match parse_ipapi_json(&text, Some(ms)) {
                    Ok(geo) => return Ok(geo),
                    Err(e) => errors.push(format!("ip-api.com: {e}")),
                }
            }
            Err(e) => errors.push(format!("ip-api.com body: {e}")),
        },
        Err(e) => errors.push(format!("ip-api.com req: {e}")),
    }

    bail!(
        "Fail-closed: all GeoIP providers failed ({})",
        errors.join(" | ")
    )
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
