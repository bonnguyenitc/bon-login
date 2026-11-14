use crate::models::{ProxyConfig, ProxyProtocol};
use anyhow::{Context, Result, bail};
use base64::Engine;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt, copy_bidirectional_with_sizes};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::oneshot;
use tokio::task::JoinSet;
use tokio::time::timeout;

const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_HEADER_BYTES: usize = 65536;

pub struct LocalProxyTunnel {
    local_port: u16,
    shutdown_tx: Option<oneshot::Sender<()>>,
}

impl LocalProxyTunnel {
    pub async fn start(proxy: ProxyConfig) -> Result<Self> {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .context("Failed to bind local proxy listener on 127.0.0.1:0")?;
        let local_port = listener.local_addr()?.port();
        let (shutdown_tx, mut shutdown_rx) = oneshot::channel::<()>();
        let upstream_addr: Arc<str> = format!("{}:{}", proxy.host, proxy.port).into();
        let auth_header: Arc<str> = build_proxy_auth_header(&proxy).unwrap_or_default().into();
        let proxy = Arc::new(proxy);

        tokio::spawn(async move {
            let mut join_set = JoinSet::new();
            loop {
                tokio::select! {
                    _ = &mut shutdown_rx => {
                        join_set.abort_all();
                        break;
                    }
                    accept_res = listener.accept() => {
                        match accept_res {
                            Ok((client_stream, _)) => {
                                let _ = client_stream.set_nodelay(true);
                                let proxy_cfg = Arc::clone(&proxy);
                                let addr = Arc::clone(&upstream_addr);
                                let auth = Arc::clone(&auth_header);
                                join_set.spawn(async move {
                                    let _ = handle_client(client_stream, &proxy_cfg, &addr, &auth).await;
                                });
                            }
                            Err(_) => {
                                tokio::time::sleep(Duration::from_millis(10)).await;
                            }
                        }
                    }
                    Some(_) = join_set.join_next(), if !join_set.is_empty() => {}
                }
            }
            join_set.abort_all();
        });

        Ok(Self {
            local_port,
            shutdown_tx: Some(shutdown_tx),
        })
    }

    pub fn local_port(&self) -> u16 {
        self.local_port
    }

    pub fn stop(&mut self) {
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(());
        }
    }
}

impl Drop for LocalProxyTunnel {
    fn drop(&mut self) {
        self.stop();
    }
}

struct ParsedClientRequest {
    is_connect: bool,
    target_host: String,
    target_port: u16,
    first_line_rewritten: String,
    rest_headers: Vec<u8>,
    body_prefix: Vec<u8>,
}

async fn read_until_double_crlf(stream: &mut TcpStream) -> Result<(Vec<u8>, Vec<u8>)> {
    let mut buf = Vec::with_capacity(2048);
    let mut chunk = [0u8; 2048];
    loop {
        if buf.len() >= MAX_HEADER_BYTES {
            bail!("HTTP header exceeded max size");
        }
        let n = stream.read(&mut chunk).await?;
        if n == 0 {
            bail!("Unexpected EOF while reading HTTP headers");
        }
        let scan_from = buf.len().saturating_sub(3);
        buf.extend_from_slice(&chunk[..n]);
        if let Some(rel) = find_double_crlf(&buf[scan_from..]) {
            let header_end = scan_from + rel + 4;
            let body_prefix = buf.split_off(header_end);
            return Ok((buf, body_prefix));
        }
    }
}

pub(crate) fn find_double_crlf(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n")
}

fn authority_host_port(host: &str, port: u16) -> String {
    if host.contains(':') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}

fn parse_host_port(authority: &str, default_port: u16) -> Result<(String, u16)> {
    let authority = authority.trim();
    if let Some(rest) = authority.strip_prefix('[')
        && let Some((ipv6, after)) = rest.split_once(']')
    {
        let port = if let Some(p_str) = after.strip_prefix(':') {
            p_str.parse::<u16>()?
        } else {
            default_port
        };
        return Ok((ipv6.to_string(), port));
    }
    if let Some((h, p)) = authority.rsplit_once(':')
        && let Ok(port) = p.parse::<u16>()
    {
        return Ok((h.to_string(), port));
    }
    Ok((authority.to_string(), default_port))
}

fn parse_client_request(header_bytes: &[u8], body_prefix: Vec<u8>) -> Result<ParsedClientRequest> {
    let first_crlf = header_bytes
        .windows(2)
        .position(|w| w == b"\r\n")
        .context("Missing request line CRLF")?;
    let request_line = std::str::from_utf8(&header_bytes[..first_crlf])?;
    let rest_headers = header_bytes[first_crlf + 2..].to_vec(); // ends with \r\n\r\n

    let mut parts = request_line.split_whitespace();
    let method = parts.next().context("Empty HTTP request line")?;
    let uri = parts.next().context("Missing URI in HTTP request")?;
    let version = parts.next().unwrap_or("HTTP/1.1");

    if method.eq_ignore_ascii_case("CONNECT") {
        let (target_host, target_port) = parse_host_port(uri, 443)?;
        return Ok(ParsedClientRequest {
            is_connect: true,
            target_host,
            target_port,
            first_line_rewritten: request_line.to_string(),
            rest_headers,
            body_prefix,
        });
    }

    // Plain HTTP proxy request: e.g. GET http://host:port/path HTTP/1.1
    let (target_host, target_port, rel_path) = if let Some(after_scheme) = uri
        .strip_prefix("http://")
        .or_else(|| uri.strip_prefix("https://"))
    {
        let default_port = if uri.starts_with("https://") { 443 } else { 80 };
        let (authority, path) = match after_scheme.find('/') {
            Some(slash_idx) => (&after_scheme[..slash_idx], &after_scheme[slash_idx..]),
            None => (after_scheme, "/"),
        };
        let (h, p) = parse_host_port(authority, default_port)?;
        (h, p, path.to_string())
    } else {
        // Fallback: inspect Host header if relative URI was sent
        let headers_str = std::str::from_utf8(&rest_headers).unwrap_or("");
        let host_val = headers_str
            .lines()
            .find_map(|line| {
                let (k, v) = line.split_once(':')?;
                if k.trim().eq_ignore_ascii_case("host") {
                    Some(v.trim())
                } else {
                    None
                }
            })
            .context("Missing Host header in plain HTTP request")?;
        let (h, p) = parse_host_port(host_val, 80)?;
        (
            h,
            p,
            if uri.is_empty() { "/".to_string() } else { uri.to_string() },
        )
    };

    let first_line_rewritten = format!("{method} {rel_path} {version}");
    Ok(ParsedClientRequest {
        is_connect: false,
        target_host,
        target_port,
        first_line_rewritten,
        rest_headers,
        body_prefix,
    })
}

fn build_proxy_auth_header(proxy: &ProxyConfig) -> Option<String> {
    let user = proxy.username.as_deref()?;
    let pass = proxy.password.as_deref().unwrap_or("");
    let encoded = base64::engine::general_purpose::STANDARD.encode(format!("{user}:{pass}"));
    Some(format!("Proxy-Authorization: Basic {encoded}\r\n"))
}

async fn handle_client(
    mut client_stream: TcpStream,
    proxy: &ProxyConfig,
    upstream_addr: &str,
    auth_header: &str,
) -> Result<()> {
    let (header_bytes, body_prefix) = timeout(HANDSHAKE_TIMEOUT, read_until_double_crlf(&mut client_stream))
        .await
        .context("Timeout reading client request")??;

    let req = parse_client_request(&header_bytes, body_prefix)?;

    let mut upstream = timeout(HANDSHAKE_TIMEOUT, TcpStream::connect(upstream_addr))
        .await
        .with_context(|| format!("Timeout connecting to upstream proxy {upstream_addr}"))?
        .with_context(|| format!("Failed connecting to upstream proxy {upstream_addr}"))?;
    let _ = upstream.set_nodelay(true);

    match proxy.protocol {
        ProxyProtocol::Http => {
            handle_http_upstream(&mut client_stream, &mut upstream, auth_header, &header_bytes, req).await?;
        }
        ProxyProtocol::Socks5 => {
            handle_socks5_upstream(&mut client_stream, &mut upstream, proxy, req).await?;
        }
    }

    let _ = copy_bidirectional_with_sizes(&mut client_stream, &mut upstream, 64 * 1024, 64 * 1024).await;
    Ok(())
}

async fn handle_http_upstream(
    client_stream: &mut TcpStream,
    upstream: &mut TcpStream,
    auth_header: &str,
    raw_header_bytes: &[u8],
    req: ParsedClientRequest,
) -> Result<()> {
    if req.is_connect {
        let authority = authority_host_port(&req.target_host, req.target_port);
        let connect_req = format!(
            "CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n{auth_header}\r\n"
        );

        let extra = timeout(HANDSHAKE_TIMEOUT, async {
            upstream.write_all(connect_req.as_bytes()).await?;
            let (resp_headers, extra) = read_until_double_crlf(upstream).await?;
            let status_line = std::str::from_utf8(&resp_headers)
                .unwrap_or("")
                .lines()
                .next()
                .unwrap_or("");
            if !status_line.contains(" 200") {
                bail!("Upstream HTTP proxy CONNECT failed: {status_line}");
            }
            Ok::<Vec<u8>, anyhow::Error>(extra)
        })
        .await
        .context("Timeout during upstream HTTP CONNECT")??;

        client_stream
            .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            .await?;
        if !extra.is_empty() {
            client_stream.write_all(&extra).await?;
        }
        if !req.body_prefix.is_empty() {
            upstream.write_all(&req.body_prefix).await?;
        }
    } else {
        // Plain HTTP request to upstream HTTP proxy: inject Proxy-Authorization if present
        let mut out = Vec::with_capacity(
            raw_header_bytes.len() + auth_header.len() + 48 + req.body_prefix.len(),
        );
        if let Ok(hdr_str) = std::str::from_utf8(raw_header_bytes) {
            for (idx, line) in hdr_str.split("\r\n").enumerate() {
                if line.is_empty() {
                    continue;
                }
                let strip = idx > 0
                    && line.split_once(':').is_some_and(|(k, _)| {
                        let k = k.trim();
                        k.eq_ignore_ascii_case("connection")
                            || k.eq_ignore_ascii_case("proxy-connection")
                            || (!auth_header.is_empty()
                                && k.eq_ignore_ascii_case("proxy-authorization"))
                    });
                if !strip {
                    out.extend_from_slice(line.as_bytes());
                    out.extend_from_slice(b"\r\n");
                }
            }
            if !auth_header.is_empty() {
                out.extend_from_slice(auth_header.as_bytes());
            }
            out.extend_from_slice(b"Proxy-Connection: close\r\nConnection: close\r\n\r\n");
        } else {
            let insert_pos = raw_header_bytes.len().saturating_sub(2);
            out.extend_from_slice(&raw_header_bytes[..insert_pos]);
            if !auth_header.is_empty() {
                out.extend_from_slice(auth_header.as_bytes());
            }
            out.extend_from_slice(b"Connection: close\r\n\r\n");
        }
        out.extend_from_slice(&req.body_prefix);
        timeout(HANDSHAKE_TIMEOUT, upstream.write_all(&out))
            .await
            .context("Timeout forwarding plain HTTP request to upstream")??;
    }

    Ok(())
}

async fn handle_socks5_upstream(
    client_stream: &mut TcpStream,
    upstream: &mut TcpStream,
    proxy: &ProxyConfig,
    req: ParsedClientRequest,
) -> Result<()> {
    timeout(HANDSHAKE_TIMEOUT, socks5_handshake_and_connect(upstream, proxy, &req.target_host, req.target_port))
        .await
        .context("Timeout during SOCKS5 handshake")??;

    if req.is_connect {
        client_stream
            .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            .await?;
        if !req.body_prefix.is_empty() {
            upstream.write_all(&req.body_prefix).await?;
        }
    } else {
        // Rewrite request line to relative path and strip proxy-only headers for direct tunnel over SOCKS5
        let mut out = Vec::with_capacity(
            req.first_line_rewritten.len() + 2 + req.rest_headers.len() + req.body_prefix.len(),
        );
        out.extend_from_slice(req.first_line_rewritten.as_bytes());
        out.extend_from_slice(b"\r\n");
        if let Ok(hdr_str) = std::str::from_utf8(&req.rest_headers) {
            for line in hdr_str.split("\r\n") {
                if line.is_empty() {
                    continue;
                }
                let is_proxy_hdr = line.split_once(':').is_some_and(|(k, _)| {
                    let k = k.trim();
                    k.eq_ignore_ascii_case("proxy-connection")
                        || k.eq_ignore_ascii_case("proxy-authorization")
                        || k.eq_ignore_ascii_case("connection")
                });
                if !is_proxy_hdr {
                    out.extend_from_slice(line.as_bytes());
                    out.extend_from_slice(b"\r\n");
                }
            }
            out.extend_from_slice(b"Connection: close\r\n\r\n");
        } else {
            out.extend_from_slice(&req.rest_headers);
        }
        out.extend_from_slice(&req.body_prefix);
        upstream.write_all(&out).await?;
    }

    Ok(())
}

async fn socks5_handshake_and_connect(
    upstream: &mut TcpStream,
    proxy: &ProxyConfig,
    target_host: &str,
    target_port: u16,
) -> Result<()> {
    if let Some(user) = proxy.username.as_deref() {
        let pass = proxy.password.as_deref().unwrap_or("");
        upstream.write_all(&[0x05, 0x01, 0x02]).await?;
        let mut greeting_resp = [0u8; 2];
        upstream.read_exact(&mut greeting_resp).await?;
        if greeting_resp != [0x05, 0x02] {
            bail!(
                "SOCKS5 server rejected username/password auth: {:02x?}",
                greeting_resp
            );
        }
        let u_bytes = user.as_bytes();
        let p_bytes = pass.as_bytes();
        if u_bytes.len() > 255 || p_bytes.len() > 255 {
            bail!("SOCKS5 username/password exceeds 255 bytes");
        }
        let mut auth_pkt = Vec::with_capacity(3 + u_bytes.len() + p_bytes.len());
        auth_pkt.push(0x01);
        auth_pkt.push(u_bytes.len() as u8);
        auth_pkt.extend_from_slice(u_bytes);
        auth_pkt.push(p_bytes.len() as u8);
        auth_pkt.extend_from_slice(p_bytes);
        upstream.write_all(&auth_pkt).await?;

        let mut auth_resp = [0u8; 2];
        upstream.read_exact(&mut auth_resp).await?;
        if auth_resp[1] != 0x00 {
            bail!("SOCKS5 username/password authentication failed");
        }
    } else {
        upstream.write_all(&[0x05, 0x01, 0x00]).await?;
        let mut greeting_resp = [0u8; 2];
        upstream.read_exact(&mut greeting_resp).await?;
        if greeting_resp != [0x05, 0x00] {
            bail!(
                "SOCKS5 no-auth handshake rejected: {:02x?}",
                greeting_resp
            );
        }
    }

    // Hostnames stay ATYP 0x03 so the Mac never resolves them. Literals are already IPs.
    let mut connect_pkt = Vec::with_capacity(22);
    connect_pkt.extend_from_slice(&[0x05, 0x01, 0x00]);
    if let Ok(ip) = target_host.parse::<std::net::IpAddr>() {
        match ip {
            std::net::IpAddr::V4(v4) => {
                connect_pkt.push(0x01);
                connect_pkt.extend_from_slice(&v4.octets());
            }
            std::net::IpAddr::V6(v6) => {
                connect_pkt.push(0x04);
                connect_pkt.extend_from_slice(&v6.octets());
            }
        }
    } else {
        let host_bytes = target_host.as_bytes();
        if host_bytes.is_empty() || host_bytes.len() > 255 {
            bail!("Invalid SOCKS5 target host length: {}", host_bytes.len());
        }
        connect_pkt.push(0x03);
        connect_pkt.push(host_bytes.len() as u8);
        connect_pkt.extend_from_slice(host_bytes);
    }
    connect_pkt.extend_from_slice(&target_port.to_be_bytes());
    upstream.write_all(&connect_pkt).await?;

    let mut reply_head = [0u8; 4];
    upstream.read_exact(&mut reply_head).await?;
    if reply_head[0] != 0x05 {
        bail!("Invalid SOCKS5 reply version: {}", reply_head[0]);
    }
    if reply_head[1] != 0x00 {
        bail!(
            "SOCKS5 CONNECT failed with status code 0x{:02x}",
            reply_head[1]
        );
    }

    // Consume BND.ADDR + BND.PORT according to ATYP
    match reply_head[3] {
        0x01 => {
            // IPv4 (4 bytes) + port (2 bytes) = 6 remaining bytes (total 10)
            let mut rest = [0u8; 6];
            upstream.read_exact(&mut rest).await?;
        }
        0x03 => {
            // Domain name: 1 byte len + len + 2 bytes port
            let mut len_buf = [0u8; 1];
            upstream.read_exact(&mut len_buf).await?;
            let mut rest = vec![0u8; (len_buf[0] as usize) + 2];
            upstream.read_exact(&mut rest).await?;
        }
        0x04 => {
            // IPv6 (16 bytes) + port (2 bytes) = 18 remaining bytes (total 22)
            let mut rest = [0u8; 18];
            upstream.read_exact(&mut rest).await?;
        }
        atyp => bail!("Unsupported SOCKS5 reply ATYP: 0x{atyp:02x}"),
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::sync::mpsc;

    #[tokio::test]
    async fn test_socks5_auth_atyp_domain_and_clean_stop() {
        let mock_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mock_port = mock_listener.local_addr().unwrap().port();
        let (atyp_tx, mut atyp_rx) = mpsc::unbounded_channel::<(u8, String, u16)>();

        // Spawn mock SOCKS5 server requiring RFC 1929 auth and asserting ATYP == 0x03
        tokio::spawn(async move {
            while let Ok((mut sock, _)) = mock_listener.accept().await {
                let atyp_tx = atyp_tx.clone();
                tokio::spawn(async move {
                    // 1. Read greeting: [0x05, nmethods, ..methods]
                    let mut head = [0u8; 2];
                    if sock.read_exact(&mut head).await.is_err() {
                        return;
                    }
                    assert_eq!(head[0], 0x05);
                    let mut methods = vec![0u8; head[1] as usize];
                    sock.read_exact(&mut methods).await.unwrap();
                    assert!(methods.contains(&0x02));

                    // Choose username/password auth (0x02)
                    sock.write_all(&[0x05, 0x02]).await.unwrap();

                    // 2. Read RFC 1929 auth: [0x01, ulen, ..user, plen, ..pass]
                    let mut auth_head = [0u8; 2];
                    sock.read_exact(&mut auth_head).await.unwrap();
                    assert_eq!(auth_head[0], 0x01);
                    let mut user = vec![0u8; auth_head[1] as usize];
                    sock.read_exact(&mut user).await.unwrap();
                    let mut plen = [0u8; 1];
                    sock.read_exact(&mut plen).await.unwrap();
                    let mut pass = vec![0u8; plen[0] as usize];
                    sock.read_exact(&mut pass).await.unwrap();

                    assert_eq!(&user, b"bonuser");
                    assert_eq!(&pass, b"bonpass");
                    sock.write_all(&[0x01, 0x00]).await.unwrap();

                    // 3. Read CONNECT request: [0x05, 0x01, 0x00, ATYP, ...]
                    let mut req_head = [0u8; 4];
                    sock.read_exact(&mut req_head).await.unwrap();
                    assert_eq!(req_head[0], 0x05);
                    assert_eq!(req_head[1], 0x01);
                    let atyp = req_head[3];
                    assert_eq!(atyp, 0x03, "Expected ATYP 0x03 Domain Name");

                    let mut dlen = [0u8; 1];
                    sock.read_exact(&mut dlen).await.unwrap();
                    let mut domain = vec![0u8; dlen[0] as usize];
                    sock.read_exact(&mut domain).await.unwrap();
                    let mut port_bytes = [0u8; 2];
                    sock.read_exact(&mut port_bytes).await.unwrap();
                    let target_port = u16::from_be_bytes(port_bytes);

                    let _ = atyp_tx.send((
                        atyp,
                        String::from_utf8(domain).unwrap(),
                        target_port,
                    ));

                    // Send SOCKS5 success reply (IPv4 0.0.0.0:0 -> 10 bytes)
                    sock.write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                        .await
                        .unwrap();

                    // Echo payload back through tunnel
                    let mut payload = [0u8; 4];
                    if sock.read_exact(&mut payload).await.is_ok() {
                        let _ = sock.write_all(b"PONG").await;
                    }
                    // Keep socket open until client or tunnel aborts
                    let mut drain = [0u8; 64];
                    let _ = sock.read(&mut drain).await;
                });
            }
        });

        let mut tunnel = LocalProxyTunnel::start(ProxyConfig {
            protocol: ProxyProtocol::Socks5,
            host: "127.0.0.1".to_string(),
            port: mock_port,
            username: Some("bonuser".to_string()),
            password: Some("bonpass".to_string()),
            change_ip_url: None,
        })
        .await
        .unwrap();

        let tunnel_port = tunnel.local_port();
        let mut client = TcpStream::connect(("127.0.0.1", tunnel_port)).await.unwrap();
        client
            .write_all(b"CONNECT browserscan.net:443 HTTP/1.1\r\nHost: browserscan.net:443\r\n\r\n")
            .await
            .unwrap();

        let (resp_hdr, _) = read_until_double_crlf(&mut client).await.unwrap();
        let resp_str = String::from_utf8_lossy(&resp_hdr);
        assert!(resp_str.starts_with("HTTP/1.1 200"));

        // Verify mock SOCKS5 server received ATYP == 0x03 with raw domain name
        let (atyp, domain, port) = atyp_rx.recv().await.unwrap();
        assert_eq!(atyp, 0x03);
        assert_eq!(domain, "browserscan.net");
        assert_eq!(port, 443);

        // Verify bidirectional traffic
        client.write_all(b"PING").await.unwrap();
        let mut pong = [0u8; 4];
        client.read_exact(&mut pong).await.unwrap();
        assert_eq!(&pong, b"PONG");

        // Verify stop() aborts open connections and closes listener
        tunnel.stop();
        let mut eof_buf = [0u8; 8];
        let n = timeout(Duration::from_secs(2), client.read(&mut eof_buf))
            .await
            .unwrap()
            .unwrap_or(0);
        assert_eq!(n, 0, "Expected open client socket to close upon tunnel.stop()");

        for prefix_len in [0usize, 1, 12, 15, 16, 17, 31, 32, 48] {
            let mut hdr = vec![b'A'; prefix_len];
            hdr.extend_from_slice(b"\r\nX: 1\r\r\n\r\nBODY");
            assert_eq!(find_double_crlf(&hdr), Some(prefix_len + 7));
        }
        assert_eq!(find_double_crlf(b"\r\n\r"), None);
    }

    #[tokio::test]
    async fn test_http_upstream_connect_plain_http_and_socks5_bnd_variants() {
        let (seen_tx, mut seen_rx) = mpsc::unbounded_channel::<String>();
        let mock_http = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let http_port = mock_http.local_addr().unwrap().port();

        // Mock upstream HTTP proxy handling both CONNECT and plain HTTP GET
        tokio::spawn(async move {
            while let Ok((mut sock, _)) = mock_http.accept().await {
                let seen_tx = seen_tx.clone();
                tokio::spawn(async move {
                    let Ok((hdr, body)) = read_until_double_crlf(&mut sock).await else {
                        return;
                    };
                    let hdr_str = String::from_utf8_lossy(&hdr).into_owned();
                    let _ = seen_tx.send(hdr_str.clone());
                    if hdr_str.starts_with("CONNECT ") {
                        let _ = sock
                            .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                            .await;
                        let mut ping = [0u8; 4];
                        if !body.is_empty() || sock.read_exact(&mut ping).await.is_ok() {
                            let _ = sock.write_all(b"HTTP_OK").await;
                        }
                    } else {
                        let _ = sock
                            .write_all(
                                b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\nPLAIN",
                            )
                            .await;
                    }
                });
            }
        });

        let mut http_tunnel = LocalProxyTunnel::start(ProxyConfig {
            protocol: ProxyProtocol::Http,
            host: "127.0.0.1".to_string(),
            port: http_port,
            username: Some("httpuser".to_string()),
            password: Some("httppass".to_string()),
            change_ip_url: None,
        })
        .await
        .unwrap();
        let t_port = http_tunnel.local_port();

        // 1. HTTP Upstream CONNECT with Basic Proxy-Authorization
        let mut c1 = TcpStream::connect(("127.0.0.1", t_port)).await.unwrap();
        c1.write_all(b"CONNECT api.example.com:8443 HTTP/1.1\r\nHost: api.example.com:8443\r\n\r\n")
            .await
            .unwrap();
        let (r1_hdr, _) = read_until_double_crlf(&mut c1).await.unwrap();
        assert!(String::from_utf8_lossy(&r1_hdr).starts_with("HTTP/1.1 200"));
        let upstream_req1 = seen_rx.recv().await.unwrap();
        assert!(upstream_req1.starts_with("CONNECT api.example.com:8443 HTTP/1.1"));
        assert!(
            upstream_req1.contains("Proxy-Authorization: Basic aHR0cHVzZXI6aHR0cHBhc3M=\r\n"),
            "missing Basic auth in upstream CONNECT: {upstream_req1}"
        );
        c1.write_all(b"PING").await.unwrap();
        let mut reply1 = [0u8; 7];
        c1.read_exact(&mut reply1).await.unwrap();
        assert_eq!(&reply1, b"HTTP_OK");
        drop(c1);

        // 2. Plain HTTP GET to HTTP upstream (strips client Proxy-Authorization, injects tunnel's)
        let mut c2 = TcpStream::connect(("127.0.0.1", t_port)).await.unwrap();
        c2.write_all(
            b"GET http://ip-api.com/json HTTP/1.1\r\nHost: ip-api.com\r\nProxy-Connection: keep-alive\r\nProxy-Authorization: Basic STALE\r\n\r\n",
        )
        .await
        .unwrap();
        let mut plain_resp = Vec::new();
        c2.read_to_end(&mut plain_resp).await.unwrap();
        assert!(String::from_utf8_lossy(&plain_resp).ends_with("PLAIN"));
        let upstream_req2 = seen_rx.recv().await.unwrap();
        assert!(upstream_req2.contains("Proxy-Authorization: Basic aHR0cHVzZXI6aHR0cHBhc3M=\r\n"));
        assert!(!upstream_req2.contains("Basic STALE"));
        http_tunnel.stop();

        // 3. No-auth SOCKS5 upstream with plain HTTP GET rewriting & ATYP 0x04 (IPv6) BND.ADDR reply
        let mock_s5 = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let s5_port = mock_s5.local_addr().unwrap().port();
        let (s5_tx, mut s5_rx) = mpsc::unbounded_channel::<String>();
        tokio::spawn(async move {
            if let Ok((mut sock, _)) = mock_s5.accept().await {
                let mut greet = [0u8; 3];
                sock.read_exact(&mut greet).await.unwrap();
                assert_eq!(greet, [0x05, 0x01, 0x00]);
                sock.write_all(&[0x05, 0x00]).await.unwrap();

                let mut req_head = [0u8; 5];
                sock.read_exact(&mut req_head).await.unwrap();
                assert_eq!(&req_head[..4], &[0x05, 0x01, 0x00, 0x03]);
                let dlen = req_head[4] as usize;
                let mut dom_port = vec![0u8; dlen + 2];
                sock.read_exact(&mut dom_port).await.unwrap();

                // Reply with ATYP = 0x04 (IPv6 16 bytes + 2 bytes port = 18 bytes)
                let mut v6_reply = vec![0x05, 0x00, 0x00, 0x04];
                v6_reply.extend_from_slice(&[0u8; 18]);
                sock.write_all(&v6_reply).await.unwrap();

                let (forwarded_hdr, _) = read_until_double_crlf(&mut sock).await.unwrap();
                let _ = s5_tx.send(String::from_utf8_lossy(&forwarded_hdr).into_owned());
                let _ = sock
                    .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK")
                    .await;
            }
        });

        let mut s5_tunnel = LocalProxyTunnel::start(ProxyConfig {
            protocol: ProxyProtocol::Socks5,
            host: "127.0.0.1".to_string(),
            port: s5_port,
            username: None,
            password: None,
            change_ip_url: None,
        })
        .await
        .unwrap();
        let mut c3 = TcpStream::connect(("127.0.0.1", s5_tunnel.local_port()))
            .await
            .unwrap();
        c3.write_all(
            b"GET http://check.example.com:8080/status?x=1 HTTP/1.1\r\nHost: check.example.com:8080\r\nProxy-Connection: keep-alive\r\n\r\n",
        )
        .await
        .unwrap();
        let mut s5_resp = Vec::new();
        c3.read_to_end(&mut s5_resp).await.unwrap();
        assert!(String::from_utf8_lossy(&s5_resp).ends_with("OK"));
        let rewritten = s5_rx.recv().await.unwrap();
        assert!(
            rewritten.starts_with("GET /status?x=1 HTTP/1.1\r\n"),
            "SOCKS5 plain HTTP must rewrite absolute URI to relative path, got: {rewritten}"
        );
        assert!(!rewritten.to_ascii_lowercase().contains("proxy-connection"));
        s5_tunnel.stop();

        // 4. Unit checks for parse_host_port IPv6 & relative URI fallback in parse_client_request
        assert_eq!(
            parse_host_port("[2001:db8::1]:9050", 443).unwrap(),
            ("2001:db8::1".to_string(), 9050)
        );
        assert_eq!(
            parse_host_port("[::1]", 443).unwrap(),
            ("::1".to_string(), 443)
        );
        let rel_req = parse_client_request(
            b"GET /v1/ping HTTP/1.1\r\nHost: internal.example.org:3000\r\n\r\n",
            Vec::new(),
        )
        .unwrap();
        assert!(!rel_req.is_connect);
        assert_eq!(rel_req.target_host, "internal.example.org");
        assert_eq!(rel_req.target_port, 3000);
        assert_eq!(rel_req.first_line_rewritten, "GET /v1/ping HTTP/1.1");
    }

    #[tokio::test]
    async fn socks5_username_does_not_continue_when_server_picks_no_auth() {
        let mock = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = mock.local_addr().unwrap().port();
        let (tx, mut rx) = mpsc::unbounded_channel::<Vec<u8>>();
        tokio::spawn(async move {
            let Ok((mut sock, _)) = mock.accept().await else {
                return;
            };
            let mut head = [0u8; 2];
            if sock.read_exact(&mut head).await.is_err() {
                return;
            }
            let mut methods = vec![0u8; head[1] as usize];
            if sock.read_exact(&mut methods).await.is_err() {
                return;
            }
            let _ = tx.send(methods);
            sock.write_all(&[0x05, 0x00]).await.unwrap();
            let mut next = [0u8; 8];
            let n = timeout(Duration::from_millis(400), sock.read(&mut next))
                .await
                .ok()
                .and_then(|r| r.ok())
                .unwrap_or(0);
            let _ = tx.send(next[..n].to_vec());
        });

        let mut tunnel = LocalProxyTunnel::start(ProxyConfig {
            protocol: ProxyProtocol::Socks5,
            host: "127.0.0.1".to_string(),
            port,
            username: Some("bonuser".to_string()),
            password: Some("bonpass".to_string()),
            change_ip_url: None,
        })
        .await
        .unwrap();
        let mut client = TcpStream::connect(("127.0.0.1", tunnel.local_port()))
            .await
            .unwrap();
        client
            .write_all(b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n")
            .await
            .unwrap();
        let methods = rx.recv().await.unwrap();
        let followed = rx.recv().await.unwrap();
        assert_eq!(methods, vec![0x02], "username must offer only RFC 1929 auth");
        assert!(
            followed.is_empty(),
            "server chose no-auth, tunnel must not send CONNECT, got {followed:02x?}"
        );
        tunnel.stop();
    }

    #[tokio::test]
    async fn socks5_plain_http_forces_connection_close() {
        let mock = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = mock.local_addr().unwrap().port();
        let (tx, mut rx) = mpsc::unbounded_channel::<String>();
        tokio::spawn(async move {
            let Ok((mut sock, _)) = mock.accept().await else {
                return;
            };
            let mut greet = [0u8; 3];
            sock.read_exact(&mut greet).await.unwrap();
            sock.write_all(&[0x05, 0x00]).await.unwrap();
            let mut req_head = [0u8; 4];
            sock.read_exact(&mut req_head).await.unwrap();
            assert_eq!(req_head[3], 0x03);
            let mut dlen = [0u8; 1];
            sock.read_exact(&mut dlen).await.unwrap();
            let mut rest = vec![0u8; dlen[0] as usize + 2];
            sock.read_exact(&mut rest).await.unwrap();
            sock.write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                .await
                .unwrap();
            let (hdr, _) = read_until_double_crlf(&mut sock).await.unwrap();
            let _ = tx.send(String::from_utf8_lossy(&hdr).into_owned());
            let _ = sock
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
                .await;
        });

        let mut tunnel = LocalProxyTunnel::start(ProxyConfig {
            protocol: ProxyProtocol::Socks5,
            host: "127.0.0.1".to_string(),
            port,
            username: None,
            password: None,
            change_ip_url: None,
        })
        .await
        .unwrap();
        let mut client = TcpStream::connect(("127.0.0.1", tunnel.local_port()))
            .await
            .unwrap();
        client
            .write_all(
                b"GET http://example.com/a.js HTTP/1.1\r\nHost: example.com\r\nConnection: keep-alive\r\nProxy-Connection: keep-alive\r\n\r\n",
            )
            .await
            .unwrap();
        let mut resp = Vec::new();
        client.read_to_end(&mut resp).await.unwrap();
        let forwarded = rx.recv().await.unwrap();
        assert!(
            forwarded.starts_with("GET /a.js HTTP/1.1\r\n"),
            "got {forwarded}"
        );
        assert!(
            forwarded.to_ascii_lowercase().contains("connection: close"),
            "plain HTTP over SOCKS must close so the next request is rewritten, got {forwarded}"
        );
        assert!(!forwarded.to_ascii_lowercase().contains("keep-alive"));
        tunnel.stop();
    }

    #[tokio::test]
    async fn ipv6_literal_keeps_brackets_on_http_connect_and_socks_atyp_4() {
        let http_mock = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let http_port = http_mock.local_addr().unwrap().port();
        let (http_tx, mut http_rx) = mpsc::unbounded_channel::<String>();
        tokio::spawn(async move {
            let Ok((mut sock, _)) = http_mock.accept().await else {
                return;
            };
            let Ok((hdr, _)) = read_until_double_crlf(&mut sock).await else {
                return;
            };
            let _ = http_tx.send(String::from_utf8_lossy(&hdr).into_owned());
            let _ = sock
                .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                .await;
        });

        let mut http_tunnel = LocalProxyTunnel::start(ProxyConfig {
            protocol: ProxyProtocol::Http,
            host: "127.0.0.1".to_string(),
            port: http_port,
            username: None,
            password: None,
            change_ip_url: None,
        })
        .await
        .unwrap();
        let mut c = TcpStream::connect(("127.0.0.1", http_tunnel.local_port()))
            .await
            .unwrap();
        c.write_all(b"CONNECT [2001:db8::1]:443 HTTP/1.1\r\nHost: [2001:db8::1]:443\r\n\r\n")
            .await
            .unwrap();
        let _ = read_until_double_crlf(&mut c).await;
        let upstream = http_rx.recv().await.unwrap();
        assert!(
            upstream.starts_with("CONNECT [2001:db8::1]:443 HTTP/1.1\r\n"),
            "got {upstream}"
        );
        assert!(
            upstream.contains("Host: [2001:db8::1]:443\r\n"),
            "got {upstream}"
        );
        http_tunnel.stop();

        let socks_mock = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let socks_port = socks_mock.local_addr().unwrap().port();
        let (atyp_tx, mut atyp_rx) = mpsc::unbounded_channel::<(u8, Vec<u8>, u16)>();
        tokio::spawn(async move {
            let Ok((mut sock, _)) = socks_mock.accept().await else {
                return;
            };
            let mut greet = [0u8; 3];
            sock.read_exact(&mut greet).await.unwrap();
            sock.write_all(&[0x05, 0x00]).await.unwrap();
            let mut head = [0u8; 4];
            sock.read_exact(&mut head).await.unwrap();
            let atyp = head[3];
            let (addr, port) = match atyp {
                0x01 => {
                    let mut rest = [0u8; 6];
                    sock.read_exact(&mut rest).await.unwrap();
                    (rest[..4].to_vec(), u16::from_be_bytes([rest[4], rest[5]]))
                }
                0x04 => {
                    let mut rest = [0u8; 18];
                    sock.read_exact(&mut rest).await.unwrap();
                    (rest[..16].to_vec(), u16::from_be_bytes([rest[16], rest[17]]))
                }
                0x03 => {
                    let mut dlen = [0u8; 1];
                    sock.read_exact(&mut dlen).await.unwrap();
                    let mut rest = vec![0u8; dlen[0] as usize + 2];
                    sock.read_exact(&mut rest).await.unwrap();
                    let port = u16::from_be_bytes([
                        rest[rest.len() - 2],
                        rest[rest.len() - 1],
                    ]);
                    rest.truncate(rest.len() - 2);
                    (rest, port)
                }
                _ => (Vec::new(), 0),
            };
            let _ = atyp_tx.send((atyp, addr, port));
            let _ = sock
                .write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                .await;
        });

        let mut socks_tunnel = LocalProxyTunnel::start(ProxyConfig {
            protocol: ProxyProtocol::Socks5,
            host: "127.0.0.1".to_string(),
            port: socks_port,
            username: None,
            password: None,
            change_ip_url: None,
        })
        .await
        .unwrap();
        let mut s = TcpStream::connect(("127.0.0.1", socks_tunnel.local_port()))
            .await
            .unwrap();
        s.write_all(b"CONNECT [2001:db8::1]:443 HTTP/1.1\r\nHost: [2001:db8::1]:443\r\n\r\n")
            .await
            .unwrap();
        let _ = timeout(Duration::from_secs(2), read_until_double_crlf(&mut s)).await;
        let (atyp, addr, port) = atyp_rx.recv().await.unwrap();
        assert_eq!(atyp, 0x04);
        assert_eq!(port, 443);
        assert_eq!(addr, std::net::Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1).octets());
        socks_tunnel.stop();
    }
}
