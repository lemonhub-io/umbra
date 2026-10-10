//! HTTP inbound: CONNECT tunnels and absolute-URI forward proxying.

use anyhow::{bail, Context, Result};
use std::net::IpAddr;
use std::time::Duration;
use tokio::io::{copy_bidirectional, AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

use crate::client::Connector;
use crate::proto::Address;

const HEADER_LIMIT: usize = 16 * 1024;
const HEADER_TIMEOUT: Duration = Duration::from_secs(15);

pub async fn handle(stream: &mut TcpStream, connector: Connector) -> Result<()> {
    let raw = read_head(stream).await?;
    let head_end = find_head_end(&raw).ok_or_else(|| anyhow::anyhow!("unterminated head"))?;
    let head = std::str::from_utf8(&raw[..head_end]).context("head not utf-8")?;
    let mut lines = head.split("\r\n");
    let request_line = lines.next().unwrap_or("");
    let mut parts = request_line.split_whitespace();
    let (method, target) = (
        parts.next().unwrap_or(""),
        parts.next().unwrap_or(""),
    );
    let version = parts.next().unwrap_or("HTTP/1.1");

    if method.eq_ignore_ascii_case("CONNECT") {
        let addr = parse_authority(target, Some(443))?;
        return tunnel(stream, connector, addr, &raw[head_end..]).await;
    }

    // Forward-proxy form: absolute URI, e.g. "GET http://host/path HTTP/1.1".
    let target_s = target.strip_prefix("http://").unwrap_or(target);
    let (authority, path) = match target_s.find('/') {
        Some(i) => (&target_s[..i], &target_s[i..]),
        None => (target_s, "/"),
    };
    let addr = parse_authority(authority, Some(80))?;
    let mut upstream = match connector.connect_tcp(&addr).await {
        Ok(s) => s,
        Err(_) => {
            stream
                .write_all(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
                .await?;
            bail!("uplink connect failed");
        }
    };
    // Rewrite the request line to origin form and strip proxy-specific headers.
    let mut out = format!("{method} {path} {version}\r\n").into_bytes();
    for line in lines {
        if line.is_empty() {
            continue;
        }
        if line
            .get(..6)
            .map(|p| p.eq_ignore_ascii_case("proxy-"))
            .unwrap_or(false)
        {
            continue;
        }
        out.extend_from_slice(line.as_bytes());
        out.extend_from_slice(b"\r\n");
    }
    out.extend_from_slice(b"\r\n");
    upstream.write_all(&out).await?;
    upstream.write_all(&raw[head_end..]).await?; // any pipelined body bytes
    let _ = copy_bidirectional(stream, &mut upstream).await;
    Ok(())
}

/// Read until \r\n\r\n or HEADER_LIMIT.
async fn read_head(stream: &mut TcpStream) -> Result<Vec<u8>> {
    let mut buf = Vec::with_capacity(1024);
    let mut chunk = [0u8; 4096];
    loop {
        let n = match timeout(HEADER_TIMEOUT, stream.read(&mut chunk)).await {
            Ok(Ok(n)) => n,
            _ => bail!("head read failed/timed out"),
        };
        if n == 0 {
            bail!("eof in head");
        }
        buf.extend_from_slice(&chunk[..n]);
        if find_head_end(&buf).is_some() || buf.len() > HEADER_LIMIT {
            return Ok(buf);
        }
    }
}

/// Byte index just past the \r\n\r\n terminator.
fn find_head_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n").map(|i| i + 4)
}

/// Parse "host[:port]" (IPv6 bracketed ok) into an Address.
fn parse_authority(s: &str, default_port: Option<u16>) -> Result<Address> {
    let s = s.trim();
    let (host, port) = if let Some(rest) = s.strip_prefix('[') {
        let end = rest.find(']').context("bad ipv6 authority")?;
        let host = &rest[..end];
        let tail = &rest[end + 1..];
        let port = tail
            .strip_prefix(':')
            .map(|p| p.parse::<u16>())
            .transpose()
            .context("bad port")?
            .or(default_port);
        (host, port)
    } else {
        match s.rsplit_once(':') {
            Some((h, p)) => (h, Some(p.parse::<u16>().context("bad port")?)),
            None => (s, default_port),
        }
    };
    let port = port.context("missing port")?;
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Ok(match ip {
            IpAddr::V4(a) => Address::V4(a.octets(), port),
            IpAddr::V6(a) => Address::V6(a.octets(), port),
        });
    }
    anyhow::ensure!(!host.is_empty() && host.len() <= 255, "bad host");
    Ok(Address::Domain(host.to_string(), port))
}

async fn tunnel(
    stream: &mut TcpStream,
    connector: Connector,
    addr: Address,
    leftover: &[u8],
) -> Result<()> {
    match connector.connect_tcp(&addr).await {
        Ok(mut remote) => {
            stream
                .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                .await?;
            if !leftover.is_empty() {
                remote.write_all(leftover).await?;
            }
            let _ = copy_bidirectional(stream, &mut remote).await;
            Ok(())
        }
        Err(e) => {
            stream
                .write_all(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
                .await?;
            Err(e.context("uplink connect"))
        }
    }
}
