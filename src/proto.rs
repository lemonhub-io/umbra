//! Umbra wire protocol.
//!
//! All Umbra traffic lives inside a genuine TLS 1.3 session. The first thing a
//! client sends after the handshake is a fixed-size authentication header:
//!
//! ```text
//!  +---------+------------+-----------+---------------+
//!  | ver (1) | nonce (32) | ts (8 BE) | auth tag (32) |
//!  +---------+------------+-----------+---------------+
//! ```
//!
//! `auth_tag = HMAC-SHA256(user_key, "umbra/1/auth" || exporter || nonce || ts)`
//!
//! where `exporter` is the 32-byte RFC 5705 TLS exporter of *this* session.
//! Because the exporter is unique per handshake, a captured header can never be
//! replayed on a new connection — active probes always fail and get spliced to
//! the cover site instead.
//!
//! A verified header is followed by a command byte and a target address:
//!
//! ```text
//!  +---------+---------------------+
//!  | cmd (1) | atyp/addr/port (...) |
//!  +---------+---------------------+
//! ```
//!
//! cmd 0x01 = TCP CONNECT, 0x02 = UDP ASSOCIATE (framed datagrams follow).
//! The server replies with a single status byte (0x00 ok, 0x01 unreachable),
//! then the stream becomes a transparent pipe (TCP) or a sequence of framed
//! datagrams `[atyp][addr][port][u16 len][payload]` (UDP).

use anyhow::{anyhow, bail, Context, Result};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::collections::HashMap;
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use subtle::ConstantTimeEq;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::time::timeout;

pub const VERSION: u8 = 0x01;
pub const NONCE_LEN: usize = 32;
pub const TAG_LEN: usize = 32;
pub const TS_LEN: usize = 8;
/// ver || nonce || ts || tag
pub const AUTH_HEADER_LEN: usize = 1 + NONCE_LEN + TS_LEN + TAG_LEN;

pub const EXPORTER_LABEL: &str = "umbra/1/exporter";
pub const EXPORTER_LEN: usize = 32;

const KEY_DERIVE_CTX: &[u8] = b"umbra/1/key";
const AUTH_CTX: &[u8] = b"umbra/1/auth";

/// Accepted clock skew for the auth timestamp (both directions).
pub const REPLAY_WINDOW: Duration = Duration::from_secs(120);
/// How long a used nonce stays banned.
const NONCE_TTL: Duration = Duration::from_secs(600);

pub const CMD_CONNECT: u8 = 0x01;
pub const CMD_UDP_ASSOCIATE: u8 = 0x02;

pub const STATUS_OK: u8 = 0x00;
pub const STATUS_UNREACHABLE: u8 = 0x01;

const ATYP_V4: u8 = 0x01;
const ATYP_DOMAIN: u8 = 0x03;
const ATYP_V6: u8 = 0x04;

/// Maximum UDP payload we will relay.
pub const MAX_UDP_PAYLOAD: usize = 65535;

/// Derive the per-user symmetric key from a passphrase.
pub fn derive_key(password: &str) -> [u8; 32] {
    let mut h = Sha256::new();
    use sha2::Digest;
    h.update(KEY_DERIVE_CTX);
    h.update(password.as_bytes());
    h.finalize().into()
}

/// Compute the auth tag for a header.
pub fn auth_tag(key: &[u8; 32], exporter: &[u8], nonce: &[u8; NONCE_LEN], ts: u64) -> [u8; TAG_LEN] {
    let mut m = <Hmac<Sha256> as Mac>::new_from_slice(key).expect("HMAC accepts any key length");
    m.update(AUTH_CTX);
    m.update(exporter);
    m.update(nonce);
    m.update(&ts.to_be_bytes());
    m.finalize().into_bytes().into()
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// A SOCKS-style address (domain or IP literal) + port.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum Address {
    V4([u8; 4], u16),
    Domain(String, u16),
    V6([u8; 16], u16),
}

impl Address {
    /// Length of the encoded form (atyp byte + addr + port).
    pub fn encoded_len(&self) -> usize {
        match self {
            Address::V4(..) => 1 + 4 + 2,
            Address::Domain(d, _) => 1 + 1 + d.len() + 2,
            Address::V6(..) => 1 + 16 + 2,
        }
    }

    pub fn encode(&self, out: &mut Vec<u8>) {
        match self {
            Address::V4(ip, port) => {
                out.push(ATYP_V4);
                out.extend_from_slice(ip);
                out.extend_from_slice(&port.to_be_bytes());
            }
            Address::Domain(d, port) => {
                assert!(d.len() <= 255, "domain too long to encode");
                out.push(ATYP_DOMAIN);
                out.push(d.len() as u8);
                out.extend_from_slice(d.as_bytes());
                out.extend_from_slice(&port.to_be_bytes());
            }
            Address::V6(ip, port) => {
                out.push(ATYP_V6);
                out.extend_from_slice(ip);
                out.extend_from_slice(&port.to_be_bytes());
            }
        }
    }

    /// Decode an address from `r` — consumes exactly its encoded length.
    pub async fn decode<R: AsyncRead + Unpin>(r: &mut R) -> Result<Address> {
        let atyp = r.read_u8().await?;
        match atyp {
            ATYP_V4 => {
                let mut ip = [0u8; 4];
                r.read_exact(&mut ip).await?;
                let port = r.read_u16().await?;
                Ok(Address::V4(ip, port))
            }
            ATYP_V6 => {
                let mut ip = [0u8; 16];
                r.read_exact(&mut ip).await?;
                let port = r.read_u16().await?;
                Ok(Address::V6(ip, port))
            }
            ATYP_DOMAIN => {
                let len = r.read_u8().await? as usize;
                let mut buf = vec![0u8; len];
                r.read_exact(&mut buf).await?;
                let d = String::from_utf8(buf).context("domain is not utf-8")?;
                let port = r.read_u16().await?;
                Ok(Address::Domain(d, port))
            }
            _ => bail!("unknown atyp {atyp:#x}"),
        }
    }

    /// Decode an address from an in-memory buffer, advancing the cursor.
    pub fn decode_slice(cur: &mut &[u8]) -> Result<Address> {
        fn take<'a>(cur: &mut &'a [u8], n: usize) -> Result<&'a [u8]> {
            if cur.len() < n {
                bail!("short buffer");
            }
            let (h, t) = cur.split_at(n);
            *cur = t;
            Ok(h)
        }
        let atyp = take(cur, 1)?[0];
        match atyp {
            ATYP_V4 => {
                let ip: [u8; 4] = take(cur, 4)?.try_into().unwrap();
                let port = u16::from_be_bytes(take(cur, 2)?.try_into().unwrap());
                Ok(Address::V4(ip, port))
            }
            ATYP_V6 => {
                let ip: [u8; 16] = take(cur, 16)?.try_into().unwrap();
                let port = u16::from_be_bytes(take(cur, 2)?.try_into().unwrap());
                Ok(Address::V6(ip, port))
            }
            ATYP_DOMAIN => {
                let len = take(cur, 1)?[0] as usize;
                let d = String::from_utf8(take(cur, len)?.to_vec()).context("domain utf-8")?;
                let port = u16::from_be_bytes(take(cur, 2)?.try_into().unwrap());
                Ok(Address::Domain(d, port))
            }
            _ => bail!("unknown atyp {atyp:#x}"),
        }
    }

    /// Resolve to all candidate SocketAddrs (DNS for domains).
    pub async fn resolve_all(&self) -> Result<Vec<SocketAddr>> {
        match self {
            Address::V4(ip, p) => Ok(vec![SocketAddr::new(IpAddr::V4((*ip).into()), *p)]),
            Address::V6(ip, p) => Ok(vec![SocketAddr::new(IpAddr::V6((*ip).into()), *p)]),
            Address::Domain(d, p) => {
                let addrs: Vec<SocketAddr> = tokio::net::lookup_host((d.as_str(), *p))
                    .await?
                    .collect();
                anyhow::ensure!(!addrs.is_empty(), "dns: no addresses for {d}");
                Ok(addrs)
            }
        }
    }

    /// First resolved address.
    pub async fn resolve(&self) -> Result<SocketAddr> {
        self.resolve_all()
            .await?
            .into_iter()
            .next()
            .ok_or_else(|| anyhow!("dns: no addresses"))
    }
}

impl fmt::Display for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Address::V4(ip, p) => write!(f, "{}:{}", Ipv4Addr::from(*ip), p),
            Address::V6(ip, p) => write!(f, "[{}]:{}", Ipv6Addr::from(*ip), p),
            Address::Domain(d, p) => write!(f, "{d}:{p}"),
        }
    }
}

/// Server-side replay cache. A nonce is accepted once; timestamps must be
/// within ±REPLAY_WINDOW of the server clock.
pub struct ReplayCache {
    /// nonce -> expiry Instant
    seen: HashMap<[u8; NONCE_LEN], Instant>,
}

impl ReplayCache {
    pub fn new() -> Self {
        ReplayCache {
            seen: HashMap::new(),
        }
    }

    /// Returns Ok(()) if (nonce, ts) is fresh, Err(reason) otherwise.
    pub fn check(&mut self, nonce: &[u8; NONCE_LEN], ts: u64) -> Result<()> {
        let now = now_secs();
        let skew = ts.abs_diff(now);
        if skew > REPLAY_WINDOW.as_secs() {
            bail!("timestamp outside replay window (skew {skew}s)");
        }
        let cutoff = Instant::now();
        // Opportunistic prune so the map stays bounded.
        if self.seen.len() > 4096 {
            self.seen.retain(|_, exp| *exp > cutoff);
        }
        if self.seen.contains_key(nonce) {
            bail!("nonce already seen");
        }
        self.seen.insert(*nonce, cutoff + NONCE_TTL);
        Ok(())
    }
}

/// Build the client auth header.
pub fn build_auth_header(key: &[u8; 32], exporter: &[u8], nonce: &[u8; NONCE_LEN]) -> Vec<u8> {
    let ts = now_secs();
    let tag = auth_tag(key, exporter, nonce, ts);
    let mut out = Vec::with_capacity(AUTH_HEADER_LEN);
    out.push(VERSION);
    out.extend_from_slice(nonce);
    out.extend_from_slice(&ts.to_be_bytes());
    out.extend_from_slice(&tag);
    out
}

/// Build a full client request: auth header + cmd + addr.
pub fn build_request(
    key: &[u8; 32],
    exporter: &[u8],
    nonce: &[u8; NONCE_LEN],
    cmd: u8,
    addr: &Address,
) -> Vec<u8> {
    let mut out = build_auth_header(key, exporter, nonce);
    out.push(cmd);
    addr.encode(&mut out);
    out
}

/// What the server decided about the fixed header it read.
pub enum HeaderVerdict {
    /// Valid Umbra client; carries the index into the server's key list.
    Valid(usize),
    /// Not Umbra — splice `buf[..len]` (what we already read) to the cover site.
    Fallback,
}

/// Deadline applied to every read while filling the auth header. A real
/// client sends the whole header in one flight right after the handshake; a
/// probe that stalls (or sends less than AUTH_HEADER_LEN) is spliced to the
/// cover site once this expires, with its bytes replayed verbatim.
pub const HEADER_READ_TIMEOUT: Duration = Duration::from_secs(10);

/// Read and validate the fixed-size auth header from a TLS stream.
/// Returns (verdict, buffered_bytes). On Fallback the buffered bytes MUST be
/// replayed to the cover origin so the probe gets a real response.
pub async fn read_auth_header<R: AsyncRead + Unpin>(
    r: &mut R,
    keys: &[[u8; 32]],
    exporter: &[u8],
    replay: &mut ReplayCache,
) -> Result<(HeaderVerdict, Vec<u8>)> {
    let mut buf = vec![0u8; AUTH_HEADER_LEN];
    let mut filled = 0usize;
    while filled < AUTH_HEADER_LEN {
        match timeout(HEADER_READ_TIMEOUT, r.read(&mut buf[filled..])).await {
            Ok(Ok(n)) if n > 0 => filled += n,
            // EOF (n=0), IO error, or stall -> splice whatever we consumed.
            _ => return Ok((HeaderVerdict::Fallback, buf[..filled].to_vec())),
        }
    }
    if buf[0] != VERSION {
        return Ok((HeaderVerdict::Fallback, buf));
    }
    let mut nonce = [0u8; NONCE_LEN];
    nonce.copy_from_slice(&buf[1..1 + NONCE_LEN]);
    let mut tsb = [0u8; TS_LEN];
    tsb.copy_from_slice(&buf[1 + NONCE_LEN..1 + NONCE_LEN + TS_LEN]);
    let ts = u64::from_be_bytes(tsb);
    let tag = &buf[1 + NONCE_LEN + TS_LEN..AUTH_HEADER_LEN];

    let mut matched = None;
    for (i, key) in keys.iter().enumerate() {
        let expect = auth_tag(key, exporter, &nonce, ts);
        if expect.ct_eq(tag).into() {
            matched = Some(i);
            break;
        }
    }
    let user = match matched {
        Some(i) => i,
        None => return Ok((HeaderVerdict::Fallback, buf)),
    };
    if let Err(e) = replay.check(&nonce, ts) {
        tracing::debug!("replay rejected: {e}");
        return Ok((HeaderVerdict::Fallback, buf));
    }
    Ok((HeaderVerdict::Valid(user), buf))
}

/// Read cmd + address after a valid auth header.
pub async fn read_request_body<R: AsyncRead + Unpin>(r: &mut R) -> Result<(u8, Address)> {
    let cmd = r.read_u8().await?;
    if cmd != CMD_CONNECT && cmd != CMD_UDP_ASSOCIATE {
        bail!("unknown cmd {cmd:#x}");
    }
    let addr = Address::decode(r).await?;
    Ok((cmd, addr))
}

/// One framed UDP datagram on the wire: [atyp][addr][port][u16 len][payload].
pub struct UdpPacket {
    pub addr: Address,
    pub payload: Vec<u8>,
}

pub async fn write_udp_packet<W: AsyncWrite + Unpin>(w: &mut W, pkt: &UdpPacket) -> Result<()> {
    let mut hdr = Vec::with_capacity(pkt.addr.encoded_len() + 2);
    pkt.addr.encode(&mut hdr);
    if pkt.payload.len() > MAX_UDP_PAYLOAD {
        bail!("udp payload too large");
    }
    hdr.extend_from_slice(&(pkt.payload.len() as u16).to_be_bytes());
    w.write_all(&hdr).await?;
    w.write_all(&pkt.payload).await?;
    w.flush().await?;
    Ok(())
}

pub async fn read_udp_packet<R: AsyncRead + Unpin>(r: &mut R) -> Result<UdpPacket> {
    let addr = Address::decode(r).await?;
    let len = r.read_u16().await? as usize;
    let mut payload = vec![0u8; len];
    r.read_exact(&mut payload).await?;
    Ok(UdpPacket { addr, payload })
}
