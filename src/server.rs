//! Umbra server: TLS front (or plain behind a terminator), auth verdict,
//! cover-site splice, proxy dispatch.

use anyhow::{bail, Context, Result};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{copy_bidirectional, split, AsyncRead, AsyncWrite, AsyncWriteExt, WriteHalf};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::{Mutex, Notify};
use tokio::time::timeout;
use tokio_rustls::TlsAcceptor;

use crate::config::ServerConfig;
use crate::proto::{self, Address, HeaderVerdict, ReplayCache, UdpPacket};
use crate::tls;

const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(15);
const FALLBACK_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(15);
/// Every UDP endpoint session is reaped after this much silence.
const DEFAULT_UDP_TIMEOUT: Duration = Duration::from_secs(300);

struct Shared {
    keys: Vec<[u8; 32]>,
    user_names: Vec<String>,
    fallback: String,
    replay: Mutex<ReplayCache>,
    udp_timeout: Duration,
}

pub async fn run(cfg: ServerConfig) -> Result<()> {
    let transport = cfg.transport.as_deref().unwrap_or("tls");
    let shared = Arc::new(Shared {
        keys: cfg
            .users
            .iter()
            .map(|u| proto::derive_key(&u.password))
            .collect(),
        user_names: cfg.users.iter().map(|u| u.name.clone()).collect(),
        fallback: cfg.fallback.clone(),
        replay: Mutex::new(ReplayCache::new()),
        udp_timeout: cfg
            .udp_timeout_secs
            .map(Duration::from_secs)
            .unwrap_or(DEFAULT_UDP_TIMEOUT),
    });

    let listener = TcpListener::bind(&cfg.listen)
        .await
        .with_context(|| format!("bind {}", cfg.listen))?;
    tracing::info!("umbra server listening on {} ({transport})", cfg.listen);
    tracing::info!("cover origin: {}", shared.fallback);

    match transport {
        // Plain mode: a real TLS terminator (nginx `stream { proxy_pass }`,
        // stunnel, haproxy) sits in front and provides the public fingerprint.
        // Auth binds to an all-zero exporter; the session binding is provided
        // by the terminator's TLS session instead.
        "plain" => loop {
            let (stream, peer) = match listener.accept().await {
                Ok(v) => v,
                Err(e) => {
                    tracing::warn!("accept: {e}");
                    continue;
                }
            };
            let shared = shared.clone();
            tokio::spawn(async move {
                if let Err(e) = handle_stream(stream, shared, [0u8; proto::EXPORTER_LEN]).await {
                    tracing::debug!("{peer}: {e:#}");
                }
            });
        },
        _ => {
            let acceptor = TlsAcceptor::from(tls::server_config(
                Path::new(cfg.cert.as_deref().context("cert required")?),
                Path::new(cfg.key.as_deref().context("key required")?),
            )?);
            loop {
                let (stream, peer) = match listener.accept().await {
                    Ok(v) => v,
                    Err(e) => {
                        tracing::warn!("accept: {e}");
                        continue;
                    }
                };
                let acceptor = acceptor.clone();
                let shared = shared.clone();
                tokio::spawn(async move {
                    if let Err(e) = handle_tls(stream, acceptor, shared).await {
                        tracing::debug!("{peer}: {e:#}");
                    }
                });
            }
        }
    }
}

async fn handle_tls(stream: TcpStream, acceptor: TlsAcceptor, shared: Arc<Shared>) -> Result<()> {
    let _ = stream.set_nodelay(true);
    let tls = match timeout(HANDSHAKE_TIMEOUT, acceptor.accept(stream)).await {
        Ok(Ok(s)) => s,
        Ok(Err(e)) => return Err(e).context("tls handshake"),
        Err(_) => bail!("tls handshake timed out"),
    };
    let exporter = tls::exporter(tls.get_ref().1)?;
    handle_stream(tls, shared, exporter).await
}

/// The core verdict/dispatch — generic over the transport stream `S`.
async fn handle_stream<S>(mut io: S, shared: Arc<Shared>, exporter: [u8; 32]) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (verdict, consumed) = {
        let mut replay = shared.replay.lock().await;
        let v = proto::read_auth_header(&mut io, &shared.keys, &exporter, &mut replay).await?;
        v
    };

    match verdict {
        HeaderVerdict::Fallback => splice_fallback(io, &shared.fallback, consumed).await,
        HeaderVerdict::Valid(user) => {
            let (cmd, addr) = match proto::read_request_body(&mut io).await {
                Ok(v) => v,
                Err(_) => {
                    // Authed but malformed — splice anyway, never reveal.
                    return splice_fallback(io, &shared.fallback, Vec::new()).await;
                }
            };
            let uname = shared.user_names.get(user).map(String::as_str).unwrap_or("?");
            tracing::info!("user={uname} cmd={cmd:#x} target={addr}");
            match cmd {
                proto::CMD_CONNECT => serve_connect(io, addr).await,
                proto::CMD_UDP_ASSOCIATE => serve_udp(io, shared.udp_timeout).await,
                _ => unreachable!(),
            }
        }
    }
}

/// Forward an unauthenticated (or malformed) connection to the cover origin.
/// `consumed` bytes already pulled from the stream are replayed first so the
/// origin sees the probe's request byte-for-byte.
async fn splice_fallback<S>(mut io: S, fallback: &str, consumed: Vec<u8>) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    let mut cover = match timeout(FALLBACK_CONNECT_TIMEOUT, TcpStream::connect(fallback)).await {
        Ok(Ok(s)) => s,
        _ => bail!("cover origin unreachable"),
    };
    if !consumed.is_empty() {
        cover.write_all(&consumed).await?;
    }
    let _ = copy_bidirectional(&mut io, &mut cover).await;
    Ok(())
}

async fn serve_connect<S>(mut io: S, addr: Address) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    let candidates = addr.resolve_all().await.unwrap_or_default();
    let mut target = None;
    for sa in candidates {
        if let Ok(Ok(s)) = timeout(CONNECT_TIMEOUT, TcpStream::connect(sa)).await {
            target = Some(s);
            break;
        }
    }
    let mut target = match target {
        Some(t) => t,
        None => {
            io.write_all(&[proto::STATUS_UNREACHABLE]).await?;
            return Ok(());
        }
    };
    let _ = target.set_nodelay(true);
    io.write_all(&[proto::STATUS_OK]).await?;
    io.flush().await?;
    let _ = copy_bidirectional(&mut io, &mut target).await;
    Ok(())
}

/// UDP associate: framed datagrams on the stream, real UDP sockets out.
/// Each distinct destination gets its own connected socket (full-cone NAT);
/// replies are framed back with their source address.
async fn serve_udp<S>(mut io: S, idle_timeout: Duration) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    io.write_all(&[proto::STATUS_OK]).await?;
    io.flush().await?;
    let (mut rd, wr) = split(io);
    let wr = Arc::new(Mutex::new(wr));
    let shutdown = Arc::new(Notify::new());

    struct Session {
        sock: Arc<UdpSocket>,
        last: Instant,
    }
    let mut sessions: HashMap<Address, Session> = HashMap::new();
    let mut gc = tokio::time::interval(Duration::from_secs(30));

    loop {
        tokio::select! {
            pkt = proto::read_udp_packet(&mut rd) => {
                let pkt = match pkt {
                    Ok(p) => p,
                    Err(_) => break, // client hung up
                };
                let entry = match sessions.get_mut(&pkt.addr) {
                    Some(e) => e,
                    None => {
                        let resolved = match pkt.addr.resolve().await {
                            Ok(a) => a,
                            Err(_) => continue,
                        };
                        let bind: SocketAddr = if resolved.is_ipv6() {
                            "[::]:0".parse().unwrap()
                        } else {
                            "0.0.0.0:0".parse().unwrap()
                        };
                        let sock = match UdpSocket::bind(bind).await {
                            Ok(s) => s,
                            Err(_) => continue,
                        };
                        if sock.connect(resolved).await.is_err() {
                            continue;
                        }
                        let sock = Arc::new(sock);
                        spawn_udp_reader(sock.clone(), wr.clone(), shutdown.clone());
                        sessions.insert(
                            pkt.addr.clone(),
                            Session { sock: sock.clone(), last: Instant::now() },
                        );
                        sessions.get_mut(&pkt.addr).unwrap()
                    }
                };
                entry.last = Instant::now();
                let _ = entry.sock.send(&pkt.payload).await;
            }
            _ = gc.tick() => {
                sessions.retain(|_, s| s.last.elapsed() < idle_timeout);
            }
        }
    }
    // Association over: stop reply readers so sockets and the writer die here.
    shutdown.notify_waiters();
    Ok(())
}

/// Relay UDP replies from one remote endpoint back into the stream.
fn spawn_udp_reader<S>(
    sock: Arc<UdpSocket>,
    wr: Arc<Mutex<WriteHalf<S>>>,
    shutdown: Arc<Notify>,
) where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    tokio::spawn(async move {
        let mut buf = vec![0u8; proto::MAX_UDP_PAYLOAD + 8];
        loop {
            tokio::select! {
                res = sock.recv(&mut buf) => {
                    let n = match res { Ok(0) => continue, Ok(n) => n, Err(_) => break };
                    let addr = match sock.peer_addr() {
                        Ok(SocketAddr::V4(a)) => Address::V4(a.ip().octets(), a.port()),
                        Ok(SocketAddr::V6(a)) => Address::V6(a.ip().octets(), a.port()),
                        Err(_) => break,
                    };
                    let pkt = UdpPacket {
                        addr,
                        payload: buf[..n].to_vec(),
                    };
                    let mut guard = wr.lock().await;
                    if proto::write_udp_packet(&mut *guard, &pkt).await.is_err() {
                        break;
                    }
                }
                _ = shutdown.notified() => break,
            }
        }
    });
}
