//! SOCKS5 inbound (RFC 1928): CONNECT and UDP ASSOCIATE, no-auth.

use anyhow::{bail, Result};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use tokio::io::{copy_bidirectional, split, AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::{watch, Mutex, Notify};
use tokio::time::{sleep_until, Instant};

use crate::client::Connector;
use crate::proto::{self, Address};

const CMD_CONNECT: u8 = 0x01;
const CMD_UDP_ASSOCIATE: u8 = 0x03;

const REP_OK: u8 = 0x00;
const REP_HOST_UNREACHABLE: u8 = 0x04;
const REP_CMD_NOT_SUPPORTED: u8 = 0x07;

pub async fn handle(stream: &mut TcpStream, connector: Connector) -> Result<()> {
    // ---- greeting ----
    let ver = stream.read_u8().await?;
    let nmethods = stream.read_u8().await? as usize;
    let mut methods = vec![0u8; nmethods];
    stream.read_exact(&mut methods).await?;
    if ver != 0x05 {
        bail!("socks: bad version {ver:#x}");
    }
    if !methods.contains(&0x00) {
        stream.write_all(&[0x05, 0xff]).await?;
        bail!("socks: client offered no no-auth method");
    }
    stream.write_all(&[0x05, 0x00]).await?;

    // ---- request ----
    let ver = stream.read_u8().await?;
    let cmd = stream.read_u8().await?;
    let _rsv = stream.read_u8().await?;
    let addr = Address::decode(stream).await?;
    if ver != 0x05 {
        bail!("socks: bad request version");
    }

    match cmd {
        CMD_CONNECT => connect(stream, connector, addr).await,
        CMD_UDP_ASSOCIATE => udp_associate(stream, connector).await,
        _ => {
            send_reply(stream, REP_CMD_NOT_SUPPORTED, bnd_v4()).await?;
            bail!("socks: unsupported cmd {cmd:#x}");
        }
    }
}

fn bnd_v4() -> SocketAddr {
    SocketAddr::new(IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED), 0)
}

async fn send_reply(stream: &mut TcpStream, rep: u8, bnd: SocketAddr) -> Result<()> {
    let mut out = vec![0x05, rep, 0x00];
    match bnd {
        SocketAddr::V4(a) => {
            out.push(0x01);
            out.extend_from_slice(&a.ip().octets());
            out.extend_from_slice(&a.port().to_be_bytes());
        }
        SocketAddr::V6(a) => {
            out.push(0x04);
            out.extend_from_slice(&a.ip().octets());
            out.extend_from_slice(&a.port().to_be_bytes());
        }
    }
    stream.write_all(&out).await?;
    Ok(())
}

async fn connect(stream: &mut TcpStream, connector: Connector, addr: Address) -> Result<()> {
    match connector.connect_tcp(&addr).await {
        Ok(mut remote) => {
            send_reply(stream, REP_OK, bnd_v4()).await?;
            let _ = copy_bidirectional(stream, &mut remote).await;
            Ok(())
        }
        Err(e) => {
            send_reply(stream, REP_HOST_UNREACHABLE, bnd_v4()).await?;
            Err(e.context("uplink connect"))
        }
    }
}

/// SOCKS5 UDP associate: relay datagrams between the client's UDP socket and a
/// framed datagram channel on an upstream Umbra session. The association dies
/// with its TCP control connection or after `udp_timeout` of silence.
async fn udp_associate(stream: &mut TcpStream, connector: Connector) -> Result<()> {
    let udp = Arc::new(UdpSocket::bind((stream.local_addr()?.ip(), 0)).await?);
    send_reply(stream, REP_OK, udp.local_addr()?).await?;

    let tls = connector.connect_udp().await?;
    let (mut rd, wr) = split(tls);
    let wr = Arc::new(Mutex::new(wr));

    // Reply task needs the client's UDP address, learned from its first packet.
    let (client_tx, client_rx) = watch::channel::<Option<SocketAddr>>(None);
    let shutdown = Arc::new(Notify::new());
    let task_shutdown = shutdown.clone();

    let udp_up = udp.clone();
    tokio::spawn(async move {
        let mut rx = client_rx;
        loop {
            tokio::select! {
                pkt = proto::read_udp_packet(&mut rd) => {
                    let pkt = match pkt { Ok(p) => p, Err(_) => break };
                    let client = loop {
                        if let Some(c) = *rx.borrow() {
                            break c;
                        }
                        if rx.changed().await.is_err() {
                            return;
                        }
                    };
                    let mut hdr = vec![0x00, 0x00, 0x00];
                    pkt.addr.encode(&mut hdr);
                    hdr.extend_from_slice(&pkt.payload);
                    let _ = udp_up.send_to(&hdr, client).await;
                }
                _ = task_shutdown.notified() => break,
            }
        }
    });

    let idle = connector.udp_timeout();
    let mut deadline = Instant::now() + idle;
    let mut buf = vec![0u8; proto::MAX_UDP_PAYLOAD + 64];
    let mut ctl = [0u8; 1];
    let peer_ip = stream.peer_addr()?.ip();

    loop {
        tokio::select! {
            // The control connection closing ends the association (RFC 1928).
            res = stream.read(&mut ctl) => {
                match res { Ok(0) | Err(_) => break, Ok(_) => {} }
            }
            res = udp.recv_from(&mut buf) => {
                let (n, from) = match res { Ok(v) => v, Err(_) => break };
                if from.ip() != peer_ip {
                    continue; // only the associating client may use this relay
                }
                if client_tx.borrow().is_none() {
                    let _ = client_tx.send(Some(from));
                }
                if let Some(pkt) = parse_socks_udp(&buf[..n]) {
                    deadline = Instant::now() + idle;
                    let mut g = wr.lock().await;
                    if proto::write_udp_packet(&mut *g, &pkt).await.is_err() {
                        break;
                    }
                }
            }
            _ = sleep_until(deadline) => break,
        }
    }
    // Drop the reply task too, so the TLS association fully closes and the
    // server's per-destination sockets get reaped.
    shutdown.notify_waiters();
    Ok(())
}

/// Parse a SOCKS5 UDP datagram: RSV(2) FRAG(1) ATYP/ADDR/PORT payload.
fn parse_socks_udp(dgram: &[u8]) -> Option<proto::UdpPacket> {
    if dgram.len() < 4 || dgram[0] != 0 || dgram[1] != 0 || dgram[2] != 0 {
        return None; // FRAG must be 0
    }
    let mut cur: &[u8] = &dgram[3..];
    let addr = Address::decode_slice(&mut cur).ok()?;
    Some(proto::UdpPacket {
        addr,
        payload: cur.to_vec(),
    })
}
