//! Umbra client: local mixed SOCKS5/HTTP inbound -> authenticated TLS uplink.

use anyhow::{bail, Context, Result};
use rand::RngCore;
use rustls::pki_types::ServerName;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::timeout;
use tokio_rustls::TlsConnector;

use crate::config::ClientConfig;
use crate::mtls::MiniConnector;
use crate::proto::{self, Address};
use crate::tls;

const TCP_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const TLS_TIMEOUT: Duration = Duration::from_secs(15);
const STATUS_TIMEOUT: Duration = Duration::from_secs(15);
const DEFAULT_UDP_TIMEOUT: Duration = Duration::from_secs(120);

/// Type-erased async stream (rustls TLS or our mimicked mini-TLS).
pub trait AsyncIo: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> AsyncIo for T {}
pub type DynStream = Box<dyn AsyncIo>;

#[derive(Clone)]
pub struct Connector {
    inner: Arc<Inner>,
}

struct Inner {
    rustls: Option<TlsConnector>,
    mini: Option<MiniConnector>,
    server: String,
    server_name: ServerName<'static>,
    key: [u8; 32],
    /// Server is a `transport = "plain"` backend behind a TLS terminator:
    /// no shared session exporter exists, so auth uses the zero exporter.
    server_plain: bool,
    udp_timeout: Duration,
}

impl Connector {
    pub fn new(cfg: &ClientConfig) -> Result<Self> {
        let server_name = ServerName::try_from(cfg.server_name()?)
            .map_err(|e| anyhow::anyhow!("invalid server name: {e}"))?
            .to_owned();
        let fingerprint = cfg.fingerprint.as_deref().unwrap_or("chrome");
        let (rustls, mini) = match fingerprint {
            "chrome" => (
                None,
                Some(MiniConnector::new(tls::client_verify(cfg)?)),
            ),
            "rustls" => (
                Some(TlsConnector::from(tls::client_config(cfg)?)),
                None,
            ),
            other => bail!("unknown fingerprint {other:?} (chrome|rustls)"),
        };
        Ok(Connector {
            inner: Arc::new(Inner {
                rustls,
                mini,
                server: cfg.server.clone(),
                server_name,
                key: proto::derive_key(&cfg.password),
                server_plain: cfg.server_plain.unwrap_or(false),
                udp_timeout: cfg
                    .udp_timeout_secs
                    .map(Duration::from_secs)
                    .unwrap_or(DEFAULT_UDP_TIMEOUT),
            }),
        })
    }

    pub fn udp_timeout(&self) -> Duration {
        self.inner.udp_timeout
    }

    /// Establish an authenticated Umbra session. Sends the auth header
    /// immediately after the (usually resumed, 1-RTT) handshake.
    async fn session(&self, cmd: u8, addr: &Address) -> Result<DynStream> {
        let tcp = match timeout(TCP_CONNECT_TIMEOUT, TcpStream::connect(&self.inner.server)).await {
            Ok(Ok(s)) => s,
            Ok(Err(e)) => return Err(e).context("tcp connect"),
            Err(_) => bail!("tcp connect timed out"),
        };
        let _ = tcp.set_nodelay(true);

        let (mut stream, exporter) = if let Some(mini) = &self.inner.mini {
            let t = match timeout(
                TLS_TIMEOUT,
                mini.connect(tcp, &self.inner.server_name),
            )
            .await
            {
                Ok(Ok(s)) => s,
                Ok(Err(e)) => return Err(e).context("tls handshake"),
                Err(_) => bail!("tls handshake timed out"),
            };
            tracing::debug!("uplink established (resumed={})", t.resumed());
            let e = tls::exporter(&t)?;
            (Box::new(t) as DynStream, e)
        } else {
            let t = match timeout(
                TLS_TIMEOUT,
                self.inner
                    .rustls
                    .as_ref()
                    .unwrap()
                    .connect(self.inner.server_name.clone(), tcp),
            )
            .await
            {
                Ok(Ok(s)) => s,
                Ok(Err(e)) => return Err(e).context("tls handshake"),
                Err(_) => bail!("tls handshake timed out"),
            };
            let e = tls::exporter(t.get_ref().1)?;
            (Box::new(t) as DynStream, e)
        };

        // Behind a TLS terminator the server's auth uses the zero exporter.
        let exporter = if self.inner.server_plain {
            [0u8; proto::EXPORTER_LEN]
        } else {
            exporter
        };

        let mut nonce = [0u8; proto::NONCE_LEN];
        rand::thread_rng().fill_bytes(&mut nonce);
        let req = proto::build_request(&self.inner.key, &exporter, &nonce, cmd, addr);
        stream.write_all(&req).await?;
        stream.flush().await?;
        match timeout(STATUS_TIMEOUT, stream.read_u8()).await {
            Ok(Ok(proto::STATUS_OK)) => Ok(stream),
            Ok(Ok(proto::STATUS_UNREACHABLE)) => bail!("server: target unreachable"),
            Ok(Ok(s)) => bail!("server: unexpected status {s:#x}"),
            Ok(Err(e)) => Err(e).context("read status"),
            Err(_) => bail!("status read timed out"),
        }
    }

    /// CONNECT a TCP tunnel to `addr` through the server.
    pub async fn connect_tcp(&self, addr: &Address) -> Result<DynStream> {
        self.session(proto::CMD_CONNECT, addr).await
    }

    /// Open a UDP-associate channel (framed datagrams follow the status byte).
    pub async fn connect_udp(&self) -> Result<DynStream> {
        // Address field is unused for associations.
        self.session(proto::CMD_UDP_ASSOCIATE, &Address::V4([0, 0, 0, 0], 0))
            .await
    }
}

pub async fn run(cfg: ClientConfig) -> Result<()> {
    let connector = Connector::new(&cfg)?;
    let listener = TcpListener::bind(&cfg.listen)
        .await
        .with_context(|| format!("bind {}", cfg.listen))?;
    tracing::info!("umbra client on {} (SOCKS5 + HTTP CONNECT)", cfg.listen);
    tracing::info!("uplink {}", cfg.server);

    loop {
        let (mut stream, peer) = match listener.accept().await {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!("accept: {e}");
                continue;
            }
        };
        let connector = connector.clone();
        tokio::spawn(async move {
            if let Err(e) = dispatch(&mut stream, connector).await {
                tracing::debug!("{peer}: {e:#}");
            }
        });
    }
}

/// Auto-detect inbound protocol on the first byte: 0x05 = SOCKS5, else HTTP.
async fn dispatch(stream: &mut TcpStream, connector: Connector) -> Result<()> {
    let mut b = [0u8; 1];
    match timeout(Duration::from_secs(15), stream.peek(&mut b)).await {
        Ok(Ok(1)) => {}
        _ => bail!("inbound peek failed"),
    }
    if b[0] == 0x05 {
        crate::socks::handle(stream, connector).await
    } else {
        crate::http::handle(stream, connector).await
    }
}
