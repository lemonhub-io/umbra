//! End-to-end tests: real TLS, real sockets, real SOCKS5/HTTP flows.
//!
//!   - proxied TCP via SOCKS5 through an authenticated session
//!   - proxied UDP datagrams via SOCKS5 UDP ASSOCIATE
//!   - cover-site splice: garbage-in-TLS and replayed auth headers must get
//!     a real HTTP response (the anti-probing property)

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};

use crate::proto::Address;
use crate::{client, config, proto, server, tls};

const PASSWORD: &str = "test-secret";

fn tmpdir() -> PathBuf {
    static N: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
    let n = N.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let d = std::env::temp_dir().join(format!("umbra-itest-{}-{n}", std::process::id()));
    std::fs::create_dir_all(&d).unwrap();
    d
}

/// Grab a free TCP port (TOCTOU-safe enough for tests).
async fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .await
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// Wait until a TCP port accepts connections.
async fn wait_port(port: u16) {
    for _ in 0..100 {
        if TcpStream::connect(("127.0.0.1", port)).await.is_ok() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("port {port} never came up");
}

/// Echo server (TCP): returns everything it receives.
fn spawn_tcp_echo() -> tokio::task::JoinHandle<u16> {
    tokio::spawn(async {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = l.local_addr().unwrap().port();
        tokio::spawn(async move {
            loop {
                let (mut s, _) = l.accept().await.unwrap();
                tokio::spawn(async move {
                    let mut b = [0u8; 8192];
                    while let Ok(n) = s.read(&mut b).await {
                        if n == 0 || s.write_all(&b[..n]).await.is_err() {
                            break;
                        }
                    }
                });
            }
        });
        port
    })
}

/// Echo server (UDP): returns every datagram.
fn spawn_udp_echo() -> tokio::task::JoinHandle<u16> {
    tokio::spawn(async {
        let s = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let port = s.local_addr().unwrap().port();
        tokio::spawn(async move {
            let mut b = [0u8; 65536];
            loop {
                let (n, from) = s.recv_from(&mut b).await.unwrap();
                let _ = s.send_to(&b[..n], from).await;
            }
        });
        port
    })
}

/// Cover origin: replies HTTP 200 to any request, then keeps the conn open.
fn spawn_cover() -> tokio::task::JoinHandle<u16> {
    tokio::spawn(async {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = l.local_addr().unwrap().port();
        tokio::spawn(async move {
            loop {
                let (mut s, _) = l.accept().await.unwrap();
                tokio::spawn(async move {
                    let mut b = [0u8; 8192];
                    while let Ok(n) = s.read(&mut b).await {
                        if n == 0 {
                            break;
                        }
                        let resp = b"HTTP/1.1 200 OK\r\nContent-Length: 7\r\nContent-Type: text/html\r\n\r\nwelcome";
                        if s.write_all(resp).await.is_err() {
                            break;
                        }
                    }
                });
            }
        });
        port
    })
}

struct Fixture {
    server_port: u16,
    socks_port: u16,
    cert_pin_hex: String,
}

async fn fixture() -> Fixture {
    fixture_fp(None).await
}

async fn fixture_fp(fingerprint: Option<&str>) -> Fixture {
    let dir = tmpdir();
    let cert = dir.join("cert.pem");
    let key = dir.join("key.pem");
    let pin = tls::generate_self_signed("localhost", &cert, &key).unwrap();

    let server_port = free_port().await;
    let socks_port = free_port().await;
    let cover_port = spawn_cover().await.unwrap();

    let scfg = config::ServerConfig {
        listen: format!("127.0.0.1:{server_port}"),
        transport: None,
        cert: Some(cert.to_string_lossy().into()),
        key: Some(key.to_string_lossy().into()),
        fallback: format!("127.0.0.1:{cover_port}"),
        users: vec![config::UserEntry {
            name: "u1".into(),
            password: PASSWORD.into(),
        }],
        udp_timeout_secs: Some(60),
    };
    tokio::spawn(server::run(scfg));

    let ccfg = config::ClientConfig {
        listen: format!("127.0.0.1:{socks_port}"),
        server: format!("127.0.0.1:{server_port}"),
        password: PASSWORD.into(),
        sni: Some("localhost".into()),
        pinned_cert_sha256: Some(hex::encode(pin)),
        insecure: None,
        fingerprint: fingerprint.map(String::from),
        server_plain: None,
        udp_timeout_secs: Some(60),
    };
    tokio::spawn(client::run(ccfg));

    wait_port(server_port).await;
    wait_port(socks_port).await;
    Fixture {
        server_port,
        socks_port,
        cert_pin_hex: hex::encode(pin),
    }
}

/// Perform the SOCKS5 greeting + CONNECT to `addr`, return the open stream.
async fn socks_connect(socks_port: u16, addr: &[u8]) -> TcpStream {
    let mut s = TcpStream::connect(("127.0.0.1", socks_port)).await.unwrap();
    s.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
    let mut r = [0u8; 2];
    s.read_exact(&mut r).await.unwrap();
    assert_eq!(r, [0x05, 0x00]);
    let mut req = vec![0x05, 0x01, 0x00];
    req.extend_from_slice(addr);
    s.write_all(&req).await.unwrap();
    // reply: ver rep rsv atyp bnd(4) port(2)
    let mut hdr = [0u8; 4];
    s.read_exact(&mut hdr).await.unwrap();
    assert_eq!(hdr[0], 0x05);
    assert_eq!(hdr[1], 0x00, "socks connect failed, rep={:#x}", hdr[1]);
    let rest = match hdr[3] {
        0x01 => 6,
        0x04 => 18,
        _ => panic!("bad atyp"),
    };
    let mut b = vec![0u8; rest];
    s.read_exact(&mut b).await.unwrap();
    s
}

fn v4_addr(ip: [u8; 4], port: u16) -> Vec<u8> {
    let mut v = vec![0x01];
    v.extend_from_slice(&ip);
    v.extend_from_slice(&port.to_be_bytes());
    v
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_tcp_via_socks() {
    tls::install_provider();
    let echo_port = spawn_tcp_echo().await.unwrap();
    let f = fixture().await;

    let mut s = socks_connect(f.socks_port, &v4_addr([127, 0, 0, 1], echo_port)).await;
    s.write_all(b"hello umbra").await.unwrap();
    let mut buf = [0u8; 64];
    let n = s.read(&mut buf).await.unwrap();
    assert_eq!(&buf[..n], b"hello umbra");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_tcp_via_domain() {
    tls::install_provider();
    let echo_port = spawn_tcp_echo().await.unwrap();
    let f = fixture().await;

    // CONNECT via domain name "localhost" exercises the domain path.
    let mut req = vec![0x03, 9];
    req.extend_from_slice(b"localhost");
    req.extend_from_slice(&echo_port.to_be_bytes());
    let mut s = socks_connect(f.socks_port, &req).await;
    s.write_all(b"domain path ok").await.unwrap();
    let mut buf = [0u8; 64];
    let n = s.read(&mut buf).await.unwrap();
    assert_eq!(&buf[..n], b"domain path ok");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_udp_via_socks() {
    tls::install_provider();
    let echo_port = spawn_udp_echo().await.unwrap();
    let f = fixture().await;

    // UDP ASSOCIATE
    let mut ctl = TcpStream::connect(("127.0.0.1", f.socks_port)).await.unwrap();
    ctl.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
    let mut r = [0u8; 2];
    ctl.read_exact(&mut r).await.unwrap();
    let mut req = vec![0x05, 0x03, 0x00];
    req.extend_from_slice(&v4_addr([0, 0, 0, 0], 0));
    ctl.write_all(&req).await.unwrap();
    let mut hdr = [0u8; 10];
    ctl.read_exact(&mut hdr).await.unwrap();
    assert_eq!(hdr[1], 0x00);
    let relay = SocketAddr::from(([127, 0, 0, 1], u16::from_be_bytes([hdr[8], hdr[9]])));

    // SOCKS UDP request to the echo server
    let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let mut dgram = vec![0x00, 0x00, 0x00];
    dgram.extend_from_slice(&v4_addr([127, 0, 0, 1], echo_port));
    dgram.extend_from_slice(b"udp-works");
    udp.send_to(&dgram, relay).await.unwrap();

    let mut buf = [0u8; 128];
    let (n, _) = tokio::time::timeout(Duration::from_secs(10), udp.recv_from(&mut buf))
        .await
        .unwrap()
        .unwrap();
    // reply: RSV(2) FRAG ATYP+ADDR+PORT payload
    assert_eq!(&buf[n - 9..n], b"udp-works");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_http_connect() {
    tls::install_provider();
    let echo_port = spawn_tcp_echo().await.unwrap();
    let f = fixture().await;

    let mut s = TcpStream::connect(("127.0.0.1", f.socks_port)).await.unwrap();
    let req = format!(
        "CONNECT 127.0.0.1:{echo_port} HTTP/1.1\r\nHost: 127.0.0.1:{echo_port}\r\n\r\n"
    );
    s.write_all(req.as_bytes()).await.unwrap();
    let mut buf = vec![0u8; 512];
    let n = s.read(&mut buf).await.unwrap();
    assert!(buf[..n].starts_with(b"HTTP/1.1 200"));
    s.write_all(b"via-http").await.unwrap();
    let n = s.read(&mut buf).await.unwrap();
    assert_eq!(&buf[..n], b"via-http");
}

/// A raw TLS client (no Umbra auth) must receive the cover site's response —
/// this is the core anti-probing guarantee.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_probe_gets_cover() {
    tls::install_provider();
    let f = fixture().await;

    let cfg = config::ClientConfig {
        listen: "127.0.0.1:0".into(),
        server: format!("127.0.0.1:{}", f.server_port),
        password: "wrong-or-unused".into(),
        sni: Some("localhost".into()),
        pinned_cert_sha256: Some(f.cert_pin_hex.clone()),
        insecure: None,
        fingerprint: None,
        server_plain: None,
        udp_timeout_secs: None,
    };
    let connector =
        tokio_rustls::TlsConnector::from(tls::client_config(&cfg).unwrap());
    let tcp = TcpStream::connect(("127.0.0.1", f.server_port)).await.unwrap();
    let name = rustls::pki_types::ServerName::try_from("localhost").unwrap().to_owned();
    let mut t = connector.connect(name, tcp).await.unwrap();
    t.write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
        .await
        .unwrap();
    let mut buf = vec![0u8; 512];
    let n = t.read(&mut buf).await.unwrap();
    assert!(
        buf[..n].starts_with(b"HTTP/1.1 200"),
        "probe should get cover response, got: {:?}",
        String::from_utf8_lossy(&buf[..n])
    );
}

/// Replaying a captured auth header on a fresh TLS session must NOT proxy —
/// the exporter binding makes the tag invalid, so we fall back to cover.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_replay_gets_cover() {
    tls::install_provider();
    let echo_port = spawn_tcp_echo().await.unwrap();
    let f = fixture().await;

    // Capture a valid request header from a real session.
    let good = {
        let mut s = socks_connect(f.socks_port, &v4_addr([127, 0, 0, 1], echo_port)).await;
        s.write_all(b"x").await.unwrap();
        s
    };
    drop(good);

    // Manually replay the *same request bytes* on a new TLS session:
    // rebuild what a "captured" header looks like by making one ourselves.
    let cfg = config::ClientConfig {
        listen: "127.0.0.1:0".into(),
        server: format!("127.0.0.1:{}", f.server_port),
        password: PASSWORD.into(),
        sni: Some("localhost".into()),
        pinned_cert_sha256: Some(f.cert_pin_hex.clone()),
        insecure: None,
        fingerprint: None,
        server_plain: None,
        udp_timeout_secs: None,
    };
    let connector =
        tokio_rustls::TlsConnector::from(tls::client_config(&cfg).unwrap());

    // Session A: produce a real request, learn its header bytes.
    let (hdr_bytes, http_probe_port) = {
        let tcp = TcpStream::connect(("127.0.0.1", f.server_port)).await.unwrap();
        let name = rustls::pki_types::ServerName::try_from("localhost").unwrap().to_owned();
        let mut t = connector.connect(name, tcp).await.unwrap();
        let exporter = tls::exporter(t.get_ref().1).unwrap();
        let nonce = [7u8; proto::NONCE_LEN];
        let req = proto::build_request(
            &proto::derive_key(PASSWORD),
            &exporter,
            &nonce,
            proto::CMD_CONNECT,
            &Address::V4([127, 0, 0, 1], echo_port),
        );
        t.write_all(&req).await.unwrap();
        let mut st = [0u8; 1];
        t.read_exact(&mut st).await.unwrap();
        assert_eq!(st[0], proto::STATUS_OK);
        (req, 0u16)
    };
    let _ = http_probe_port;

    // Session B: replay hdr_bytes verbatim. Different exporter -> invalid tag.
    let tcp = TcpStream::connect(("127.0.0.1", f.server_port)).await.unwrap();
    let name = rustls::pki_types::ServerName::try_from("localhost").unwrap().to_owned();
    let mut t = connector.connect(name, tcp).await.unwrap();
    t.write_all(&hdr_bytes).await.unwrap();
    // Server should splice to cover: cover responds to garbage with 200.
    let mut buf = vec![0u8; 512];
    let n = tokio::time::timeout(Duration::from_secs(10), t.read(&mut buf))
        .await
        .unwrap()
        .unwrap();
    assert!(
        buf[..n].starts_with(b"HTTP/1.1 200"),
        "replayed header must hit cover, got {:?}",
        String::from_utf8_lossy(&buf[..n])
    );
}

/// Wrong password = unauthenticated = cover site.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_wrong_password_gets_cover() {
    tls::install_provider();
    let echo_port = spawn_tcp_echo().await.unwrap();
    let f = fixture().await;

    let cfg = config::ClientConfig {
        listen: "127.0.0.1:0".into(),
        server: format!("127.0.0.1:{}", f.server_port),
        password: "definitely-wrong".into(),
        sni: Some("localhost".into()),
        pinned_cert_sha256: Some(f.cert_pin_hex.clone()),
        insecure: None,
        fingerprint: None,
        server_plain: None,
        udp_timeout_secs: None,
    };
    let connector =
        tokio_rustls::TlsConnector::from(tls::client_config(&cfg).unwrap());
    let tcp = TcpStream::connect(("127.0.0.1", f.server_port)).await.unwrap();
    let name = rustls::pki_types::ServerName::try_from("localhost").unwrap().to_owned();
    let mut t = connector.connect(name, tcp).await.unwrap();
    let exporter = tls::exporter(t.get_ref().1).unwrap();
    let nonce = [9u8; proto::NONCE_LEN];
    let req = proto::build_request(
        &proto::derive_key("definitely-wrong"),
        &exporter,
        &nonce,
        proto::CMD_CONNECT,
        &Address::V4([127, 0, 0, 1], echo_port),
    );
    t.write_all(&req).await.unwrap();
    let mut buf = vec![0u8; 512];
    let n = tokio::time::timeout(Duration::from_secs(10), t.read(&mut buf))
        .await
        .unwrap()
        .unwrap();
    assert!(buf[..n].starts_with(b"HTTP/1.1 200"));
}

#[tokio::test]
async fn test_addr_roundtrip() {
    let cases = [
        Address::V4([1, 2, 3, 4], 443),
        Address::V6([0xab; 16], 8080),
        Address::Domain("example.com".into(), 53),
    ];
    for a in &cases {
        let mut buf = Vec::new();
        a.encode(&mut buf);
        let mut cur: &[u8] = &buf;
        let back = Address::decode_slice(&mut cur).unwrap();
        assert_eq!(&back, a);
        assert!(cur.is_empty());
    }
}

#[tokio::test]
async fn test_replay_cache() {
    let mut rc = proto::ReplayCache::new();
    let nonce = [1u8; 32];
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    assert!(rc.check(&nonce, ts).is_ok());
    assert!(rc.check(&nonce, ts).is_err(), "nonce reuse must fail");
    assert!(rc.check(&[2u8; 32], ts - 10_000).is_err(), "stale ts must fail");
    assert!(rc.check(&[3u8; 32], ts + 10_000).is_err(), "future ts must fail");
}

/// The rustls fingerprint path must still proxy correctly end-to-end.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_rustls_fingerprint_mode() {
    tls::install_provider();
    let echo_port = spawn_tcp_echo().await.unwrap();
    let f = fixture_fp(Some("rustls")).await;

    let mut s = socks_connect(f.socks_port, &v4_addr([127, 0, 0, 1], echo_port)).await;
    s.write_all(b"rustls path").await.unwrap();
    let mut buf = [0u8; 64];
    let n = s.read(&mut buf).await.unwrap();
    assert_eq!(&buf[..n], b"rustls path");
}

/// A minimal TLS terminator: accepts TLS and pipes plaintext to a backend —
/// the shape of an nginx `stream { proxy_pass }` deployment in front of a
/// `transport = "plain"` Umbra server.
fn spawn_terminator(
    cert: &Path,
    key: &Path,
    backend_port: u16,
) -> tokio::task::JoinHandle<u16> {
    let acceptor = tokio_rustls::TlsAcceptor::from(tls::server_config(cert, key).unwrap());
    tokio::spawn(async move {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = l.local_addr().unwrap().port();
        tokio::spawn(async move {
            loop {
                let (s, _) = l.accept().await.unwrap();
                let acceptor = acceptor.clone();
                tokio::spawn(async move {
                    if let Ok(mut t) = acceptor.accept(s).await {
                        if let Ok(mut be) =
                            TcpStream::connect(("127.0.0.1", backend_port)).await
                        {
                            let _ = tokio::io::copy_bidirectional(&mut t, &mut be).await;
                        }
                    }
                });
            }
        });
        port
    })
}

/// `transport = "plain"`: auth binds to a zero exporter. Verified twice:
/// raw TCP straight to the backend, and the full deployment shape —
/// client -> TLS terminator -> plain umbra -> target.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_plain_transport() {
    tls::install_provider();
    let echo_port = spawn_tcp_echo().await.unwrap();
    let server_port = free_port().await;
    let cover_port = spawn_cover().await.unwrap();

    let scfg = config::ServerConfig {
        listen: format!("127.0.0.1:{server_port}"),
        transport: Some("plain".into()),
        cert: None,
        key: None,
        fallback: format!("127.0.0.1:{cover_port}"),
        users: vec![config::UserEntry {
            name: "u1".into(),
            password: PASSWORD.into(),
        }],
        udp_timeout_secs: Some(60),
    };
    tokio::spawn(server::run(scfg));
    wait_port(server_port).await;

    // Raw TCP + auth built against the zero exporter.
    let mut s = TcpStream::connect(("127.0.0.1", server_port)).await.unwrap();
    let nonce = [5u8; proto::NONCE_LEN];
    let req = proto::build_request(
        &proto::derive_key(PASSWORD),
        &[0u8; proto::EXPORTER_LEN],
        &nonce,
        proto::CMD_CONNECT,
        &Address::V4([127, 0, 0, 1], echo_port),
    );
    s.write_all(&req).await.unwrap();
    let mut st = [0u8; 1];
    s.read_exact(&mut st).await.unwrap();
    assert_eq!(st[0], proto::STATUS_OK);
    s.write_all(b"plain-mode").await.unwrap();
    let mut buf = [0u8; 64];
    let n = s.read(&mut buf).await.unwrap();
    assert_eq!(&buf[..n], b"plain-mode");
    drop(s);

    // Full path: real client through a TLS terminator (nginx-style) into the
    // plain backend. The public fingerprint is the terminator's rustls stack.
    let dir = tmpdir();
    let tcert = dir.join("tcert.pem");
    let tkey = dir.join("tkey.pem");
    let tpin = tls::generate_self_signed("localhost", &tcert, &tkey).unwrap();
    let term_port = spawn_terminator(&tcert, &tkey, server_port).await.unwrap();
    let socks_port = free_port().await;
    let ccfg = config::ClientConfig {
        listen: format!("127.0.0.1:{socks_port}"),
        server: format!("127.0.0.1:{term_port}"),
        password: PASSWORD.into(),
        sni: Some("localhost".into()),
        pinned_cert_sha256: Some(hex::encode(tpin)),
        insecure: None,
        fingerprint: Some("chrome".into()),
        server_plain: Some(true),
        udp_timeout_secs: Some(60),
    };
    tokio::spawn(client::run(ccfg));
    wait_port(socks_port).await;

    let mut s = socks_connect(socks_port, &v4_addr([127, 0, 0, 1], echo_port)).await;
    s.write_all(b"via terminator").await.unwrap();
    let n = s.read(&mut buf).await.unwrap();
    assert_eq!(&buf[..n], b"via terminator");
}

/// The mini-TLS client must handshake, verify the pinned cert, and export
/// keying material that differs per session — directly against a server.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_mini_tls_direct() {
    tls::install_provider();
    let echo_port = spawn_tcp_echo().await.unwrap();
    let f = fixture().await;

    let pin = hex::decode(&f.cert_pin_hex).unwrap();
    let mut pin32 = [0u8; 32];
    pin32.copy_from_slice(&pin);
    let conn = crate::mtls::MiniConnector::new(crate::mtls::Verify::Pinned(pin32));
    let name = rustls::pki_types::ServerName::try_from("localhost")
        .unwrap()
        .to_owned();

    let mut e1 = [0u8; 32];
    let mut e2 = [0u8; 32];
    for (i, out) in [&mut e1, &mut e2].into_iter().enumerate() {
        let tcp = TcpStream::connect(("127.0.0.1", f.server_port)).await.unwrap();
        let mut t = conn.connect(tcp, &name).await.unwrap();
        if i == 1 {
            assert!(t.resumed(), "second connect should resume via NST");
        }
        out.copy_from_slice(
            &t.export(proto::EXPORTER_LABEL.as_bytes(), None, 32)
                .unwrap(),
        );
        // Full Umbra auth + CONNECT over the mimicked session.
        let nonce = [3u8 + i as u8; proto::NONCE_LEN];
        let req = proto::build_request(
            &proto::derive_key(PASSWORD),
            out,
            &nonce,
            proto::CMD_CONNECT,
            &Address::V4([127, 0, 0, 1], echo_port),
        );
        t.write_all(&req).await.unwrap();
        let mut st = [0u8; 1];
        t.read_exact(&mut st).await.unwrap();
        assert_eq!(st[0], proto::STATUS_OK);
        t.write_all(b"mini").await.unwrap();
        let mut buf = [0u8; 8];
        let n = t.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"mini");
    }
    assert_ne!(e1, e2, "exporters must differ across sessions");
}

/// Interop: the mimicked-ClientHello client must handshake against OpenSSL,
/// not just rustls. Skipped silently when `openssl` is not installed.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_openssl_interop() {
    tls::install_provider();
    if std::process::Command::new("openssl")
        .arg("version")
        .output()
        .is_err()
    {
        eprintln!("openssl not installed; skipping");
        return;
    }
    let dir = tmpdir();
    let cert = dir.join("o.pem");
    let key = dir.join("ok.pem");
    let st = std::process::Command::new("openssl")
        .args([
            "req", "-x509", "-newkey", "rsa:2048", "-nodes",
            "-keyout", key.to_str().unwrap(), "-out", cert.to_str().unwrap(),
            "-subj", "/CN=localhost", "-days", "1",
        ])
        .output()
        .unwrap()
        .status;
    assert!(st.success());
    let port = free_port().await;
    let mut srv = std::process::Command::new("openssl")
        .args([
            // wait_port's readiness probe consumes one accept; keep margin.
            "s_server",
            "-accept", &port.to_string(),
            "-cert", cert.to_str().unwrap(),
            "-key", key.to_str().unwrap(),
            "-tls1_3", "-www", "-naccept", "4", "-num_tickets", "2",
        ])
        .spawn()
        .unwrap();
    wait_port(port).await;

    let conn = crate::mtls::MiniConnector::new(crate::mtls::Verify::Insecure);
    let name = rustls::pki_types::ServerName::try_from("localhost")
        .unwrap()
        .to_owned();
    for i in 0..2 {
        let tcp = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        let mut t = conn.connect(tcp, &name).await.unwrap();
        if i == 1 {
            assert!(t.resumed(), "second openssl conn should resume via NST");
        }
        t.write_all(b"GET / HTTP/1.0\r\n\r\n").await.unwrap();
        let mut buf = vec![0u8; 512];
        let n = t.read(&mut buf).await.unwrap();
        assert!(
            buf[..n].starts_with(b"HTTP/"),
            "expected openssl -www response, got {:?}",
            String::from_utf8_lossy(&buf[..n])
        );
        // Let the post-handshake NewSessionTicket land so the resumption
        // cache is populated before the next connect.
        let mut scratch = [0u8; 64];
        let _ = tokio::time::timeout(Duration::from_millis(300), t.read(&mut scratch)).await;
    }
    let _ = srv.kill();
}
