# Umbra

A probe-resistant, replay-immune TLS proxy protocol in a single Rust binary.

Umbra tunnels TCP and UDP traffic inside a genuine TLS 1.3 session. To an
observer — passive or active — the server is indistinguishable from a normal
web server: real certificate, real handshake, and every connection that fails
authentication is spliced byte-for-byte to a real cover website.

## Why Umbra — what it fixes in existing protocols

| | Shadowsocks | Trojan / VLESS | Hysteria / TUIC | Umbra |
|---|---|---|---|---|
| Active-probe resistance | none (any bytes get a response) | fallback to cover site | N/A (QUIC) | **byte-exact splice to cover site** |
| Replayable credentials | yes | yes — a captured `SHA224(password)` confirms a proxy forever | yes | **no — auth is bound to the TLS exporter + nonce + timestamp** |
| UDP relay | yes | partial/absent | yes (native) | **yes — per-destination full-cone NAT sessions** |
| Transport | own TCP/UDP | TLS/TCP | QUIC/UDP | TLS 1.3/TCP (works where UDP is throttled/blocked) |
| Reconnect latency | 0-RTT cipher | 2-RTT TLS | 0/1-RTT QUIC | **1-RTT via TLS resumption** |
| Deployment | simple | needs real cert | simple | **one binary, one TOML file, cert-pinning bootstrap** |

### The replay problem

Trojan-style protocols authenticate with a static string
(`SHA224(password)` in Trojan). A censor that suspects a server can replay a
captured header: if the response differs from an ordinary web server, the
server is confirmed and blocked. Every mainstream TLS-mimic protocol shares
this weakness because the auth material is fixed per-connection.

Umbra's auth tag is:

```
tag = HMAC-SHA256(user_key, "umbra/1/auth" || exporter || nonce || timestamp)
```

`exporter` is the RFC 5705 keying-material exporter of the *current* TLS
session — a value that is different for every handshake and unknowable to
anyone replaying a recorded header. Replays fail authentication and get the
cover site. Combined with a nonce replay cache and a ±120 s timestamp window,
the server cryptographically cannot distinguish itself from the cover.

### The fingerprint problem

Most TLS-mimic proxies betray themselves at the first packet: the client's
ClientHello carries the TLS library's fingerprint (rustls/Go/OpenSSL all
look different from a browser), and censors fingerprint servers the same
way. Umbra solves both sides:

- **Client**: Umbra ships its own minimal TLS 1.3 client (`src/mtls/`) that
  writes the ClientHello byte-for-byte like Chrome — GREASE values in every
  position Chrome greases (including the same GREASE group shared between
  `supported_groups` and `key_share`, the detail strict stacks like OpenSSL
  enforce), Chrome's extension set and cipher list, ALPS, ECH GREASE, and a
  randomly permuted extension order like Chrome ≥ 110. Session resumption,
  cert pinning, WebPKI, and exporter binding are all preserved.
- **Server**: with `transport = "plain"` Umbra runs behind a real TLS
  terminator (nginx `stream`, HAProxy, stunnel), so the public fingerprint
  is the terminator's production-grade stack — indistinguishable because
  it *is* the real thing.

## Wire protocol (inside TLS)

```
client -> server:
  u8    version = 0x01
  [32]  nonce                    random
  u64be timestamp                unix seconds
  [32]  auth_tag                 HMAC-SHA256(key, "umbra/1/auth" || exporter || nonce || ts)
  u8    cmd                      0x01 CONNECT | 0x02 UDP_ASSOCIATE
  addr  atyp + address + u16be port   (atyp: 0x01 ipv4, 0x03 domain, 0x04 ipv6)

server -> client:
  u8    status                   0x00 ok | 0x01 unreachable

then: CONNECT   -> raw bidirectional stream
      UDP_ASSOC -> framed datagrams [addr][u16be len][payload]
```

Key derivation: `key = SHA256("umbra/1/key" || password)`.
Config stores passphrases; keys are never on disk.

## Quick start

Build:

```
cargo build --release
```

### Server

```bash
# testing: self-signed cert
./umbra gencert --cn example.com --cert cert.pem --key key.pem
# -> prints pinned_cert_sha256 for the client config

# production: use a real cert (Let's Encrypt) and run nginx on the fallback port
./umbra server -c server.toml
```

`server.toml` — see `examples/server.toml`:

```toml
listen   = "0.0.0.0:443"
cert     = "cert.pem"
key      = "key.pem"
fallback = "127.0.0.1:8080"        # nginx serving a real site

[[users]]
name     = "alice"
password = "…"
```

Alternatively, for a literally perfect server TLS fingerprint, let a real
TLS terminator face the network and run Umbra in `transport = "plain"`:

```toml
listen    = "127.0.0.1:8443"
transport = "plain"
fallback  = "127.0.0.1:8080"
# nginx: stream { server { listen 443 ssl; proxy_pass 127.0.0.1:8443; ... } }
```

### Client

`client.toml` — see `examples/client.toml`:

```toml
listen   = "127.0.0.1:1080"
server   = "example.com:443"
password = "…"
# with a self-signed server cert, bootstrap by pinning instead of a CA:
pinned_cert_sha256 = "<hex printed by gencert>"
# fingerprint = "chrome"   # default; "rustls" = generic library hello
# server_plain = true      # server is transport="plain" behind a terminator
```

```bash
./umbra client -c client.toml
# then point anything at 127.0.0.1:1080
curl --socks5-hostname 127.0.0.1:1080 https://example.org
curl -x http://127.0.0.1:1080 http://example.org
```

The inbound port auto-detects SOCKS5 (incl. UDP ASSOCIATE) and HTTP CONNECT
/ absolute-URI proxying — one port for everything.

## Design notes

- **Cover splice, not emulation.** Invalid sessions are forwarded to a real
  HTTP origin after TLS termination (Trojan model). Probes get a real website
  with a real certificate on a real domain — there is no Umbra signature to
  match. Byte-exactness: bytes already consumed during header parsing are
  replayed to the cover verbatim before bidirectional splicing.
- **Fail-closed everywhere.** Any deviation — bad version, bad tag, replayed
  nonce, stalled header, malformed request — routes to the cover. The proxy
  path is reachable only with a cryptographically valid header.
- **1-RTT reconnects.** The client keeps a session-ticket cache (TLS 1.3
  resumption), so repeated proxied connections hand the request to the server
  one round trip after the TCP handshake.
- **True UDP.** UDP ASSOCIATE opens per-destination connected sockets on the
  server (full-cone NAT). DNS, QUIC-to-destination, games — real UDP in and out.
- **Multi-user.** `[[users]]` entries each derive their own key; auth reports
  the user name in logs. Clock skew tolerance ±120 s; a 10-minute nonce cache
  kills replays.

## Honest limitations

- The mini-TLS client speaks TLS 1.3 only. The ClientHello still advertises
  Chrome's TLS 1.2 suites (fingerprint fidelity), but a server that actually
  negotiates 1.2 will fail the handshake — real TLS 1.3 deployment is
  universal enough that this is the right trade.
- `transport = "plain"` mode has no shared TLS exporter between client and
  server (the terminator owns the session), so auth binds to a zero exporter
  and replay protection rests on the nonce cache + ±120 s window — still
  single-use headers, just not session-bound. Set `server_plain = true` on
  the client to match.
- TCP transport means proxied TCP-over-TCP retransmission stacking under
  loss. That is the price of a fully TCP/TLS-plausible transport; use UDP
  ASSOCIATE where the application supports it.
- `insecure = true` exists for testing. Never ship it — pinning is the secure
  bootstrap.

## Security properties

- Confidentiality/integrity: TLS 1.3 (AES-GCM / ChaCha20-Poly1305) — no custom
  AEAD, no double encryption.
- Authentication: HMAC-SHA256 over a per-session exporter → immune to replay,
  immune to cross-session credential reuse, invisible to passive observers.
- Active probing: indistinguishable from the cover origin for every input that
  is not a valid session.
- Constant-time tag comparison; no auth-bypass path.

## Layout

```
src/proto.rs    wire format, auth, replay cache, UDP framing
src/mtls/       mini TLS 1.3 client — Chrome-fingerprinted ClientHello,
                key schedule, record layer, cert verify, resumption, exporter
src/tls.rs      rustls configs, cert pinning, exporter binding
src/server.rs   accept loop, verdict, cover splice, TCP/UDP dispatch
src/client.rs   uplink connector, session resumption, inbound dispatch
src/socks.rs    SOCKS5 CONNECT + UDP ASSOCIATE
src/http.rs     HTTP CONNECT + absolute-URI forward proxy
src/config.rs   TOML config
src/itest.rs    end-to-end tests (proxy paths + anti-probing properties)
examples/       annotated server/client configs
```

Tests: `cargo test` — 13 end-to-end tests covering proxied TCP/UDP, HTTP
CONNECT, plain-transport terminator deployments, OpenSSL interop for the
mimicked ClientHello, and the three anti-probing guarantees (garbage,
replayed header, wrong password all receive the cover site).
