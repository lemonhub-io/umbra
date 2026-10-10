//! TOML configuration for `umbra server` and `umbra client`.

use anyhow::{Context, Result};
use serde::Deserialize;
use std::path::Path;

#[derive(Debug, Deserialize)]
pub struct ServerConfig {
    /// TCP address to listen on, e.g. "0.0.0.0:443".
    pub listen: String,
    /// "tls" (default): Umbra terminates TLS itself.
    /// "plain": run behind a real TLS terminator (nginx stream proxy_pass);
    /// gives the deployment the terminator's genuine TLS fingerprint.
    pub transport: Option<String>,
    /// PEM certificate chain file (required in tls mode).
    pub cert: Option<String>,
    /// PEM private key file (required in tls mode).
    pub key: Option<String>,
    /// Cover origin that receives every non-Umbra connection (plaintext HTTP),
    /// e.g. "127.0.0.1:8080" served by nginx.
    pub fallback: String,
    /// Per-user passphrases. Arbitrary strings; keys are derived via SHA-256.
    pub users: Vec<UserEntry>,
    /// Seconds a UDP session stays alive without traffic (default 300).
    pub udp_timeout_secs: Option<u64>,
}

#[derive(Debug, Deserialize)]
pub struct UserEntry {
    pub name: String,
    pub password: String,
}

#[derive(Debug, Deserialize)]
pub struct ClientConfig {
    /// Local mixed SOCKS5/HTTP-CONNECT listen address, e.g. "127.0.0.1:1080".
    pub listen: String,
    /// Umbra server address, e.g. "example.com:443".
    pub server: String,
    /// Passphrase (must match a server user).
    pub password: String,
    /// SNI / verify name override. Defaults to the host part of `server`.
    pub sni: Option<String>,
    /// Hex-encoded SHA-256 pin of the server leaf certificate.
    /// Enables bootstrap without a CA bundle (works with self-signed certs).
    pub pinned_cert_sha256: Option<String>,
    /// Disable server certificate verification entirely (insecure; testing).
    pub insecure: Option<bool>,
    /// ClientHello fingerprint: "chrome" (default, byte-mimicked handshake)
    /// or "rustls" (generic library fingerprint).
    pub fingerprint: Option<String>,
    /// Set when the server runs `transport = "plain"` behind a TLS
    /// terminator. The client's TLS session ends at the terminator, so no
    /// shared TLS exporter exists — auth binds to a zero exporter and
    /// anti-replay rests on the nonce + timestamp window alone.
    pub server_plain: Option<bool>,
    /// Seconds a SOCKS UDP association stays alive (default 120).
    pub udp_timeout_secs: Option<u64>,
}

impl ServerConfig {
    pub fn load(path: &Path) -> Result<Self> {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("reading {}", path.display()))?;
        let cfg: ServerConfig = toml::from_str(&text).context("parsing server config")?;
        anyhow::ensure!(!cfg.users.is_empty(), "config must define at least one user");
        let transport = cfg.transport.as_deref().unwrap_or("tls");
        anyhow::ensure!(
            transport == "tls" || transport == "plain",
            "transport must be \"tls\" or \"plain\""
        );
        if transport == "tls" {
            anyhow::ensure!(cfg.cert.is_some() && cfg.key.is_some(),
                "tls transport requires cert and key");
        }
        Ok(cfg)
    }
}

impl ClientConfig {
    pub fn load(path: &Path) -> Result<Self> {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("reading {}", path.display()))?;
        let cfg: ClientConfig = toml::from_str(&text).context("parsing client config")?;
        anyhow::ensure!(!cfg.password.is_empty(), "password must not be empty");
        Ok(cfg)
    }

    /// The name used for SNI and certificate verification.
    pub fn server_name(&self) -> Result<String> {
        if let Some(s) = &self.sni {
            return Ok(s.clone());
        }
        let host = self
            .server
            .rsplit_once(':')
            .map(|(h, _)| h)
            .unwrap_or(&self.server)
            .trim_start_matches('[')
            .trim_end_matches(']');
        Ok(host.to_string())
    }
}
