//! umbra — a probe-resistant, replay-immune TLS proxy protocol.
//!
//! Subcommands:
//!   umbra server -c server.toml    run the server
//!   umbra client -c client.toml    run the local client (SOCKS5/HTTP inbound)
//!   umbra genkey                   print a random passphrase
//!   umbra gencert --cn NAME ...    self-signed cert for testing (+ cert pin)

mod client;
mod config;
mod http;
mod mtls;
mod proto;
mod server;
mod socks;
mod tls;

#[cfg(test)]
mod itest;

use anyhow::Result;
use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "umbra", version, about = "Umbra anti-censorship proxy")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Run the Umbra server (TLS front + cover-site fallback).
    Server {
        #[arg(short, long, default_value = "server.toml")]
        config: PathBuf,
    },
    /// Run the local client (mixed SOCKS5 / HTTP-CONNECT listener).
    Client {
        #[arg(short, long, default_value = "client.toml")]
        config: PathBuf,
    },
    /// Print a random passphrase for use in `users`/`password` fields.
    Genkey,
    /// Generate a self-signed certificate (testing / bootstrap).
    Gencert {
        /// Common name / SAN for the cert (e.g. your domain).
        #[arg(long, default_value = "localhost")]
        cn: String,
        /// Output cert path.
        #[arg(long, default_value = "cert.pem")]
        cert: PathBuf,
        /// Output key path.
        #[arg(long, default_value = "key.pem")]
        key: PathBuf,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "umbra=info".into()),
        )
        .init();
    tls::install_provider();

    let cli = Cli::parse();
    match cli.cmd {
        Cmd::Server { config } => {
            let cfg = config::ServerConfig::load(&config)?;
            server::run(cfg).await
        }
        Cmd::Client { config } => {
            let cfg = config::ClientConfig::load(&config)?;
            client::run(cfg).await
        }
        Cmd::Genkey => {
            use base64::Engine;
            let mut k = [0u8; 32];
            rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut k);
            println!("{}", base64::engine::general_purpose::STANDARD.encode(k));
            Ok(())
        }
        Cmd::Gencert { cn, cert, key } => {
            let pin = tls::generate_self_signed(&cn, &cert, &key)?;
            println!("cert: {}", cert.display());
            println!("key:  {}", key.display());
            println!("pinned_cert_sha256 = \"{}\"", hex::encode(pin));
            Ok(())
        }
    }
}
