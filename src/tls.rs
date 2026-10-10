//! TLS plumbing: configs, cert loading, pinning/verifier logic, exporter.

use anyhow::{anyhow, Context, Result};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::client::Resumption;
use rustls::crypto::{verify_tls12_signature, verify_tls13_signature, WebPkiSupportedAlgorithms};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, ServerConfig, SignatureScheme};
use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::BufReader;
use std::path::Path;
use std::sync::Arc;
use subtle::ConstantTimeEq;

/// Install the ring crypto provider (idempotent).
pub fn install_provider() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}

/// The TLS exporter (RFC 5705 / RFC 8446 §7.5) binds our auth header to the
/// exact TLS session it rides in — this is what makes replayed headers useless.
pub fn exporter(conn: &impl Exportable) -> Result<[u8; crate::proto::EXPORTER_LEN]> {
    conn.keying_material(crate::proto::EXPORTER_LABEL.as_bytes(), None)
}

pub trait Exportable {
    fn keying_material(
        &self,
        label: &[u8],
        context: Option<&[u8]>,
    ) -> Result<[u8; crate::proto::EXPORTER_LEN]>;
}

impl Exportable for rustls::ServerConnection {
    fn keying_material(
        &self,
        label: &[u8],
        context: Option<&[u8]>,
    ) -> Result<[u8; crate::proto::EXPORTER_LEN]> {
        let mut out = [0u8; crate::proto::EXPORTER_LEN];
        self.export_keying_material(&mut out, label, context)
            .map_err(|e| anyhow!("tls exporter: {e}"))?;
        Ok(out)
    }
}

impl Exportable for rustls::ClientConnection {
    fn keying_material(
        &self,
        label: &[u8],
        context: Option<&[u8]>,
    ) -> Result<[u8; crate::proto::EXPORTER_LEN]> {
        let mut out = [0u8; crate::proto::EXPORTER_LEN];
        self.export_keying_material(&mut out, label, context)
            .map_err(|e| anyhow!("tls exporter: {e}"))?;
        Ok(out)
    }
}

impl<S> Exportable for crate::mtls::MiniTls<S> {
    fn keying_material(
        &self,
        label: &[u8],
        context: Option<&[u8]>,
    ) -> Result<[u8; crate::proto::EXPORTER_LEN]> {
        let v = self.export(label, context, crate::proto::EXPORTER_LEN)?;
        let mut out = [0u8; crate::proto::EXPORTER_LEN];
        out.copy_from_slice(&v);
        Ok(out)
    }
}

/// Map client config -> verification mode shared by both TLS stacks.
pub fn client_verify(cfg: &crate::config::ClientConfig) -> Result<crate::mtls::Verify> {
    if cfg.insecure.unwrap_or(false) {
        return Ok(crate::mtls::Verify::Insecure);
    }
    if let Some(pin_hex) = &cfg.pinned_cert_sha256 {
        let bytes = hex::decode(pin_hex.trim()).context("pinned_cert_sha256 is not hex")?;
        anyhow::ensure!(bytes.len() == 32, "pinned_cert_sha256 must be 32 bytes");
        let mut pin = [0u8; 32];
        pin.copy_from_slice(&bytes);
        return Ok(crate::mtls::Verify::Pinned(pin));
    }
    Ok(crate::mtls::Verify::WebPki)
}

fn load_certs(path: &Path) -> Result<Vec<CertificateDer<'static>>> {
    let f = File::open(path).with_context(|| format!("open cert {}", path.display()))?;
    let certs: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut BufReader::new(f))
        .collect::<Result<_, _>>()
        .with_context(|| format!("parse certs in {}", path.display()))?;
    anyhow::ensure!(!certs.is_empty(), "no certificates in {}", path.display());
    Ok(certs)
}

fn load_key(path: &Path) -> Result<PrivateKeyDer<'static>> {
    let f = File::open(path).with_context(|| format!("open key {}", path.display()))?;
    rustls_pemfile::private_key(&mut BufReader::new(f))
        .with_context(|| format!("parse key in {}", path.display()))?
        .ok_or_else(|| anyhow!("no private key in {}", path.display()))
}

/// Server-side TLS: real certificate, ALPN http/1.1 (the cover site speaks
/// plain HTTP behind us), session tickets enabled for fast reconnects.
pub fn server_config(cert_path: &Path, key_path: &Path) -> Result<Arc<ServerConfig>> {
    let certs = load_certs(cert_path)?;
    let key = load_key(key_path)?;
    let mut cfg = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .context("invalid cert/key pair")?;
    cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(Arc::new(cfg))
}

/// Accept a cert only if the leaf's SHA-256 matches the pin, while still
/// verifying the handshake signature chain (so the pin can't be stripped by
/// a MiTM swapping in a different valid cert for a different keypair —
/// TLS 1.3 signs the transcript with the cert's key).
#[derive(Debug)]
pub(crate) struct PinnedVerifier {
    pin: [u8; 32],
    algs: WebPkiSupportedAlgorithms,
}

impl PinnedVerifier {
    pub(crate) fn new(pin: [u8; 32]) -> Self {
        PinnedVerifier {
            pin,
            algs: rustls::crypto::ring::default_provider().signature_verification_algorithms,
        }
    }
}

impl ServerCertVerifier for PinnedVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        let fp: [u8; 32] = Sha256::digest(end_entity.as_ref()).into();
        if bool::from(fp.ct_eq(&self.pin)) {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(rustls::Error::General("certificate pin mismatch".into()))
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls12_signature(message, cert, dss, &self.algs)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls13_signature(message, cert, dss, &self.algs)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.algs.supported_schemes()
    }
}

#[derive(Debug)]
pub(crate) struct InsecureVerifier {
    algs: WebPkiSupportedAlgorithms,
}

impl InsecureVerifier {
    pub(crate) fn new() -> Self {
        InsecureVerifier {
            algs: rustls::crypto::ring::default_provider().signature_verification_algorithms,
        }
    }
}

impl ServerCertVerifier for InsecureVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls12_signature(message, cert, dss, &self.algs)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls13_signature(message, cert, dss, &self.algs)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.algs.supported_schemes()
    }
}

/// Client-side TLS. Modes: pinned leaf hash, standard WebPKI (default),
/// or insecure (testing only). Session resumption is on so reconnects are 1-RTT.
pub fn client_config(cfg: &crate::config::ClientConfig) -> Result<Arc<ClientConfig>> {
    let algs = rustls::crypto::ring::default_provider().signature_verification_algorithms;

    let builder = ClientConfig::builder_with_provider(
        rustls::crypto::ring::default_provider().into(),
    )
        .with_safe_default_protocol_versions()
        .context("build tls client config")?;

    let mut cfg = if cfg.insecure.unwrap_or(false) {
        builder
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(InsecureVerifier { algs }))
            .with_no_client_auth()
    } else if let Some(pin_hex) = &cfg.pinned_cert_sha256 {
        let bytes = hex::decode(pin_hex.trim()).context("pinned_cert_sha256 is not hex")?;
        anyhow::ensure!(bytes.len() == 32, "pinned_cert_sha256 must be 32 bytes");
        let mut pin = [0u8; 32];
        pin.copy_from_slice(&bytes);
        builder
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(PinnedVerifier { pin, algs }))
            .with_no_client_auth()
    } else {
        let mut roots = rustls::RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        builder.with_root_certificates(roots).with_no_client_auth()
    };

    cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
    cfg.resumption = Resumption::in_memory_sessions(256);
    Ok(Arc::new(cfg))
}

/// Create a self-signed cert pair and write them to disk (test/bootstrap use).
pub fn generate_self_signed(cn: &str, cert_path: &Path, key_path: &Path) -> Result<[u8; 32]> {
    let rcgen::CertifiedKey { cert, key_pair } =
        rcgen::generate_simple_self_signed(vec![cn.to_string()]).context("rcgen")?;
    let pem = cert.pem();
    std::fs::write(cert_path, &pem).with_context(|| format!("write {}", cert_path.display()))?;
    std::fs::write(key_path, key_pair.serialize_pem())
        .with_context(|| format!("write {}", key_path.display()))?;
    Ok(Sha256::digest(cert.der().as_ref()).into())
}
