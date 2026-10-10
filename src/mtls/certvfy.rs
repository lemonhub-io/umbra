//! Server certificate + CertificateVerify checking, built on rustls's
//! `ServerCertVerifier` machinery (WebPKI / pinned / insecure modes).

use anyhow::{bail, Result};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerifier};
use rustls::client::WebPkiServerVerifier;
use rustls::internal::msgs::codec::{Codec, Reader};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, RootCertStore, SignatureScheme};
use std::sync::Arc;

/// Verification policy for the mini-TLS client.
#[derive(Clone)]
pub enum Verify {
    /// Standard WebPKI against Mozilla roots (default).
    WebPki,
    /// Accept only a leaf cert whose SHA-256 matches the pin.
    Pinned([u8; 32]),
    /// Skip all verification (testing only).
    Insecure,
}

impl Verify {
    fn verifier(&self) -> Result<Arc<dyn ServerCertVerifier>> {
        match self {
            Verify::WebPki => {
                let roots = RootCertStore {
                    roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
                };
                WebPkiServerVerifier::builder(Arc::new(roots))
                    .build()
                    .map(|v| v as Arc<dyn ServerCertVerifier>)
                    .map_err(|e| anyhow::anyhow!("webpki verifier: {e}"))
            }
            Verify::Pinned(pin) => Ok(Arc::new(crate::tls::PinnedVerifier::new(*pin))),
            Verify::Insecure => Ok(Arc::new(crate::tls::InsecureVerifier::new())),
        }
    }
}

/// TLS 1.3 CertificateVerify context (RFC 8446 §4.4.3): 64 spaces,
/// "TLS 1.3, server CertificateVerify", 0x00, transcript hash.
fn cv_message(transcript_hash: &[u8]) -> Vec<u8> {
    let mut m = Vec::with_capacity(64 + 33 + 1 + transcript_hash.len());
    m.extend_from_slice(&[0x20u8; 64]);
    m.extend_from_slice(b"TLS 1.3, server CertificateVerify");
    m.push(0);
    m.extend_from_slice(transcript_hash);
    m
}

/// Verify the certificate chain + name under `policy`.
pub fn verify_chain(
    policy: &Verify,
    ee: &CertificateDer<'_>,
    inters: &[CertificateDer<'_>],
    server_name: &ServerName<'_>,
) -> Result<()> {
    let v = policy.verifier()?;
    v.verify_server_cert(ee, inters, server_name, &[], UnixTime::now())
        .map_err(|e| anyhow::anyhow!("certificate verify failed: {e}"))?;
    Ok(())
}

/// Verify the CertificateVerify signature over the handshake transcript.
pub fn verify_cert_verify(
    policy: &Verify,
    scheme: u16,
    signature: &[u8],
    ee: &CertificateDer<'_>,
    transcript_hash: &[u8],
) -> Result<()> {
    let v = policy.verifier()?;
    if !v
        .supported_verify_schemes()
        .contains(&SignatureScheme::from(scheme))
    {
        bail!("unsupported signature scheme {scheme:#x}");
    }
    // Rebuild the DigitallySignedStruct via its public wire codec.
    let mut wire = Vec::with_capacity(4 + signature.len());
    wire.extend_from_slice(&scheme.to_be_bytes());
    wire.extend_from_slice(&(signature.len() as u16).to_be_bytes());
    wire.extend_from_slice(signature);
    let mut r = Reader::init(&wire);
    let dss = DigitallySignedStruct::read(&mut r)
        .map_err(|_| anyhow::anyhow!("dss decode"))?;
    let msg = cv_message(transcript_hash);
    let _: HandshakeSignatureValid = v
        .verify_tls13_signature(&msg, ee, &dss)
        .map_err(|e| anyhow::anyhow!("certificate_verify: {e}"))?;
    Ok(())
}
