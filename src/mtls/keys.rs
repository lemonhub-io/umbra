//! TLS 1.3 key schedule (RFC 8446 §7.1) and record-protection state.

use anyhow::{anyhow, Result};
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256, Sha384};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Cipher {
    Aes128GcmSha256,
    Aes256GcmSha384,
    Chacha20Poly1305Sha256,
}

impl Cipher {
    pub fn from_suite(suite: u16) -> Option<Self> {
        match suite {
            0x1301 => Some(Cipher::Aes128GcmSha256),
            0x1302 => Some(Cipher::Aes256GcmSha384),
            0x1303 => Some(Cipher::Chacha20Poly1305Sha256),
            _ => None,
        }
    }

    pub fn hash_len(&self) -> usize {
        match self {
            Cipher::Aes256GcmSha384 => 48,
            _ => 32,
        }
    }
    pub fn key_len(&self) -> usize {
        match self {
            Cipher::Aes256GcmSha384 => 32,
            _ => 16,
        }
    }
    pub fn is_sha384(&self) -> bool {
        matches!(self, Cipher::Aes256GcmSha384)
    }
}

pub fn hmac(sha384: bool, key: &[u8], msg: &[u8]) -> Vec<u8> {
    if sha384 {
        let mut m = <Hmac<Sha384> as Mac>::new_from_slice(key).unwrap();
        m.update(msg);
        m.finalize().into_bytes().to_vec()
    } else {
        let mut m = <Hmac<Sha256> as Mac>::new_from_slice(key).unwrap();
        m.update(msg);
        m.finalize().into_bytes().to_vec()
    }
}

fn hkdf_extract(sha384: bool, salt: &[u8], ikm: &[u8]) -> Vec<u8> {
    hmac(sha384, salt, ikm)
}

fn hkdf_expand(sha384: bool, prk: &[u8], info: &[u8], out: &mut [u8]) -> Result<()> {
    let hash_len = if sha384 { 48 } else { 32 };
    let mut t = Vec::new();
    let mut off = 0usize;
    let mut i = 1u8;
    while off < out.len() {
        let mut buf = Vec::with_capacity(t.len() + info.len() + 1);
        buf.extend_from_slice(&t);
        buf.extend_from_slice(info);
        buf.push(i);
        t = hmac(sha384, prk, &buf);
        let n = (out.len() - off).min(hash_len);
        out[off..off + n].copy_from_slice(&t[..n]);
        off += n;
        i = i.checked_add(1).ok_or_else(|| anyhow!("hkdf overflow"))?;
    }
    Ok(())
}

/// HKDF-Expand-Label (RFC 8446 §7.1): info = len u16 | "tls13 "label | ctx.
pub fn expand_label(
    sha384: bool,
    secret: &[u8],
    label: &str,
    context: &[u8],
    out_len: usize,
) -> Result<Vec<u8>> {
    let full = format!("tls13 {label}");
    let mut info = Vec::with_capacity(2 + 1 + full.len() + 1 + context.len());
    info.extend_from_slice(&(out_len as u16).to_be_bytes());
    info.push(full.len() as u8);
    info.extend_from_slice(full.as_bytes());
    info.push(context.len() as u8);
    info.extend_from_slice(context);
    let mut out = vec![0u8; out_len];
    hkdf_expand(sha384, secret, &info, &mut out)?;
    Ok(out)
}

/// Derive-Secret = Expand-Label(secret, label, Hash(msgs)).
pub fn derive_secret(
    sha384: bool,
    secret: &[u8],
    label: &str,
    transcript_hash: &[u8],
) -> Result<Vec<u8>> {
    let hl = if sha384 { 48 } else { 32 };
    expand_label(sha384, secret, label, transcript_hash, hl)
}

/// All secrets for one connection direction's traffic keys.
pub struct TrafficSecret {
    pub secret: Vec<u8>,
    pub cipher: Cipher,
}

impl TrafficSecret {
    pub fn key_iv(&self) -> Result<(Vec<u8>, [u8; 12])> {
        let sha384 = self.cipher.is_sha384();
        let key = expand_label(sha384, &self.secret, "key", &[], self.cipher.key_len())?;
        let ivv = expand_label(sha384, &self.secret, "iv", &[], 12)?;
        let mut iv = [0u8; 12];
        iv.copy_from_slice(&ivv);
        Ok((key, iv))
    }
    /// finished_key for Finished MACs.
    pub fn finished_key(&self) -> Result<Vec<u8>> {
        expand_label(
            self.cipher.is_sha384(),
            &self.secret,
            "finished",
            &[],
            self.cipher.hash_len(),
        )
    }
}

/// The full set of connection secrets.
pub struct KeySchedule {
    pub client_ap: TrafficSecret,
    pub server_ap: TrafficSecret,
    pub exporter_master: Vec<u8>,
    pub resumption_master: Vec<u8>,
}

/// Derive the handshake secrets after ServerHello.
pub fn handshake_secrets(
    cipher: Cipher,
    shared_secret: &[u8],
    early_secret: &[u8],
    transcript_hash_through_sh: &[u8],
) -> Result<(Vec<u8>, TrafficSecret, TrafficSecret)> {
    let sha384 = cipher.is_sha384();
    let empty_hash = if sha384 {
        Sha384::digest([]).to_vec()
    } else {
        Sha256::digest([]).to_vec()
    };
    let derived = derive_secret(sha384, early_secret, "derived", &empty_hash)?;
    let handshake_secret = hkdf_extract(sha384, &derived, shared_secret);
    let c = derive_secret(
        sha384,
        &handshake_secret,
        "c hs traffic",
        transcript_hash_through_sh,
    )?;
    let s = derive_secret(
        sha384,
        &handshake_secret,
        "s hs traffic",
        transcript_hash_through_sh,
    )?;
    Ok((
        handshake_secret,
        TrafficSecret {
            secret: c,
            cipher,
        },
        TrafficSecret {
            secret: s,
            cipher,
        },
    ))
}

/// Derive application + exporter secrets once server Finished is verified.
pub fn finish_schedule(
    cipher: Cipher,
    handshake_secret: &[u8],
    transcript_through_server_fin: &[u8],
    transcript_through_client_fin: &[u8],
) -> Result<KeySchedule> {
    let sha384 = cipher.is_sha384();
    let empty_hash = if sha384 {
        Sha384::digest([]).to_vec()
    } else {
        Sha256::digest([]).to_vec()
    };
    let hl = cipher.hash_len();
    let derived = derive_secret(sha384, handshake_secret, "derived", &empty_hash)?;
    let master = hkdf_extract(sha384, &derived, &vec![0u8; hl]);
    let client_ap = TrafficSecret {
        secret: derive_secret(sha384, &master, "c ap traffic", transcript_through_server_fin)?,
        cipher,
    };
    let server_ap = TrafficSecret {
        secret: derive_secret(sha384, &master, "s ap traffic", transcript_through_server_fin)?,
        cipher,
    };
    let exporter_master = derive_secret(
        sha384,
        &master,
        "exp master",
        transcript_through_server_fin,
    )?;
    let resumption_master = derive_secret(
        sha384,
        &master,
        "res master",
        transcript_through_client_fin,
    )?;
    Ok(KeySchedule {
        client_ap,
        server_ap,
        exporter_master,
        resumption_master,
    })
}

/// early_secret and the binder key for resumption PSK.
pub fn early_secret(cipher: Cipher, psk: &[u8]) -> Vec<u8> {
    let sha384 = cipher.is_sha384();
    hkdf_extract(sha384, &vec![0u8; cipher.hash_len()], psk)
}

/// res binder finished key -> used to compute the PSK binder tag.
pub fn binder_verify(
    cipher: Cipher,
    early_secret: &[u8],
    transcript_hash_of_truncated_ch: &[u8],
) -> Result<Vec<u8>> {
    let sha384 = cipher.is_sha384();
    let empty_hash = if sha384 {
        Sha384::digest([]).to_vec()
    } else {
        Sha256::digest([]).to_vec()
    };
    let binder_key = derive_secret(sha384, early_secret, "res binder", &empty_hash)?;
    let fin_key = expand_label(sha384, &binder_key, "finished", &[], cipher.hash_len())?;
    Ok(hmac(sha384, &fin_key, transcript_hash_of_truncated_ch))
}

/// resumption PSK from a NewSessionTicket.
pub fn resumption_psk(cipher: Cipher, res_master: &[u8], nonce: &[u8]) -> Result<Vec<u8>> {
    expand_label(
        cipher.is_sha384(),
        res_master,
        "resumption",
        nonce,
        cipher.hash_len(),
    )
}

/// RFC 8446 §7.5 exporter, matching rustls/OpenSSL:
///   inner = Expand-Label(exp_master, label, Hash(""))
///   out   = Expand-Label(inner, "exporter", Hash(context), out_len)
pub fn export(
    cipher: Cipher,
    exporter_master: &[u8],
    label: &[u8],
    context: Option<&[u8]>,
    out_len: usize,
) -> Result<Vec<u8>> {
    let sha384 = cipher.is_sha384();
    let hl = cipher.hash_len();
    let hash = |data: &[u8]| -> Vec<u8> {
        if sha384 {
            Sha384::digest(data).to_vec()
        } else {
            Sha256::digest(data).to_vec()
        }
    };
    let label_str = std::str::from_utf8(label).map_err(|_| anyhow!("exporter label not utf8"))?;
    let inner = expand_label(sha384, exporter_master, label_str, &hash(&[]), hl)?;
    expand_label(sha384, &inner, "exporter", &hash(context.unwrap_or(&[])), out_len)
}
