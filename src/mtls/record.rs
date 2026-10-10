//! TLS 1.3 record layer: framing + AEAD protection (AES-GCM / ChaCha20).

use anyhow::{bail, Context, Result};
use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey};
use tokio::io::{AsyncRead, AsyncReadExt};

use super::keys::{Cipher, TrafficSecret};

pub const CT_CHANGE_CIPHER_SPEC: u8 = 20;
pub const CT_ALERT: u8 = 21;
pub const CT_HANDSHAKE: u8 = 22;
pub const CT_APPLICATION_DATA: u8 = 23;

pub const MAX_RECORD: usize = 16384 + 256; // plaintext + expansion

/// One direction's AEAD state: key, fixed IV, sequence counter.
pub struct CipherState {
    key: LessSafeKey,
    iv: [u8; 12],
    seq: u64,
}

impl CipherState {
    pub fn new(cipher: Cipher, secret: &TrafficSecret) -> Result<Self> {
        let (key, iv) = secret.key_iv()?;
        let alg = match cipher {
            Cipher::Aes128GcmSha256 => &ring::aead::AES_128_GCM,
            Cipher::Aes256GcmSha384 => &ring::aead::AES_256_GCM,
            Cipher::Chacha20Poly1305Sha256 => &ring::aead::CHACHA20_POLY1305,
        };
        let key = LessSafeKey::new(
            UnboundKey::new(alg, &key).map_err(|_| anyhow::anyhow!("aead key"))?,
        );
        Ok(CipherState { key, iv, seq: 0 })
    }

    fn nonce(&self) -> Result<Nonce> {
        let mut n = self.iv;
        let s = self.seq.to_be_bytes();
        for i in 0..8 {
            n[4 + i] ^= s[i];
        }
        Ok(Nonce::assume_unique_for_key(n))
    }

    /// Encrypt `plaintext` under `outer_type` (should be 23 for encrypted msgs;
    /// the real inner type is appended to the plaintext before sealing).
    pub fn encrypt(
        &mut self,
        outer_type: u8,
        inner_type: u8,
        plaintext: &[u8],
    ) -> Result<Vec<u8>> {
        let mut body = Vec::with_capacity(plaintext.len() + 1 + 16);
        body.extend_from_slice(plaintext);
        body.push(inner_type);
        let mut rec = Vec::with_capacity(5 + body.len() + 16);
        rec.push(outer_type);
        rec.extend_from_slice(&[0x03, 0x03]);
        rec.extend_from_slice(&((body.len() + 16) as u16).to_be_bytes());
        let aad = Aad::from(&rec[..]);
        let nonce = self.nonce()?;
        self.key
            .seal_in_place_append_tag(nonce, aad, &mut body)
            .map_err(|_| anyhow::anyhow!("aead seal"))?;
        self.seq += 1;
        rec.extend_from_slice(&body);
        Ok(rec)
    }

    /// Decrypt a record; returns (inner_type, plaintext).
    pub fn decrypt(&mut self, outer_type: u8, record: &[u8]) -> Result<(u8, Vec<u8>)> {
        if record.len() < 5 + 16 + 1 {
            bail!("short record");
        }
        let aad = Aad::from(&record[..5]);
        let mut body = record[5..].to_vec();
        let nonce = self.nonce()?;
        let pt_len = self
            .key
            .open_in_place(nonce, aad, &mut body)
            .map_err(|_| anyhow::anyhow!("aead open failed (bad record)"))?
            .len();
        body.truncate(pt_len);
        self.seq += 1;
        // Strip inner-content-type (last non-zero byte per RFC 8446 §5.2).
        while let Some(&0) = body.last() {
            body.pop();
        }
        let inner = body.pop().context("no inner content type")?;
        if outer_type == CT_APPLICATION_DATA {
            Ok((inner, body))
        } else {
            Ok((outer_type, body)) // alerts/CCS may arrive un-encrypted-form too
        }
    }
}

/// Read one raw TLS record header+body from the stream.
pub async fn read_record<R: AsyncRead + Unpin>(r: &mut R) -> Result<(u8, Vec<u8>)> {
    let mut hdr = [0u8; 5];
    r.read_exact(&mut hdr).await?;
    let len = u16::from_be_bytes([hdr[3], hdr[4]]) as usize;
    if len > MAX_RECORD + 2048 {
        bail!("oversized record {len}");
    }
    let mut rec = Vec::with_capacity(5 + len);
    rec.extend_from_slice(&hdr);
    rec.resize(5 + len, 0);
    r.read_exact(&mut rec[5..]).await?;
    Ok((hdr[0], rec))
}

/// Frame with an explicit legacy record version.
pub fn frame_v(content_type: u8, version: [u8; 2], payload: &[u8]) -> Vec<u8> {
    let mut rec = Vec::with_capacity(5 + payload.len());
    rec.push(content_type);
    rec.extend_from_slice(&version);
    rec.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    rec.extend_from_slice(payload);
    rec
}
