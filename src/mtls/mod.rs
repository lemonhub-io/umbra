//! Mini TLS 1.3 client: a self-contained handshake + record layer built for
//! byte-exact ClientHello mimicry (Chrome fingerprint), session resumption
//! (1-RTT reconnects), and RFC 5705 keying-material export.
//!
//! Only a client; only TLS 1.3. Crypto primitives come from `ring`.

mod certvfy;
mod hello;
mod hs;
mod keys;
mod record;

use anyhow::{bail, Context, Result};
use rustls::pki_types::{CertificateDer, ServerName};
use sha2::Digest;
use std::collections::{HashMap, VecDeque};
use std::io;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context as TaskContext, Poll};
use std::time::Instant;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf};

pub use certvfy::Verify;
use keys::Cipher;
use record::{CipherState, CT_ALERT, CT_APPLICATION_DATA, CT_CHANGE_CIPHER_SPEC, CT_HANDSHAKE};

const GROUP_X25519: u16 = 0x001d;
const GROUP_P256: u16 = 0x0017;
const GROUP_P384: u16 = 0x0018;

/// (group, private key, public key bytes)
type KeyShare = (u16, ring::agreement::EphemeralPrivateKey, Vec<u8>);
/// (signature scheme, signature) + transcript hash through Certificate.
type CertVerify = ((u16, Vec<u8>), Vec<u8>);

/// One stored resumption PSK derived from a NewSessionTicket.
struct StoredPsk {
    psk: Vec<u8>,
    ticket: Vec<u8>,
    age_add: u32,
    lifetime_ms: u64,
    obtained: Instant,
    cipher: Cipher,
}

#[derive(Default)]
struct ResumptionCache {
    // server name -> newest usable PSK
    by_name: HashMap<String, StoredPsk>,
}

/// Connector: builds Chrome-fingerprinted TLS sessions. Clone-cheap.
#[derive(Clone)]
pub struct MiniConnector {
    cfg: Arc<Cfg>,
}

struct Cfg {
    verify: Verify,
    /// ALPN protocols to offer (mimic order: h2, http/1.1).
    alpn: Vec<Vec<u8>>,
    resumption: Mutex<ResumptionCache>,
}

impl MiniConnector {
    pub fn new(verify: Verify) -> Self {
        MiniConnector {
            cfg: Arc::new(Cfg {
                verify,
                alpn: vec![b"h2".to_vec(), b"http/1.1".to_vec()],
                resumption: Mutex::new(ResumptionCache::default()),
            }),
        }
    }

    /// Full TLS 1.3 handshake over `io`; returns the encrypted stream.
    pub async fn connect<S>(&self, mut io: S, server_name: &ServerName<'_>) -> Result<MiniTls<S>>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let name = match server_name {
            ServerName::DnsName(d) => d.as_ref().to_string(),
            ServerName::IpAddress(ip) => std::net::IpAddr::from(*ip).to_string(),
            _ => bail!("unsupported server name type"),
        };

        let rng = ring::rand::SystemRandom::new();
        let mut random = [0u8; 32];
        let mut session_id = [0u8; 32];
        use ring::rand::SecureRandom;
        rng.fill(&mut random).map_err(|_| anyhow::anyhow!("rng"))?;
        rng.fill(&mut session_id).map_err(|_| anyhow::anyhow!("rng"))?;

        // Key shares offered in CH: x25519 only, like current Chrome.
        let mut shares: Vec<KeyShare> = Vec::new();
        shares.push(gen_share(GROUP_X25519, &rng)?);

        // Resumption?
        let stored = self
            .cfg
            .resumption
            .lock()
            .unwrap()
            .by_name
            .get(&name)
            .and_then(|s| {
                let age = s.obtained.elapsed().as_millis() as u64;
                if age < s.lifetime_ms {
                    Some((s.psk.clone(), s.ticket.clone(), s.age_add, age as u32, s.cipher))
                } else {
                    None
                }
            });

        let early = stored
            .as_ref()
            .map(|(psk, _, _, _, cipher)| (keys::early_secret(*cipher, psk), *cipher));

        let mut params = hello::HelloParams {
            server_name: &name,
            random,
            session_id,
            shares: shares.iter().map(|(g, _, p)| (*g, p.clone())).collect(),
            alpn: self.cfg.alpn.clone(),
            psk: None,
            cookie: None,
        };
        if let Some((_, ticket, age_add, age, cipher)) = &stored {
            params.psk = Some(hello::PskOffer {
                identity: ticket.clone(),
                obfuscated_age: age.wrapping_add(*age_add),
                binder_len: cipher.hash_len(),
            });
        }
        let mut built = hello::build(&params);

        // Fill in the PSK binder if offering resumption.
        if let (Some(off), Some((early_secret, cipher))) = (built.binder_offset, early.as_ref()) {
            let truncated = &built.message[..off];
            let th = if cipher.is_sha384() {
                sha2::Sha384::digest(truncated).to_vec()
            } else {
                sha2::Sha256::digest(truncated).to_vec()
            };
            let binder = keys::binder_verify(*cipher, early_secret, &th)?;
            // binder field: [u16 list_len][u8 len][binder]
            let b = &mut built.message;
            b[off] = 0; // list_len high byte (len < 256)
            b[off + 1] = (1 + binder.len()) as u8;
            b[off + 2] = binder.len() as u8;
            b[off + 3..off + 3 + binder.len()].copy_from_slice(&binder);
        }

        // Wire: ClientHello record + middlebox-compat CCS (record version 0x0303).
        io.write_all(&record::frame_v(CT_HANDSHAKE, [0x03, 0x01], &built.message))
            .await?;
        io.write_all(&record::frame_v(CT_CHANGE_CIPHER_SPEC, [0x03, 0x03], &[0x01]))
            .await?;
        io.flush().await?;

        // ---- transcript bookkeeping ----
        // `msgs` accumulates handshake message bytes that hash into the
        // transcript. On HRR the prefix is replaced by message_hash(CH1).
        let mut msgs: Vec<u8> = built.message.clone();
        let ch1 = built.message.clone();
        let mut hrr_prefix_ch1: Option<Vec<u8>> = None;

        // ---- read ServerHello ----
        let mut hsbuf: Vec<u8> = Vec::new();
        let mut sh_body: Option<Vec<u8>> = None;
        while sh_body.is_none() {
            let (ty, rec) = record::read_record(&mut io).await?;
            match ty {
                CT_CHANGE_CIPHER_SPEC => continue,
                CT_ALERT => {
                    bail!("{}", alert_err(&rec))
                }
                CT_HANDSHAKE => hsbuf.extend_from_slice(&rec[5..]),
                ty => {
                    bail!("unexpected record type {ty} before ServerHello")
                }
            }
            let mut cur: &[u8] = &hsbuf;
            if let Some((msg, ty2, body)) = hs::next_hs_msg(&mut cur)? {
                if ty2 != hs::HS_SERVER_HELLO {
                    bail!("expected server_hello, got {ty2}");
                }
                sh_body = Some(body.to_vec());
                msgs.extend_from_slice(msg);
                let used = hsbuf.len() - cur.len();
                hsbuf.drain(..used);
            }
        }

        let mut sh = hs::parse_server_hello(&sh_body.unwrap())?;

        // ---- HelloRetryRequest ----
        if sh.is_hrr {
            let want = sh.hrr_group.unwrap_or(GROUP_X25519);
            if !shares.iter().any(|(g, _, _)| *g == want) {
                shares.clear();
                shares.push(gen_share(want, &rng)?);
            } else {
                shares.retain(|(g, _, _)| *g == want);
            }
            params.shares = shares.iter().map(|(g, _, p)| (*g, p.clone())).collect();
            params.cookie = if sh.hrr_cookie.is_empty() {
                None
            } else {
                Some(sh.hrr_cookie.clone())
            };
            let built2 = hello::build(&params);
            io.write_all(&record::frame_v(CT_HANDSHAKE, [0x03, 0x01], &built2.message))
                .await?;
            io.flush().await?;

            hrr_prefix_ch1 = Some(ch1);
            msgs = built2.message.clone();

            // read SH again
            let mut sh2: Option<Vec<u8>> = None;
            while sh2.is_none() {
                let (ty, rec) = record::read_record(&mut io).await?;
                match ty {
                    CT_CHANGE_CIPHER_SPEC => continue,
                    CT_ALERT => bail!("{}", alert_err(&rec)),
                    CT_HANDSHAKE => hsbuf.extend_from_slice(&rec[5..]),
                    _ => bail!("unexpected record {ty}"),
                }
                let mut cur: &[u8] = &hsbuf;
                if let Some((msg, ty2, body)) = hs::next_hs_msg(&mut cur)? {
                    if ty2 != hs::HS_SERVER_HELLO {
                        bail!("expected server_hello after hrr, got {ty2}");
                    }
                    sh2 = Some(body.to_vec());
                    msgs.extend_from_slice(msg);
                    let used = hsbuf.len() - cur.len();
                    hsbuf.drain(..used);
                }
            }
            sh = hs::parse_server_hello(&sh2.unwrap())?;
        }

        let cipher = Cipher::from_suite(sh.cipher)
            .ok_or_else(|| anyhow::anyhow!("unsupported suite {:#x}", sh.cipher))?;

        let transcript_hash = |msgs_tail: &[u8]| -> Vec<u8> {
            let mut all: Vec<u8> = match &hrr_prefix_ch1 {
                Some(ch1b) => {
                    let d = if cipher.is_sha384() {
                        sha2::Sha384::digest(ch1b).to_vec()
                    } else {
                        sha2::Sha256::digest(ch1b).to_vec()
                    };
                    let mut v = hs::hs_msg(254, &d);
                    v.extend_from_slice(msgs_tail);
                    v
                }
                None => msgs_tail.to_vec(),
            };
            let h = if cipher.is_sha384() {
                sha2::Sha384::digest(&all).to_vec()
            } else {
                sha2::Sha256::digest(&all).to_vec()
            };
            all.clear();
            h
        };

        // ---- ECDHE ----
        let group = sh.key_share_group.context("server gave no key_share")?;
        let idx = shares
            .iter()
            .position(|(g, _, _)| *g == group)
            .context("server picked unoffered group")?;
        let (_, eph, _) = shares.swap_remove(idx);
        let shared = agree(eph, group, &sh.server_key_share)?;

        // ---- handshake secrets ----
        let early_secret = match &early {
            Some((e, _)) => e.clone(),
            None => keys::early_secret(cipher, &vec![0u8; cipher.hash_len()]),
        };
        let th_sh = transcript_hash(&msgs);
        let (handshake_secret, c_hs, s_hs) =
            keys::handshake_secrets(cipher, &shared, &early_secret, &th_sh)?;
        let mut recv_cipher = CipherState::new(cipher, &s_hs)?;
        let mut send_cipher_hs = CipherState::new(cipher, &c_hs)?;

        // ---- read encrypted server flight ----
        let mut cert_chain: Option<(Vec<u8>, Vec<Vec<u8>>)> = None;
        // (scheme, signature) + transcript-hash-through-Certificate
        let mut cert_verify: Option<CertVerify> = None;
        let mut server_fin: Option<Vec<u8>> = None;
        let mut fin_msg_raw: Option<Vec<u8>> = None;

        while server_fin.is_none() {
            let (ty, rec) = record::read_record(&mut io).await?;
            match ty {
                CT_CHANGE_CIPHER_SPEC => continue,
                CT_ALERT => bail!("{}", alert_err(&rec)),
                CT_APPLICATION_DATA => {}
                _ => bail!("unexpected record {ty} during handshake"),
            }
            let (inner, data) = recv_cipher.decrypt(ty, &rec)?;
            match inner {
                CT_HANDSHAKE => hsbuf.extend_from_slice(&data),
                CT_ALERT => bail!("flight {}", alert_err_plain(&data)),
                _ => continue,
            }
            loop {
                let mut cur: &[u8] = &hsbuf;
                match hs::next_hs_msg(&mut cur)? {
                    None => break,
                    Some((msg, ty2, body)) => {
                        let consumed = hsbuf.len() - cur.len();
                        match ty2 {
                            hs::HS_ENCRYPTED_EXTENSIONS => {
                                let _ = hs::parse_ee_alpn(body);
                                msgs.extend_from_slice(msg);
                            }
                            hs::HS_CERTIFICATE => {
                                cert_chain = Some(hs::parse_certificate(body)?);
                                msgs.extend_from_slice(msg);
                            }
                            hs::HS_CERTIFICATE_VERIFY => {
                                // The signed transcript covers CH..Certificate
                                // (i.e. excludes this CV message itself).
                                let th = transcript_hash(&msgs);
                                cert_verify = Some((hs::parse_cert_verify(body)?, th));
                                msgs.extend_from_slice(msg);
                            }
                            hs::HS_FINISHED => {
                                server_fin = Some(body.to_vec());
                                fin_msg_raw = Some(msg.to_vec());
                                // msgs gets it after verify (verify hash excludes Fin)
                            }
                            _ => {
                                msgs.extend_from_slice(msg);
                            }
                        }
                        hsbuf.drain(..consumed);
                    }
                }
                if server_fin.is_some() {
                    break;
                }
            }
        }

        let resumed = sh.selected_psk.is_some();

        // ---- verify CertificateVerify + Finished ----
        if !resumed {
            let (ee, inters) = cert_chain.context("server sent no certificate")?;
            let ee_der = CertificateDer::from(ee.clone());
            let inter_ders: Vec<CertificateDer> =
                inters.iter().map(|c| CertificateDer::from(c.clone())).collect();
            certvfy::verify_chain(&self.cfg.verify, &ee_der, &inter_ders, server_name)?;
            let ((scheme, sig), cv_th) = cert_verify.context("no certificate_verify")?;
            certvfy::verify_cert_verify(&self.cfg.verify, scheme, &sig, &ee_der, &cv_th)?;
        }

        let fin_key = s_hs.finished_key()?;
        let expect = keys::hmac(cipher.is_sha384(), &fin_key, &transcript_hash(&msgs));
        if expect != server_fin.unwrap() {
            bail!("server Finished verify_data mismatch");
        }
        msgs.extend_from_slice(&fin_msg_raw.unwrap());
        let th_server_fin = transcript_hash(&msgs);

        // ---- client Finished ----
        let fin_key_c = c_hs.finished_key()?;
        let cfin_body = keys::hmac(cipher.is_sha384(), &fin_key_c, &th_server_fin);
        let cfin_msg = hs::hs_msg(hs::HS_FINISHED, &cfin_body);
        let fin_rec =
            send_cipher_hs.encrypt(CT_APPLICATION_DATA, CT_HANDSHAKE, &cfin_msg)?;
        io.write_all(&fin_rec).await?;
        io.flush().await?;
        msgs.extend_from_slice(&cfin_msg);
        let th_client_fin = transcript_hash(&msgs);

        // ---- application secrets ----
        let ks = keys::finish_schedule(cipher, &handshake_secret, &th_server_fin, &th_client_fin)?;
        let send = CipherState::new(cipher, &ks.client_ap)?;
        let recv = CipherState::new(cipher, &ks.server_ap)?;

        Ok(MiniTls {
            io,
            recv: Some(recv),
            send: Some(send),
            raw_in: Vec::with_capacity(20480),
            plain_out: VecDeque::new(),
            write_pending: VecDeque::new(),
            // Handshake bytes that coalesced with Finished (e.g. first NST).
            hs_post: hsbuf,
            res_master: ks.resumption_master,
            exp_master: ks.exporter_master,
            cipher,
            resumed,
            ticket_sink: Some(TicketSink {
                cfg: self.cfg.clone(),
                name,
            }),
            inbound_closed: false,
            want_close_sent: false,
        })
    }
}

fn gen_share(
    group: u16,
    rng: &ring::rand::SystemRandom,
) -> Result<(u16, ring::agreement::EphemeralPrivateKey, Vec<u8>)> {
    use ring::agreement;
    let alg = match group {
        GROUP_X25519 => &agreement::X25519,
        GROUP_P256 => &agreement::ECDH_P256,
        GROUP_P384 => &agreement::ECDH_P384,
        _ => bail!("unsupported group {group:#x}"),
    };
    let eph = agreement::EphemeralPrivateKey::generate(alg, rng)
        .map_err(|_| anyhow::anyhow!("keygen"))?;
    let pubkey = eph
        .compute_public_key()
        .map_err(|_| anyhow::anyhow!("pubkey"))?;
    Ok((group, eph, pubkey.as_ref().to_vec()))
}

fn agree(
    eph: ring::agreement::EphemeralPrivateKey,
    group: u16,
    peer: &[u8],
) -> Result<Vec<u8>> {
    use ring::agreement;
    let alg = match group {
        GROUP_X25519 => &agreement::X25519,
        GROUP_P256 => &agreement::ECDH_P256,
        GROUP_P384 => &agreement::ECDH_P384,
        _ => bail!("unsupported group {group:#x}"),
    };
    let peer = agreement::UnparsedPublicKey::new(alg, peer);
    agreement::agree_ephemeral(eph, &peer, |s| s.to_vec())
        .map_err(|_| anyhow::anyhow!("ecdhe failed"))
}

fn alert_err(rec: &[u8]) -> String {
    if rec.len() >= 7 {
        format!("tls alert: {}", hs::alert_name(rec[6]))
    } else {
        "tls alert".into()
    }
}
fn alert_err_plain(data: &[u8]) -> String {
    if data.len() >= 2 {
        format!("tls alert: {}", hs::alert_name(data[1]))
    } else {
        "tls alert".into()
    }
}

struct TicketSink {
    cfg: Arc<Cfg>,
    name: String,
}

/// An established TLS 1.3 session: AsyncRead + AsyncWrite over the record layer.
pub struct MiniTls<S> {
    io: S,
    recv: Option<CipherState>,
    send: Option<CipherState>,
    /// Raw received bytes not yet framed into a complete record.
    raw_in: Vec<u8>,
    /// Decrypted application data awaiting the caller.
    plain_out: VecDeque<u8>,
    /// Encrypted records not yet fully written.
    write_pending: VecDeque<u8>,
    /// Post-handshake handshake bytes being reassembled (NewSessionTicket).
    hs_post: Vec<u8>,
    res_master: Vec<u8>,
    exp_master: Vec<u8>,
    cipher: Cipher,
    /// True when the server accepted the offered resumption PSK.
    resumed: bool,
    ticket_sink: Option<TicketSink>,
    inbound_closed: bool,
    want_close_sent: bool,
}

impl<S> MiniTls<S> {
    /// RFC 5705 keying material export — used by the Umbra auth layer.
    pub fn export(&self, label: &[u8], context: Option<&[u8]>, out_len: usize) -> Result<Vec<u8>> {
        keys::export(self.cipher, &self.exp_master, label, context, out_len)
    }

    /// Whether this session was resumed via a stored PSK (1-RTT reconnect).
    pub fn resumed(&self) -> bool {
        self.resumed
    }

    fn process_post_hs(&mut self) {
        let buf = std::mem::take(&mut self.hs_post);
        let mut cur: &[u8] = &buf;
        while let Ok(Some((_, ty, body))) = hs::next_hs_msg(&mut cur) {
            if ty != hs::HS_NEW_SESSION_TICKET {
                continue; // key_update etc. are ignored
            }
            if let (Ok(t), Some(sink)) =
                (hs::parse_new_session_ticket(body), &self.ticket_sink)
            {
                if let Ok(psk) = keys::resumption_psk(self.cipher, &self.res_master, &t.nonce) {
                    sink.cfg.resumption.lock().unwrap().by_name.insert(
                        sink.name.clone(),
                        StoredPsk {
                            psk,
                            ticket: t.ticket,
                            age_add: t.age_add,
                            // RFC 8446 ticket lifetime is seconds; keep a
                            // 60 s safety margin before expiry.
                            lifetime_ms: (t.lifetime_secs as u64)
                                .saturating_mul(1000)
                                .saturating_sub(60_000),
                            obtained: Instant::now(),
                            cipher: self.cipher,
                        },
                    );
                }
            }
        }
        self.hs_post = cur.to_vec();
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncRead for MiniTls<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        loop {
            // 1. serve pending plaintext
            if !self.plain_out.is_empty() {
                let n = buf.remaining().min(self.plain_out.len());
                let mut tmp = Vec::with_capacity(n);
                for _ in 0..n {
                    tmp.push(self.plain_out.pop_front().unwrap());
                }
                buf.put_slice(&tmp);
                return Poll::Ready(Ok(()));
            }
            if self.inbound_closed {
                return Poll::Ready(Ok(()));
            }
            // 2. try to parse a complete record out of raw_in
            if self.raw_in.len() >= 5 {
                let len = u16::from_be_bytes([self.raw_in[3], self.raw_in[4]]) as usize;
                if self.raw_in.len() >= 5 + len {
                    let rec: Vec<u8> = self.raw_in.drain(..5 + len).collect();
                    let outer = rec[0];
                    if outer == CT_APPLICATION_DATA {
                        let inner = self
                            .recv
                            .as_mut()
                            .and_then(|c| c.decrypt(outer, &rec).ok());
                        match inner {
                            Some((CT_APPLICATION_DATA, data)) => {
                                self.plain_out.extend(data);
                                continue;
                            }
                            Some((CT_HANDSHAKE, data)) => {
                                self.hs_post.extend_from_slice(&data);
                                self.process_post_hs();
                                continue;
                            }
                            Some((CT_ALERT, _data)) => {
                                self.inbound_closed = true;
                                continue;
                            }
                            Some((_, _)) => continue,
                            None => {
                                return Poll::Ready(Err(io::Error::new(
                                    io::ErrorKind::InvalidData,
                                    "bad tls record",
                                )));
                            }
                        }
                    } else if outer == CT_ALERT {
                        self.inbound_closed = true;
                        continue;
                    } else if outer == CT_CHANGE_CIPHER_SPEC {
                        continue;
                    } else {
                        continue; // stray record type: ignore
                    }
                }
            }
            // 3. need more bytes
            let mut tmp = [0u8; 16384];
            let mut rb = ReadBuf::new(&mut tmp);
            match Pin::new(&mut self.io).poll_read(cx, &mut rb) {
                Poll::Ready(Ok(())) => {
                    if rb.filled().is_empty() {
                        self.inbound_closed = true;
                    } else {
                        self.raw_in.extend_from_slice(rb.filled());
                    }
                    continue;
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncWrite for MiniTls<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = &mut *self;
        // Flush pending encrypted output first.
        match drain_pending(this, cx) {
            Poll::Ready(Ok(())) => {}
            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
            Poll::Pending => return Poll::Pending,
        }
        // Encrypt the caller's chunk into a fresh record, buffer it, flush inline.
        let rec = match this
            .send
            .as_mut()
            .and_then(|c| c.encrypt(CT_APPLICATION_DATA, CT_APPLICATION_DATA, buf).ok())
        {
            Some(r) => r,
            None => {
                return Poll::Ready(Err(io::Error::other("tls closed")))
            }
        };
        this.write_pending.extend(rec);
        // Try to write immediately; the data is safely queued either way.
        let _ = drain_pending(this, cx);
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        let this = &mut *self;
        match drain_pending(this, cx) {
            Poll::Ready(Ok(())) => Pin::new(&mut this.io).poll_flush(cx),
            other => other,
        }
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        let this = &mut *self;
        if !this.want_close_sent {
            if let Some(c) = this.send.as_mut() {
                if let Ok(rec) = c.encrypt(CT_APPLICATION_DATA, CT_ALERT, &[0x01, 0x00]) {
                    this.write_pending.extend(rec);
                }
            }
            this.want_close_sent = true;
        }
        match drain_pending(this, cx) {
            Poll::Ready(Ok(())) => Pin::new(&mut this.io).poll_shutdown(cx),
            other => other,
        }
    }
}

/// Push as much buffered ciphertext as the socket takes right now.
fn drain_pending<S: AsyncWrite + Unpin>(
    this: &mut MiniTls<S>,
    cx: &mut TaskContext<'_>,
) -> Poll<io::Result<()>> {
    while !this.write_pending.is_empty() {
        match Pin::new(&mut this.io).poll_write(cx, this.write_pending.make_contiguous()) {
            Poll::Ready(Ok(0)) => {
                return Poll::Ready(Err(io::Error::new(io::ErrorKind::WriteZero, "tls write")))
            }
            Poll::Ready(Ok(n)) => {
                this.write_pending.drain(..n);
            }
            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
            Poll::Pending => return Poll::Pending,
        }
    }
    Poll::Ready(Ok(()))
}
