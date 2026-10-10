//! ClientHello construction with byte-level control — Chrome fingerprint.
//!
//! Mirrors a real Chrome (~v120-era) ClientHello: identical extension set,
//! GREASE values in all the same positions Chrome greases, ALPS for h2,
//! ECH GREASE, and (like Chrome >= 110) a randomly permuted extension order.

use rand::seq::SliceRandom;
use rand::RngCore;

/// GREASE values are 0x?a?a with both nibbles equal (0x0a0a..0xfafa).
fn grease(rng: &mut impl RngCore) -> u16 {
    let i = (rng.next_u32() & 0xf) as u16;
    let b = (i << 4) | 0x0a; // nibble pair "i a"
    (b << 8) | b
}

struct Ext {
    ty: u16,
    data: Vec<u8>,
}

fn ext(ty: u16, data: Vec<u8>) -> Ext {
    Ext { ty, data }
}

fn ext_u8list(ty: u16, items: &[u8]) -> Ext {
    let mut d = Vec::with_capacity(1 + items.len());
    d.push(items.len() as u8);
    d.extend_from_slice(items);
    ext(ty, d)
}

fn ext_u16list(ty: u16, items: &[u16]) -> Ext {
    let mut d = Vec::with_capacity(2 + 2 * items.len());
    d.extend_from_slice(&(2 * items.len() as u16).to_be_bytes());
    for i in items {
        d.extend_from_slice(&i.to_be_bytes());
    }
    ext(ty, d)
}

fn ext_server_name(name: &str) -> Ext {
    let h = name.as_bytes();
    let mut d = Vec::with_capacity(2 + 3 + h.len());
    d.extend_from_slice(&((3 + h.len()) as u16).to_be_bytes());
    d.push(0); // host_name
    d.extend_from_slice(&(h.len() as u16).to_be_bytes());
    d.extend_from_slice(h);
    ext(0x0000, d)
}

fn ext_alpn(protos: &[Vec<u8>]) -> Ext {
    let mut list = Vec::new();
    for p in protos {
        list.push(p.len() as u8);
        list.extend_from_slice(p);
    }
    let mut d = Vec::with_capacity(2 + list.len());
    d.extend_from_slice(&(list.len() as u16).to_be_bytes());
    d.extend_from_slice(&list);
    ext(0x0010, d)
}

fn ext_status_request() -> Ext {
    // OCSP: responder_id_list empty, extensions empty
    ext(0x0005, vec![0x01, 0x00, 0x00, 0x00, 0x00])
}

fn ext_key_share(shares: &[(u16, Vec<u8>)], group_grease: u16, rng: &mut impl RngCore) -> Ext {
    let mut list = Vec::new();
    // Chrome leads with a GREASE key share carrying 1 random byte. The group
    // must be the *same* GREASE value advertised in supported_groups, like
    // BoringSSL's ssl_grease_group — strict servers (OpenSSL) reject shares
    // whose group was not offered in supported_groups.
    list.extend_from_slice(&group_grease.to_be_bytes());
    list.extend_from_slice(&1u16.to_be_bytes());
    list.push(rng.next_u32() as u8);
    for (group, key) in shares {
        list.extend_from_slice(&group.to_be_bytes());
        list.extend_from_slice(&(key.len() as u16).to_be_bytes());
        list.extend_from_slice(key);
    }
    let mut d = Vec::with_capacity(2 + list.len());
    d.extend_from_slice(&(list.len() as u16).to_be_bytes());
    d.extend_from_slice(&list);
    ext(0x0033, d)
}

fn ext_supported_groups(group_grease: u16) -> Ext {
    ext_u16list(
        0x000a,
        &[
            group_grease,
            0x001d, // x25519
            0x0017, // secp256r1
            0x0018, // secp384r1
        ],
    )
}

fn ext_supported_versions(rng: &mut impl RngCore) -> Ext {
    let items = vec![grease(rng), 0x0304, 0x0303];
    let mut d = Vec::with_capacity(1 + 2 * items.len());
    d.push((2 * items.len()) as u8);
    for i in items {
        d.extend_from_slice(&i.to_be_bytes());
    }
    ext(0x002b, d)
}

const SIG_ALGS: [u16; 9] = [
    0x0403, // ecdsa_secp256r1_sha256
    0x0807, // ed25519
    0x0503, // ecdsa_secp384r1_sha384
    0x0804, // rsa_pss_rsae_sha256
    0x0401, // rsa_pkcs1_sha256
    0x0805, // rsa_pss_rsae_sha384
    0x0501, // rsa_pkcs1_sha384
    0x0806, // rsa_pss_rsae_sha512
    0x0601, // rsa_pkcs1_sha512
];

fn ext_signature_algorithms() -> Ext {
    ext_u16list(0x000d, &SIG_ALGS)
}

fn ext_signature_algorithms_cert() -> Ext {
    ext_u16list(0x0032, &SIG_ALGS)
}

fn ext_delegated_credentials() -> Ext {
    // SignatureSchemeList, same preferred order Chrome uses.
    ext_u16list(
        0x0022,
        &[0x0403, 0x0807, 0x0503, 0x0804, 0x0805, 0x0806],
    )
}

/// ALPS for h2 — the SETTINGS payload Chrome advertises.
fn ext_alps() -> Ext {
    // MAX_CONCURRENT_STREAMS=100, INITIAL_WINDOW_SIZE=6291456
    let data: &[u8] = &[0x00, 0x03, 0x00, 0x00, 0x00, 0x64, 0x00, 0x04, 0x00, 0x60, 0x00, 0x00];
    ext(0x4469, data.to_vec())
}

/// Structurally-valid ECH GREASE (draft-ietf-tls-esni-13 outer format).
fn ext_ech_grease(rng: &mut impl RngCore) -> Ext {
    let enc_len = 32usize;
    let payload_len = 96 + (rng.next_u32() as usize % 128);
    let mut d = Vec::with_capacity(1 + 4 + 1 + 2 + enc_len + 2 + payload_len);
    d.push(0x00); // outer
    d.extend_from_slice(&0x0001u16.to_be_bytes()); // kdf hkdf_sha256
    d.extend_from_slice(&0x0001u16.to_be_bytes()); // aead aes_128_gcm
    d.push(rng.next_u32() as u8); // config_id
    d.extend_from_slice(&(enc_len as u16).to_be_bytes());
    let mut junk = vec![0u8; enc_len + payload_len];
    rng.fill_bytes(&mut junk);
    d.extend_from_slice(&junk[..enc_len]);
    d.extend_from_slice(&(payload_len as u16).to_be_bytes());
    d.extend_from_slice(&junk[enc_len..]);
    ext(0xfe0d, d)
}

fn ext_cookie(cookie: &[u8]) -> Ext {
    let mut d = Vec::with_capacity(2 + cookie.len());
    d.extend_from_slice(&(cookie.len() as u16).to_be_bytes());
    d.extend_from_slice(cookie);
    ext(0x002c, d)
}

/// Resumption parameters for the pre_shared_key extension.
pub struct PskOffer {
    pub identity: Vec<u8>,
    pub obfuscated_age: u32,
    /// Length of the binder to emit (32 or 48 depending on the PSK's suite).
    pub binder_len: usize,
}

pub struct HelloParams<'a> {
    pub server_name: &'a str,
    pub random: [u8; 32],
    /// Middlebox-compat session id (32 random bytes, echo'ed by server).
    pub session_id: [u8; 32],
    /// (group, public_key) pairs to put in key_share.
    pub shares: Vec<(u16, Vec<u8>)>,
    pub alpn: Vec<Vec<u8>>,
    pub psk: Option<PskOffer>,
    /// HRR only: echo cookie extension.
    pub cookie: Option<Vec<u8>>,
}

pub struct BuiltHello {
    /// Complete handshake message (header + body).
    pub message: Vec<u8>,
    /// Offset within `message` where the PSK binders list begins —
    /// the truncated ClientHello for binder computation ends here.
    pub binder_offset: Option<usize>,
}

/// Build a Chrome-fingerprinted ClientHello.
pub fn build(params: &HelloParams) -> BuiltHello {
    let rng = &mut rand::thread_rng();

    let mut exts: Vec<Ext> = Vec::new();

    // One GREASE extension with small random payload, like Chrome.
    let g1 = grease(rng);
    exts.push(ext(g1, vec![0u8; (rng.next_u32() % 4) as usize]));

    // BoringSSL's ssl_grease_group: one GREASE value shared between the
    // supported_groups list and the GREASE key-share entry.
    let group_grease = grease(rng);

    exts.push(ext_server_name(params.server_name));
    exts.push(ext(0x0017, vec![])); // extended_master_secret
    exts.push(ext(0xff01, vec![0x00])); // renegotiation_info
    exts.push(ext_supported_groups(group_grease));
    exts.push(ext_u8list(0x000b, &[0x00])); // ec_point_formats: uncompressed
    exts.push(ext(0x0023, vec![])); // session_ticket
    exts.push(ext_alpn(&params.alpn));
    exts.push(ext_status_request());
    exts.push(ext_signature_algorithms());
    exts.push(ext_signature_algorithms_cert());
    exts.push(ext_delegated_credentials());
    exts.push(ext(0x0012, vec![])); // signed_certificate_timestamp
    exts.push(ext_key_share(&params.shares, group_grease, rng));
    exts.push(ext_u8list(0x002d, &[0x01])); // psk_key_exchange_modes: psk_dhe_ke
    exts.push(ext_supported_versions(rng));
    // compress_certificate: u8 byte-len + u16 algorithm ids (Chrome: brotli)
    exts.push(ext(0x001b, vec![0x02, 0x00, 0x02]));
    exts.push(ext_alps());
    exts.push(ext_ech_grease(rng));
    if let Some(c) = &params.cookie {
        exts.push(ext_cookie(c));
    }

    // pre_shared_key must be the final extension (binders cover the transcript).
    let mut psk_binder_off: Option<usize> = None;
    if let Some(psk) = &params.psk {
        // PskIdentity: opaque identity<1..2^16-1> + uint32 obfuscated_ticket_age
        let mut id_list = Vec::with_capacity(6 + psk.identity.len());
        id_list.extend_from_slice(&(psk.identity.len() as u16).to_be_bytes());
        id_list.extend_from_slice(&psk.identity);
        id_list.extend_from_slice(&psk.obfuscated_age.to_be_bytes());
        let binders_len = 1 + psk.binder_len; // u8 len + binder
        let mut d = Vec::with_capacity(2 + id_list.len() + 2 + binders_len);
        d.extend_from_slice(&(id_list.len() as u16).to_be_bytes());
        d.extend_from_slice(&id_list);
        // binder list: placeholder, patched by caller after transcript hash
        psk_binder_off = Some(d.len());
        d.extend_from_slice(&(binders_len as u16).to_be_bytes());
        d.push(psk.binder_len as u8);
        d.extend(std::iter::repeat_n(0u8, psk.binder_len));
        exts.push(ext(0x0029, d));
    }

    // Chrome >= 110 permutes all extensions; keep only the psk last.
    let (psk_ext, rest): (Vec<Ext>, Vec<Ext>) = if psk_binder_off.is_some() {
        let last = exts.pop().unwrap();
        (vec![last], exts)
    } else {
        (vec![], exts)
    };
    let mut ordered = rest;
    ordered.shuffle(&mut rand::thread_rng());
    ordered.extend(psk_ext);

    // Serialize body.
    let mut body = Vec::with_capacity(512);
    body.extend_from_slice(&[0x03, 0x03]); // legacy_version
    body.extend_from_slice(&params.random);
    body.push(params.session_id.len() as u8);
    body.extend_from_slice(&params.session_id);
    // Cipher suites: GREASE, then Chrome's full offer — TLS 1.3 suites first,
    // then the TLS 1.2 ECDHE/RSA legacy list every real Chrome sends.
    let suites: [u16; 15] = [
        0x1301, 0x1302, 0x1303, // tls13 aes-128-gcm, aes-256-gcm, chacha20
        0xc02b, 0xc02f, 0xc02c, 0xc030, // ecdhe-ecdsa/rsa aes128/256 gcm
        0xcca9, 0xcca8, // ecdhe ecdsa/rsa chacha20
        0xc013, 0xc014, // ecdhe rsa aes128/256 cbc
        0x009c, 0x009d, // rsa aes128/256 gcm
        0x002f, 0x0035, // rsa aes128/256 cbc
    ];
    let mut cs = Vec::with_capacity(2 + 2 * suites.len());
    cs.extend_from_slice(&grease(rng).to_be_bytes());
    for s in suites {
        cs.extend_from_slice(&s.to_be_bytes());
    }
    body.extend_from_slice(&(cs.len() as u16).to_be_bytes());
    body.extend_from_slice(&cs);
    body.push(1);
    body.push(0); // null compression

    let mut ext_bytes = Vec::new();
    for e in &ordered {
        ext_bytes.extend_from_slice(&e.ty.to_be_bytes());
        ext_bytes.extend_from_slice(&(e.data.len() as u16).to_be_bytes());
        ext_bytes.extend_from_slice(&e.data);
    }
    body.extend_from_slice(&(ext_bytes.len() as u16).to_be_bytes());
    body.extend_from_slice(&ext_bytes);

    // Locate the binders position within the *serialized message*:
    // 4 (hs header) + body prefix + psk ext data offset + binder_off.
    let binder_offset = psk_binder_off.map(|off| {
        let mut pos = 4 + body.len() - ext_bytes.len();
        for e in &ordered {
            if e.ty == 0x0029 {
                return pos + 4 + off;
            }
            pos += 4 + e.data.len();
        }
        unreachable!()
    });

    let mut message = Vec::with_capacity(4 + body.len());
    message.extend_from_slice(&super::hs::hs_header(super::hs::HS_CLIENT_HELLO, body.len()));
    message.extend_from_slice(&body);

    BuiltHello {
        message,
        binder_offset,
    }
}
