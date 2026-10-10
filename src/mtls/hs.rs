//! TLS 1.3 handshake message parsing (read-only views + small helpers).

use anyhow::{bail, Context, Result};

pub const HS_CLIENT_HELLO: u8 = 1;
pub const HS_SERVER_HELLO: u8 = 2;
pub const HS_NEW_SESSION_TICKET: u8 = 4;
pub const HS_ENCRYPTED_EXTENSIONS: u8 = 8;
pub const HS_CERTIFICATE: u8 = 11;
pub const HS_CERTIFICATE_VERIFY: u8 = 15;
pub const HS_FINISHED: u8 = 20;

/// Handshake message header: type + u24 length.
pub fn hs_header(ty: u8, body_len: usize) -> [u8; 4] {
    let l = body_len as u32;
    [ty, (l >> 16) as u8, (l >> 8) as u8, l as u8]
}

/// Wrap a body into a complete handshake message.
pub fn hs_msg(ty: u8, body: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(4 + body.len());
    v.extend_from_slice(&hs_header(ty, body.len()));
    v.extend_from_slice(body);
    v
}

/// (full_message_bytes_including_header, type, body)
pub type HsMsg<'a> = (&'a [u8], u8, &'a [u8]);

/// Iterator over handshake messages inside a byte buffer.
pub fn next_hs_msg<'a>(buf: &mut &'a [u8]) -> Result<Option<HsMsg<'a>>> {
    if buf.len() < 4 {
        return Ok(None);
    }
    let len = u32::from_be_bytes([0, buf[1], buf[2], buf[3]]) as usize;
    if buf.len() < 4 + len {
        return Ok(None);
    }
    let (msg, rest) = buf.split_at(4 + len);
    *buf = rest;
    Ok(Some((msg, msg[0], &msg[4..])))
}

pub struct Ext<'a> {
    pub ty: u16,
    pub data: &'a [u8],
}

/// Iterate extension entries (u16 type + u16 len + data).
pub fn parse_extensions(mut buf: &[u8]) -> Result<Vec<Ext<'_>>> {
    let mut out = Vec::new();
    while buf.len() >= 4 {
        let ty = u16::from_be_bytes([buf[0], buf[1]]);
        let len = u16::from_be_bytes([buf[2], buf[3]]) as usize;
        buf = &buf[4..];
        if buf.len() < len {
            bail!("extension {ty:#x} truncated");
        }
        out.push(Ext {
            ty,
            data: &buf[..len],
        });
        buf = &buf[len..];
    }
    Ok(out)
}

pub struct ServerHello {
    pub is_hrr: bool,
    pub cipher: u16,
    pub key_share_group: Option<u16>,
    pub server_key_share: Vec<u8>,
    pub selected_psk: Option<u16>,
    /// HRR only: the group the server wants + cookie to echo.
    pub hrr_group: Option<u16>,
    pub hrr_cookie: Vec<u8>,
}

const HRR_MAGIC: [u8; 32] = [
    0xcf, 0x21, 0xad, 0x74, 0xe5, 0x9a, 0x61, 0x11, 0xbe, 0x1d, 0x8c, 0x02, 0x1e, 0x65, 0xb8,
    0x91, 0xc2, 0xa2, 0x11, 0x16, 0x7a, 0xbb, 0x8c, 0x5e, 0x07, 0x9e, 0x09, 0xe2, 0xc8, 0xa8,
    0x33, 0x9c,
];

pub fn parse_server_hello(body: &[u8]) -> Result<ServerHello> {
    if body.len() < 38 {
        bail!("short server_hello");
    }
    let random: &[u8] = &body[2..34];
    let is_hrr = random == HRR_MAGIC;
    let sid_len = body[34] as usize;
    let mut cur = &body[35..];
    if cur.len() < sid_len + 3 {
        bail!("short sid");
    }
    cur = &cur[sid_len..];
    let cipher = u16::from_be_bytes([cur[0], cur[1]]);
    let _comp = cur[2];
    cur = &cur[3..];
    let ext_len = u16::from_be_bytes([cur[0], cur[1]]) as usize;
    cur = &cur[2..];
    if cur.len() < ext_len {
        bail!("short exts");
    }
    let exts = parse_extensions(&cur[..ext_len])?;

    let mut sh = ServerHello {
        is_hrr,
        cipher,
        key_share_group: None,
        server_key_share: Vec::new(),
        selected_psk: None,
        hrr_group: None,
        hrr_cookie: Vec::new(),
    };
    for e in exts {
        match e.ty {
            0x002b => {
                // supported_versions — ignore contents (always 1.3 for us)
            }
            0x0033 => {
                // key_share
                if e.data.len() < 4 {
                    bail!("short key_share");
                }
                let group = u16::from_be_bytes([e.data[0], e.data[1]]);
                let klen = u16::from_be_bytes([e.data[2], e.data[3]]) as usize;
                if is_hrr {
                    sh.hrr_group = Some(group); // HRR carries just the group
                } else {
                    if e.data.len() < 4 + klen {
                        bail!("short share");
                    }
                    sh.key_share_group = Some(group);
                    sh.server_key_share = e.data[4..4 + klen].to_vec();
                }
            }
            0x0029 => {
                // pre_shared_key: selected_identity u16
                if e.data.len() >= 2 {
                    sh.selected_psk = Some(u16::from_be_bytes([e.data[0], e.data[1]]));
                }
            }
            // cookie (HRR): u16 len + cookie
            0x002c if e.data.len() >= 2 => {
                let l = u16::from_be_bytes([e.data[0], e.data[1]]) as usize;
                sh.hrr_cookie = e.data[2..2 + l.min(e.data.len() - 2)].to_vec();
            }
            _ => {}
        }
    }
    Ok(sh)
}

/// certificate_list entry: u24 len | der | u16 exts_len | exts
pub fn parse_certificate(body: &[u8]) -> Result<(Vec<u8>, Vec<Vec<u8>>)> {
    if body.is_empty() {
        bail!("empty certificate msg");
    }
    let ctx_len = body[0] as usize;
    if body.len() < 1 + ctx_len + 3 {
        bail!("short certificate msg");
    }
    let mut cur = &body[1 + ctx_len..];
    let list_len = u32::from_be_bytes([0, cur[0], cur[1], cur[2]]) as usize;
    cur = &cur[3..];
    if cur.len() < list_len {
        bail!("short cert list");
    }
    cur = &cur[..list_len];
    let mut ee = None;
    let mut inters = Vec::new();
    while !cur.is_empty() {
        if cur.len() < 3 {
            bail!("short cert entry");
        }
        let clen = u32::from_be_bytes([0, cur[0], cur[1], cur[2]]) as usize;
        cur = &cur[3..];
        if cur.len() < clen + 2 {
            bail!("short cert data");
        }
        let der = cur[..clen].to_vec();
        cur = &cur[clen..];
        let elen = u16::from_be_bytes([cur[0], cur[1]]) as usize;
        cur = &cur[2..];
        if cur.len() < elen {
            bail!("short cert exts");
        }
        cur = &cur[elen..];
        if ee.is_none() {
            ee = Some(der);
        } else {
            inters.push(der);
        }
    }
    Ok((ee.context("no end-entity cert")?, inters))
}

pub fn parse_cert_verify(body: &[u8]) -> Result<(u16, Vec<u8>)> {
    if body.len() < 4 {
        bail!("short certificate_verify");
    }
    let scheme = u16::from_be_bytes([body[0], body[1]]);
    let slen = u16::from_be_bytes([body[2], body[3]]) as usize;
    if body.len() < 4 + slen {
        bail!("short signature");
    }
    Ok((scheme, body[4..4 + slen].to_vec()))
}

pub struct Ticket {
    /// RFC 8446 §4.6.1: lifetime in seconds (max 604800 = 7 days).
    pub lifetime_secs: u32,
    pub age_add: u32,
    pub nonce: Vec<u8>,
    pub ticket: Vec<u8>,
}

pub fn parse_new_session_ticket(body: &[u8]) -> Result<Ticket> {
    if body.len() < 15 {
        bail!("short new_session_ticket");
    }
    let lifetime_secs = u32::from_be_bytes(body[0..4].try_into().unwrap());
    let age_add = u32::from_be_bytes(body[4..8].try_into().unwrap());
    let nlen = body[8] as usize;
    if body.len() < 9 + nlen + 2 {
        bail!("short nst nonce");
    }
    let nonce = body[9..9 + nlen].to_vec();
    let mut cur = &body[9 + nlen..];
    let tlen = u16::from_be_bytes([cur[0], cur[1]]) as usize;
    cur = &cur[2..];
    if cur.len() < tlen + 2 {
        bail!("short ticket");
    }
    let ticket = cur[..tlen].to_vec();
    Ok(Ticket {
        lifetime_secs,
        age_add,
        nonce,
        ticket,
    })
}

/// Pull ALPN protocol out of EncryptedExtensions (extension type 0x0010).
pub fn parse_ee_alpn(body: &[u8]) -> Result<Option<Vec<u8>>> {
    if body.len() < 2 {
        return Ok(None);
    }
    let elen = u16::from_be_bytes([body[0], body[1]]) as usize;
    if body.len() < 2 + elen {
        bail!("short ee");
    }
    for e in parse_extensions(&body[2..2 + elen])? {
        if e.ty == 0x0010 && e.data.len() >= 3 {
            let plen = e.data[2] as usize;
            if e.data.len() >= 3 + plen {
                return Ok(Some(e.data[3..3 + plen].to_vec()));
            }
        }
    }
    Ok(None)
}

/// Alert description -> human string for the common cases.
pub fn alert_name(code: u8) -> &'static str {
    match code {
        0 => "close_notify",
        10 => "unexpected_message",
        20 => "record_overflow",
        22 => "handshake_failure",
        40 => "handshake_failure",
        42 => "bad_certificate",
        43 => "unsupported_certificate",
        44 => "certificate_revoked",
        45 => "certificate_expired",
        46 => "certificate_unknown",
        47 => "illegal_parameter",
        48 => "unknown_ca",
        49 => "access_denied",
        50 => "decode_error",
        51 => "decrypt_error",
        70 => "protocol_version",
        71 => "insufficient_security",
        80 => "internal_error",
        86 => "inappropriate_fallback",
        90 => "user_canceled",
        109 => "missing_extension",
        110 => "unsupported_extension",
        112 => "unrecognized_name",
        113 => "bad_certificate_status_response",
        115 => "unknown_psk_identity",
        116 => "certificate_required",
        120 => "no_application_protocol",
        _ => "unknown_alert",
    }
}
