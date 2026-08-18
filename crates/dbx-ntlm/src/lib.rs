//! Pure-Rust NTLMSSP for TDS integrated (Windows) authentication.
//!
//! Scope is deliberately narrow: exactly what a TDS LOGIN7/SSPI exchange
//! needs — Type 1 (negotiate), Type 2 (parse), Type 3 (authenticate) with
//! NTLMv2 responses, a REAL LMv2 (SQL Server's DC-side validation rejects a
//! zeroed LMv2 even though the spec calls it optional), and a proper MIC
//! (required whenever the server sends MsvAvTimestamp in its target info).
//!
//! No SSPI, no GSSAPI, no system libraries — works on musl static builds
//! and enables pass-the-hash by construction (the NT hash IS the key).
//!
//! Post-login TDS traffic is protected by TLS, so NTLM signing/sealing
//! (key exchange, session security on messages) is intentionally omitted.

use hmac::{Hmac, Mac};
use md4::{Digest, Md4};
use md5::Md5;

pub const NTLMSSP_SIG: &[u8; 8] = b"NTLMSSP\0";
pub const MSG_NEGOTIATE: u32 = 1;
pub const MSG_CHALLENGE: u32 = 2;
pub const MSG_AUTHENTICATE: u32 = 3;

mod flags {
    pub const NEGOTIATE_UNICODE: u32 = 0x0000_0001;
    pub const REQUEST_TARGET: u32 = 0x0000_0004;
    pub const NEGOTIATE_NTLM: u32 = 0x0000_0200;
    pub const NEGOTIATE_EXTENDED_SESSION_SECURITY: u32 = 0x0008_0000;
    pub const NEGOTIATE_TARGET_INFO: u32 = 0x0080_0000;
    pub const NEGOTIATE_VERSION: u32 = 0x0200_0000;
    pub const NEGOTIATE_128: u32 = 0x2000_0000;
    pub const NEGOTIATE_56: u32 = 0x8000_0000;
}

/// What we advertise in Type 1.
const NEGOTIATE_FLAGS: u32 = flags::NEGOTIATE_UNICODE
    | flags::REQUEST_TARGET
    | flags::NEGOTIATE_NTLM
    | flags::NEGOTIATE_EXTENDED_SESSION_SECURITY
    | flags::NEGOTIATE_TARGET_INFO
    | flags::NEGOTIATE_VERSION
    | flags::NEGOTIATE_128
    | flags::NEGOTIATE_56;

/// OS version block: 6.1 (build 7601), NTLMSSP_REVISION_W2K3.
const VERSION: [u8; 8] = [6, 1, 0xb1, 0x1d, 0, 0, 0, 0x0f];

#[derive(Debug, thiserror::Error)]
pub enum NtlmError {
    #[error("not an NTLMSSP message (bad signature)")]
    BadSignature,
    #[error("expected message type {expected}, got {got}")]
    WrongType { expected: u32, got: u32 },
    #[error("truncated message: need {need} bytes, have {have}")]
    Truncated { need: usize, have: usize },
}

// ---------------------------------------------------------------- credentials

/// The NT hash is the credential. Password is just one way to derive it —
/// pass-the-hash skips that step entirely.
#[derive(Debug, Clone)]
pub enum NtlmSecret {
    Password(String),
    NtHash([u8; 16]),
}

impl NtlmSecret {
    fn nt_hash(&self) -> [u8; 16] {
        match self {
            NtlmSecret::Password(pw) => nt_hash(pw),
            NtlmSecret::NtHash(h) => *h,
        }
    }
}

#[derive(Debug, Clone)]
pub struct NtlmCredential {
    pub domain: String,
    pub username: String,
    pub secret: NtlmSecret,
}

// ---------------------------------------------------------------- crypto core

/// NT hash: MD4(UTF-16LE(password)).
pub fn nt_hash(password: &str) -> [u8; 16] {
    let mut h = Md4::new();
    h.update(utf16le(password));
    h.finalize().into()
}

fn utf16le(s: &str) -> Vec<u8> {
    s.encode_utf16().flat_map(|c| c.to_le_bytes()).collect()
}

fn hmac_md5(key: &[u8], data: &[u8]) -> [u8; 16] {
    let mut m = <Hmac<Md5> as Mac>::new_from_slice(key).expect("any key length");
    m.update(data);
    m.finalize().into_bytes().into()
}

/// NTOWFv2 = HMAC_MD5(NT hash, UTF-16LE(UPPER(user) + domain)).
fn ntowfv2(nth: &[u8; 16], user: &str, domain: &str) -> [u8; 16] {
    hmac_md5(nth, &utf16le(&format!("{}{}", user.to_uppercase(), domain)))
}

/// NTLMv2 + LMv2 responses and the session base key.
/// Returns (nt_response, lm_response, session_base_key).
fn ntlmv2_responses(
    key: &[u8; 16],
    server_challenge: &[u8; 8],
    client_challenge: &[u8; 8],
    timestamp: &[u8; 8],
    target_info: &[u8],
) -> (Vec<u8>, Vec<u8>, [u8; 16]) {
    let mut blob = Vec::new();
    blob.extend_from_slice(&[0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]); // resp type, hi
    blob.extend_from_slice(timestamp);
    blob.extend_from_slice(client_challenge);
    blob.extend_from_slice(&[0x00; 4]); // reserved
    blob.extend_from_slice(target_info);
    blob.extend_from_slice(&[0x00; 4]); // reserved

    let mut sc_blob = Vec::with_capacity(8 + blob.len());
    sc_blob.extend_from_slice(server_challenge);
    sc_blob.extend_from_slice(&blob);
    let nt_proof = hmac_md5(key, &sc_blob);

    let mut nt_response = Vec::with_capacity(16 + blob.len());
    nt_response.extend_from_slice(&nt_proof);
    nt_response.extend_from_slice(&blob);

    let mut sc_cc = Vec::with_capacity(16);
    sc_cc.extend_from_slice(server_challenge);
    sc_cc.extend_from_slice(client_challenge);
    let lm_hmac = hmac_md5(key, &sc_cc);
    let mut lm_response = Vec::with_capacity(24);
    lm_response.extend_from_slice(&lm_hmac);
    lm_response.extend_from_slice(client_challenge);

    let session_base_key = hmac_md5(key, &nt_proof);
    (nt_response, lm_response, session_base_key)
}

/// MIC = HMAC_MD5(ExportedSessionKey, type1 || type2 || type3[MIC zeroed]).
/// No key exchange is negotiated, so ExportedSessionKey == SessionBaseKey.
fn compute_mic(session_key: &[u8; 16], type1: &[u8], type2: &[u8], type3_zeroed: &[u8]) -> [u8; 16] {
    let mut data = Vec::with_capacity(type1.len() + type2.len() + type3_zeroed.len());
    data.extend_from_slice(type1);
    data.extend_from_slice(type2);
    data.extend_from_slice(type3_zeroed);
    hmac_md5(session_key, &data)
}

// ---------------------------------------------------------------- wire format

fn put_fields(buf: &mut Vec<u8>, data: &[u8], offset: u32) {
    buf.extend_from_slice(&(data.len() as u16).to_le_bytes());
    buf.extend_from_slice(&(data.len() as u16).to_le_bytes());
    buf.extend_from_slice(&offset.to_le_bytes());
}

fn read_fields(msg: &[u8], at: usize) -> Result<(usize, usize), NtlmError> {
    if msg.len() < at + 8 {
        return Err(NtlmError::Truncated { need: at + 8, have: msg.len() });
    }
    let len = u16::from_le_bytes([msg[at], msg[at + 1]]) as usize;
    let off = u32::from_le_bytes([msg[at + 4], msg[at + 5], msg[at + 6], msg[at + 7]]) as usize;
    Ok((len, off))
}

fn slice_at(msg: &[u8], len: usize, off: usize) -> Result<&[u8], NtlmError> {
    if len == 0 {
        return Ok(&[]);
    }
    msg.get(off..off + len)
        .ok_or(NtlmError::Truncated { need: off + len, have: msg.len() })
}

/// Parsed Type 2 CHALLENGE.
pub struct Challenge {
    pub flags: u32,
    pub server_challenge: [u8; 8],
    pub target_info: Vec<u8>,
    /// MsvAvNbDomainName from target info, if present.
    pub nb_domain: Option<String>,
    /// MsvAvTimestamp from target info, if present (its presence makes the MIC mandatory).
    pub timestamp: Option<[u8; 8]>,
}

pub fn parse_challenge(msg: &[u8]) -> Result<Challenge, NtlmError> {
    if msg.len() < 32 {
        return Err(NtlmError::Truncated { need: 32, have: msg.len() });
    }
    if &msg[..8] != NTLMSSP_SIG {
        return Err(NtlmError::BadSignature);
    }
    let ty = u32::from_le_bytes([msg[8], msg[9], msg[10], msg[11]]);
    if ty != MSG_CHALLENGE {
        return Err(NtlmError::WrongType { expected: MSG_CHALLENGE, got: ty });
    }
    let flags = u32::from_le_bytes([msg[20], msg[21], msg[22], msg[23]]);
    let server_challenge: [u8; 8] = msg[24..32].try_into().unwrap();

    let (ti_len, ti_off) = read_fields(msg, 40).unwrap_or((0, 0));
    let target_info = if ti_len > 0 && msg.len() >= 48 {
        slice_at(msg, ti_len, ti_off)?.to_vec()
    } else {
        Vec::new()
    };

    // walk AV pairs
    let mut nb_domain = None;
    let mut timestamp = None;
    let mut i = 0;
    while i + 4 <= target_info.len() {
        let id = u16::from_le_bytes([target_info[i], target_info[i + 1]]);
        let len = u16::from_le_bytes([target_info[i + 2], target_info[i + 3]]) as usize;
        i += 4;
        if id == 0 || i + len > target_info.len() {
            break;
        }
        match id {
            2 => {
                nb_domain = Some(
                    String::from_utf16_lossy(
                        &target_info[i..i + len]
                            .chunks_exact(2)
                            .map(|c| u16::from_le_bytes([c[0], c[1]]))
                            .collect::<Vec<_>>(),
                    ),
                );
            }
            7 if len == 8 => {
                timestamp = Some(target_info[i..i + 8].try_into().unwrap());
            }
            _ => {}
        }
        i += len;
    }

    Ok(Challenge { flags, server_challenge, target_info, nb_domain, timestamp })
}

// ---------------------------------------------------------------- the client

pub struct NtlmClient {
    cred: NtlmCredential,
    client_challenge: [u8; 8],
    workstation: String,
}

impl NtlmClient {
    /// Random client challenge — production path.
    pub fn new(cred: NtlmCredential) -> Self {
        let mut cc = [0u8; 8];
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut cc);
        Self { cred, client_challenge: cc, workstation: String::new() }
    }

    /// Deterministic — tests and known-answer verification.
    pub fn with_client_challenge(cred: NtlmCredential, client_challenge: [u8; 8]) -> Self {
        Self { cred, client_challenge, workstation: String::new() }
    }

    /// Type 1 NEGOTIATE.
    pub fn negotiate(&self) -> Vec<u8> {
        let domain = utf16le(&self.cred.domain);
        let ws = utf16le(&self.workstation);

        let mut m = Vec::new();
        m.extend_from_slice(NTLMSSP_SIG);
        m.extend_from_slice(&MSG_NEGOTIATE.to_le_bytes());
        m.extend_from_slice(&NEGOTIATE_FLAGS.to_le_bytes());
        let payload_off = 40u32;
        put_fields(&mut m, &domain, payload_off);
        put_fields(&mut m, &ws, payload_off + domain.len() as u32);
        m.extend_from_slice(&VERSION);
        m.extend_from_slice(&domain);
        m.extend_from_slice(&ws);
        m
    }

    /// Type 2 in, Type 3 AUTHENTICATE out (NTLMv2 + LMv2 + MIC).
    pub fn authenticate(&self, type2: &[u8]) -> Result<Vec<u8>, NtlmError> {
        let ch = parse_challenge(type2)?;

        let domain = match self.cred.domain.is_empty() {
            false => self.cred.domain.clone(),
            true => ch.nb_domain.clone().unwrap_or_default(),
        };

        // If the server sent MsvAvTimestamp, the blob must reuse it
        // (and the MIC becomes mandatory — we always send one anyway).
        let timestamp: [u8; 8] = ch.timestamp.unwrap_or_else(current_filetime);

        let nth = self.cred.secret.nt_hash();
        let key = ntowfv2(&nth, &self.cred.username, &domain);
        let (nt_resp, lm_resp, session_key) = ntlmv2_responses(
            &key,
            &ch.server_challenge,
            &self.client_challenge,
            &timestamp,
            &ch.target_info,
        );

        let dom_b = utf16le(&domain);
        let user_b = utf16le(&self.cred.username);
        let ws_b = utf16le(&self.workstation);

        let mut m = Vec::new();
        m.extend_from_slice(NTLMSSP_SIG);
        m.extend_from_slice(&MSG_AUTHENTICATE.to_le_bytes());

        let payload_off = 88u32; // header(12) + 6 field-pairs(48) + flags(4) + version(8) + MIC(16)
        let mut off = payload_off;
        for data in [&lm_resp[..], &nt_resp[..], &dom_b[..], &user_b[..], &ws_b[..], &[][..]] {
            put_fields(&mut m, data, off);
            off += data.len() as u32;
        }
        // negotiated flags: echo server flags minus what we never offered
        m.extend_from_slice(&(ch.flags & NEGOTIATE_FLAGS).to_le_bytes());
        m.extend_from_slice(&VERSION);
        m.extend_from_slice(&[0u8; 16]); // MIC placeholder

        m.extend_from_slice(&lm_resp);
        m.extend_from_slice(&nt_resp);
        m.extend_from_slice(&dom_b);
        m.extend_from_slice(&user_b);
        m.extend_from_slice(&ws_b);

        let mic = compute_mic(&session_key, &self.negotiate(), type2, &m);
        m[72..88].copy_from_slice(&mic);
        Ok(m)
    }
}

/// Windows FILETIME (100ns ticks since 1601-01-01).
fn current_filetime() -> [u8; 8] {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    ((secs + 11_644_473_600) * 10_000_000).to_le_bytes()
}

// ---------------------------------------------------------------- tests

#[cfg(test)]
mod tests {
    use super::*;

    const SC: [u8; 8] = [0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef];
    const CC: [u8; 8] = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77];
    const TS: [u8; 8] = [0x00, 0x90, 0xd3, 0x36, 0xb7, 0x34, 0xc3, 0x01];

    fn kat_target_info() -> Vec<u8> {
        let mut ti = Vec::new();
        let mut av = |id: u16, data: &[u8]| {
            ti.extend_from_slice(&id.to_le_bytes());
            ti.extend_from_slice(&(data.len() as u16).to_le_bytes());
            ti.extend_from_slice(data);
        };
        av(2, &utf16le("DOMAIN")); // MsvAvNbDomainName
        av(1, &utf16le("SERVER")); // MsvAvNbComputerName
        av(7, &TS); // MsvAvTimestamp
        av(0, b"");
        ti
    }

    #[test]
    fn nt_hash_kat() {
        assert_eq!(nt_hash("Password"), [
            0xa4, 0xf4, 0x9c, 0x40, 0x65, 0x10, 0xbd, 0xca,
            0xb6, 0x82, 0x4e, 0xe7, 0xc3, 0x0f, 0xd8, 0x52,
        ]);
    }

    #[test]
    fn ntowfv2_kat() {
        let nth = nt_hash("Password");
        let key = ntowfv2(&nth, "User", "Domain");
        assert_eq!(key, [
            0x0c, 0x86, 0x8a, 0x40, 0x3b, 0xfd, 0x7a, 0x93,
            0xa3, 0x00, 0x1e, 0xf2, 0x2e, 0xf0, 0x2e, 0x3f,
        ]);
    }

    #[test]
    fn ntlmv2_responses_kat() {
        let nth = nt_hash("Password");
        let key = ntowfv2(&nth, "User", "Domain");
        let (nt, lm, skb) = ntlmv2_responses(&key, &SC, &CC, &TS, &kat_target_info());
        assert_eq!(&nt[..16].hex(), "e25a9003089effe41ea78776cb39ef71"); // NTProofStr
        assert_eq!(
            nt.hex(),
            "e25a9003089effe41ea78776cb39ef71\
             01010000000000000090d336b734c301001122334455667700000000\
             02000c0044004f004d00410049004e0001000c00530045005200560045005200\
             070008000090d336b734c3010000000000000000"
        );
        assert_eq!(lm.hex(), "cf348aaf3bd48479f42c314e377c40cf0011223344556677");
        assert_eq!(skb.hex(), "e0ef9a9b783b22a87027547ab5ec6d03");
    }

    #[test]
    fn mic_kat() {
        let skb: [u8; 16] = "e0ef9a9b783b22a87027547ab5ec6d03"
            .parse::<HexArray>().unwrap().0;
        let t3 = [b"DBX-TEST-TYPE3".as_slice(), &[0u8; 16]].concat();
        let mic = compute_mic(&skb, b"DBX-TEST-TYPE1", b"DBX-TEST-TYPE2", &t3);
        assert_eq!(mic.hex(), "2faa013cad5675e35533da11b15d3173");
    }

    // tiny hex helper for the test above
    struct HexArray([u8; 16]);
    impl std::str::FromStr for HexArray {
        type Err = ();
        fn from_str(s: &str) -> Result<Self, ()> {
            let v = (0..16)
                .map(|i| u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).map_err(|_| ()))
                .collect::<Result<Vec<u8>, _>>()?;
            Ok(HexArray(v.try_into().map_err(|_| ())?))
        }
    }

    trait HexExt { fn hex(&self) -> String; }
    impl HexExt for [u8] {
        fn hex(&self) -> String { self.iter().map(|b| format!("{b:02x}")).collect() }
    }
    impl HexExt for [u8; 16] {
        fn hex(&self) -> String { self.as_slice().hex() }
    }
    impl HexExt for Vec<u8> {
        fn hex(&self) -> String { self.as_slice().hex() }
    }

    /// Build a synthetic Type 2 the way a server would.
    fn fake_type2() -> Vec<u8> {
        let ti = kat_target_info();
        let mut m = Vec::new();
        m.extend_from_slice(NTLMSSP_SIG);
        m.extend_from_slice(&MSG_CHALLENGE.to_le_bytes());
        put_fields(&mut m, &utf16le("DOMAIN"), 56); // target name
        m.extend_from_slice(&NEGOTIATE_FLAGS.to_le_bytes());
        m.extend_from_slice(&SC);
        m.extend_from_slice(&[0u8; 8]); // reserved
        put_fields(&mut m, &ti, 56 + 12); // target info fields
        m.extend_from_slice(&VERSION);
        m.extend_from_slice(&utf16le("DOMAIN"));
        m.extend_from_slice(&ti);
        m
    }

    #[test]
    fn end_to_end_type3_structure() {
        let cred = NtlmCredential {
            domain: "Domain".into(),
            username: "User".into(),
            secret: NtlmSecret::Password("Password".into()),
        };
        let client = NtlmClient::with_client_challenge(cred, CC);
        let t2 = fake_type2();
        let t3 = client.authenticate(&t2).unwrap();

        assert_eq!(&t3[..8], NTLMSSP_SIG);
        assert_eq!(u32::from_le_bytes([t3[8], t3[9], t3[10], t3[11]]), MSG_AUTHENTICATE);
        // MIC is present and non-zero (timestamp in target info => mandatory)
        assert!(t3[72..88].iter().any(|&b| b != 0));
        // NT response field points at our KAT bytes
        let (nt_len, nt_off) = read_fields(&t3, 20).unwrap();
        let nt = slice_at(&t3, nt_len, nt_off).unwrap();
        assert_eq!(&nt[..16], &[
            0xe2, 0x5a, 0x90, 0x03, 0x08, 0x9e, 0xff, 0xe4,
            0x1e, 0xa7, 0x87, 0x76, 0xcb, 0x39, 0xef, 0x71,
        ]);
        // user/domain fields readable
        let (u_len, u_off) = read_fields(&t3, 36).unwrap();
        assert_eq!(slice_at(&t3, u_len, u_off).unwrap(), utf16le("User").as_slice());
    }

    #[test]
    fn pass_the_hash_matches_password() {
        let nth = nt_hash("Password");
        let by_hash = NtlmClient::with_client_challenge(
            NtlmCredential { domain: "Domain".into(), username: "User".into(), secret: NtlmSecret::NtHash(nth) },
            CC,
        );
        let by_pass = NtlmClient::with_client_challenge(
            NtlmCredential { domain: "Domain".into(), username: "User".into(), secret: NtlmSecret::Password("Password".into()) },
            CC,
        );
        let t2 = fake_type2();
        assert_eq!(by_hash.authenticate(&t2).unwrap(), by_pass.authenticate(&t2).unwrap());
    }
}
