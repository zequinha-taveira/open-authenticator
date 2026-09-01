#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]

extern crate alloc;

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use alloc::vec;

use oa_core::{Algorithm, AuthenticatorInfo, CtapStatusCode, KeyHandle, Options, SecureEnvironment, Signature};
use sha2::{Digest, Sha256};
use thiserror::Error;

pub const CMD_MAKE_CREDENTIAL: u8 = 0x01;
pub const CMD_GET_ASSERTION: u8 = 0x02;
pub const CMD_GET_INFO: u8 = 0x04;
pub const CMD_CLIENT_PIN: u8 = 0x06;
pub const CMD_RESET: u8 = 0x07;
pub const CMD_GET_NEXT_ASSERTION: u8 = 0x08;

const CTAP2_OK: u8 = 0x00;

// ---------------------------------------------------------------------------
// Erros
// ---------------------------------------------------------------------------

#[derive(Debug, Error)]
pub enum CtapError<E: core::fmt::Debug + 'static> {
    #[error("environment: {0:?}")]
    Environment(E),
    #[error("ctap status")]
    Status(CtapStatusCode),
    #[error("malformed request")]
    MalformedRequest,
}

impl<E: core::fmt::Debug> From<CtapStatusCode> for CtapError<E> {
    fn from(c: CtapStatusCode) -> Self {
        Self::Status(c)
    }
}

// ---------------------------------------------------------------------------
// Cbor helpers — codificação canônica mínima (RFC8949)
// ---------------------------------------------------------------------------

pub mod cbor {
    use super::*;
    use alloc::string::String;
    use alloc::vec::Vec;

    // ---- encoding ----

    pub fn encode_unsigned(buf: &mut Vec<u8>, n: u64) {
        encode_head(buf, 0, n);
    }

    pub fn encode_negative(buf: &mut Vec<u8>, n: i64) {
        // CBOR negative is -1 - n  (major 1)
        debug_assert!(n < 0);
        let v = (-1 - n) as u64;
        encode_head(buf, 1, v);
    }

    pub fn encode_int(buf: &mut Vec<u8>, n: i64) {
        if n >= 0 {
            encode_unsigned(buf, n as u64);
        } else {
            encode_negative(buf, n);
        }
    }

    pub fn encode_bytes(buf: &mut Vec<u8>, bytes: &[u8]) {
        encode_head(buf, 2, bytes.len() as u64);
        buf.extend_from_slice(bytes);
    }

    pub fn encode_text(buf: &mut Vec<u8>, s: &str) {
        encode_head(buf, 3, s.len() as u64);
        buf.extend_from_slice(s.as_bytes());
    }

    pub fn encode_array_header(buf: &mut Vec<u8>, len: u64) {
        encode_head(buf, 4, len);
    }

    pub fn encode_map_header(buf: &mut Vec<u8>, len: u64) {
        encode_head(buf, 5, len);
    }

    pub fn encode_bool(buf: &mut Vec<u8>, v: bool) {
        buf.push(if v { 0xf5 } else { 0xf4 });
    }

    pub fn encode_null(buf: &mut Vec<u8>) {
        buf.push(0xf6);
    }

    fn encode_head(buf: &mut Vec<u8>, major: u8, value: u64) {
        let major = major << 5;
        if value < 24 {
            buf.push(major | value as u8);
        } else if value < 256 {
            buf.push(major | 24);
            buf.push(value as u8);
        } else if value < 65536 {
            buf.push(major | 25);
            buf.extend_from_slice(&(value as u16).to_be_bytes());
        } else if value < 4294967296 {
            buf.push(major | 26);
            buf.extend_from_slice(&(value as u32).to_be_bytes());
        } else {
            buf.push(major | 27);
            buf.extend_from_slice(&value.to_be_bytes());
        }
    }

    // ---- decoding ----

    #[derive(Debug)]
    pub struct Decoder<'a> {
        data: &'a [u8],
        pos: usize,
    }

    impl<'a> Decoder<'a> {
        pub fn new(data: &'a [u8]) -> Self {
            Self { data, pos: 0 }
        }

        pub fn pos(&self) -> usize {
            self.pos
        }

        pub fn remaining(&self) -> usize {
            self.data.len().saturating_sub(self.pos)
        }

        pub fn is_empty(&self) -> bool {
            self.pos >= self.data.len()
        }

        pub fn peek(&self) -> Option<u8> {
            self.data.get(self.pos).copied()
        }

        fn read_byte(&mut self) -> Result<u8, CtapStatusCode> {
            if self.pos >= self.data.len() {
                return Err(CtapStatusCode::InvalidCbor);
            }
            let b = self.data[self.pos];
            self.pos += 1;
            Ok(b)
        }

        /// Decodifica header CBOR: retorna (major, value) e valida encoding mínimo.
        pub fn decode_head(&mut self) -> Result<(u8, u64), CtapStatusCode> {
            let b = self.read_byte()?;
            // Indefinidos 0x9f, 0xbf, 0x5f, 0x7f etc => additional 31
            let major = b >> 5;
            let info = b & 0x1f;
            // Reservado / indefinido
            if info == 31 {
                return Err(CtapStatusCode::InvalidCbor);
            }
            // simple values 24.. quebra? 0xf8..0xfb já cairiam em major 7 info 24..27
            // Mas para major 7, info 24..27 tem semântica diferente; vamos rejeitar indefinidos e tags
            if major == 6 {
                // tag — não usado em CTAP2, rejeita para estrito
                return Err(CtapStatusCode::InvalidCbor);
            }
            if major == 7 && info >= 24 {
                // simple / float — só permitimos 20 false,21 true,22 null,23 undef?? Para CTAP só bool/null
                // info 24 => simple in next byte, 25..27 float. Rejeitamos exceto bool/null que são 20..23 encoded como single byte
                // Se chegou aqui com info 24..27, é encoding de simple/float com byte extra — rejeita por enquanto
                // Mas 0xf4..0xf7 são major 7 info 20..23 single-byte, já tratados antes (info <24). Então qualquer info>=24 aqui é inválido para CTAP restrito.
                return Err(CtapStatusCode::InvalidCbor);
            }
            let value = match info {
                n @ 0..=23 => n as u64,
                24 => {
                    let v = self.read_byte()? as u64;
                    if v < 24 {
                        return Err(CtapStatusCode::InvalidCbor); // não-canônico
                    }
                    v
                }
                25 => {
                    if self.remaining() < 2 {
                        return Err(CtapStatusCode::InvalidCbor);
                    }
                    let mut arr = [0u8; 2];
                    arr.copy_from_slice(&self.data[self.pos..self.pos + 2]);
                    self.pos += 2;
                    let v = u16::from_be_bytes(arr) as u64;
                    if v < 256 {
                        return Err(CtapStatusCode::InvalidCbor);
                    }
                    v
                }
                26 => {
                    if self.remaining() < 4 {
                        return Err(CtapStatusCode::InvalidCbor);
                    }
                    let mut arr = [0u8; 4];
                    arr.copy_from_slice(&self.data[self.pos..self.pos + 4]);
                    self.pos += 4;
                    let v = u32::from_be_bytes(arr) as u64;
                    if v < 65536 {
                        return Err(CtapStatusCode::InvalidCbor);
                    }
                    v
                }
                27 => {
                    if self.remaining() < 8 {
                        return Err(CtapStatusCode::InvalidCbor);
                    }
                    let mut arr = [0u8; 8];
                    arr.copy_from_slice(&self.data[self.pos..self.pos + 8]);
                    self.pos += 8;
                    let v = u64::from_be_bytes(arr);
                    if v < 4294967296 {
                        return Err(CtapStatusCode::InvalidCbor);
                    }
                    v
                }
                _ => unreachable!(),
            };
            Ok((major, value))
        }

        pub fn decode_unsigned(&mut self) -> Result<u64, CtapStatusCode> {
            let (major, v) = self.decode_head()?;
            if major != 0 {
                return Err(CtapStatusCode::CborUnexpectedType);
            }
            Ok(v)
        }

        pub fn decode_int(&mut self) -> Result<i64, CtapStatusCode> {
            let (major, v) = self.decode_head()?;
            match major {
                0 => {
                    if v > i64::MAX as u64 {
                        return Err(CtapStatusCode::InvalidCbor);
                    }
                    Ok(v as i64)
                }
                1 => {
                    // negative = -1 - v
                    let n = -1 - (v as i64);
                    Ok(n)
                }
                _ => Err(CtapStatusCode::CborUnexpectedType),
            }
        }

        pub fn decode_bytes(&mut self) -> Result<Vec<u8>, CtapStatusCode> {
            let (major, len) = self.decode_head()?;
            if major != 2 {
                return Err(CtapStatusCode::CborUnexpectedType);
            }
            let len = len as usize;
            if self.remaining() < len {
                return Err(CtapStatusCode::InvalidCbor);
            }
            let out = self.data[self.pos..self.pos + len].to_vec();
            self.pos += len;
            Ok(out)
        }

        pub fn decode_text(&mut self) -> Result<String, CtapStatusCode> {
            let (major, len) = self.decode_head()?;
            if major != 3 {
                return Err(CtapStatusCode::CborUnexpectedType);
            }
            let len = len as usize;
            if self.remaining() < len {
                return Err(CtapStatusCode::InvalidCbor);
            }
            let slice = &self.data[self.pos..self.pos + len];
            self.pos += len;
            String::from_utf8(slice.to_vec()).map_err(|_| CtapStatusCode::InvalidCbor)
        }

        pub fn decode_bool(&mut self) -> Result<bool, CtapStatusCode> {
            let b = self.read_byte()?;
            match b {
                0xf4 => Ok(false),
                0xf5 => Ok(true),
                _ => Err(CtapStatusCode::CborUnexpectedType),
            }
        }

        /// Decodifica um simples CBOR que pode ser bool (usado em options valores)
        pub fn decode_simple_bool(&mut self) -> Result<bool, CtapStatusCode> {
            self.decode_bool()
        }

        pub fn decode_array_header(&mut self) -> Result<u64, CtapStatusCode> {
            let (major, v) = self.decode_head()?;
            if major != 4 {
                return Err(CtapStatusCode::CborUnexpectedType);
            }
            Ok(v)
        }

        pub fn decode_map_header(&mut self) -> Result<u64, CtapStatusCode> {
            let (major, v) = self.decode_head()?;
            if major != 5 {
                return Err(CtapStatusCode::CborUnexpectedType);
            }
            Ok(v)
        }

        pub fn decode_null(&mut self) -> Result<(), CtapStatusCode> {
            let b = self.read_byte()?;
            if b != 0xf6 {
                return Err(CtapStatusCode::CborUnexpectedType);
            }
            Ok(())
        }

        /// Avança 1 valor CBOR genérico (skip) — usado para ignorar extensões desconhecidas.
        pub fn skip_value(&mut self) -> Result<(), CtapStatusCode> {
            let (major, value) = self.decode_head()?;
            match major {
                0 | 1 => Ok(()), // int já consumido
                2 | 3 => {
                    // bytes/text payload
                    let len = value as usize;
                    if self.remaining() < len {
                        return Err(CtapStatusCode::InvalidCbor);
                    }
                    self.pos += len;
                    Ok(())
                }
                4 => {
                    // array
                    for _ in 0..value {
                        self.skip_value()?;
                    }
                    Ok(())
                }
                5 => {
                    for _ in 0..value {
                        self.skip_value()?;
                        self.skip_value()?;
                    }
                    Ok(())
                }
                7 => {
                    // já consumiu header; para 20..23 é single-byte bool/null já tratado; info 24..27 rejeitado antes
                    // Se chegou aqui com major 7 e value correspondente a bool/null, já foi consumido; but decode_head for 7 só permite <24
                    Ok(())
                }
                _ => Err(CtapStatusCode::InvalidCbor),
            }
        }

        pub fn expect_end(&self) -> Result<(), CtapStatusCode> {
            if self.pos != self.data.len() {
                return Err(CtapStatusCode::InvalidCbor);
            }
            Ok(())
        }
    }

    // helpers públicos para validação rápida
    pub fn decode_map_int_keys<'a>(dec: &mut Decoder<'a>, seen: &mut BTreeSet<u64>) -> Result<u64, CtapStatusCode> {
        // placeholder — não usado
        let _ = seen;
        dec.decode_map_header()
    }
}

// ---------------------------------------------------------------------------
// Modelo de credencial interna
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
struct StoredCredential {
    id: Vec<u8>,
    rp_id: String,
    user_id: Vec<u8>,
    private_key: KeyHandle,
    counter: u32,
    // COSE key material dummy (x,y)
    cose_x: [u8; 32],
    cose_y: [u8; 32],
}

struct MakeCredentialParams {
    client_data_hash: [u8; 32],
    rp_id: String,
    user_id: Vec<u8>,
    pub_key_cred_params: Vec<(String, i32)>,
    exclude_list: Vec<Vec<u8>>,
    require_resident_key: bool,
    require_user_presence: bool,
    require_user_verification: bool,
    pin_uv_auth_param: Option<Vec<u8>>,
    pin_uv_auth_protocol: Option<u32>,
    rp_name: Option<String>,
    user_name: Option<String>,
}

struct GetAssertionParams {
    rp_id: String,
    client_data_hash: [u8; 32],
    allow_list: Vec<Vec<u8>>,
    require_user_presence: bool,
    require_user_verification: bool,
    pin_uv_auth_param: Option<Vec<u8>>,
    pin_uv_auth_protocol: Option<u32>,
}

// ---------------------------------------------------------------------------
// Ctap2 Authenticator
// ---------------------------------------------------------------------------

pub struct Ctap2<E> {
    env: E,
    info: AuthenticatorInfo,
    // estado
    counter: u32,
    credentials: Vec<StoredCredential>,
    // para getNextAssertion
    last_assertion_results: Vec<(Vec<u8>, Vec<u8>)>, // (credId, signature placeholder)
    pin_retries: u8,
    uv_retries: u8,
}

impl<E> Ctap2<E>
where
    E: SecureEnvironment,
    E::Error: core::fmt::Debug + 'static,
{
    pub fn new(env: E, aaguid: [u8; 16]) -> Self {
        let mut info = AuthenticatorInfo::new(aaguid);
        // garante valores consistentes com virtual hardware Python
        info.versions = vec!["FIDO_2_0", "FIDO_2_1"];
        info.options = Options {
            rk: true,
            up: true,
            uv: false,
            always_uv: false,
            plat: false,
            client_pin: Some(false),
        };
        info.max_msg_size = 1200;
        info.pin_uv_auth_protocols = vec![1];
        info.transports = vec!["usb"];
        info.algorithms = vec![Algorithm::Es256];
        Self {
            env,
            info,
            counter: 0,
            credentials: Vec::new(),
            last_assertion_results: Vec::new(),
            pin_retries: 8,
            uv_retries: 3,
        }
    }

    pub fn get_info(&self) -> &AuthenticatorInfo {
        &self.info
    }

    pub fn reset_counter(&mut self) {
        self.counter = 0;
    }

    // ----- helpers internos -----

    fn next_counter(&mut self) -> Result<u32, CtapError<E::Error>> {
        // incrementa monotonicamente, checking overflow
        if self.counter == u32::MAX {
            return Err(CtapStatusCode::KeyStoreFull.into());
        }
        self.counter = self.counter.wrapping_add(1);
        if self.counter == 0 {
            self.counter = 1;
        }
        Ok(self.counter)
    }

    fn check_user_presence(&mut self) -> Result<bool, CtapError<E::Error>> {
        self.env.user_presence().map_err(CtapError::Environment)
    }

    fn sha256(data: &[u8]) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(data);
        let result = hasher.finalize();
        let mut out = [0u8; 32];
        out.copy_from_slice(&result);
        out
    }

    fn build_auth_data(
        &self,
        rp_id: &str,
        flags: u8,
        counter: u32,
        attested: Option<(&[u8; 16], &[u8], &[u8; 32], &[u8; 32])>,
    ) -> Vec<u8> {
        // attested = (aaguid, credId, x, y)
        let rp_hash = Self::sha256(rp_id.as_bytes());
        let mut out = Vec::with_capacity(32 + 1 + 4 + 128);
        out.extend_from_slice(&rp_hash);
        out.push(flags);
        out.extend_from_slice(&counter.to_be_bytes());
        if let Some((aaguid, cred_id, x, y)) = attested {
            out.extend_from_slice(aaguid);
            out.extend_from_slice(&(cred_id.len() as u16).to_be_bytes());
            out.extend_from_slice(cred_id);
            // COSE key como CBOR map
            let mut cose = Vec::new();
            cbor::encode_map_header(&mut cose, 5);
            cbor::encode_int(&mut cose, 1);
            cbor::encode_int(&mut cose, 2); // kty EC2
            cbor::encode_int(&mut cose, 3);
            cbor::encode_int(&mut cose, -7); // alg ES256
            cbor::encode_int(&mut cose, -1);
            cbor::encode_int(&mut cose, 1); // crv P-256
            cbor::encode_int(&mut cose, -2);
            cbor::encode_bytes(&mut cose, x);
            cbor::encode_int(&mut cose, -3);
            cbor::encode_bytes(&mut cose, y);
            out.extend_from_slice(&cose);
        }
        out
    }

    // ----- CBOR encoding para respostas -----

    fn encode_get_info(&self) -> Vec<u8> {
        let mut cbor = Vec::new();
        // 7 chaves principais (1,3,4,5,6,9,10) — canonical ordering
        cbor::encode_map_header(&mut cbor, 7);

        cbor::encode_unsigned(&mut cbor, 0x01);
        cbor::encode_array_header(&mut cbor, self.info.versions.len() as u64);
        for v in &self.info.versions {
            cbor::encode_text(&mut cbor, v);
        }

        cbor::encode_unsigned(&mut cbor, 0x03);
        cbor::encode_bytes(&mut cbor, &self.info.aaguid);

        cbor::encode_unsigned(&mut cbor, 0x04);
        // options map com 3 entradas (rk, up, uv) + plat/clientPin se presentes
        let mut opt_len = 3u64;
        if self.info.options.plat {
            opt_len += 1;
        }
        if self.info.options.client_pin.is_some() {
            opt_len += 1;
        }
        if self.info.options.always_uv {
            opt_len += 1;
        }
        cbor::encode_map_header(&mut cbor, opt_len);
        cbor::encode_text(&mut cbor, "rk");
        cbor::encode_bool(&mut cbor, self.info.options.rk);
        cbor::encode_text(&mut cbor, "up");
        cbor::encode_bool(&mut cbor, self.info.options.up);
        cbor::encode_text(&mut cbor, "uv");
        cbor::encode_bool(&mut cbor, self.info.options.uv);
        if self.info.options.plat {
            cbor::encode_text(&mut cbor, "plat");
            cbor::encode_bool(&mut cbor, true);
        }
        if let Some(cp) = self.info.options.client_pin {
            cbor::encode_text(&mut cbor, "clientPin");
            cbor::encode_bool(&mut cbor, cp);
        }
        if self.info.options.always_uv {
            cbor::encode_text(&mut cbor, "alwaysUv");
            cbor::encode_bool(&mut cbor, true);
        }

        cbor::encode_unsigned(&mut cbor, 0x05);
        cbor::encode_unsigned(&mut cbor, self.info.max_msg_size as u64);

        cbor::encode_unsigned(&mut cbor, 0x06);
        cbor::encode_array_header(&mut cbor, self.info.pin_uv_auth_protocols.len() as u64);
        for p in &self.info.pin_uv_auth_protocols {
            cbor::encode_unsigned(&mut cbor, *p as u64);
        }

        cbor::encode_unsigned(&mut cbor, 0x09);
        cbor::encode_array_header(&mut cbor, self.info.transports.len() as u64);
        for t in &self.info.transports {
            cbor::encode_text(&mut cbor, t);
        }

        cbor::encode_unsigned(&mut cbor, 0x0A);
        cbor::encode_array_header(&mut cbor, self.info.algorithms.len() as u64);
        for alg in &self.info.algorithms {
            cbor::encode_map_header(&mut cbor, 2);
            cbor::encode_text(&mut cbor, "type");
            cbor::encode_text(&mut cbor, "public-key");
            cbor::encode_text(&mut cbor, "alg");
            cbor::encode_int(&mut cbor, alg.cose_id() as i64);
        }

        let mut out = Vec::with_capacity(1 + cbor.len());
        out.push(CTAP2_OK);
        out.extend_from_slice(&cbor);
        out
    }

    fn encode_make_credential_response(
        &self,
        credential_id: &[u8],
        auth_data: &[u8],
    ) -> Vec<u8> {
        let mut cbor = Vec::new();
        cbor::encode_map_header(&mut cbor, 3);
        cbor::encode_unsigned(&mut cbor, 0x01); // fmt
        cbor::encode_text(&mut cbor, "none");
        cbor::encode_unsigned(&mut cbor, 0x02); // authData
        cbor::encode_bytes(&mut cbor, auth_data);
        cbor::encode_unsigned(&mut cbor, 0x03); // attStmt
        cbor::encode_map_header(&mut cbor, 0);
        let mut out = Vec::with_capacity(1 + cbor.len());
        out.push(CTAP2_OK);
        out.extend_from_slice(&cbor);
        let _ = credential_id;
        out
    }

    fn encode_get_assertion_response(
        &self,
        cred: &StoredCredential,
        auth_data: &[u8],
        signature: &[u8],
    ) -> Vec<u8> {
        let mut cbor = Vec::new();
        // keys: 0x01 credential, 0x02 authData, 0x03 signature, optional 0x04 user?
        cbor::encode_map_header(&mut cbor, 3);
        cbor::encode_unsigned(&mut cbor, 0x01);
        // credential descriptor: map { id: bstr, type: tstr }
        cbor::encode_map_header(&mut cbor, 2);
        cbor::encode_text(&mut cbor, "id");
        cbor::encode_bytes(&mut cbor, &cred.id);
        cbor::encode_text(&mut cbor, "type");
        cbor::encode_text(&mut cbor, "public-key");

        cbor::encode_unsigned(&mut cbor, 0x02);
        cbor::encode_bytes(&mut cbor, auth_data);
        cbor::encode_unsigned(&mut cbor, 0x03);
        cbor::encode_bytes(&mut cbor, signature);

        let mut out = Vec::with_capacity(1 + cbor.len());
        out.push(CTAP2_OK);
        out.extend_from_slice(&cbor);
        out
    }

    // ----- handlers -----

    fn handle_get_info(&self, payload: &[u8]) -> Result<Vec<u8>, CtapError<E::Error>> {
        if !payload.is_empty() {
            // CTAP2 getInfo deve ter CBOR vazio; qualquer payload => InvalidLength
            // Também tenta decodificar se payload é CBOR inválido — mas spec usa 0x03
            // Verifica se payload é CBOR; se for mais que 0 bytes => erro
            return Err(CtapStatusCode::InvalidLength.into());
        }
        Ok(self.encode_get_info())
    }

    fn handle_reset(&mut self, payload: &[u8]) -> Result<Vec<u8>, CtapError<E::Error>> {
        if !payload.is_empty() {
            return Err(CtapStatusCode::InvalidLength.into());
        }
        // Requer presença do usuário (spec: 10s after power-on + UP)
        let present = self.check_user_presence()?;
        if !present {
            return Err(CtapStatusCode::OperationDenied.into());
        }
        self.credentials.clear();
        self.counter = 0;
        self.last_assertion_results.clear();
        // resposta é apenas 0x00 sem CBOR payload (reset não retorna mapa)
        Ok(vec![CTAP2_OK])
    }

    fn handle_make_credential(
        &mut self,
        payload: &[u8],
    ) -> Result<Vec<u8>, CtapError<E::Error>> {
        if payload.is_empty() {
            return Err(CtapStatusCode::MissingParameter.into());
        }
        // Strict CBOR parsing
        let params = self.decode_make_credential_payload(payload)?;

        // valida pubKeyCredParams — deve conter ao menos um alg suportado
        let mut supported = false;
        for (_t, alg) in &params.pub_key_cred_params {
            if Algorithm::from_cose_id(*alg).is_some() {
                supported = true;
                break;
            }
        }
        if !supported {
            return Err(CtapStatusCode::UnsupportedAlgorithm.into());
        }

        // excludeList: se algum credId já existe para rp, retorna CredentialExcluded
        for exclude_id in &params.exclude_list {
            if self.credentials.iter().any(|c| &c.id == exclude_id && c.rp_id == params.rp_id) {
                return Err(CtapStatusCode::CredentialExcluded.into());
            }
        }

        // verifica opções: se rk requerido, garante espaço
        if params.require_resident_key {
            if self.credentials.len() >= self.info.remaining_discoverable_credentials.unwrap_or(25) as usize {
                return Err(CtapStatusCode::KeyStoreFull.into());
            }
            if self.credentials.len() >= self.info.max_credential_count_in_list.unwrap_or(8) as usize * 3 {
                // limite extra
                return Err(CtapStatusCode::KeyStoreFull.into());
            }
        }

        // UV: se requerido mas não suportado => UnsupportedOption
        if params.require_user_verification && !self.info.options.uv {
            // spec: se uv não suportado, deveria retornar InvalidOption? usamos UnsupportedOption
            return Err(CtapStatusCode::UnsupportedOption.into());
        }

        // UP: se requerido, verifica presença
        if params.require_user_presence {
            let present = self.check_user_presence()?;
            if !present {
                return Err(CtapStatusCode::OperationDenied.into());
            }
        }

        // PIN: se pinUvAuthParam presente mas protocolo não é 1 => PinAuthInvalid
        if params.pin_uv_auth_param.is_some() && params.pin_uv_auth_protocol != Some(1) {
            return Err(CtapStatusCode::PinAuthInvalid.into());
        }
        if params.pin_uv_auth_param.is_some() && self.info.options.client_pin == Some(false) {
            return Err(CtapStatusCode::PinNotSet.into());
        }

        // Gera credential id determinístico (random + counter)
        let mut cred_id = vec![0u8; 16];
        self.env.random(&mut cred_id).map_err(CtapError::Environment)?;
        // mistura counter para unicidade mesmo com mesmo random seed determinístico
        let ctr = self.next_counter()?;
        cred_id[0] ^= (ctr & 0xff) as u8;
        cred_id[1] ^= ((ctr >> 8) & 0xff) as u8;

        // Verifica armazenamento cheio por tamanho do id
        if cred_id.len() > self.info.max_credential_id_length.unwrap_or(128) as usize {
            return Err(CtapStatusCode::LimitExceeded.into());
        }

        // Gera material COSE dummy (em produção viria de CryptoProvider)
        let mut x = [0u8; 32];
        let mut y = [0u8; 32];
        self.env.random(&mut x).map_err(CtapError::Environment)?;
        self.env.random(&mut y).map_err(CtapError::Environment)?;

        let flags: u8 = 0x01 | 0x40; // UP | AT
        let flags = if params.require_user_verification {
            flags | 0x04 // UV
        } else {
            flags
        };
        let counter = ctr;
        let auth_data = self.build_auth_data(&params.rp_id, flags, counter, Some((&self.info.aaguid, &cred_id, &x, &y)));

        // armazena credencial
        let stored = StoredCredential {
            id: cred_id.clone(),
            rp_id: params.rp_id.clone(),
            user_id: params.user_id.clone(),
            private_key: KeyHandle(vec![0u8; 32]), // placeholder; em produção CryptoProvider::generate_key
            counter,
            cose_x: x,
            cose_y: y,
        };
        self.credentials.push(stored);

        Ok(self.encode_make_credential_response(&cred_id, &auth_data))
    }

    fn handle_get_assertion(
        &mut self,
        payload: &[u8],
    ) -> Result<Vec<u8>, CtapError<E::Error>> {
        if payload.is_empty() {
            return Err(CtapStatusCode::MissingParameter.into());
        }
        let params = self.decode_get_assertion_payload(payload)?;

        // UV check
        if params.require_user_verification && !self.info.options.uv {
            return Err(CtapStatusCode::UnsupportedOption.into());
        }
        if params.require_user_presence {
            let present = self.check_user_presence()?;
            if !present {
                return Err(CtapStatusCode::OperationDenied.into());
            }
        }

        // filtra credenciais por rpId e allowList
        let mut candidates: Vec<StoredCredential> = self
            .credentials
            .iter()
            .filter(|c| c.rp_id == params.rp_id)
            .cloned()
            .collect();

        if !params.allow_list.is_empty() {
            candidates.retain(|c| params.allow_list.iter().any(|id| id == &c.id));
        }

        if candidates.is_empty() {
            return Err(CtapStatusCode::NoCredentials.into());
        }

        // seleciona primeira (em real, precisaria de ordenação, largeBlob etc)
        let cred = candidates[0].clone();
        let ctr = self.next_counter()?;

        let mut flags: u8 = 0x01; // UP
        if params.require_user_verification {
            flags |= 0x04;
        }
        let auth_data = self.build_auth_data(&params.rp_id, flags, ctr, None);

        // assinatura dummy: SHA256(authData || clientDataHash) truncated / dummy
        // Para protótipo, usamos hash como placeholder de 64 bytes
        let mut to_sign = Vec::with_capacity(auth_data.len() + 32);
        to_sign.extend_from_slice(&auth_data);
        to_sign.extend_from_slice(&params.client_data_hash);
        let hash = Self::sha256(&to_sign);
        let mut signature = Vec::with_capacity(64);
        signature.extend_from_slice(&hash);
        signature.extend_from_slice(&hash); // dup para 64

        // atualiza counter no stored
        if let Some(stored) = self.credentials.iter_mut().find(|c| c.id == cred.id) {
            stored.counter = ctr;
        }

        // salva para getNextAssertion (se múltiplos)
        self.last_assertion_results = candidates
            .into_iter()
            .skip(1)
            .map(|c| (c.id.clone(), signature.clone()))
            .collect();

        let stored_ref = self.credentials.iter().find(|c| c.id == cred.id).unwrap();
        Ok(self.encode_get_assertion_response(stored_ref, &auth_data, &signature))
    }

    fn handle_get_next_assertion(
        &mut self,
        payload: &[u8],
    ) -> Result<Vec<u8>, CtapError<E::Error>> {
        if !payload.is_empty() {
            return Err(CtapStatusCode::InvalidLength.into());
        }
        if self.last_assertion_results.is_empty() {
            return Err(CtapStatusCode::NotAllowed.into());
        }
        let (cred_id, sig) = self.last_assertion_results.remove(0);
        let cred = self
            .credentials
            .iter()
            .find(|c| c.id == cred_id)
            .cloned()
            .ok_or(CtapStatusCode::NoCredentials)?;
        let ctr = self.next_counter()?;
        let auth_data = self.build_auth_data(&cred.rp_id, 0x01, ctr, None);
        let stored = self.credentials.iter().find(|c| c.id == cred_id).unwrap();
        Ok(self.encode_get_assertion_response(stored, &auth_data, &sig))
    }

    fn handle_client_pin(
        &mut self,
        payload: &[u8],
    ) -> Result<Vec<u8>, CtapError<E::Error>> {
        if payload.is_empty() {
            return Err(CtapStatusCode::MissingParameter.into());
        }
        // parsing mínimo para subcomando 0x01..0x09
        let mut dec = cbor::Decoder::new(payload);
        let map_len = dec.decode_map_header().map_err(|e| CtapError::Status(e))?;
        if map_len == 0 {
            return Err(CtapStatusCode::MissingParameter.into());
        }
        let mut seen = BTreeSet::new();
        let mut subcommand: Option<u64> = None;
        for _ in 0..map_len {
            let key = dec.decode_unsigned().map_err(|e| CtapError::Status(e))?;
            if !seen.insert(key) {
                return Err(CtapStatusCode::InvalidCbor.into());
            }
            match key {
                0x01 => {
                    subcommand = Some(dec.decode_unsigned().map_err(|e| CtapError::Status(e))?);
                }
                _ => {
                    dec.skip_value().map_err(|e| CtapError::Status(e))?;
                }
            }
        }
        dec.expect_end().map_err(|e| CtapError::Status(e))?;
        match subcommand {
            Some(0x01) | Some(0x02) | Some(0x03) => Err(CtapStatusCode::PinNotSet.into()),
            Some(0x04) => Err(CtapStatusCode::PinRequired.into()),
            Some(0x06) | Some(0x09) => Err(CtapStatusCode::PinAuthInvalid.into()),
            Some(_) => Err(CtapStatusCode::InvalidSubcommand.into()),
            None => Err(CtapStatusCode::MissingParameter.into()),
        }
    }

    // ----- Decoders para payloads -----

    fn decode_make_credential_payload(
        &self,
        payload: &[u8],
    ) -> Result<MakeCredentialParams, CtapError<E::Error>> {
        let mut dec = cbor::Decoder::new(payload);
        let map_len = dec.decode_map_header().map_err(|e| CtapError::Status(e))?;
        if map_len > 9 {
            return Err(CtapStatusCode::InvalidCbor.into());
        }
        let mut seen = BTreeSet::new();
        let mut client_data_hash: Option<[u8; 32]> = None;
        let mut rp_id: Option<String> = None;
        let mut rp_name: Option<String> = None;
        let mut user_id: Option<Vec<u8>> = None;
        let mut user_name: Option<String> = None;
        let mut pub_key_cred_params: Option<Vec<(String, i32)>> = None;
        let mut exclude_list: Vec<Vec<u8>> = Vec::new();
        let mut rk = false;
        let mut uv = false;
        let mut up = true;
        let mut pin_uv_auth_param: Option<Vec<u8>> = None;
        let mut pin_uv_auth_protocol: Option<u32> = None;

        for _ in 0..map_len {
            let key = dec.decode_unsigned().map_err(|e| CtapError::Status(e))?;
            if !seen.insert(key) {
                return Err(CtapStatusCode::InvalidCbor.into());
            }
            match key {
                0x01 => {
                    let bytes = dec.decode_bytes().map_err(|e| CtapError::Status(e))?;
                    if bytes.len() != 32 {
                        return Err(CtapStatusCode::InvalidParameter.into());
                    }
                    let mut arr = [0u8; 32];
                    arr.copy_from_slice(&bytes);
                    client_data_hash = Some(arr);
                }
                0x02 => {
                    // rp map { id, name }
                    let inner_len = dec.decode_map_header().map_err(|e| CtapError::Status(e))?;
                    if inner_len == 0 || inner_len > 3 {
                        return Err(CtapStatusCode::InvalidCbor.into());
                    }
                    let mut inner_seen = BTreeSet::new();
                    for _ in 0..inner_len {
                        let ikey = dec.decode_text().map_err(|e| CtapError::Status(e))?;
                        if !inner_seen.insert(ikey.clone()) {
                            return Err(CtapStatusCode::InvalidCbor.into());
                        }
                        if ikey == "id" {
                            rp_id = Some(dec.decode_text().map_err(|e| CtapError::Status(e))?);
                        } else if ikey == "name" {
                            rp_name = Some(dec.decode_text().map_err(|e| CtapError::Status(e))?);
                        } else {
                            dec.skip_value().map_err(|e| CtapError::Status(e))?;
                        }
                    }
                    if rp_id.is_none() {
                        return Err(CtapStatusCode::MissingParameter.into());
                    }
                }
                0x03 => {
                    // user map { id, name, displayName }
                    let inner_len = dec.decode_map_header().map_err(|e| CtapError::Status(e))?;
                    if inner_len == 0 || inner_len > 4 {
                        return Err(CtapStatusCode::InvalidCbor.into());
                    }
                    let mut inner_seen = BTreeSet::new();
                    for _ in 0..inner_len {
                        let ikey = dec.decode_text().map_err(|e| CtapError::Status(e))?;
                        if !inner_seen.insert(ikey.clone()) {
                            return Err(CtapStatusCode::InvalidCbor.into());
                        }
                        if ikey == "id" {
                            let b = dec.decode_bytes().map_err(|e| CtapError::Status(e))?;
                            if b.is_empty() || b.len() > 64 {
                                return Err(CtapStatusCode::InvalidParameter.into());
                            }
                            user_id = Some(b);
                        } else if ikey == "name" {
                            user_name = Some(dec.decode_text().map_err(|e| CtapError::Status(e))?);
                        } else if ikey == "displayName" {
                            let _ = dec.decode_text().map_err(|e| CtapError::Status(e))?;
                        } else {
                            dec.skip_value().map_err(|e| CtapError::Status(e))?;
                        }
                    }
                    if user_id.is_none() {
                        return Err(CtapStatusCode::MissingParameter.into());
                    }
                }
                0x04 => {
                    // pubKeyCredParams array of maps
                    let arr_len = dec.decode_array_header().map_err(|e| CtapError::Status(e))?;
                    if arr_len == 0 {
                        return Err(CtapStatusCode::MissingParameter.into());
                    }
                    if arr_len > 8 {
                        return Err(CtapStatusCode::LimitExceeded.into());
                    }
                    let mut out = Vec::new();
                    for _ in 0..arr_len {
                        let mlen = dec.decode_map_header().map_err(|e| CtapError::Status(e))?;
                        let mut t: Option<String> = None;
                        let mut alg: Option<i64> = None;
                        let mut inner_seen = BTreeSet::new();
                        for _ in 0..mlen {
                            let k = dec.decode_text().map_err(|e| CtapError::Status(e))?;
                            if !inner_seen.insert(k.clone()) {
                                return Err(CtapStatusCode::InvalidCbor.into());
                            }
                            if k == "type" {
                                t = Some(dec.decode_text().map_err(|e| CtapError::Status(e))?);
                            } else if k == "alg" {
                                alg = Some(dec.decode_int().map_err(|e| CtapError::Status(e))?);
                            } else {
                                dec.skip_value().map_err(|e| CtapError::Status(e))?;
                            }
                        }
                        let t = t.ok_or(CtapError::Status(CtapStatusCode::MissingParameter))?;
                        let alg = alg.ok_or(CtapError::Status(CtapStatusCode::MissingParameter))? as i32;
                        out.push((t, alg));
                    }
                    pub_key_cred_params = Some(out);
                }
                0x05 => {
                    // excludeList
                    let arr_len = dec.decode_array_header().map_err(|e| CtapError::Status(e))?;
                    if arr_len > 16 {
                        return Err(CtapStatusCode::LimitExceeded.into());
                    }
                    for _ in 0..arr_len {
                        let mlen = dec.decode_map_header().map_err(|e| CtapError::Status(e))?;
                        let mut id_opt: Option<Vec<u8>> = None;
                        let mut inner_seen = BTreeSet::new();
                        for _ in 0..mlen {
                            let k = dec.decode_text().map_err(|e| CtapError::Status(e))?;
                            if !inner_seen.insert(k.clone()) {
                                return Err(CtapStatusCode::InvalidCbor.into());
                            }
                            if k == "id" {
                                id_opt = Some(dec.decode_bytes().map_err(|e| CtapError::Status(e))?);
                            } else if k == "type" {
                                let _ = dec.decode_text().map_err(|e| CtapError::Status(e))?;
                            } else {
                                dec.skip_value().map_err(|e| CtapError::Status(e))?;
                            }
                        }
                        if let Some(id) = id_opt {
                            exclude_list.push(id);
                        }
                    }
                }
                0x06 => {
                    // extensions map — skip
                    dec.skip_value().map_err(|e| CtapError::Status(e))?;
                }
                0x07 => {
                    // options map { rk, uv }
                    let mlen = dec.decode_map_header().map_err(|e| CtapError::Status(e))?;
                    let mut seen2 = BTreeSet::new();
                    for _ in 0..mlen {
                        let k = dec.decode_text().map_err(|e| CtapError::Status(e))?;
                        if !seen2.insert(k.clone()) {
                            return Err(CtapStatusCode::InvalidCbor.into());
                        }
                        if k == "rk" {
                            rk = dec.decode_bool().map_err(|e| CtapError::Status(e))?;
                        } else if k == "uv" {
                            uv = dec.decode_bool().map_err(|e| CtapError::Status(e))?;
                        } else if k == "up" {
                            up = dec.decode_bool().map_err(|e| CtapError::Status(e))?;
                        } else {
                            // unknown option => skip value mas depois retorna UnsupportedOption?
                            let _ = dec.skip_value().map_err(|e| CtapError::Status(e))?;
                            // spec: unknown option should be ignored? Para strict, retorna UnsupportedOption
                        }
                    }
                }
                0x08 => {
                    let b = dec.decode_bytes().map_err(|e| CtapError::Status(e))?;
                    pin_uv_auth_param = Some(b);
                }
                0x09 => {
                    let v = dec.decode_unsigned().map_err(|e| CtapError::Status(e))?;
                    if v > u32::MAX as u64 {
                        return Err(CtapStatusCode::InvalidParameter.into());
                    }
                    pin_uv_auth_protocol = Some(v as u32);
                }
                _ => {
                    // chave desconhecida — por spec deve ser ignorada? Para estrito retornamos InvalidParameter
                    // Mas para compat futura, ignoramos e pulamos valor
                    dec.skip_value().map_err(|e| CtapError::Status(e))?;
                }
            }
        }
        dec.expect_end().map_err(|e| CtapError::Status(e))?;

        let client_data_hash = client_data_hash.ok_or(CtapError::Status(CtapStatusCode::MissingParameter))?;
        let rp_id = rp_id.ok_or(CtapError::Status(CtapStatusCode::MissingParameter))?;
        let user_id = user_id.ok_or(CtapError::Status(CtapStatusCode::MissingParameter))?;
        let pub_key_cred_params = pub_key_cred_params.ok_or(CtapError::Status(CtapStatusCode::MissingParameter))?;

        Ok(MakeCredentialParams {
            client_data_hash,
            rp_id,
            user_id,
            pub_key_cred_params,
            exclude_list,
            require_resident_key: rk,
            require_user_verification: uv,
            require_user_presence: up,
            pin_uv_auth_param,
            pin_uv_auth_protocol,
            rp_name,
            user_name,
        })
    }

    fn decode_get_assertion_payload(
        &self,
        payload: &[u8],
    ) -> Result<GetAssertionParams, CtapError<E::Error>> {
        let mut dec = cbor::Decoder::new(payload);
        let map_len = dec.decode_map_header().map_err(|e| CtapError::Status(e))?;
        if map_len > 8 {
            return Err(CtapStatusCode::InvalidCbor.into());
        }
        let mut seen = BTreeSet::new();
        let mut rp_id: Option<String> = None;
        let mut client_data_hash: Option<[u8; 32]> = None;
        let mut allow_list: Vec<Vec<u8>> = Vec::new();
        let mut up = true;
        let mut uv = false;
        let mut pin_uv_auth_param: Option<Vec<u8>> = None;
        let mut pin_uv_auth_protocol: Option<u32> = None;

        for _ in 0..map_len {
            let key = dec.decode_unsigned().map_err(|e| CtapError::Status(e))?;
            if !seen.insert(key) {
                return Err(CtapStatusCode::InvalidCbor.into());
            }
            match key {
                0x01 => {
                    rp_id = Some(dec.decode_text().map_err(|e| CtapError::Status(e))?);
                }
                0x02 => {
                    let bytes = dec.decode_bytes().map_err(|e| CtapError::Status(e))?;
                    if bytes.len() != 32 {
                        return Err(CtapStatusCode::InvalidParameter.into());
                    }
                    let mut arr = [0u8; 32];
                    arr.copy_from_slice(&bytes);
                    client_data_hash = Some(arr);
                }
                0x03 => {
                    let arr_len = dec.decode_array_header().map_err(|e| CtapError::Status(e))?;
                    if arr_len > 16 {
                        return Err(CtapStatusCode::LimitExceeded.into());
                    }
                    for _ in 0..arr_len {
                        let mlen = dec.decode_map_header().map_err(|e| CtapError::Status(e))?;
                        let mut id_opt: Option<Vec<u8>> = None;
                        let mut inner_seen = BTreeSet::new();
                        for _ in 0..mlen {
                            let k = dec.decode_text().map_err(|e| CtapError::Status(e))?;
                            if !inner_seen.insert(k.clone()) {
                                return Err(CtapStatusCode::InvalidCbor.into());
                            }
                            if k == "id" {
                                id_opt = Some(dec.decode_bytes().map_err(|e| CtapError::Status(e))?);
                            } else if k == "type" {
                                let _ = dec.decode_text().map_err(|e| CtapError::Status(e))?;
                            } else {
                                dec.skip_value().map_err(|e| CtapError::Status(e))?;
                            }
                        }
                        if let Some(id) = id_opt {
                            allow_list.push(id);
                        }
                    }
                }
                0x04 => {
                    // extensions — skip
                    dec.skip_value().map_err(|e| CtapError::Status(e))?;
                }
                0x05 => {
                    // options { up, uv }
                    let mlen = dec.decode_map_header().map_err(|e| CtapError::Status(e))?;
                    let mut s2 = BTreeSet::new();
                    for _ in 0..mlen {
                        let k = dec.decode_text().map_err(|e| CtapError::Status(e))?;
                        if !s2.insert(k.clone()) {
                            return Err(CtapStatusCode::InvalidCbor.into());
                        }
                        if k == "up" {
                            up = dec.decode_bool().map_err(|e| CtapError::Status(e))?;
                        } else if k == "uv" {
                            uv = dec.decode_bool().map_err(|e| CtapError::Status(e))?;
                        } else {
                            dec.skip_value().map_err(|e| CtapError::Status(e))?;
                        }
                    }
                }
                0x06 => {
                    let b = dec.decode_bytes().map_err(|e| CtapError::Status(e))?;
                    pin_uv_auth_param = Some(b);
                }
                0x07 => {
                    let v = dec.decode_unsigned().map_err(|e| CtapError::Status(e))?;
                    pin_uv_auth_protocol = Some(v as u32);
                }
                _ => {
                    dec.skip_value().map_err(|e| CtapError::Status(e))?;
                }
            }
        }
        dec.expect_end().map_err(|e| CtapError::Status(e))?;
        let rp_id = rp_id.ok_or(CtapError::Status(CtapStatusCode::MissingParameter))?;
        let client_data_hash = client_data_hash.ok_or(CtapError::Status(CtapStatusCode::MissingParameter))?;
        Ok(GetAssertionParams {
            rp_id,
            client_data_hash,
            allow_list,
            require_user_presence: up,
            require_user_verification: uv,
            pin_uv_auth_param,
            pin_uv_auth_protocol,
        })
    }

    // -----------------------------------------------------------------------
    // Dispatch principal
    // -----------------------------------------------------------------------

    pub fn dispatch(&mut self, request: &[u8]) -> Result<Vec<u8>, CtapError<E::Error>> {
        let (&command, payload) = request.split_first().ok_or(CtapError::MalformedRequest)?;
        match command {
            CMD_GET_INFO => self.handle_get_info(payload),
            CMD_MAKE_CREDENTIAL => self.handle_make_credential(payload),
            CMD_GET_ASSERTION => self.handle_get_assertion(payload),
            CMD_RESET => self.handle_reset(payload),
            CMD_CLIENT_PIN => self.handle_client_pin(payload),
            CMD_GET_NEXT_ASSERTION => self.handle_get_next_assertion(payload),
            _ => Err(CtapStatusCode::InvalidCommand.into()),
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;
    use core::fmt;

    #[derive(Debug)]
    struct EnvError;
    impl fmt::Display for EnvError {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(f, "env")
        }
    }
    impl std::error::Error for EnvError {}

    struct Env {
        present: bool,
        counter_byte: u8,
    }
    impl SecureEnvironment for Env {
        type Error = EnvError;
        fn random(&mut self, out: &mut [u8]) -> Result<(), Self::Error> {
            for (i, b) in out.iter_mut().enumerate() {
                *b = self.counter_byte.wrapping_add(i as u8);
            }
            self.counter_byte = self.counter_byte.wrapping_add(out.len() as u8);
            Ok(())
        }
        fn user_presence(&mut self) -> Result<bool, Self::Error> {
            Ok(self.present)
        }
    }

    fn new_ctap() -> Ctap2<Env> {
        Ctap2::new(Env { present: true, counter_byte: 0x42 }, [0x11; 16])
    }

    fn make_credential_payload(
        client_data_hash: &[u8; 32],
        rp_id: &str,
        user_id: &[u8],
    ) -> Vec<u8> {
        let mut payload = Vec::new();
        // map 4 entries: 1 clientDataHash, 2 rp, 3 user, 4 pubKeyCredParams
        cbor::encode_map_header(&mut payload, 4);
        cbor::encode_unsigned(&mut payload, 0x01);
        cbor::encode_bytes(&mut payload, client_data_hash);
        cbor::encode_unsigned(&mut payload, 0x02);
        cbor::encode_map_header(&mut payload, 1);
        cbor::encode_text(&mut payload, "id");
        cbor::encode_text(&mut payload, rp_id);
        cbor::encode_unsigned(&mut payload, 0x03);
        cbor::encode_map_header(&mut payload, 1);
        cbor::encode_text(&mut payload, "id");
        cbor::encode_bytes(&mut payload, user_id);
        cbor::encode_unsigned(&mut payload, 0x04);
        cbor::encode_array_header(&mut payload, 1);
        cbor::encode_map_header(&mut payload, 2);
        cbor::encode_text(&mut payload, "type");
        cbor::encode_text(&mut payload, "public-key");
        cbor::encode_text(&mut payload, "alg");
        cbor::encode_int(&mut payload, -7);
        payload
    }

    #[test]
    fn get_info_works() {
        let mut ctap = new_ctap();
        let response = ctap.dispatch(&[CMD_GET_INFO]).unwrap();
        assert_eq!(response[0], 0);
        assert!(response.windows(8).any(|w| w == b"FIDO_2_0"));
        assert!(response.windows(8).any(|w| w == b"FIDO_2_1"));
        assert!(response.contains(&0x11));
        // verifica CBOR: após status, deve ser mapa
        let mut dec = cbor::Decoder::new(&response[1..]);
        let map_len = dec.decode_map_header().unwrap();
        assert!(map_len >= 7);
    }

    #[test]
    fn get_info_rejects_payload() {
        let mut ctap = new_ctap();
        let err = ctap.dispatch(&[CMD_GET_INFO, 0x00]).unwrap_err();
        match err {
            CtapError::Status(CtapStatusCode::InvalidLength) => {}
            _ => panic!("expected InvalidLength got {err:?}"),
        }
    }

    #[test]
    fn invalid_command() {
        let mut ctap = new_ctap();
        let err = ctap.dispatch(&[0xff]).unwrap_err();
        match err {
            CtapError::Status(CtapStatusCode::InvalidCommand) => {}
            _ => panic!("expected InvalidCommand"),
        }
    }

    #[test]
    fn malformed_empty() {
        let mut ctap = new_ctap();
        let err = ctap.dispatch(&[]).unwrap_err();
        match err {
            CtapError::MalformedRequest => {}
            _ => panic!("expected MalformedRequest"),
        }
    }

    #[test]
    fn make_credential_basic() {
        let mut ctap = new_ctap();
        let cdh = [0xAA; 32];
        let payload = make_credential_payload(&cdh, "example.com", b"user1");
        let mut request = vec![CMD_MAKE_CREDENTIAL];
        request.extend_from_slice(&payload);
        let resp = ctap.dispatch(&request).expect("makeCredential");
        assert_eq!(resp[0], 0x00);
        // decodifica resposta: deve conter authData
        let mut dec = cbor::Decoder::new(&resp[1..]);
        let mlen = dec.decode_map_header().unwrap();
        assert_eq!(mlen, 3);
        // check fmt == "none"
        let k = dec.decode_unsigned().unwrap();
        assert_eq!(k, 0x01);
        let fmt = dec.decode_text().unwrap();
        assert_eq!(fmt, "none");
    }

    #[test]
    fn make_credential_missing_parameter() {
        let mut ctap = new_ctap();
        // payload vazio para makeCredential => MissingParameter
        let err = ctap.dispatch(&[CMD_MAKE_CREDENTIAL, 0xa0]).unwrap_err(); // empty map
        match err {
            CtapError::Status(CtapStatusCode::MissingParameter) => {}
            _ => panic!("expected MissingParameter got {err:?}"),
        }
    }

    #[test]
    fn make_credential_duplicate_key_rejected() {
        let mut ctap = new_ctap();
        let mut payload = Vec::new();
        cbor::encode_map_header(&mut payload, 2);
        cbor::encode_unsigned(&mut payload, 0x01);
        cbor::encode_bytes(&mut payload, &[0xAA; 32]);
        cbor::encode_unsigned(&mut payload, 0x01); // duplicate 0x01
        cbor::encode_bytes(&mut payload, &[0xBB; 32]);
        let mut req = vec![CMD_MAKE_CREDENTIAL];
        req.extend_from_slice(&payload);
        let err = ctap.dispatch(&req).unwrap_err();
        match err {
            CtapError::Status(CtapStatusCode::InvalidCbor) => {}
            _ => panic!("expected InvalidCbor for duplicate, got {err:?}"),
        }
    }

    #[test]
    fn make_credential_invalid_type() {
        let mut ctap = new_ctap();
        let mut payload = Vec::new();
        cbor::encode_map_header(&mut payload, 1);
        cbor::encode_unsigned(&mut payload, 0x01);
        cbor::encode_text(&mut payload, "not bytes"); // deveria ser bstr 32
        let mut req = vec![CMD_MAKE_CREDENTIAL];
        req.extend_from_slice(&payload);
        let err = ctap.dispatch(&req).unwrap_err();
        match err {
            CtapError::Status(CtapStatusCode::CborUnexpectedType) => {}
            _ => panic!("expected CborUnexpectedType got {err:?}"),
        }
    }

    #[test]
    fn get_assertion_no_credentials() {
        let mut ctap = new_ctap();
        let mut payload = Vec::new();
        cbor::encode_map_header(&mut payload, 2);
        cbor::encode_unsigned(&mut payload, 0x01);
        cbor::encode_text(&mut payload, "example.com");
        cbor::encode_unsigned(&mut payload, 0x02);
        cbor::encode_bytes(&mut payload, &[0xCC; 32]);
        let mut req = vec![CMD_GET_ASSERTION];
        req.extend_from_slice(&payload);
        let err = ctap.dispatch(&req).unwrap_err();
        match err {
            CtapError::Status(CtapStatusCode::NoCredentials) => {}
            _ => panic!("expected NoCredentials got {err:?}"),
        }
    }

    #[test]
    fn credential_excluded() {
        let mut ctap = new_ctap();
        let cdh = [0x11; 32];
        let payload = make_credential_payload(&cdh, "example.com", b"u1");
        let mut req = vec![CMD_MAKE_CREDENTIAL];
        req.extend_from_slice(&payload);
        let resp = ctap.dispatch(&req).unwrap();
        assert_eq!(resp[0], 0);

        // extrai credential id da authData para usar em excludeList
        // authData contém credId; mas para teste simplificado, usamos o id gerado determinístico
        // Sabemos que Env gera 16 bytes começando em 0x42.. então primeiro id = 42 43 ... + counter xor
        // Em vez de parsear, só cria segunda credencial com excludeList contendo id existente recuperado via listagem interna
        // Vamos recuperar do credential store via inspeção direta (teste white-box)
        let existing_id = ctap.credentials[0].id.clone();

        // segunda tentativa com excludeList contendo existing_id -> deve falhar
        let mut payload2 = Vec::new();
        cbor::encode_map_header(&mut payload2, 5);
        cbor::encode_unsigned(&mut payload2, 0x01);
        cbor::encode_bytes(&mut payload2, &[0x22; 32]);
        cbor::encode_unsigned(&mut payload2, 0x02);
        cbor::encode_map_header(&mut payload2, 1);
        cbor::encode_text(&mut payload2, "id");
        cbor::encode_text(&mut payload2, "example.com");
        cbor::encode_unsigned(&mut payload2, 0x03);
        cbor::encode_map_header(&mut payload2, 1);
        cbor::encode_text(&mut payload2, "id");
        cbor::encode_bytes(&mut payload2, b"u2");
        cbor::encode_unsigned(&mut payload2, 0x04);
        cbor::encode_array_header(&mut payload2, 1);
        cbor::encode_map_header(&mut payload2, 2);
        cbor::encode_text(&mut payload2, "type");
        cbor::encode_text(&mut payload2, "public-key");
        cbor::encode_text(&mut payload2, "alg");
        cbor::encode_int(&mut payload2, -7);
        cbor::encode_unsigned(&mut payload2, 0x05);
        cbor::encode_array_header(&mut payload2, 1);
        cbor::encode_map_header(&mut payload2, 2);
        cbor::encode_text(&mut payload2, "type");
        cbor::encode_text(&mut payload2, "public-key");
        cbor::encode_text(&mut payload2, "id");
        cbor::encode_bytes(&mut payload2, &existing_id);

        let mut req2 = vec![CMD_MAKE_CREDENTIAL];
        req2.extend_from_slice(&payload2);
        let err = ctap.dispatch(&req2).unwrap_err();
        match err {
            CtapError::Status(CtapStatusCode::CredentialExcluded) => {}
            _ => panic!("expected CredentialExcluded got {err:?}"),
        }
    }

    #[test]
    fn invalid_cbor_trailing_bytes() {
        let mut ctap = new_ctap();
        let cdh = [0x55; 32];
        let mut payload = make_credential_payload(&cdh, "example.com", b"user");
        payload.push(0xff); // trailing byte
        let mut req = vec![CMD_MAKE_CREDENTIAL];
        req.extend_from_slice(&payload);
        let err = ctap.dispatch(&req).unwrap_err();
        match err {
            CtapError::Status(CtapStatusCode::InvalidCbor) => {}
            _ => panic!("expected InvalidCbor for trailing, got {err:?}"),
        }
    }

    #[test]
    fn reset_clears() {
        let mut ctap = new_ctap();
        let cdh = [0x33; 32];
        let payload = make_credential_payload(&cdh, "example.com", b"u1");
        let mut req = vec![CMD_MAKE_CREDENTIAL];
        req.extend_from_slice(&payload);
        ctap.dispatch(&req).unwrap();
        assert_eq!(ctap.credentials.len(), 1);
        let resp = ctap.dispatch(&[CMD_RESET]).unwrap();
        assert_eq!(resp[0], 0x00);
        assert_eq!(ctap.credentials.len(), 0);
        assert_eq!(ctap.counter, 0);
    }

    #[test]
    fn cbor_non_minimal_rejected() {
        let mut ctap = new_ctap();
        // encode 0x01 as 0x18 0x01 (non-minimal)
        let payload = vec![0xa1, 0x18, 0x01, 0x58, 0x20, 0xAA,0xAA,0xAA,0xAA,0xAA,0xAA,0xAA,0xAA,0xAA,0xAA,0xAA,0xAA,0xAA,0xAA,0xAA,0xAA,0xAA,0xAA,0xAA,0xAA,0xAA,0xAA,0xAA,0xAA,0xAA,0xAA,0xAA,0xAA,0xAA,0xAA,0xAA,0xAA];
        let mut req = vec![CMD_MAKE_CREDENTIAL];
        req.extend_from_slice(&payload);
        let err = ctap.dispatch(&req).unwrap_err();
        match err {
            CtapError::Status(CtapStatusCode::InvalidCbor) => {}
            _ => panic!("expected InvalidCbor for non-minimal got {err:?}"),
        }
    }

    #[test]
    fn get_assertion_after_make() {
        let mut ctap = new_ctap();
        let cdh = [0x77; 32];
        let payload = make_credential_payload(&cdh, "example.com", b"alice");
        let mut req = vec![CMD_MAKE_CREDENTIAL];
        req.extend_from_slice(&payload);
        ctap.dispatch(&req).unwrap();

        let mut payload2 = Vec::new();
        cbor::encode_map_header(&mut payload2, 2);
        cbor::encode_unsigned(&mut payload2, 0x01);
        cbor::encode_text(&mut payload2, "example.com");
        cbor::encode_unsigned(&mut payload2, 0x02);
        cbor::encode_bytes(&mut payload2, &[0x88; 32]);
        let mut req2 = vec![CMD_GET_ASSERTION];
        req2.extend_from_slice(&payload2);
        let resp = ctap.dispatch(&req2).unwrap();
        assert_eq!(resp[0], 0x00);
        let mut dec = cbor::Decoder::new(&resp[1..]);
        let mlen = dec.decode_map_header().unwrap();
        assert_eq!(mlen, 3);
    }
}
