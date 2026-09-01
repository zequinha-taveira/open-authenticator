#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;

#[cfg(feature = "zeroize-derive")]
use zeroize::{Zeroize, ZeroizeOnDrop};

// ---------------------------------------------------------------------------
// Algoritmos e identificadores
// ---------------------------------------------------------------------------

/// Algoritmos COSE suportados pelo framework.
/// Expansível sem quebrar `match` exaustivo em forks (non_exhaustive).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Algorithm {
    Es256,
    EdDsa,
    Rs256,
}

impl Algorithm {
    pub fn cose_id(self) -> i32 {
        match self {
            Self::Es256 => -7,
            Self::EdDsa => -8,
            Self::Rs256 => -257,
        }
    }

    pub fn from_cose_id(id: i32) -> Option<Self> {
        match id {
            -7 => Some(Self::Es256),
            -8 => Some(Self::EdDsa),
            -257 => Some(Self::Rs256),
            _ => None,
        }
    }
}

// ---------------------------------------------------------------------------
// Códigos de status CTAP2 (spec §6.1)
// ---------------------------------------------------------------------------

/// Códigos de erro CTAP2. Valores são os bytes de status na resposta.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
#[non_exhaustive]
pub enum CtapStatusCode {
    Ok = 0x00,
    InvalidCommand = 0x01,
    InvalidParameter = 0x02,
    InvalidLength = 0x03,
    InvalidSeq = 0x04,
    Timeout = 0x05,
    ChannelBusy = 0x06,
    LockRequired = 0x0A,
    InvalidChannel = 0x0B,
    CborUnexpectedType = 0x11,
    InvalidCbor = 0x12,
    MissingParameter = 0x14,
    LimitExceeded = 0x15,
    UnsupportedExtension = 0x16,
    CredentialExcluded = 0x19,
    Processing = 0x21,
    InvalidCredential = 0x22,
    UserActionPending = 0x23,
    OperationPending = 0x24,
    NoOperations = 0x25,
    UnsupportedAlgorithm = 0x26,
    OperationDenied = 0x27,
    KeyStoreFull = 0x28,
    NoOperationPending = 0x2A,
    UnsupportedOption = 0x2B,
    InvalidOption = 0x2C,
    KeepAliveCancel = 0x2D,
    NoCredentials = 0x2E,
    UserActionTimeout = 0x2F,
    NotAllowed = 0x30,
    PinInvalid = 0x31,
    PinBlocked = 0x32,
    PinAuthInvalid = 0x33,
    PinAuthBlocked = 0x34,
    PinNotSet = 0x35,
    PinRequired = 0x36,
    PinPolicyViolation = 0x37,
    PinTokenExpired = 0x38,
    RequestTooLarge = 0x39,
    ActionTimeout = 0x3A,
    UpRequired = 0x3B,
    UvBlocked = 0x3C,
    IntegrityFailure = 0x3D,
    InvalidSubcommand = 0x3E,
    UvInvalid = 0x3F,
    UnauthorizedPermission = 0x40,
    Other(u8),
}

impl CtapStatusCode {
    pub fn as_u8(self) -> u8 {
        match self {
            Self::Ok => 0x00,
            Self::InvalidCommand => 0x01,
            Self::InvalidParameter => 0x02,
            Self::InvalidLength => 0x03,
            Self::InvalidSeq => 0x04,
            Self::Timeout => 0x05,
            Self::ChannelBusy => 0x06,
            Self::LockRequired => 0x0A,
            Self::InvalidChannel => 0x0B,
            Self::CborUnexpectedType => 0x11,
            Self::InvalidCbor => 0x12,
            Self::MissingParameter => 0x14,
            Self::LimitExceeded => 0x15,
            Self::UnsupportedExtension => 0x16,
            Self::CredentialExcluded => 0x19,
            Self::Processing => 0x21,
            Self::InvalidCredential => 0x22,
            Self::UserActionPending => 0x23,
            Self::OperationPending => 0x24,
            Self::NoOperations => 0x25,
            Self::UnsupportedAlgorithm => 0x26,
            Self::OperationDenied => 0x27,
            Self::KeyStoreFull => 0x28,
            Self::NoOperationPending => 0x2A,
            Self::UnsupportedOption => 0x2B,
            Self::InvalidOption => 0x2C,
            Self::KeepAliveCancel => 0x2D,
            Self::NoCredentials => 0x2E,
            Self::UserActionTimeout => 0x2F,
            Self::NotAllowed => 0x30,
            Self::PinInvalid => 0x31,
            Self::PinBlocked => 0x32,
            Self::PinAuthInvalid => 0x33,
            Self::PinAuthBlocked => 0x34,
            Self::PinNotSet => 0x35,
            Self::PinRequired => 0x36,
            Self::PinPolicyViolation => 0x37,
            Self::PinTokenExpired => 0x38,
            Self::RequestTooLarge => 0x39,
            Self::ActionTimeout => 0x3A,
            Self::UpRequired => 0x3B,
            Self::UvBlocked => 0x3C,
            Self::IntegrityFailure => 0x3D,
            Self::InvalidSubcommand => 0x3E,
            Self::UvInvalid => 0x3F,
            Self::UnauthorizedPermission => 0x40,
            Self::Other(b) => b,
        }
    }

    pub fn from_u8(b: u8) -> Self {
        match b {
            0x00 => Self::Ok,
            0x01 => Self::InvalidCommand,
            0x02 => Self::InvalidParameter,
            0x03 => Self::InvalidLength,
            0x04 => Self::InvalidSeq,
            0x05 => Self::Timeout,
            0x06 => Self::ChannelBusy,
            0x0A => Self::LockRequired,
            0x0B => Self::InvalidChannel,
            0x11 => Self::CborUnexpectedType,
            0x12 => Self::InvalidCbor,
            0x14 => Self::MissingParameter,
            0x15 => Self::LimitExceeded,
            0x16 => Self::UnsupportedExtension,
            0x19 => Self::CredentialExcluded,
            0x21 => Self::Processing,
            0x22 => Self::InvalidCredential,
            0x23 => Self::UserActionPending,
            0x24 => Self::OperationPending,
            0x25 => Self::NoOperations,
            0x26 => Self::UnsupportedAlgorithm,
            0x27 => Self::OperationDenied,
            0x28 => Self::KeyStoreFull,
            0x2A => Self::NoOperationPending,
            0x2B => Self::UnsupportedOption,
            0x2C => Self::InvalidOption,
            0x2D => Self::KeepAliveCancel,
            0x2E => Self::NoCredentials,
            0x2F => Self::UserActionTimeout,
            0x30 => Self::NotAllowed,
            0x31 => Self::PinInvalid,
            0x32 => Self::PinBlocked,
            0x33 => Self::PinAuthInvalid,
            0x34 => Self::PinAuthBlocked,
            0x35 => Self::PinNotSet,
            0x36 => Self::PinRequired,
            0x37 => Self::PinPolicyViolation,
            0x38 => Self::PinTokenExpired,
            0x39 => Self::RequestTooLarge,
            0x3A => Self::ActionTimeout,
            0x3B => Self::UpRequired,
            0x3C => Self::UvBlocked,
            0x3D => Self::IntegrityFailure,
            0x3E => Self::InvalidSubcommand,
            0x3F => Self::UvInvalid,
            0x40 => Self::UnauthorizedPermission,
            other => Self::Other(other),
        }
    }
}

impl core::fmt::Display for CtapStatusCode {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "CTAP 0x{:02x}", self.as_u8())
    }
}

#[cfg(feature = "std")]
impl std::error::Error for CtapStatusCode {}

// ---------------------------------------------------------------------------
// Info do autenticador (getInfo)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthenticatorInfo {
    pub versions: Vec<&'static str>,
    pub extensions: Vec<&'static str>,
    pub aaguid: [u8; 16],
    pub options: Options,
    pub max_msg_size: u32,
    pub pin_uv_auth_protocols: Vec<u32>,
    pub max_credential_count_in_list: Option<u32>,
    pub max_credential_id_length: Option<u32>,
    pub transports: Vec<&'static str>,
    pub algorithms: Vec<Algorithm>,
    pub max_serialized_large_blob_array: Option<u32>,
    pub force_pin_change: bool,
    pub min_pin_length: Option<u32>,
    pub firmware_version: Option<u32>,
    pub max_cred_blob_length: Option<u32>,
    pub remaining_discoverable_credentials: Option<u32>,
    pub vendor_prototype_config_commands: Option<Vec<u32>>,
}

impl Default for AuthenticatorInfo {
    fn default() -> Self {
        Self {
            versions: alloc::vec!["FIDO_2_0", "FIDO_2_1"],
            extensions: Vec::new(),
            aaguid: [0u8; 16],
            options: Options::default(),
            max_msg_size: 1200,
            pin_uv_auth_protocols: alloc::vec![1],
            max_credential_count_in_list: Some(8),
            max_credential_id_length: Some(128),
            transports: alloc::vec!["usb"],
            algorithms: alloc::vec![Algorithm::Es256],
            max_serialized_large_blob_array: None,
            force_pin_change: false,
            min_pin_length: Some(4),
            firmware_version: None,
            max_cred_blob_length: None,
            remaining_discoverable_credentials: Some(25),
            vendor_prototype_config_commands: None,
        }
    }
}

impl AuthenticatorInfo {
    pub fn new(aaguid: [u8; 16]) -> Self {
        Self {
            aaguid,
            ..Self::default()
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Options {
    pub rk: bool,
    pub up: bool,
    pub uv: bool,
    /// alwaysUv (CTAP 2.1)
    pub always_uv: bool,
    pub plat: bool,
    pub client_pin: Option<bool>,
}

impl Options {
    pub fn new(rk: bool, up: bool, uv: bool) -> Self {
        Self {
            rk,
            up,
            uv,
            ..Self::default()
        }
    }
}

// ---------------------------------------------------------------------------
// Handles sensíveis — política de zeroização
// ---------------------------------------------------------------------------

/// Handle opaco para material de chave. O backend decide o armazenamento.
/// Deve ser zeroizado quando descartado se contiver bytes sensíveis.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyHandle(pub Vec<u8>);

#[cfg(feature = "zeroize-derive")]
impl Zeroize for KeyHandle {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}
#[cfg(feature = "zeroize-derive")]
impl ZeroizeOnDrop for KeyHandle {}
#[cfg(feature = "zeroize-derive")]
impl Drop for KeyHandle {
    fn drop(&mut self) {
        self.zeroize();
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Signature(pub Vec<u8>);

#[cfg(feature = "zeroize-derive")]
impl Zeroize for Signature {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}
#[cfg(feature = "zeroize-derive")]
impl ZeroizeOnDrop for Signature {}

/// Chave para storage seguro. Não deve conter segredo em claro em logs.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct StorageKey(pub Vec<u8>);

impl StorageKey {
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }
}

impl From<&str> for StorageKey {
    fn from(s: &str) -> Self {
        Self(s.as_bytes().to_vec())
    }
}

/// Credencial residente mínima (para state machine inicial).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Credential {
    pub id: Vec<u8>,
    pub rp_id: String,
    pub user_handle: Vec<u8>,
    pub private_key: KeyHandle,
    pub counter: u32,
}

// ---------------------------------------------------------------------------
// Traits de ambiente seguro
// ---------------------------------------------------------------------------

/// RNG abstrato — única fonte de aleatoriedade para o protocolo.
/// Implementações de produção MUST usar TRNG do hardware.
pub trait RandomSource {
    type Error;
    fn fill_bytes(&mut self, out: &mut [u8]) -> Result<(), Self::Error>;
}

/// Provedor de presença do usuário (botão/toque).
pub trait UserPresence {
    type Error;
    fn check(&mut self) -> Result<bool, Self::Error>;
}

/// Contador monotônico persistente (signature counter).
pub trait MonotonicCounter {
    type Error;
    fn next(&mut self) -> Result<u32, Self::Error>;
}

/// Provedor criptográfico mínimo. Não implementa primitivas novas;
/// delega a bibliotecas maduras (ver auditoria.md §5C).
pub trait CryptoProvider {
    type Error;
    fn generate_key(&mut self, algorithm: Algorithm) -> Result<KeyHandle, Self::Error>;
    fn sign(&mut self, key: &KeyHandle, message: &[u8]) -> Result<Signature, Self::Error>;
}

/// Storage seguro abstrato. Produção: flash protegida / secure element.
pub trait SecureStorage {
    type Error;
    fn read(&mut self, key: &StorageKey) -> Result<Option<Vec<u8>>, Self::Error>;
    fn write(&mut self, key: StorageKey, value: &[u8]) -> Result<(), Self::Error>;
    fn remove(&mut self, key: &StorageKey) -> Result<bool, Self::Error>;
    fn clear(&mut self) -> Result<(), Self::Error>;
}

/// Transporte framing-independente de semântica CTAP.
pub trait Transport {
    type Error;
    fn send(&mut self, frame: &[u8]) -> Result<(), Self::Error>;
    fn receive(&mut self, buffer: &mut [u8]) -> Result<usize, Self::Error>;
}

/// Erros para o transporte em memória (testes / simulador).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InMemoryTransportError {
    Full,
    Empty,
    Disconnected,
}

impl core::fmt::Display for InMemoryTransportError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Full => write!(f, "transport full"),
            Self::Empty => write!(f, "transport empty"),
            Self::Disconnected => write!(f, "transport disconnected"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for InMemoryTransportError {}

/// Transporte em memória para testes e simulador. Mantém framing separado da semântica CTAP.
#[derive(Debug, Default)]
pub struct InMemoryTransport {
    queue: Vec<Vec<u8>>,
    max_frames: usize,
    max_frame_size: usize,
    disconnected: bool,
}

impl InMemoryTransport {
    pub fn new(max_frames: usize, max_frame_size: usize) -> Self {
        Self {
            queue: Vec::new(),
            max_frames: if max_frames == 0 { 16 } else { max_frames },
            max_frame_size: if max_frame_size == 0 {
                1200
            } else {
                max_frame_size
            },
            disconnected: false,
        }
    }

    pub fn len(&self) -> usize {
        self.queue.len()
    }

    pub fn is_empty(&self) -> bool {
        self.queue.is_empty()
    }

    pub fn disconnect(&mut self) {
        self.disconnected = true;
    }

    pub fn reconnect(&mut self) {
        self.disconnected = false;
    }

    pub fn corrupt_next(&mut self) {
        if let Some(frame) = self.queue.first_mut() {
            if let Some(b) = frame.first_mut() {
                *b ^= 0xFF;
            }
        }
    }

    pub fn clear_queue(&mut self) {
        self.queue.clear();
    }
}

impl Transport for InMemoryTransport {
    type Error = InMemoryTransportError;

    fn send(&mut self, frame: &[u8]) -> Result<(), Self::Error> {
        if self.disconnected {
            return Err(InMemoryTransportError::Disconnected);
        }
        if frame.len() > self.max_frame_size {
            return Err(InMemoryTransportError::Full);
        }
        if self.queue.len() >= self.max_frames {
            return Err(InMemoryTransportError::Full);
        }
        self.queue.push(frame.to_vec());
        Ok(())
    }

    fn receive(&mut self, buffer: &mut [u8]) -> Result<usize, Self::Error> {
        if self.disconnected {
            return Err(InMemoryTransportError::Disconnected);
        }
        if self.queue.is_empty() {
            return Err(InMemoryTransportError::Empty);
        }
        let frame = self.queue.remove(0);
        if buffer.len() < frame.len() {
            // devolve frame para não perder dados (mantém ordem FIFO)
            self.queue.insert(0, frame);
            return Err(InMemoryTransportError::Full);
        }
        let len = frame.len();
        buffer[..len].copy_from_slice(&frame);
        Ok(len)
    }
}

impl Transport for Vec<Vec<u8>> {
    type Error = InMemoryTransportError;
    fn send(&mut self, frame: &[u8]) -> Result<(), Self::Error> {
        self.push(frame.to_vec());
        Ok(())
    }
    fn receive(&mut self, buffer: &mut [u8]) -> Result<usize, Self::Error> {
        let frame = self.pop().ok_or(InMemoryTransportError::Empty)?;
        if buffer.len() < frame.len() {
            self.push(frame);
            return Err(InMemoryTransportError::Full);
        }
        let len = frame.len();
        buffer[..len].copy_from_slice(&frame);
        Ok(len)
    }
}

/// Ambiente seguro legado (compatibilidade com código existente).
/// Novos códigos SHOULD preferir traits granulares acima.
pub trait SecureEnvironment {
    type Error;
    fn random(&mut self, out: &mut [u8]) -> Result<(), Self::Error>;
    fn user_presence(&mut self) -> Result<bool, Self::Error>;
}

impl<T> RandomSource for T
where
    T: SecureEnvironment,
{
    type Error = T::Error;
    fn fill_bytes(&mut self, out: &mut [u8]) -> Result<(), Self::Error> {
        self.random(out)
    }
}

impl<T> UserPresence for T
where
    T: SecureEnvironment,
{
    type Error = T::Error;
    fn check(&mut self) -> Result<bool, Self::Error> {
        self.user_presence()
    }
}

// ---------------------------------------------------------------------------
// Interface Authenticator conceitual (spec §3.1)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MakeCredentialRequest {
    pub client_data_hash: [u8; 32],
    pub rp_id: String,
    pub user_id: Vec<u8>,
    pub user_name: Option<String>,
    pub require_resident_key: bool,
    pub require_user_presence: bool,
    pub require_user_verification: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MakeCredentialResponse {
    pub credential_id: Vec<u8>,
    pub counter: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GetAssertionRequest {
    pub rp_id: String,
    pub client_data_hash: [u8; 32],
    pub allow_list: Vec<Vec<u8>>,
    pub require_user_presence: bool,
    pub require_user_verification: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GetAssertionResponse {
    pub credential_id: Vec<u8>,
    pub counter: u32,
    pub signature: Signature,
}

pub trait Authenticator {
    type Error;
    fn get_info(&self) -> &AuthenticatorInfo;
    fn make_credential(
        &mut self,
        request: MakeCredentialRequest,
    ) -> Result<MakeCredentialResponse, Self::Error>;
    fn get_assertion(
        &mut self,
        request: GetAssertionRequest,
    ) -> Result<GetAssertionResponse, Self::Error>;
    fn reset(&mut self) -> Result<(), Self::Error>;
}

// ---------------------------------------------------------------------------
// Helpers de zeroização para buffers temporários
// ---------------------------------------------------------------------------

/// Apaga buffer sensível se feature `zeroize` estiver ativa, senão no-op.
/// Use para limpar `clientDataHash`, `pinToken`, etc. após uso.
pub fn sensitive_zeroize(buf: &mut [u8]) {
    #[cfg(feature = "zeroize-derive")]
    {
        buf.zeroize();
    }
    #[cfg(not(feature = "zeroize-derive"))]
    {
        let _ = buf;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inmemory_transport_send_receive_fifo() {
        let mut t = InMemoryTransport::new(10, 1200);
        t.send(b"frame1").unwrap();
        t.send(b"frame2").unwrap();
        let mut buf = vec![0u8; 16];
        let n = t.receive(&mut buf).unwrap();
        assert_eq!(&buf[..n], b"frame1");
        let n = t.receive(&mut buf).unwrap();
        assert_eq!(&buf[..n], b"frame2");
        assert!(matches!(
            t.receive(&mut buf),
            Err(InMemoryTransportError::Empty)
        ));
    }

    #[test]
    fn inmemory_transport_disconnect() {
        let mut t = InMemoryTransport::new(10, 1200);
        t.disconnect();
        assert!(matches!(
            t.send(b"x"),
            Err(InMemoryTransportError::Disconnected)
        ));
        let mut buf = [0u8; 10];
        assert!(matches!(
            t.receive(&mut buf),
            Err(InMemoryTransportError::Disconnected)
        ));
        t.reconnect();
        t.send(b"ok").unwrap();
        let n = t.receive(&mut buf).unwrap();
        assert_eq!(&buf[..n], b"ok");
    }

    #[test]
    fn inmemory_transport_full() {
        let mut t = InMemoryTransport::new(1, 10);
        t.send(b"a").unwrap();
        assert!(matches!(t.send(b"b"), Err(InMemoryTransportError::Full)));
        // buffer too small
        t.send(b"toolongpayload").unwrap_err(); // frame too large vs max_frame_size? Actually max 10, payload 14 => Full
        let mut t2 = InMemoryTransport::new(10, 1200);
        t2.send(b"hello world").unwrap();
        let mut tiny = [0u8; 2];
        assert!(matches!(
            t2.receive(&mut tiny),
            Err(InMemoryTransportError::Full)
        ));
        // depois de falhar, frame ainda está na fila
        let mut big = [0u8; 20];
        let n = t2.receive(&mut big).unwrap();
        assert_eq!(&big[..n], b"hello world");
    }

    #[test]
    fn inmemory_transport_corrupt() {
        let mut t = InMemoryTransport::new(10, 1200);
        t.send(b"\x04\x00").unwrap();
        t.corrupt_next();
        let mut buf = [0u8; 10];
        let n = t.receive(&mut buf).unwrap();
        assert_ne!(buf[0], 0x04);
        assert_eq!(n, 2);
    }

    #[test]
    fn ctap_status_codes_roundtrip() {
        for code in 0u8..=0x40 {
            let s = CtapStatusCode::from_u8(code);
            assert_eq!(s.as_u8(), code, "code {code:#x} roundtrip falhou {:?}", s);
        }
        assert_eq!(CtapStatusCode::from_u8(0xFF), CtapStatusCode::Other(0xFF));
    }

    #[test]
    fn zeroize_helper_noop_when_disabled() {
        let mut buf = [0xAAu8; 16];
        sensitive_zeroize(&mut buf);
        // sem feature zeroize, não apaga
        #[cfg(not(feature = "zeroize-derive"))]
        assert_eq!(buf, [0xAA; 16]);
        #[cfg(feature = "zeroize-derive")]
        assert_eq!(buf, [0x00; 16]);
    }

    #[test]
    fn algorithm_ids() {
        assert_eq!(Algorithm::Es256.cose_id(), -7);
        assert_eq!(Algorithm::from_cose_id(-7), Some(Algorithm::Es256));
        assert_eq!(Algorithm::from_cose_id(-999), None);
    }
}
