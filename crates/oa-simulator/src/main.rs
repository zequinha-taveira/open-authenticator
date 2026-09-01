#![forbid(unsafe_code)]

use oa_core::SecureEnvironment;
use oa_ctap2::{cbor, Ctap2, CMD_GET_ASSERTION, CMD_GET_INFO, CMD_MAKE_CREDENTIAL, CMD_RESET};
use std::fmt;

#[derive(Debug)]
struct SimError;
impl fmt::Display for SimError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "simulator error")
    }
}
impl std::error::Error for SimError {}

#[derive(Default)]
struct VirtualEnvironment {
    present: bool,
    entropy: u8,
}

impl SecureEnvironment for VirtualEnvironment {
    type Error = SimError;
    fn random(&mut self, out: &mut [u8]) -> Result<(), Self::Error> {
        for byte in out.iter_mut() {
            *byte = self.entropy;
            self.entropy = self.entropy.wrapping_add(1);
        }
        Ok(())
    }
    fn user_presence(&mut self) -> Result<bool, Self::Error> {
        Ok(self.present)
    }
}

fn build_make_credential_payload(
    client_data_hash: &[u8; 32],
    rp_id: &str,
    user_id: &[u8],
) -> Vec<u8> {
    let mut payload = Vec::new();
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

fn build_get_assertion_payload(rp_id: &str, client_data_hash: &[u8; 32]) -> Vec<u8> {
    let mut payload = Vec::new();
    cbor::encode_map_header(&mut payload, 2);
    cbor::encode_unsigned(&mut payload, 0x01);
    cbor::encode_text(&mut payload, rp_id);
    cbor::encode_unsigned(&mut payload, 0x02);
    cbor::encode_bytes(&mut payload, client_data_hash);
    payload
}

fn main() {
    println!("Open Authenticator — Simulador CTAP2 (protótipo, não produção)");
    let env = VirtualEnvironment {
        present: true,
        entropy: 0x42,
    };
    let mut authenticator = Ctap2::new(env, [0xAA; 16]);

    // getInfo
    let resp = authenticator.dispatch(&[CMD_GET_INFO]).expect("getInfo");
    println!("getInfo ({} bytes): {:02x?}", resp.len(), resp);
    assert_eq!(resp[0], 0x00);
    println!(
        "  -> versões e aaguid presentes: {}",
        if resp.windows(8).any(|w| w == b"FIDO_2_0") {
            "ok"
        } else {
            "falha"
        }
    );

    // makeCredential
    let cdh = [0x11; 32];
    let payload = build_make_credential_payload(&cdh, "example.com", b"alice");
    let mut req = vec![CMD_MAKE_CREDENTIAL];
    req.extend_from_slice(&payload);
    match authenticator.dispatch(&req) {
        Ok(resp) => {
            println!(
                "makeCredential ok ({} bytes): {:02x?}",
                resp.len(),
                &resp[..64.min(resp.len())]
            );
            assert_eq!(resp[0], 0x00);
        }
        Err(e) => {
            println!("makeCredential erro: {e:?}");
        }
    }

    // getAssertion
    let cdh2 = [0x22; 32];
    let payload2 = build_get_assertion_payload("example.com", &cdh2);
    let mut req2 = vec![CMD_GET_ASSERTION];
    req2.extend_from_slice(&payload2);
    match authenticator.dispatch(&req2) {
        Ok(resp) => {
            println!("getAssertion ok ({} bytes)", resp.len());
        }
        Err(e) => println!("getAssertion erro: {e:?}"),
    }

    // reset
    match authenticator.dispatch(&[CMD_RESET]) {
        Ok(r) => println!("reset ok: {:02x?}", r),
        Err(e) => println!("reset erro: {e:?}"),
    }

    println!("Simulador finalizado. Transporte em memória demonstrado via dispatch direto; para framing CTAPHID-like use InMemoryTransport em oa-core.");
}
