import json
import pathlib
import pytest
from virtual_hardware import VirtualSecurityKey
from virtual_hardware.device import CtapError

VECTORS_DIR = pathlib.Path(__file__).parents[2] / "vectors"

def load_vectors():
    vectors = []
    for p in VECTORS_DIR.glob("*.json"):
        with open(p, "r", encoding="utf-8") as f:
            data = json.load(f)
            # normalize: some old vectors have different schema
            vectors.append((p.name, data))
    return vectors

@pytest.mark.parametrize("filename,data", load_vectors())
def test_vector(filename, data):
    request_hex = data.get("request_hex")
    if not request_hex:
        pytest.skip("no request_hex")
    expected_status = data.get("expected_status")
    if expected_status is None:
        # old schema: expected_status may be 0
        expected_status = 0
    request = bytes.fromhex(request_hex)
    key = VirtualSecurityKey()
    # reset to clean state for each vector (isolado)
    try:
        resp = key.ctap(request)
        # sucesso: primeiro byte deve ser 0x00
        assert resp[0] == expected_status, f"{filename} esperado {expected_status} obteve {resp[0]}"
        if expected_status == 0 and "expected_contains_utf8" in data:
            assert data["expected_contains_utf8"].encode() in resp, f"missing utf8 in {filename}"
    except CtapError as e:
        assert e.code == expected_status, f"{filename} esperado status {expected_status} obteve {e.code} ({e})"
    except ValueError as e:
        # compat: alguns erros antigos levantavam ValueError sem código; mapeia
        if expected_status != 0:
            # tenta extrair código se for CtapError disfarçado
            pytest.fail(f"{filename} ValueError sem código: {e} esperado {expected_status}")
        else:
            pytest.fail(f"{filename} falhou inesperado: {e}")

def test_make_credential_then_get_assertion():
    key = VirtualSecurityKey()
    from virtual_hardware.device import cbor_encode_unsigned, cbor_encode_text, cbor_encode_bytes, cbor_encode_array_header, cbor_encode_map_header, cbor_encode_int
    cdh = bytes([0x11]*32)
    payload = b""
    payload += cbor_encode_map_header(4)
    payload += cbor_encode_unsigned(0x01) + cbor_encode_bytes(cdh)
    payload += cbor_encode_unsigned(0x02) + cbor_encode_map_header(1) + cbor_encode_text("id") + cbor_encode_text("example.com")
    payload += cbor_encode_unsigned(0x03) + cbor_encode_map_header(1) + cbor_encode_text("id") + cbor_encode_bytes(b"alice")
    payload += cbor_encode_unsigned(0x04) + cbor_encode_array_header(1) + cbor_encode_map_header(2) + cbor_encode_text("type") + cbor_encode_text("public-key") + cbor_encode_text("alg") + cbor_encode_int(-7)
    resp = key.ctap(bytes([0x01]) + payload)
    assert resp[0] == 0x00
    # getAssertion deve encontrar credencial
    cdh2 = bytes([0x22]*32)
    payload2 = b""
    payload2 += cbor_encode_map_header(2)
    payload2 += cbor_encode_unsigned(0x01) + cbor_encode_text("example.com")
    payload2 += cbor_encode_unsigned(0x02) + cbor_encode_bytes(cdh2)
    resp2 = key.ctap(bytes([0x02]) + payload2)
    assert resp2[0] == 0x00
    assert len(resp2) > 10

def test_credential_excluded():
    from virtual_hardware.device import cbor_encode_unsigned, cbor_encode_text, cbor_encode_bytes, cbor_encode_array_header, cbor_encode_map_header, cbor_encode_int
    key = VirtualSecurityKey()
    cdh = bytes([0x11]*32)
    payload = b""
    payload += cbor_encode_map_header(4)
    payload += cbor_encode_unsigned(0x01) + cbor_encode_bytes(cdh)
    payload += cbor_encode_unsigned(0x02) + cbor_encode_map_header(1) + cbor_encode_text("id") + cbor_encode_text("example.com")
    payload += cbor_encode_unsigned(0x03) + cbor_encode_map_header(1) + cbor_encode_text("id") + cbor_encode_bytes(b"alice")
    payload += cbor_encode_unsigned(0x04) + cbor_encode_array_header(1) + cbor_encode_map_header(2) + cbor_encode_text("type") + cbor_encode_text("public-key") + cbor_encode_text("alg") + cbor_encode_int(-7)
    key.ctap(bytes([0x01]) + payload)
    # tenta criar novamente com excludeList contendo credId existente
    existing = key.credentials[0].cred_id
    payload2 = b""
    payload2 += cbor_encode_map_header(5)
    payload2 += cbor_encode_unsigned(0x01) + cbor_encode_bytes(bytes([0x22]*32))
    payload2 += cbor_encode_unsigned(0x02) + cbor_encode_map_header(1) + cbor_encode_text("id") + cbor_encode_text("example.com")
    payload2 += cbor_encode_unsigned(0x03) + cbor_encode_map_header(1) + cbor_encode_text("id") + cbor_encode_bytes(b"bob")
    payload2 += cbor_encode_unsigned(0x04) + cbor_encode_array_header(1) + cbor_encode_map_header(2) + cbor_encode_text("type") + cbor_encode_text("public-key") + cbor_encode_text("alg") + cbor_encode_int(-7)
    payload2 += cbor_encode_unsigned(0x05) + cbor_encode_array_header(1) + cbor_encode_map_header(2) + cbor_encode_text("type") + cbor_encode_text("public-key") + cbor_encode_text("id") + cbor_encode_bytes(existing)
    try:
        key.ctap(bytes([0x01]) + payload2)
        assert False, "deveria ter falhado com CredentialExcluded"
    except CtapError as e:
        assert e.code == 0x19, f"esperado 0x19 obteve {e.code:#x}"
