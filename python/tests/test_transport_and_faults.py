import time
import pytest
from virtual_hardware import VirtualSecurityKey
from virtual_hardware.device import CtapError, cbor_encode_unsigned, cbor_encode_text, cbor_encode_bytes, cbor_encode_array_header, cbor_encode_map_header, cbor_encode_int


def make_cred_payload(cdh, rp, user):
    p = b""
    p += cbor_encode_map_header(4)
    p += cbor_encode_unsigned(0x01) + cbor_encode_bytes(cdh)
    p += cbor_encode_unsigned(0x02) + cbor_encode_map_header(1) + cbor_encode_text("id") + cbor_encode_text(rp)
    p += cbor_encode_unsigned(0x03) + cbor_encode_map_header(1) + cbor_encode_text("id") + cbor_encode_bytes(user)
    p += cbor_encode_unsigned(0x04) + cbor_encode_array_header(1) + cbor_encode_map_header(2) + cbor_encode_text("type") + cbor_encode_text("public-key") + cbor_encode_text("alg") + cbor_encode_int(-7)
    return p

def test_transport_send_receive():
    key = VirtualSecurityKey()
    frame = b"\x04"
    key.transport_send(frame)
    assert not key.transport_queue == []
    out = key.transport_receive()
    assert out == frame

def test_transport_disconnect():
    key = VirtualSecurityKey()
    key.disconnect()
    try:
        key.transport_send(b"\x04")
    except ConnectionError:
        pass
    else:
        assert False, "expected ConnectionError"
    key.reconnect()
    # deve voltar a funcionar
    key.transport_send(b"\x04")
    assert key.transport_receive() == b"\x04"

def test_corrupt_next_frame():
    key = VirtualSecurityKey()
    # send valid getInfo
    key.transport_send(bytes([0x04]))
    key.corrupt_next_frame()
    corrupted = key.transport_receive()
    assert corrupted[0] != 0x04

def test_corrupt_via_ctap():
    key = VirtualSecurityKey()
    key.corrupt_next_frame()
    # ctap com corrupção deve falhar como InvalidCommand ou InvalidCbor
    # request original 0x04 corrompido vira 0xFB
    try:
        key.ctap(bytes([0x04]))
        assert False, "should have raised"
    except CtapError as e:
        assert e.code in (0x01, 0x12, 0x02)
    except ValueError:
        pass

def test_deny_presence_make_credential():
    key = VirtualSecurityKey()
    key.deny_user_presence()
    cdh = bytes([0x11]*32)
    payload = make_cred_payload(cdh, "example.com", b"alice")
    # up requerido => deve retornar OperationDenied 0x27
    try:
        key.ctap(bytes([0x01]) + payload)
        assert False
    except CtapError as e:
        assert e.code == 0x27

def test_fill_storage():
    key = VirtualSecurityKey()
    key.fill_storage()
    cdh = bytes([0x33]*32)
    payload = make_cred_payload(cdh, "example.com", b"bob")
    try:
        key.ctap(bytes([0x01]) + payload)
        assert False
    except CtapError as e:
        assert e.code == 0x28

def test_delay():
    key = VirtualSecurityKey()
    key.delay_ms(50)
    start = time.time()
    key.ctap(bytes([0x04]))
    elapsed = time.time() - start
    assert elapsed >= 0.04

def test_reset_clears_credentials():
    key = VirtualSecurityKey()
    cdh = bytes([0x44]*32)
    payload = make_cred_payload(cdh, "example.com", b"carol")
    key.ctap(bytes([0x01]) + payload)
    assert len(key.credentials) == 1
    key.reset()
    assert len(key.credentials) == 0
    assert key.counter == 0

def test_inmemory_transport_overflow():
    key = VirtualSecurityKey(max_msg_size=10)
    # frame muito grande deve falhar
    try:
        key.transport_send(b"\x00"*20)
        assert False
    except CtapError as e:
        assert e.code == 0x15
