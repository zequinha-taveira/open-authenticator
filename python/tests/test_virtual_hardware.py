from virtual_hardware import VirtualSecurityKey


def test_get_info():
    key = VirtualSecurityKey()
    response = key.ctap(bytes([0x04]))
    assert response[0] == 0x00
    assert b"FIDO_2_0" in response
    assert response.count(0xAA) >= 16


def test_disconnect_fault():
    key = VirtualSecurityKey()
    key.disconnect()
    try:
        key.ctap(b"\x04")
    except ConnectionError as exc:
        assert "disconnected" in str(exc)
    else:
        raise AssertionError("expected ConnectionError")


def test_reset():
    key = VirtualSecurityKey()
    key.storage[b"k"] = b"v"
    key.counter = 9
    key.reset()
    assert key.storage == {}
    assert key.counter == 0
