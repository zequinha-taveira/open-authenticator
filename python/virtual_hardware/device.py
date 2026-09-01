from dataclasses import dataclass, field
import hashlib
import time
from typing import List, Dict, Tuple, Optional, Set

CTAP2_OK = 0x00
CMD_MAKE_CREDENTIAL = 0x01
CMD_GET_ASSERTION = 0x02
CMD_GET_INFO = 0x04
CMD_CLIENT_PIN = 0x06
CMD_RESET = 0x07
CMD_GET_NEXT_ASSERTION = 0x08

# CTAP status codes (espelho de oa-core CtapStatusCode)
CTAP_INVALID_COMMAND = 0x01
CTAP_INVALID_PARAMETER = 0x02
CTAP_INVALID_LENGTH = 0x03
CTAP_CBOR_UNEXPECTED_TYPE = 0x11
CTAP_INVALID_CBOR = 0x12
CTAP_MISSING_PARAMETER = 0x14
CTAP_LIMIT_EXCEEDED = 0x15
CTAP_CREDENTIAL_EXCLUDED = 0x19
CTAP_UNSUPPORTED_ALGORITHM = 0x26
CTAP_OPERATION_DENIED = 0x27
CTAP_KEY_STORE_FULL = 0x28
CTAP_UNSUPPORTED_OPTION = 0x2B
CTAP_NO_CREDENTIALS = 0x2E
CTAP_NOT_ALLOWED = 0x30
CTAP_PIN_NOT_SET = 0x35
CTAP_PIN_REQUIRED = 0x36
CTAP_PIN_AUTH_INVALID = 0x33
CTAP_INVALID_SUBCOMMAND = 0x3E
CTAP_NOT_ALLOWED_2 = 0x2A  # alias


class CtapError(ValueError):
    """Erro CTAP2 com código de status. Subclasse de ValueError para compatibilidade."""
    def __init__(self, code: int, msg: str = ""):
        super().__init__(msg or f"CTAP 0x{code:02x}")
        self.code = code


# ---------------------------------------------------------------------------
# CBOR canônico mínimo (RFC8949) — espelho do módulo Rust cbor
# ---------------------------------------------------------------------------

def _cbor_encode_head(major: int, value: int) -> bytes:
    major = major << 5
    if value < 24:
        return bytes([major | value])
    elif value < 256:
        return bytes([major | 24, value])
    elif value < 65536:
        return bytes([major | 25]) + value.to_bytes(2, "big")
    elif value < 4294967296:
        return bytes([major | 26]) + value.to_bytes(4, "big")
    else:
        return bytes([major | 27]) + value.to_bytes(8, "big")


def cbor_encode_unsigned(n: int) -> bytes:
    return _cbor_encode_head(0, n)


def cbor_encode_negative(n: int) -> bytes:
    assert n < 0
    return _cbor_encode_head(1, -1 - n)


def cbor_encode_int(n: int) -> bytes:
    if n >= 0:
        return cbor_encode_unsigned(n)
    return cbor_encode_negative(n)


def cbor_encode_bytes(b: bytes) -> bytes:
    return _cbor_encode_head(2, len(b)) + b


def cbor_encode_text(s: str) -> bytes:
    bb = s.encode()
    return _cbor_encode_head(3, len(bb)) + bb


def cbor_encode_array_header(n: int) -> bytes:
    return _cbor_encode_head(4, n)


def cbor_encode_map_header(n: int) -> bytes:
    return _cbor_encode_head(5, n)


def cbor_encode_bool(v: bool) -> bytes:
    return bytes([0xf5 if v else 0xf4])

def cbor_encode_null() -> bytes:
    return bytes([0xf6])


class CborDecoder:
    def __init__(self, data: bytes):
        self.data = data
        self.pos = 0

    def remaining(self) -> int:
        return len(self.data) - self.pos

    def _read_byte(self) -> int:
        if self.pos >= len(self.data):
            raise CtapError(CTAP_INVALID_CBOR, "truncated cbor")
        b = self.data[self.pos]
        self.pos += 1
        return b

    def peek(self) -> Optional[int]:
        if self.pos < len(self.data):
            return self.data[self.pos]
        return None

    def decode_head(self) -> Tuple[int, int]:
        b = self._read_byte()
        major = b >> 5
        info = b & 0x1f
        if info == 31:
            raise CtapError(CTAP_INVALID_CBOR, "indefinite length not allowed")
        if major == 6:
            raise CtapError(CTAP_INVALID_CBOR, "tag not allowed")
        if major == 7 and info >= 24:
            raise CtapError(CTAP_INVALID_CBOR, "simple/float not allowed except bool/null")
        if info < 24:
            value = info
        elif info == 24:
            v = self._read_byte()
            if v < 24:
                raise CtapError(CTAP_INVALID_CBOR, "non-canonical int")
            value = v
        elif info == 25:
            if self.remaining() < 2:
                raise CtapError(CTAP_INVALID_CBOR, "truncated")
            v = int.from_bytes(self.data[self.pos:self.pos+2], "big")
            self.pos += 2
            if v < 256:
                raise CtapError(CTAP_INVALID_CBOR, "non-canonical 2-byte")
            value = v
        elif info == 26:
            if self.remaining() < 4:
                raise CtapError(CTAP_INVALID_CBOR, "truncated")
            v = int.from_bytes(self.data[self.pos:self.pos+4], "big")
            self.pos += 4
            if v < 65536:
                raise CtapError(CTAP_INVALID_CBOR, "non-canonical 4-byte")
            value = v
        elif info == 27:
            if self.remaining() < 8:
                raise CtapError(CTAP_INVALID_CBOR, "truncated")
            v = int.from_bytes(self.data[self.pos:self.pos+8], "big")
            self.pos += 8
            if v < 4294967296:
                raise CtapError(CTAP_INVALID_CBOR, "non-canonical 8-byte")
            value = v
        else:
            raise CtapError(CTAP_INVALID_CBOR, "reserved")
        return major, value

    def decode_unsigned(self) -> int:
        major, v = self.decode_head()
        if major != 0:
            raise CtapError(CTAP_CBOR_UNEXPECTED_TYPE, "expected unsigned")
        return v

    def decode_int(self) -> int:
        major, v = self.decode_head()
        if major == 0:
            if v > 2**63 - 1:
                raise CtapError(CTAP_INVALID_CBOR, "int overflow")
            return v
        elif major == 1:
            return -1 - v
        else:
            raise CtapError(CTAP_CBOR_UNEXPECTED_TYPE, "expected int")

    def decode_bytes(self) -> bytes:
        major, ln = self.decode_head()
        if major != 2:
            raise CtapError(CTAP_CBOR_UNEXPECTED_TYPE, "expected bstr")
        if self.remaining() < ln:
            raise CtapError(CTAP_INVALID_CBOR, "truncated bstr")
        out = self.data[self.pos:self.pos+ln]
        self.pos += ln
        return bytes(out)

    def decode_text(self) -> str:
        major, ln = self.decode_head()
        if major != 3:
            raise CtapError(CTAP_CBOR_UNEXPECTED_TYPE, "expected tstr")
        if self.remaining() < ln:
            raise CtapError(CTAP_INVALID_CBOR, "truncated tstr")
        raw = self.data[self.pos:self.pos+ln]
        self.pos += ln
        try:
            return raw.decode("utf-8")
        except Exception:
            raise CtapError(CTAP_INVALID_CBOR, "invalid utf8")

    def decode_bool(self) -> bool:
        b = self._read_byte()
        if b == 0xf4:
            return False
        if b == 0xf5:
            return True
        raise CtapError(CTAP_CBOR_UNEXPECTED_TYPE, "expected bool")

    def decode_array_header(self) -> int:
        major, v = self.decode_head()
        if major != 4:
            raise CtapError(CTAP_CBOR_UNEXPECTED_TYPE, "expected array")
        return v

    def decode_map_header(self) -> int:
        major, v = self.decode_head()
        if major != 5:
            raise CtapError(CTAP_CBOR_UNEXPECTED_TYPE, "expected map")
        return v

    def skip_value(self):
        major, value = self.decode_head()
        if major in (0, 1):
            return
        if major in (2, 3):
            if self.remaining() < value:
                raise CtapError(CTAP_INVALID_CBOR, "truncated skip")
            self.pos += value
        elif major == 4:
            for _ in range(value):
                self.skip_value()
        elif major == 5:
            for _ in range(value):
                self.skip_value()
                self.skip_value()
        elif major == 7:
            return
        else:
            raise CtapError(CTAP_INVALID_CBOR, "skip unknown major")

    def expect_end(self):
        if self.pos != len(self.data):
            raise CtapError(CTAP_INVALID_CBOR, "trailing bytes")


def _sha256(b: bytes) -> bytes:
    return hashlib.sha256(b).digest()


@dataclass
class StoredCredential:
    cred_id: bytes
    rp_id: str
    user_id: bytes
    counter: int
    cose_x: bytes
    cose_y: bytes


@dataclass
class VirtualSecurityKey:
    """Hardware virtual determinístico — espelha oa-ctap2 Ctap2 com CBOR canônico."""
    aaguid: bytes = bytes.fromhex("aa" * 16)
    present: bool = True
    storage: dict[bytes, bytes] = field(default_factory=dict)
    counter: int = 0
    connected: bool = True
    credentials: List[StoredCredential] = field(default_factory=list)
    last_assertion: List[Tuple[bytes, bytes]] = field(default_factory=list)
    # transport/virtual framing
    transport_queue: List[bytes] = field(default_factory=list)
    # deterministic entropy para credId/x,y
    _entropy: int = 0x42
    # fault injection
    _corrupt_next: bool = False
    _deny_presence_next: bool = False
    _force_storage_full: bool = False
    _delay_ms: int = 0
    # info defaults (espelho de AuthenticatorInfo)
    versions: List[str] = field(default_factory=lambda: ["FIDO_2_0", "FIDO_2_1"])
    rk: bool = True
    up: bool = True
    uv: bool = False
    max_msg_size: int = 1200
    transports: List[str] = field(default_factory=lambda: ["usb"])

    # ----- helpers -----
    def _random_bytes(self, n: int) -> bytes:
        out = bytes((self._entropy + i) & 0xFF for i in range(n))
        self._entropy = (self._entropy + n) & 0xFF
        return out

    def _next_counter(self) -> int:
        if self.counter == 0xFFFFFFFF:
            raise CtapError(CTAP_KEY_STORE_FULL)
        self.counter = (self.counter + 1) & 0xFFFFFFFF
        if self.counter == 0:
            self.counter = 1
        return self.counter

    def _check_presence(self) -> bool:
        if self._deny_presence_next:
            self._deny_presence_next = False
            return False
        return bool(self.present)

    def _build_auth_data(self, rp_id: str, flags: int, counter: int, attested=None) -> bytes:
        rp_hash = _sha256(rp_id.encode())
        out = rp_hash + bytes([flags]) + counter.to_bytes(4, "big")
        if attested is not None:
            aaguid, cred_id, x, y = attested
            out += aaguid
            out += len(cred_id).to_bytes(2, "big")
            out += cred_id
            # COSE key CBOR
            cose = b""
            cose += cbor_encode_map_header(5)
            cose += cbor_encode_int(1) + cbor_encode_int(2)
            cose += cbor_encode_int(3) + cbor_encode_int(-7)
            cose += cbor_encode_int(-1) + cbor_encode_int(1)
            cose += cbor_encode_int(-2) + cbor_encode_bytes(x)
            cose += cbor_encode_int(-3) + cbor_encode_bytes(y)
            out += cose
        return out

    def _encode_get_info(self) -> bytes:
        # 7 chaves: 01 versions, 03 aaguid, 04 options, 05 maxMsgSize, 06 pinUvAuthProtocols, 09 transports, 0A algorithms
        cbor = b""
        cbor += cbor_encode_map_header(7)
        cbor += cbor_encode_unsigned(0x01)
        cbor += cbor_encode_array_header(len(self.versions))
        for v in self.versions:
            cbor += cbor_encode_text(v)
        cbor += cbor_encode_unsigned(0x03)
        cbor += cbor_encode_bytes(self.aaguid)
        cbor += cbor_encode_unsigned(0x04)
        # options map: rk, up, uv, clientPin (sempre presente)
        # espelha Rust: 3 + clientPin?
        opts = []
        opts.append((b"rk", self.rk))
        opts.append((b"up", self.up))
        opts.append((b"uv", self.uv))
        opts.append((b"clientPin", False))
        cbor += cbor_encode_map_header(len(opts))
        for k, v in opts:
            cbor += cbor_encode_text(k.decode())
            cbor += cbor_encode_bool(v)
        cbor += cbor_encode_unsigned(0x05)
        cbor += cbor_encode_unsigned(self.max_msg_size)
        cbor += cbor_encode_unsigned(0x06)
        cbor += cbor_encode_array_header(1)
        cbor += cbor_encode_unsigned(1)
        cbor += cbor_encode_unsigned(0x09)
        cbor += cbor_encode_array_header(len(self.transports))
        for t in self.transports:
            cbor += cbor_encode_text(t)
        cbor += cbor_encode_unsigned(0x0A)
        cbor += cbor_encode_array_header(1)
        cbor += cbor_encode_map_header(2)
        cbor += cbor_encode_text("type")
        cbor += cbor_encode_text("public-key")
        cbor += cbor_encode_text("alg")
        cbor += cbor_encode_int(-7)
        return bytes([CTAP2_OK]) + cbor

    def _encode_make_credential_response(self, cred_id: bytes, auth_data: bytes) -> bytes:
        cbor = b""
        cbor += cbor_encode_map_header(3)
        cbor += cbor_encode_unsigned(0x01)
        cbor += cbor_encode_text("none")
        cbor += cbor_encode_unsigned(0x02)
        cbor += cbor_encode_bytes(auth_data)
        cbor += cbor_encode_unsigned(0x03)
        cbor += cbor_encode_map_header(0)
        return bytes([CTAP2_OK]) + cbor

    def _encode_get_assertion_response(self, cred: StoredCredential, auth_data: bytes, signature: bytes) -> bytes:
        cbor = b""
        cbor += cbor_encode_map_header(3)
        cbor += cbor_encode_unsigned(0x01)
        cbor += cbor_encode_map_header(2)
        cbor += cbor_encode_text("id")
        cbor += cbor_encode_bytes(cred.cred_id)
        cbor += cbor_encode_text("type")
        cbor += cbor_encode_text("public-key")
        cbor += cbor_encode_unsigned(0x02)
        cbor += cbor_encode_bytes(auth_data)
        cbor += cbor_encode_unsigned(0x03)
        cbor += cbor_encode_bytes(signature)
        return bytes([CTAP2_OK]) + cbor

    # ----- transport framing (separado da semântica) -----
    def transport_send(self, frame: bytes) -> None:
        if not self.connected:
            raise ConnectionError("virtual transport disconnected")
        if len(frame) > self.max_msg_size:
            raise CtapError(CTAP_LIMIT_EXCEEDED, "frame too large")
        self.transport_queue.append(frame)

    def transport_receive(self, max_len: int = 1200) -> bytes:
        if not self.connected:
            raise ConnectionError("virtual transport disconnected")
        if not self.transport_queue:
            raise CtapError(CTAP_INVALID_CBOR, "empty queue")
        frame = self.transport_queue.pop(0)
        if self._corrupt_next:
            self._corrupt_next = False
            if frame:
                frame = bytes([frame[0] ^ 0xFF]) + frame[1:]
                return frame
        return frame

    def corrupt_next_frame(self) -> None:
        self._corrupt_next = True

    def delay_ms(self, ms: int) -> None:
        self._delay_ms = ms

    def deny_user_presence(self) -> None:
        self._deny_presence_next = True

    def fill_storage(self) -> None:
        self._force_storage_full = True

    # ----- core dispatch -----
    def ctap(self, request: bytes) -> bytes:
        if not self.connected:
            raise ConnectionError("virtual transport disconnected")
        if self._delay_ms:
            time.sleep(self._delay_ms / 1000.0)
            self._delay_ms = 0
        if self._corrupt_next:
            # corrompe request antes de decodificar (simula corrupção de transporte)
            self._corrupt_next = False
            # flip first byte
            if request:
                request = bytes([request[0] ^ 0xFF]) + request[1:]
        if not request:
            raise CtapError(CTAP_INVALID_CBOR, "empty request")
        command, payload = request[0], request[1:]
        if command == CMD_GET_INFO:
            if payload:
                raise CtapError(CTAP_INVALID_LENGTH, "getInfo with payload")
            return self._encode_get_info()
        elif command == CMD_RESET:
            if payload:
                raise CtapError(CTAP_INVALID_LENGTH, "reset with payload")
            if not self._check_presence():
                raise CtapError(CTAP_OPERATION_DENIED, "presence denied")
            self.credentials.clear()
            self.storage.clear()
            self.counter = 0
            self.last_assertion.clear()
            return bytes([CTAP2_OK])
        elif command == CMD_MAKE_CREDENTIAL:
            if not payload:
                raise CtapError(CTAP_MISSING_PARAMETER)
            return self._handle_make_credential(payload)
        elif command == CMD_GET_ASSERTION:
            if not payload:
                raise CtapError(CTAP_MISSING_PARAMETER)
            return self._handle_get_assertion(payload)
        elif command == CMD_GET_NEXT_ASSERTION:
            if payload:
                raise CtapError(CTAP_INVALID_LENGTH)
            if not self.last_assertion:
                raise CtapError(CTAP_NOT_ALLOWED)
            cred_id, sig = self.last_assertion.pop(0)
            cred = next((c for c in self.credentials if c.cred_id == cred_id), None)
            if not cred:
                raise CtapError(CTAP_NO_CREDENTIALS)
            ctr = self._next_counter()
            auth_data = self._build_auth_data(cred.rp_id, 0x01, ctr, None)
            return self._encode_get_assertion_response(cred, auth_data, sig)
        elif command == CMD_CLIENT_PIN:
            if not payload:
                raise CtapError(CTAP_MISSING_PARAMETER)
            # parsing mínimo
            dec = CborDecoder(payload)
            mlen = dec.decode_map_header()
            seen: Set[int] = set()
            sub = None
            for _ in range(mlen):
                k = dec.decode_unsigned()
                if k in seen:
                    raise CtapError(CTAP_INVALID_CBOR, "duplicate key")
                seen.add(k)
                if k == 0x01:
                    sub = dec.decode_unsigned()
                else:
                    dec.skip_value()
            dec.expect_end()
            if sub is None:
                raise CtapError(CTAP_MISSING_PARAMETER)
            if sub in (0x01, 0x02, 0x03):
                raise CtapError(CTAP_PIN_NOT_SET)
            if sub == 0x04:
                raise CtapError(CTAP_PIN_REQUIRED)
            if sub in (0x06, 0x09):
                raise CtapError(CTAP_PIN_AUTH_INVALID)
            raise CtapError(CTAP_INVALID_SUBCOMMAND)
        else:
            raise CtapError(CTAP_INVALID_COMMAND, f"unsupported command 0x{command:02x}")

    # ----- helpers de decode makeCredential / getAssertion -----
    def _handle_make_credential(self, payload: bytes) -> bytes:
        dec = CborDecoder(payload)
        mlen = dec.decode_map_header()
        if mlen > 9:
            raise CtapError(CTAP_INVALID_CBOR)
        seen: Set[int] = set()
        client_data_hash = None
        rp_id = None
        rp_name = None
        user_id = None
        pub_params = None
        exclude_list: List[bytes] = []
        rk = False
        uv = False
        up = True
        pin_param = None
        pin_proto = None
        for _ in range(mlen):
            k = dec.decode_unsigned()
            if k in seen:
                raise CtapError(CTAP_INVALID_CBOR, "duplicate key")
            seen.add(k)
            if k == 0x01:
                b = dec.decode_bytes()
                if len(b) != 32:
                    raise CtapError(CTAP_INVALID_PARAMETER)
                client_data_hash = b
            elif k == 0x02:
                inner_len = dec.decode_map_header()
                if inner_len == 0 or inner_len > 3:
                    raise CtapError(CTAP_INVALID_CBOR)
                inner_seen: Set[str] = set()
                for _ in range(inner_len):
                    ikey = dec.decode_text()
                    if ikey in inner_seen:
                        raise CtapError(CTAP_INVALID_CBOR)
                    inner_seen.add(ikey)
                    if ikey == "id":
                        rp_id = dec.decode_text()
                    elif ikey == "name":
                        rp_name = dec.decode_text()
                    else:
                        dec.skip_value()
                if rp_id is None:
                    raise CtapError(CTAP_MISSING_PARAMETER)
            elif k == 0x03:
                inner_len = dec.decode_map_header()
                if inner_len == 0 or inner_len > 4:
                    raise CtapError(CTAP_INVALID_CBOR)
                inner_seen = set()
                for _ in range(inner_len):
                    ikey = dec.decode_text()
                    if ikey in inner_seen:
                        raise CtapError(CTAP_INVALID_CBOR)
                    inner_seen.add(ikey)
                    if ikey == "id":
                        b = dec.decode_bytes()
                        if not b or len(b) > 64:
                            raise CtapError(CTAP_INVALID_PARAMETER)
                        user_id = b
                    elif ikey == "name":
                        _ = dec.decode_text()
                    elif ikey == "displayName":
                        _ = dec.decode_text()
                    else:
                        dec.skip_value()
                if user_id is None:
                    raise CtapError(CTAP_MISSING_PARAMETER)
            elif k == 0x04:
                arr_len = dec.decode_array_header()
                if arr_len == 0:
                    raise CtapError(CTAP_MISSING_PARAMETER)
                if arr_len > 8:
                    raise CtapError(CTAP_LIMIT_EXCEEDED)
                out = []
                for _ in range(arr_len):
                    ml = dec.decode_map_header()
                    t = None
                    alg = None
                    seen2: Set[str] = set()
                    for _ in range(ml):
                        kk = dec.decode_text()
                        if kk in seen2:
                            raise CtapError(CTAP_INVALID_CBOR)
                        seen2.add(kk)
                        if kk == "type":
                            t = dec.decode_text()
                        elif kk == "alg":
                            alg = dec.decode_int()
                        else:
                            dec.skip_value()
                    if t is None or alg is None:
                        raise CtapError(CTAP_MISSING_PARAMETER)
                    out.append((t, alg))
                pub_params = out
            elif k == 0x05:
                arr_len = dec.decode_array_header()
                if arr_len > 16:
                    raise CtapError(CTAP_LIMIT_EXCEEDED)
                for _ in range(arr_len):
                    ml = dec.decode_map_header()
                    id_opt = None
                    seen2 = set()
                    for _ in range(ml):
                        kk = dec.decode_text()
                        if kk in seen2:
                            raise CtapError(CTAP_INVALID_CBOR)
                        seen2.add(kk)
                        if kk == "id":
                            id_opt = dec.decode_bytes()
                        elif kk == "type":
                            _ = dec.decode_text()
                        else:
                            dec.skip_value()
                    if id_opt is not None:
                        exclude_list.append(id_opt)
            elif k == 0x06:
                dec.skip_value()
            elif k == 0x07:
                ml = dec.decode_map_header()
                seen2 = set()
                for _ in range(ml):
                    kk = dec.decode_text()
                    if kk in seen2:
                        raise CtapError(CTAP_INVALID_CBOR)
                    seen2.add(kk)
                    if kk == "rk":
                        rk = dec.decode_bool()
                    elif kk == "uv":
                        uv = dec.decode_bool()
                    elif kk == "up":
                        up = dec.decode_bool()
                    else:
                        dec.skip_value()
            elif k == 0x08:
                pin_param = dec.decode_bytes()
            elif k == 0x09:
                vv = dec.decode_unsigned()
                if vv > 0xFFFFFFFF:
                    raise CtapError(CTAP_INVALID_PARAMETER)
                pin_proto = vv
            else:
                dec.skip_value()
        dec.expect_end()
        if client_data_hash is None or rp_id is None or user_id is None or pub_params is None:
            raise CtapError(CTAP_MISSING_PARAMETER)
        # valida pubKeyCredParams suportados
        supported = any(alg in (-7, -8, -257) for _, alg in pub_params)
        if not supported:
            raise CtapError(CTAP_UNSUPPORTED_ALGORITHM)
        for eid in exclude_list:
            if any(c.cred_id == eid and c.rp_id == rp_id for c in self.credentials):
                raise CtapError(CTAP_CREDENTIAL_EXCLUDED)
        if self._force_storage_full:
            self._force_storage_full = False
            raise CtapError(CTAP_KEY_STORE_FULL)
        if rk and len(self.credentials) >= 25:
            raise CtapError(CTAP_KEY_STORE_FULL)
        if uv and not self.uv:
            raise CtapError(CTAP_UNSUPPORTED_OPTION)
        if up and not self._check_presence():
            raise CtapError(CTAP_OPERATION_DENIED)
        if pin_param is not None and pin_proto != 1:
            raise CtapError(CTAP_PIN_AUTH_INVALID)
        if pin_param is not None and not self.uv:
            # clientPin false -> PinNotSet
            raise CtapError(CTAP_PIN_NOT_SET)
        # gera credential
        cred_id = bytearray(self._random_bytes(16))
        ctr = self._next_counter()
        cred_id[0] ^= ctr & 0xFF
        cred_id[1] ^= (ctr >> 8) & 0xFF
        cred_id = bytes(cred_id)
        if len(cred_id) > 128:
            raise CtapError(CTAP_LIMIT_EXCEEDED)
        x = self._random_bytes(32)
        y = self._random_bytes(32)
        flags = 0x01 | 0x40
        if uv:
            flags |= 0x04
        auth_data = self._build_auth_data(rp_id, flags, ctr, (self.aaguid, cred_id, x, y))
        cred = StoredCredential(cred_id, rp_id, user_id, ctr, x, y)
        self.credentials.append(cred)
        # zeroiza clientDataHash sensível (simulado)
        # em Python não há zeroize real, apenas sobrescreve
        return self._encode_make_credential_response(cred_id, auth_data)

    def _handle_get_assertion(self, payload: bytes) -> bytes:
        dec = CborDecoder(payload)
        mlen = dec.decode_map_header()
        if mlen > 8:
            raise CtapError(CTAP_INVALID_CBOR)
        seen: Set[int] = set()
        rp_id = None
        cdh = None
        allow_list: List[bytes] = []
        up = True
        uv = False
        pin_param = None
        pin_proto = None
        for _ in range(mlen):
            k = dec.decode_unsigned()
            if k in seen:
                raise CtapError(CTAP_INVALID_CBOR)
            seen.add(k)
            if k == 0x01:
                rp_id = dec.decode_text()
            elif k == 0x02:
                b = dec.decode_bytes()
                if len(b) != 32:
                    raise CtapError(CTAP_INVALID_PARAMETER)
                cdh = b
            elif k == 0x03:
                arr_len = dec.decode_array_header()
                if arr_len > 16:
                    raise CtapError(CTAP_LIMIT_EXCEEDED)
                for _ in range(arr_len):
                    ml = dec.decode_map_header()
                    id_opt = None
                    seen2 = set()
                    for _ in range(ml):
                        kk = dec.decode_text()
                        if kk in seen2:
                            raise CtapError(CTAP_INVALID_CBOR)
                        seen2.add(kk)
                        if kk == "id":
                            id_opt = dec.decode_bytes()
                        elif kk == "type":
                            _ = dec.decode_text()
                        else:
                            dec.skip_value()
                    if id_opt is not None:
                        allow_list.append(id_opt)
            elif k == 0x04:
                dec.skip_value()
            elif k == 0x05:
                ml = dec.decode_map_header()
                seen2 = set()
                for _ in range(ml):
                    kk = dec.decode_text()
                    if kk in seen2:
                        raise CtapError(CTAP_INVALID_CBOR)
                    seen2.add(kk)
                    if kk == "up":
                        up = dec.decode_bool()
                    elif kk == "uv":
                        uv = dec.decode_bool()
                    else:
                        dec.skip_value()
            elif k == 0x06:
                pin_param = dec.decode_bytes()
            elif k == 0x07:
                pin_proto = dec.decode_unsigned()
            else:
                dec.skip_value()
        dec.expect_end()
        if rp_id is None or cdh is None:
            raise CtapError(CTAP_MISSING_PARAMETER)
        if uv and not self.uv:
            raise CtapError(CTAP_UNSUPPORTED_OPTION)
        if up and not self._check_presence():
            raise CtapError(CTAP_OPERATION_DENIED)
        candidates = [c for c in self.credentials if c.rp_id == rp_id]
        if allow_list:
            candidates = [c for c in candidates if any(a == c.cred_id for a in allow_list)]
        if not candidates:
            raise CtapError(CTAP_NO_CREDENTIALS)
        cred = candidates[0]
        ctr = self._next_counter()
        flags = 0x01
        if uv:
            flags |= 0x04
        auth_data = self._build_auth_data(rp_id, flags, ctr, None)
        to_sign = auth_data + cdh
        h = _sha256(to_sign)
        sig = h + h
        # atualiza counter
        cred.counter = ctr
        self.last_assertion = [(c.cred_id, sig) for c in candidates[1:]]
        return self._encode_get_assertion_response(cred, auth_data, sig)

    def disconnect(self) -> None:
        self.connected = False

    def reconnect(self) -> None:
        self.connected = True

    def reset(self) -> None:
        self.storage.clear()
        self.credentials.clear()
        self.counter = 0
        self.last_assertion.clear()
        self.transport_queue.clear()
        self._entropy = 0x42

    # compat: allow storage dict access like before
    def __post_init__(self):
        # limit aaguid size
        if len(self.aaguid) != 16:
            self.aaguid = (self.aaguid + b"\x00"*16)[:16]
