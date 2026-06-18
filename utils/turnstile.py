"""Turnstile challenge-VM payload primitives.

Reverse-engineered from the Turnstile challenge *iframe* VM script -- the real
fingerprinting / payload engine. (``api.js`` is only the loader/orchestrator and
contains none of this.) The full analysis, line references, and the execution-based
verification of every primitive below live in
``research/turnstile-vm/TURNSTILE-ALGORITHM-RECOVERY.md``.

This mirrors the JSD path already in the repo:

    JSD        fingerprint map -> lz-string encode                  -> POST /jsd/r/
    Turnstile  fingerprint map -> JSON -> LZW -> XTEA -> RSA -> b64  -> POST /flow/ov

The ``/flow/ov`` request *body* is built by the plain-JS function ``pZ``
(decoded.js:2746-2937), NOT by the JSVMP bytecode: the ``runProgram`` interpreter
(decoded.js:8410) only returns the closure that *calls* ``pZ`` and fires the XHR, so
the whole body chain is recoverable as straight-line code. The chain ``pZ`` runs is:

    serialize(fingerprint)            # an  : JSON.stringify-equivalent UTF-8 bytes
      + append one 0x20 byte          #       H[V++] = aS<<am
    -> LZW compress                   # av  : variable-width codes, 16-bit-word writer
    -> zero-pad to an 8-byte boundary #       pad = (8 - len % 8) % 8
    -> XTEA encrypt (per-block keys)  # p3  : 32-round XTEA, key = p5[9*pad+40 : +16]
    -> blob = RSA_block(128) | pad-count byte | ciphertext
    -> custom base64 over ``aj``      #       -> body string

The 128-byte ``RSA_block`` transports the random buffer ``p5`` (with ``p5[0]=1``)
that the XTEA key is sliced from, so the server recovers the symmetric key with its
private key. SHA-256 exists in the bundle but is NOT part of this body chain.

RECOVERED + VERIFIED byte-for-byte against the JS oracle
(research/turnstile-vm/{build-oracle,oracle-run}.js, harness verify_body.py):
    * UTF-8 JSON serializer ``an``              -> ``_serialize_an``
    * LZW compressor ``av``                     -> ``_lzw_compress``
    * XTEA key schedule / per-block keys / cipher -> ``_xtea_*``
    * RSA-1024 key-transport block, e=65537     -> ``rsa_keytransport`` / ``rsa_block``
    * custom-alphabet base64 over ``aj``        -> ``custom_b64encode``
    * full ``/flow/ov`` body assembly ``pZ``    -> ``build_flow_ov_body``
    * fingerprint value-classifier category model -> ``classify_value`` / ``CATEGORY``
    * /flow/ov endpoint construction            -> ``build_flow_ov_url``

PER-LOAD / VERSION-PINNED -- the RSA modulus, ``aj`` alphabet and string-table
rotation rotate across Turnstile versions and must be re-extracted from a fresh
bundle (see ``research/turnstile-vm/`` and the TODOs in ``TurnstileSolver``).

``KJuRf8`` (the 16-byte transform applied to the XTEA key slice at decoded.js:2884)
is RESOLVED: it is a repeating-key XOR ``key[i] ^ s[i % len(s)]`` with a 16-byte
ASCII key ``s``. ``s`` is assembled at runtime from the obfuscator's string-table
so it is not greppable in the bundle, but it is recovered directly by calling the
live global ``KJuRf8(new Uint8Array(16))`` over CDP (which returns ``s`` itself).
The value was verified against two independent live ``/flow/ov`` captures: both
decrypt (RSA -> XTEA) to the identical, coherent LZW/JSON plaintext with correct
zero-padding. ``s`` is stable across loads for a given deployment; :func:`make_kjurf8`
builds the transform and :data:`KJURF8_KEY` is the captured default.
"""
from __future__ import annotations

import hashlib
import json
import os
import secrets
import subprocess
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple, Union

# ---------------------------------------------------------------------------
# Per-load / version-pinned constants.
#
# The RSA modulus, `aj` alphabet and string-table rotation all rotate across
# Turnstile versions. They are NOT meant to be hardcoded for a real solve --
# extract them fresh from a captured bundle with
# ``research/turnstile-vm/extract-constants.js`` and apply them via
# :func:`load_constants_from_bundle` + :func:`apply_constants` (or pass a bundle
# to ``TurnstileSolver``). The literals below are the values captured from the
# one analysed bundle; they back :data:`DEFAULT_CONSTANTS` and serve only as the
# offline default that the verification harness (verify_body.py) pins against.
# ---------------------------------------------------------------------------

# Custom base64 alphabet (`aj`). Same family as the JSD alphabet -- it matches the
# repo regex `[a-zA-Z0-9+\-$]{65}` in utils/constants.py (ENC_KEY_RE). 65th char is
# unused by the encoder (no padding is emitted), so only indices 0..63 are reachable.
_DEFAULT_ALPHABET = "D9nyKPm+ZdgzraW-e3NEo4Hp76GXsU52jIVuRtwcxlfi$YC10QkqMOSFbvBTA8LhJ"

# RSA public key (`ag` / `ae`). 1024-bit modulus; the literal carries a redundant
# leading 0x00 byte. e = 0x10001.
_DEFAULT_RSA_N = int(
    "00e9d3dca1328a49ad3403e4badda37a6a13610b608b5099839e1074e720f5a3"
    "3b2ebd8c2ffd12c09be0015a4635aa9d2022d8f72f90ed11610c3742b0baef5b"
    "7da73d7e79aff6cdbdeab72492ce0a858e4c1f4c27a14ebbb4ce3beacfda982f"
    "e74463e76f654aab0c597d5e73686ea149023e8f60ae6365a30055fe2c5eb2ebfb",
    16,
)
_DEFAULT_RSA_E = 65537
# Load-time string-table rotation K + decoder offset captured from the same bundle
# (derived by executing the obfuscator's checksum shuffler; see extract-constants.js).
_DEFAULT_ROTATION_K = 421
_DEFAULT_TABLE_LEN = 1821
_DEFAULT_DECODER_OFFSET = 114
# KJuRf8 XOR key ``s`` (decoded.js:2884): the repeating-key XOR applied to the
# 16-byte XTEA key slice. Recovered live by calling ``KJuRf8(new Uint8Array(16))``
# over CDP -- a zero input returns ``s`` directly because the transform is
# ``out[i] = in[i] ^ s.charCodeAt(i % s.length)``. It is assembled at runtime from
# the obfuscator string-table (NOT a static literal in the bundle), so unlike the
# alphabet/RSA literals it cannot be pulled from the AST -- re-probe live for a new
# deployment. Verified against two independent live /flow/ov captures.
_DEFAULT_KJURF8_KEY = b"ENdhiMvjWPEYrXrp"  # == bytes.fromhex("454e6468694d766a5750455972587270")


def _rsa_key_size(modulus: int) -> int:
    """RSA block size in bytes = byte length of the modulus (128 for 1024-bit)."""
    return (modulus.bit_length() + 7) // 8


# Active per-load constants used by the verified primitives below. They read these
# module globals at call time, so :func:`apply_constants` swaps the whole set in.
ALPHABET = _DEFAULT_ALPHABET
RSA_N = _DEFAULT_RSA_N
RSA_E = _DEFAULT_RSA_E
RSA_KEY_SIZE = _rsa_key_size(_DEFAULT_RSA_N)  # bytes (128 == 1024-bit)
KJURF8_KEY = _DEFAULT_KJURF8_KEY

# Value-classifier category chars produced by `aP` (decoded.js:7025) + the `aK`
# typeof table (decoded.js:2553). See report section 2b for the full legend.
CATEGORY = {
    "undefined": "u",
    "null": "x",
    "promise": "p",
    "array": "a",
    "array_ctor": "D",
    "true": "T",
    "false": "F",
    "native_fn": "N",
    "user_fn": "f",
    "object": "o",
    "string": "s",
    "symbol": "z",
    "number": "n",
    "bigint": "I",
    "inaccessible": "i",
    "unknown": "?",
}


# ---------------------------------------------------------------------------
# Per-load constant loading (Task 2)
#
# The values above rotate per Turnstile version. `extract-constants.js` pulls a
# fresh set straight out of a captured bundle's AST (alphabet/RSA literals are
# inline; the string-table rotation is derived by executing the obfuscator's own
# checksum shuffler). This module shells out to that script and applies the result
# so the verified primitives operate on the live values -- nothing is hardcoded
# for a real solve.
# ---------------------------------------------------------------------------

_EXTRACTOR_JS = Path(__file__).resolve().parent.parent / "research" / "turnstile-vm" / "extract-constants.js"


@dataclass(frozen=True)
class TurnstileConstants:
    """Per-load constants extracted from one Turnstile VM bundle."""

    alphabet: str
    rsa_n: int
    rsa_e: int
    rotation_k: Optional[int] = None
    table_len: Optional[int] = None
    decoder_offset: Optional[int] = None
    # The XTEA-key-slice XOR transform `s`. Not extractable from the bundle AST
    # (built at runtime from the string-table); defaults to the captured key and
    # must be re-probed live via `KJuRf8(new Uint8Array(16))` for a new deployment.
    kjurf8_key: bytes = _DEFAULT_KJURF8_KEY
    warnings: Tuple[str, ...] = field(default_factory=tuple)

    @property
    def rsa_key_size(self) -> int:
        return _rsa_key_size(self.rsa_n)

    def validate(self) -> "TurnstileConstants":
        """Raise if the set is structurally unusable for the body builder."""
        if not isinstance(self.alphabet, str) or len(self.alphabet) != 65:
            raise ValueError(f"alphabet must be 65 chars, got {len(self.alphabet or '')!r}")
        if not isinstance(self.rsa_n, int) or self.rsa_n <= 0:
            raise ValueError("rsa_n must be a positive integer modulus")
        if self.rsa_n.bit_length() < 512:
            raise ValueError(f"rsa_n is only {self.rsa_n.bit_length()} bits (<512); extraction likely wrong")
        if self.rsa_e <= 1 or (self.rsa_e & 1) == 0:
            raise ValueError(f"rsa_e must be an odd integer > 1, got {self.rsa_e}")
        if not isinstance(self.kjurf8_key, (bytes, bytearray)) or not self.kjurf8_key:
            raise ValueError("kjurf8_key must be non-empty bytes")
        return self


# The captured-bundle default; backs the offline path and the verification harness.
DEFAULT_CONSTANTS = TurnstileConstants(
    alphabet=_DEFAULT_ALPHABET,
    rsa_n=_DEFAULT_RSA_N,
    rsa_e=_DEFAULT_RSA_E,
    rotation_k=_DEFAULT_ROTATION_K,
    table_len=_DEFAULT_TABLE_LEN,
    decoder_offset=_DEFAULT_DECODER_OFFSET,
    kjurf8_key=_DEFAULT_KJURF8_KEY,
)


def load_constants_from_bundle(
    bundle: Union[str, bytes, os.PathLike],
    *,
    node_bin: str = "node",
    extractor: Optional[Union[str, os.PathLike]] = None,
    timeout: float = 120.0,
) -> TurnstileConstants:
    """Extract a fresh :class:`TurnstileConstants` set from a captured bundle.

    ``bundle`` may be a path to a ``.js`` file, or the raw source as ``str``/``bytes``
    (written to a temp file for the subprocess). Runs ``extract-constants.js`` with
    Node; the script's ``@babel/*`` deps must be importable (the environment sets
    ``NODE_PATH`` to the global module dir -- it is forwarded automatically).

    Raises ``RuntimeError`` if the extractor fails and ``ValueError`` if the
    extracted set is structurally invalid.
    """
    script = Path(extractor) if extractor is not None else _EXTRACTOR_JS
    if not script.is_file():
        raise FileNotFoundError(f"extractor not found: {script}")

    tmp_path: Optional[str] = None
    try:
        bundle_path = _resolve_bundle_path(bundle)
        if bundle_path is None:  # raw source -> temp file
            src = bundle.encode("utf-8") if isinstance(bundle, str) else bytes(bundle)
            fd, tmp_path = tempfile.mkstemp(suffix=".js", prefix="ts_bundle_")
            with os.fdopen(fd, "wb") as fh:
                fh.write(src)
            bundle_path = tmp_path

        env = os.environ.copy()
        if "NODE_PATH" not in env:
            # Best-effort: let `npm root -g` populate it so Babel resolves.
            try:
                root = subprocess.run(
                    ["npm", "root", "-g"], capture_output=True, text=True, timeout=30
                ).stdout.strip()
                if root:
                    env["NODE_PATH"] = root
            except (OSError, subprocess.SubprocessError):
                pass

        proc = subprocess.run(
            [node_bin, str(script), str(bundle_path)],
            capture_output=True,
            text=True,
            env=env,
            timeout=timeout,
        )
    finally:
        if tmp_path is not None:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass

    if proc.returncode != 0:
        raise RuntimeError(
            f"extract-constants.js failed (rc={proc.returncode}): {proc.stderr.strip() or proc.stdout.strip()}"
        )
    try:
        data = json.loads(proc.stdout)
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"extractor produced non-JSON output: {proc.stdout[:200]!r}") from exc

    if data.get("rsa_n_hex") is None:
        raise ValueError(f"extractor could not find RSA modulus; warnings={data.get('warnings')}")
    # KJuRf8's key is assembled at runtime from the string-table, so it is not in the
    # AST the extractor walks. If the bundle reports one, use it; otherwise fall back
    # to the captured default and flag that it should be re-probed live.
    kj_hex = data.get("kjurf8_key_hex")
    if kj_hex:
        kjurf8_key = bytes.fromhex(kj_hex)
        kj_warnings: Tuple[str, ...] = ()
    else:
        kjurf8_key = _DEFAULT_KJURF8_KEY
        kj_warnings = (
            "kjurf8_key not extractable from bundle (runtime-assembled); using captured "
            "default -- re-probe live via KJuRf8(new Uint8Array(16)) for a new deployment",
        )
    consts = TurnstileConstants(
        alphabet=data.get("alphabet"),
        rsa_n=int(data["rsa_n_hex"], 16),
        rsa_e=int(data.get("rsa_e") or 0),
        rotation_k=data.get("rotation_k"),
        table_len=data.get("table_len"),
        decoder_offset=data.get("decoder_offset"),
        kjurf8_key=kjurf8_key,
        warnings=tuple(data.get("warnings") or ()) + kj_warnings,
    )
    return consts.validate()


def _resolve_bundle_path(bundle: Union[str, bytes, os.PathLike]) -> Optional[str]:
    """Return a filesystem path if ``bundle`` denotes one, else ``None`` (raw source)."""
    if isinstance(bundle, (bytes, bytearray)):
        return None
    if isinstance(bundle, os.PathLike):
        return os.fspath(bundle)
    if isinstance(bundle, str):
        # Treat as a path only if it looks like one and exists; otherwise raw source.
        if "\n" not in bundle and len(bundle) < 4096:
            try:
                if os.path.isfile(bundle):
                    return bundle
            except OSError:
                return None
    return None


def apply_constants(consts: TurnstileConstants) -> TurnstileConstants:
    """Swap the active per-load constants used by the verified primitives.

    Updates the module globals (``ALPHABET``/``RSA_N``/``RSA_E``/``RSA_KEY_SIZE``/
    ``KJURF8_KEY``) that :func:`custom_b64encode`, :func:`rsa_block`,
    :func:`make_kjurf8`, etc. read at call time. Returns the applied set.
    """
    global ALPHABET, RSA_N, RSA_E, RSA_KEY_SIZE, KJURF8_KEY
    consts.validate()
    ALPHABET = consts.alphabet
    RSA_N = consts.rsa_n
    RSA_E = consts.rsa_e
    RSA_KEY_SIZE = consts.rsa_key_size
    KJURF8_KEY = bytes(consts.kjurf8_key)
    return consts


def active_constants() -> TurnstileConstants:
    """Snapshot the constants currently applied to the module globals."""
    return TurnstileConstants(alphabet=ALPHABET, rsa_n=RSA_N, rsa_e=RSA_E, kjurf8_key=KJURF8_KEY)


# ---------------------------------------------------------------------------
# Verified crypto primitives
# ---------------------------------------------------------------------------

def custom_b64encode(data: bytes) -> str:
    """Custom-alphabet base64 (``aj``), faithful transcription of the VM encoder.

    Classic 3-byte -> 4-symbol base64 packing each 3 bytes into a 24-bit int and
    emitting four 6-bit symbols; no padding char is emitted. The VM's float
    "noise" (e.g. ``>> 18.89``, ``& 63.42``) is a no-op because JS bitwise ops
    truncate to int32 -- proven in research/turnstile-vm/verify-primitives.js.
    """
    out: List[str] = []
    n = len(data)
    rem = n % 3
    main = n - rem
    for i in range(0, main, 3):
        g = (data[i] << 16) | (data[i + 1] << 8) | data[i + 2]
        out.append(ALPHABET[(g >> 18) & 63])
        out.append(ALPHABET[(g >> 12) & 63])
        out.append(ALPHABET[(g >> 6) & 63])
        out.append(ALPHABET[g & 63])
    if rem == 1:
        g = data[main] << 16
        out.append(ALPHABET[(g >> 18) & 63])
        out.append(ALPHABET[(g >> 12) & 63])
    elif rem == 2:
        g = (data[main] << 16) | (data[main + 1] << 8)
        out.append(ALPHABET[(g >> 18) & 63])
        out.append(ALPHABET[(g >> 12) & 63])
        out.append(ALPHABET[(g >> 6) & 63])
    return "".join(out)


def sha256_hex(data: Union[str, bytes]) -> str:
    """SHA-256 hex digest. The VM ships a canonical ``binb_sha256`` (constants
    verified at decoded.js:9662-9663); ``hashlib`` is the byte-identical stdlib
    equivalent. NOTE: SHA-256 is present in the bundle but is NOT part of the
    ``/flow/ov`` body chain (kept here only for completeness)."""
    if isinstance(data, str):
        data = data.encode("utf-8")
    return hashlib.sha256(data).hexdigest()


def rsa_keytransport(key_buffer: Optional[bytes] = None) -> Dict[str, bytes]:
    """RSA-1024 hybrid key transport (decoded.js:2713-2744).

    The VM fills a 128-byte buffer from ``crypto.getRandomValues`` then forces
    ``buf[0] = 1`` so the message's top byte (0x01) is below the modulus's
    (0xe9), guaranteeing ``m < N``. The buffer is read big-endian as ``m``,
    encrypted ``c = m**e mod N`` (square-and-multiply), and ``c`` is serialized
    big-endian into 128 bytes.

    Returns the random ``key`` (the symmetric secret the server recovers with the
    private key) and the 128-byte ``cipher`` that goes on the wire.
    """
    if key_buffer is None:
        buf = bytearray(secrets.token_bytes(RSA_KEY_SIZE))
        buf[0] = 1
        key_buffer = bytes(buf)
    if len(key_buffer) != RSA_KEY_SIZE:
        raise ValueError(f"key_buffer must be {RSA_KEY_SIZE} bytes, got {len(key_buffer)}")

    m = int.from_bytes(key_buffer, "big")
    if m >= RSA_N:
        raise ValueError("message integer must be < RSA modulus (set buf[0]=1)")
    c = pow(m, RSA_E, RSA_N)
    cipher = c.to_bytes(RSA_KEY_SIZE, "big")
    return {"key": key_buffer, "cipher": cipher}


def rsa_block(random_buffer: bytes) -> bytes:
    """The 128-byte RSA key-transport block prepended to the body (decoded.js:2713-2744).

    Identical maths to :func:`rsa_keytransport` but takes the raw 128-byte
    ``crypto.getRandomValues`` buffer (``p5``), forces ``buf[0]=1`` (so ``m < N``),
    and returns only the big-endian ciphertext block ``c = m**e mod N``.
    """
    if len(random_buffer) != RSA_KEY_SIZE:
        raise ValueError(f"random_buffer must be {RSA_KEY_SIZE} bytes")
    buf = bytearray(random_buffer)
    buf[0] = 1
    m = int.from_bytes(bytes(buf), "big")
    c = pow(m, RSA_E, RSA_N)
    return c.to_bytes(RSA_KEY_SIZE, "big")


# ---------------------------------------------------------------------------
# /flow/ov body assembly  (decoded.js:2746-2937, function `pZ`)
#
# Every primitive below is a faithful port of the plain-JS body builder and is
# checked byte-for-byte against the JS oracle by research/turnstile-vm/verify_body.py.
# ---------------------------------------------------------------------------

_U32 = 0xFFFFFFFF
_XTEA_DELTA = 0x9E3779B9  # 2654435769

# JSON string-escape map (`ao`, decoded.js:2705-2712): code point -> escape char byte.
_ESCAPE = {8: 0x62, 9: 0x74, 10: 0x6E, 12: 0x66, 13: 0x72, 34: 0x22, 92: 0x5C}


def _num_to_bytes(value: Union[int, float]) -> bytes:
    """Mirror JS ``'' + number``. NaN / +-Infinity render as ``null`` (JSON.stringify)."""
    if isinstance(value, float):
        if value != value or value in (float("inf"), float("-inf")):
            return b"null"
        if value.is_integer():
            return str(int(value)).encode("ascii")
        return repr(value).encode("ascii")
    return str(value).encode("ascii")


def _serialize_an(value: Any, out: bytearray) -> None:
    """Faithful port of ``an`` (decoded.js:7157-7402): a JSON.stringify-equivalent
    UTF-8 serializer. Emits bytes into ``out``. Object/array members whose value is a
    function (JS function/undefined/symbol/bigint) are dropped exactly as JSON does.

    Caveat: JS ``for-in`` visits integer-like keys in ascending numeric order before
    string keys; Python preserves dict insertion order. Real fingerprint maps use
    non-integer string keys, so the orders coincide.
    """
    if value is None:
        out += b"null"
        return
    if isinstance(value, bool):  # must precede int (bool is an int subclass)
        out += b"true" if value else b"false"
        return
    if isinstance(value, (int, float)):
        out += _num_to_bytes(value)
        return
    if isinstance(value, str):
        out.append(0x22)
        for ch in value:
            cp = ord(ch)
            if 32 <= cp <= 127 and cp != 34 and cp != 92:
                out.append(cp)
            elif cp in _ESCAPE:
                out.append(0x5C)
                out.append(_ESCAPE[cp])
            elif cp < 32:
                out += b"\\u" + ("%04x" % cp).encode("ascii")
            else:
                out += ch.encode("utf-8")
        out.append(0x22)
        return
    if isinstance(value, (list, tuple)):
        out.append(0x5B)  # [
        for i, item in enumerate(value):
            if i > 0:
                out.append(0x2C)  # ,
            before = len(out)
            _serialize_an(item, out)
            if len(out) == before:  # element serialized to nothing -> null
                out += b"null"
        out.append(0x5D)  # ]
        return
    if isinstance(value, dict):
        out.append(0x7B)  # {
        first = True
        for key, val in value.items():
            if callable(val):  # JS skips function/undefined/symbol/bigint values
                continue
            start = len(out)
            if not first:
                out.append(0x2C)  # ,
            _serialize_an(str(key), out)
            out.append(0x3A)  # :
            after_key = len(out)
            _serialize_an(val, out)
            if after_key == len(out):  # value emitted nothing -> drop the pair
                del out[start:]
            else:
                first = False
        out.append(0x7D)  # }
        return
    # callables / anything else: emit nothing (mirrors `an` returning H unchanged)


def _lzw_compress(data: List[int]) -> List[int]:
    """Port of ``av`` (decoded.js:3383-3536): dictionary LZW with variable-width
    codes and an MSB-first 16-bit-word bit writer. ``data`` is a list of byte ints;
    returns the compressed byte list."""
    out: List[int] = []
    acc = 0       # Vl : bit accumulator
    nbits = 0     # VH : bits buffered into the current 16-bit word (0..15)
    width = 2     # VV : current code width
    width_left = 2  # Va : codes left before the width grows

    def emit(value: int, count: int) -> None:
        nonlocal acc, nbits
        for _ in range(count):
            acc = ((acc << 1) | (value & 1)) & _U32
            if nbits == 15:
                out.append((acc >> 8) & 0xFF)
                out.append(acc & 0xFF)
                nbits = 0
                acc = 0
            else:
                nbits += 1
            value >>= 1

    def grow() -> None:
        nonlocal width, width_left
        width_left -= 1
        if width_left == 0:
            width_left = 2 ** width
            width += 1

    single: Dict[int, int] = {}  # Y : byte value -> code
    is_new: Dict[int, int] = {}  # V5: code -> 1 while still a fresh single char
    pairs: Dict[int, int] = {}   # V6: 256*prev + cur -> code
    next_code = 3                # Vp
    w = 0                        # V7 : current code
    last_byte = 0                # V8
    started = False              # V9

    for cur in data:
        code = single.get(cur, 0)
        if not code:
            code = next_code
            next_code += 1
            single[cur] = code
            is_new[code] = 1
        if started:
            key = 256 * w + cur
            pc = pairs.get(key, 0)
            if pc:
                w = pc
            else:
                if is_new.get(w):
                    emit(0, width)
                    emit(last_byte, 8)
                    grow()
                    is_new[w] = 0
                else:
                    emit(w, width)
                grow()
                pairs[key] = next_code
                next_code += 1
                w = code
                last_byte = cur
        else:
            w = code
            last_byte = cur
            started = True

    if started:
        if is_new.get(w):
            emit(0, width)
            emit(last_byte, 8)
            grow()
            is_new[w] = 0
        else:
            emit(w, width)
        grow()
    emit(2, width)

    # flush the final partial word out to a 16-bit boundary (decoded.js:3502-3510)
    while True:
        acc = (acc << 1) & _U32
        if nbits == 15:
            out.append((acc >> 8) & 0xFF)
            out.append(acc & 0xFF)
            break
        nbits += 1
    return out


def _xtea_round_keys(words: tuple) -> List[int]:
    """``p0`` (decoded.js:4004): expand 4 key words into 64 XTEA subkeys
    (``sum + key[sum & 3]`` / ``sum + key[(sum >> 11) & 3]``, delta 0x9E3779B9)."""
    k = (words[0] & _U32, words[1] & _U32, words[2] & _U32, words[3] & _U32)
    out: List[int] = []
    s = 0
    for _ in range(32):
        out.append((s + k[s & 3]) & _U32)
        s = (s + _XTEA_DELTA) & _U32
        out.append((s + k[(s >> 11) & 3]) & _U32)
    return out


def _xtea_encrypt_block(v0: int, v1: int, subkeys: List[int]) -> tuple:
    """``p2`` core (decoded.js:3706-3722): 32-round XTEA on one 64-bit block.

    ``v0``/``v1`` are kept as exact Python ints (masked only inside the shifts and
    XOR), exactly mirroring how the JS accumulates in doubles while ``+v`` uses the
    unreduced value; only the low 32 bits ever reach the output.
    """
    i = 0
    for _ in range(32):
        t = ((((v1 & _U32) << 4) & _U32) ^ ((v1 & _U32) >> 5)) + v1
        v0 = v0 + ((t & _U32) ^ subkeys[i])
        i += 1
        t = ((((v0 & _U32) << 4) & _U32) ^ ((v0 & _U32) >> 5)) + v0
        v1 = v1 + ((t & _U32) ^ subkeys[i])
        i += 1
    return v0 & _U32, v1 & _U32


def _xtea_block_keys(base_keys: List[int], block_index: int) -> List[int]:
    """``p1`` (decoded.js:6898): fresh per-block subkeys, derived by XTEA-encrypting
    the block counter ``(0, idx)`` and ``(0, idx+1)`` under the base schedule."""
    w0, w1 = _xtea_encrypt_block(0, block_index & 0xFF, base_keys)
    w2, w3 = _xtea_encrypt_block(0, (block_index + 1) & 0xFF, base_keys)
    return _xtea_round_keys((w0, w1, w2, w3))


def _xtea_encrypt(plaintext: bytes, base_keys: List[int]) -> bytes:
    """``p3`` (decoded.js:7909): encrypt the padded plaintext block-by-block. Each
    8-byte block (big-endian words) uses subkeys keyed by ``(offset >> 3) & 255``."""
    out = bytearray()
    cache: Dict[int, List[int]] = {}
    for off in range(0, len(plaintext), 8):
        bi = (off >> 3) & 0xFF
        sub = cache.get(bi)
        if sub is None:
            sub = _xtea_block_keys(base_keys, bi)
            cache[bi] = sub
        v0 = (plaintext[off] << 24) | (plaintext[off + 1] << 16) | (plaintext[off + 2] << 8) | plaintext[off + 3]
        v1 = (plaintext[off + 4] << 24) | (plaintext[off + 5] << 16) | (plaintext[off + 6] << 8) | plaintext[off + 7]
        c0, c1 = _xtea_encrypt_block(v0, v1, sub)
        out += bytes((
            (c0 >> 24) & 0xFF, (c0 >> 16) & 0xFF, (c0 >> 8) & 0xFF, c0 & 0xFF,
            (c1 >> 24) & 0xFF, (c1 >> 16) & 0xFF, (c1 >> 8) & 0xFF, c1 & 0xFF,
        ))
    return bytes(out)


def make_kjurf8(xor_key: Optional[bytes] = None) -> Callable[[bytes], bytes]:
    """Build ``KJuRf8`` (decoded.js:2884): a repeating-key XOR over ``xor_key``.

    The live global is ``function(k){ for i: out[i] = k[i] ^ s[i % s.length]; }``.
    For the 16-byte XTEA key slice the key is applied straight (``len(s) == 16``).
    ``xor_key`` defaults to the active :data:`KJURF8_KEY` (resolved at call time, so
    :func:`apply_constants` swaps it in alongside the alphabet/RSA modulus). Pass the
    bytes returned by a live ``KJuRf8(new Uint8Array(16))`` probe to target a
    different deployment without mutating the module globals.
    """
    if xor_key is None:
        xor_key = KJURF8_KEY
    if not xor_key:
        raise ValueError("KJuRf8 xor_key must be non-empty")

    def _kjurf8(data: bytes) -> bytes:
        return bytes(b ^ xor_key[i % len(xor_key)] for i, b in enumerate(data))

    return _kjurf8


def build_flow_ov_body(
    fingerprint: Any,
    *,
    random_buffer: Optional[bytes] = None,
    kjurf8: Optional[Any] = None,
) -> Dict[str, Any]:
    """Assemble the byte-exact ``/flow/ov`` request body (``pZ``, decoded.js:2746-2937).

    Args:
        fingerprint: the enumerate->classify->bucket map (any JSON-serializable value).
        random_buffer: the 128-byte ``crypto.getRandomValues`` buffer ``p5`` (the XTEA
            key is sliced from it and it is RSA-transported to the server). Generated
            fresh if omitted.
        kjurf8: the transform applied to the 16-byte XTEA key slice (decoded.js:2884),
            a ``bytes -> bytes`` callable. Defaults to the resolved repeating-key XOR
            (:func:`make_kjurf8` with :data:`KJURF8_KEY`); pass a custom callable to
            target a different deployment's key.

    Returns a dict with the final ``body`` string and every intermediate layer
    (``json_bytes``, ``lzw``, ``pad``, ``plaintext_len``, ``rsa_block``, ``blob``) so
    the port can be verified layer-by-layer against the JS oracle.
    """
    if kjurf8 is None:
        kjurf8 = make_kjurf8()
    if random_buffer is None:
        random_buffer = secrets.token_bytes(RSA_KEY_SIZE)
    if len(random_buffer) != RSA_KEY_SIZE:
        raise ValueError(f"random_buffer must be {RSA_KEY_SIZE} bytes")
    p5 = bytearray(random_buffer)

    # 1) serialize fingerprint, then append the single 0x20 byte (H[V++] = aS<<am)
    json_bytes = bytearray()
    _serialize_an(fingerprint, json_bytes)
    json_bytes.append(0x20)

    # 2) LZW compress
    lzw = _lzw_compress(list(json_bytes))

    # 3) zero-pad the compressed stream to an 8-byte boundary
    pad = (8 - (len(lzw) % 8)) % 8
    plaintext = bytes(lzw) + b"\x00" * pad

    # 4) RSA key-transport block (consumes p5 with p5[0]=1); VM restores p5[0]=0 after
    pv = rsa_block(bytes(p5))
    p5[0] = 0

    # 5) XTEA key = KJuRf8(p5[9*pad+40 : +16]) -> 4 big-endian words -> key schedule
    off = 9 * pad + 40
    key16 = kjurf8(bytes(p5[off:off + 16]))
    if len(key16) != 16:
        raise ValueError("KJuRf8 must return 16 bytes")
    words = (
        int.from_bytes(key16[0:4], "big"),
        int.from_bytes(key16[4:8], "big"),
        int.from_bytes(key16[8:12], "big"),
        int.from_bytes(key16[12:16], "big"),
    )
    base_keys = _xtea_round_keys(words)

    # 6) encrypt the padded plaintext
    ciphertext = _xtea_encrypt(plaintext, base_keys)

    # 7) blob = RSA block (128B) | pad-count byte | ciphertext
    blob = bytes(pv) + bytes((pad,)) + ciphertext

    # 8) custom-alphabet base64 -> body string
    body = custom_b64encode(blob)

    return {
        "body": body,
        "json_bytes": bytes(json_bytes),
        "lzw": bytes(lzw),
        "pad": pad,
        "plaintext_len": len(plaintext),
        "rsa_block": bytes(pv),
        "blob": blob,
    }


# ---------------------------------------------------------------------------
# Fingerprint value-classifier (mirrors `aP`, decoded.js:7025)
# ---------------------------------------------------------------------------

def classify_value(value: Any) -> str:
    """Best-effort Python port of the VM classifier ``aP``.

    NOTE: ``aP`` runs over *live JS values* in the browser global graph, so the
    authoritative fingerprint can only be produced in a real browser environment
    (or by driving the VM). This port classifies Python stand-ins and is provided
    for parity/testing of the bucketing logic, not as a substitute for that graph.
    """
    if value is None:
        return CATEGORY["null"]  # JS null; there is no Python equivalent of `undefined`
    if isinstance(value, bool):
        return CATEGORY["true"] if value else CATEGORY["false"]
    if isinstance(value, (list, tuple)):
        return CATEGORY["array"]
    if isinstance(value, str):
        return CATEGORY["string"]
    if isinstance(value, int):
        return CATEGORY["number"]
    if callable(value):
        return CATEGORY["user_fn"]
    return CATEGORY["object"]


def build_fingerprint_payload(fingerprint: Dict[str, List[str]]) -> str:
    """Serialize the fingerprint bucket map to the compact JSON the VM hashes.

    ``fingerprint`` is the ``{ <value-or-category> : [propName, ...] }`` map (same
    shape as the JSD ``wb_result`` built in utils/fingerprint.py). The VM keys most
    buckets by the value's category char, but numbers/arrays/non-numeric strings by
    their literal value (see report section 2c). JSON uses compact separators to match
    ``JSON.stringify`` with no spaces.
    """
    return json.dumps(fingerprint, separators=(",", ":"))


# ---------------------------------------------------------------------------
# Endpoint construction (decoded.js:8404)
# ---------------------------------------------------------------------------

def build_flow_ov_url(challenge_website: str, cf_chl_opt: Dict[str, str], challenge_token: str) -> str:
    """Assemble the ``/flow/ov`` submit URL exactly as the VM does at decoded.js:8404:

        "/cdn-cgi/challenge-platform/h/" + SvTRd8 + "/flow/ov" + "1"
          + "/" + <challenge_token> + "/" + wKbN9 + "/" + TJERQ4

    where ``SvTRd8`` / ``wKbN9`` / ``TJERQ4`` come from the page's ``_cf_chl_opt`` and
    ``challenge_token`` is the per-load ``<num>:<ts>:<token>`` triple embedded in the VM.
    """
    sv = cf_chl_opt["SvTRd8"]
    wk = cf_chl_opt["wKbN9"]
    tj = cf_chl_opt["TJERQ4"]
    return (
        f"{challenge_website}/cdn-cgi/challenge-platform/h/{sv}/flow/ov1/"
        f"{challenge_token}/{wk}/{tj}"
    )


# ---------------------------------------------------------------------------
# Solver scaffold
# ---------------------------------------------------------------------------

class TurnstileSolver:
    """Faithful scaffold of the Turnstile submit flow built on the verified
    primitives above. The ``/flow/ov`` request *body* is now fully recovered
    (``build_flow_ov_body``); what remains for an end-to-end solve is dynamic
    per-load data (a real env-probe fingerprint, fresh per-load constants, and the
    page's ``_cf_chl_opt`` tokens) -- see the TODOs at the bottom of the module.
    """

    def __init__(
        self,
        fingerprint: Any,
        *,
        constants: Optional[TurnstileConstants] = None,
        bundle: Optional[Union[str, bytes, os.PathLike]] = None,
    ) -> None:
        # TODO(dynamic): `fingerprint` must be the live env-probe bucket map produced
        # by aM (enumerate) -> aP (classify) -> bucket over the real browser global
        # graph (window/navigator/document/...). It cannot be hand-authored reliably;
        # collect it from a real Chromium context or by executing the VM.
        self.fingerprint = fingerprint
        # Per-load constants: extract fresh from a bundle when given, else use an
        # explicit set, else fall back to the captured-bundle DEFAULT_CONSTANTS.
        # Always apply: the verified primitives read the module globals, so the
        # default path must reset them too -- otherwise a prior solver built with
        # bundle=/constants= would leave the globals pointing at its constants.
        if bundle is not None and constants is None:
            constants = load_constants_from_bundle(bundle)
        self.constants = apply_constants(constants if constants is not None else DEFAULT_CONSTANTS)

    def build_submit_body(
        self,
        *,
        random_buffer: Optional[bytes] = None,
        kjurf8: Optional[Any] = None,
    ) -> str:
        """Build the byte-exact ``/flow/ov`` request body from the fingerprint map.

        Returns the custom-base64 body string POSTed to ``/flow/ov``. The full
        intermediate-layer dict is available via :func:`build_flow_ov_body` if you
        need to inspect/verify the chain.
        """
        return build_flow_ov_body(
            self.fingerprint, random_buffer=random_buffer, kjurf8=kjurf8
        )["body"]


# ===========================================================================
# TODO -- per-load / version-pinned wiring required for an end-to-end solve:
#
#   1. [DONE] RSA modulus N + custom alphabet (ALPHABET) + the string-table rotation
#      all change per Turnstile version. Now auto-extracted from a fresh bundle via
#      research/turnstile-vm/extract-constants.js -> load_constants_from_bundle() +
#      apply_constants() (pass `bundle=` to TurnstileSolver).
#   2. The fingerprint bucket map must be enumerated/classified over a REAL browser
#      global graph (aM/aP) -- it cannot be statically hardcoded like the JSD map and
#      stay correct across UA/version.
#   3. [DONE] KJuRf8 (decoded.js:2884) is a repeating-key XOR on the XTEA key slice.
#      Resolved + verified against live ground truth; it is carried as
#      `TurnstileConstants.kjurf8_key` and applied via `apply_constants()` to the
#      `KJURF8_KEY` global that `make_kjurf8()` (and thus the default body builder)
#      reads -- so `TurnstileSolver(..., constants=)` swaps it in alongside the
#      alphabet/RSA modulus. The key is built at runtime from the string-table (not a
#      static literal), so the AST extractor cannot recover it: for a new deployment
#      re-probe it live via `KJuRf8(new Uint8Array(16))` and pass the bytes as
#      `TurnstileConstants(..., kjurf8_key=...)` (or `make_kjurf8(bytes)` directly).
#   4. _cf_chl_opt tokens (SvTRd8 / wKbN9 / TJERQ4) and the embedded <num>:<ts>:<token>
#      triple are per-load; scrape them from the challenge page / iframe at solve time.
# ===========================================================================
