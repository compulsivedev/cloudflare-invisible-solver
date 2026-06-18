"""Turnstile challenge-VM payload primitives (scaffold).

Reverse-engineered from the Turnstile challenge *iframe* VM script -- the real
fingerprinting / payload engine. (``api.js`` is only the loader/orchestrator and
contains none of this.) The full analysis, line references, and the execution-based
verification of every primitive below live in
``research/turnstile-vm/TURNSTILE-ALGORITHM-RECOVERY.md``.

This mirrors the JSD path already in the repo:

    JSD        fingerprint map -> lz-string encode                       -> POST /jsd/r/
    Turnstile  fingerprint map -> JSON -> SHA-256 + RSA(key) + base64(aj) -> POST /flow/ov

RECOVERED + VERIFIED (faithful, runnable -- see research/turnstile-vm/verify-primitives.js):
    * custom-alphabet base64 over ``aj``        -> ``custom_b64encode``
    * RSA-1024 hybrid key transport, e=65537    -> ``rsa_keytransport``
    * SHA-256 hex digest                        -> ``sha256_hex``
    * fingerprint value-classifier category model -> ``classify_value`` / ``CATEGORY``
    * /flow/ov endpoint construction            -> ``build_flow_ov_url``

PER-LOAD / VERSION-PINNED -- must be re-extracted, see the TODOs at the bottom and
in ``TurnstileSolver``. The constants below were captured from ONE bundle and rotate
across Turnstile versions; the env-probe graph and the exact request *body* assembly
are produced inside the VM (the body is driven by the residual JSVMP bytecode).
"""
from __future__ import annotations

import hashlib
import json
import secrets
from typing import Any, Dict, List, Optional, Union

# ---------------------------------------------------------------------------
# Version-pinned constants captured from one Turnstile VM bundle.
# These rotate per challenge version -- re-extract from a fresh bundle with the
# scripts under research/turnstile-vm/ (decode-strings.js + derive-rotation.js).
# ---------------------------------------------------------------------------

# Custom base64 alphabet (`aj`). Same family as the JSD alphabet -- it matches the
# repo regex `[a-zA-Z0-9+\-$]{65}` in utils/constants.py (ENC_KEY_RE). 65th char is
# unused by the encoder (no padding is emitted), so only indices 0..63 are reachable.
ALPHABET = "D9nyKPm+ZdgzraW-e3NEo4Hp76GXsU52jIVuRtwcxlfi$YC10QkqMOSFbvBTA8LhJ"

# RSA public key (`ag` / `ae`). 1024-bit modulus; the literal carries a redundant
# leading 0x00 byte. e = 0x10001.
RSA_N = int(
    "00e9d3dca1328a49ad3403e4badda37a6a13610b608b5099839e1074e720f5a3"
    "3b2ebd8c2ffd12c09be0015a4635aa9d2022d8f72f90ed11610c3742b0baef5b"
    "7da73d7e79aff6cdbdeab72492ce0a858e4c1f4c27a14ebbb4ce3beacfda982f"
    "e74463e76f654aab0c597d5e73686ea149023e8f60ae6365a30055fe2c5eb2ebfb",
    16,
)
RSA_E = 65537
RSA_KEY_SIZE = 128  # bytes (1024-bit)

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
    equivalent. Used for integrity/keying -- no PoW difficulty loop exists."""
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
    primitives above. It deliberately does NOT claim to produce a passing token:
    the env-probe graph and the byte-exact ``/flow/ov`` body are produced inside
    the version-pinned VM (the body is assembled by the residual JSVMP bytecode).
    The TODOs below enumerate exactly what dynamic wiring remains.
    """

    def __init__(self, fingerprint: Dict[str, List[str]]) -> None:
        # TODO(dynamic): `fingerprint` must be the live env-probe bucket map produced
        # by aM (enumerate) -> aP (classify) -> bucket over the real browser global
        # graph (window/navigator/document/...). It cannot be hand-authored reliably;
        # collect it from a real Chromium context or by executing the VM.
        self.fingerprint = fingerprint

    def build_submit_body(self) -> Dict[str, str]:
        """Build the recovered payload pieces. The field names/order of the real
        request body are JSVMP-driven (see report section 5) and are left as a TODO."""
        fp_json = build_fingerprint_payload(self.fingerprint)
        digest = sha256_hex(fp_json)
        kt = rsa_keytransport()
        encrypted_key = custom_b64encode(kt["cipher"])

        # TODO(dynamic): the symmetric `kt["key"]` is used by the VM to encrypt the
        # fingerprint/telemetry blob; that symmetric step + the exact field layout of
        # the body are assembled by the JSVMP bytecode and are not recovered here.
        return {
            "hash": digest,
            "encrypted_key": encrypted_key,
        }


# ===========================================================================
# TODO -- per-load / version-pinned wiring required for an end-to-end solve:
#
#   1. RSA modulus N + custom alphabet (ALPHABET) + the VM string table & its
#      load-time rotation all change per Turnstile version. Re-extract them from a
#      fresh bundle using research/turnstile-vm/{decode-strings,derive-rotation}.js.
#   2. The fingerprint bucket map must be enumerated/classified over a REAL browser
#      global graph (aM/aP) -- it cannot be statically hardcoded like the JSD map and
#      stay correct across UA/version.
#   3. The exact /flow/ov request *body* (field names, order, the symmetric encryption
#      of the blob) is assembled by the JSVMP bytecode interpreter (runProgram / V3)
#      and would require lifting/executing that bytecode to reproduce byte-for-byte.
#   4. _cf_chl_opt tokens (SvTRd8 / wKbN9 / TJERQ4) and the embedded <num>:<ts>:<token>
#      triple are per-load; scrape them from the challenge page / iframe at solve time.
# ===========================================================================
