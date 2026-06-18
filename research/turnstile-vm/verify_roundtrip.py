"""Round-trip verification of the inverse /flow/ov primitives.

The forward chain (serialize -> LZW -> pad -> XTEA -> RSA -> custom-b64) is verified
byte-for-byte against the JS oracle in ``verify_body.py``. This harness verifies the
*inverse* primitives added to ``utils.turnstile``:

    * ``custom_b64decode``  (inverse of ``custom_b64encode``)
    * ``_lzw_decompress``   (inverse of ``_lzw_compress``)
    * ``_xtea_decrypt``     (inverse of ``_xtea_encrypt``)
    * ``parse_flow_ov_body``(inverse of ``build_flow_ov_body``)

It builds a body with the forward path, parses it back with the inverse path, and
asserts every recovered layer (blob, rsa_block, pad, lzw, json_bytes, fingerprint)
matches. RSA is one-way, so the inverse path is supplied the same ``random_buffer``
(``p5``) the forward path used -- exactly the live-capture model the Opt-1 validation
gate uses (where ``p5`` is captured by hooking ``crypto.getRandomValues``).

No secrets, no network, no node: this runs purely in Python and is safe for CI.

Run:  python research/turnstile-vm/verify_roundtrip.py [num_cases]
Exit code 0 == all layers round-trip on every case.
"""
from __future__ import annotations

import os
import random
import secrets
import string
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.abspath(os.path.join(HERE, os.pardir, os.pardir))
sys.path.insert(0, REPO)

from utils import turnstile  # noqa: E402


def _primitive_roundtrips(rng: random.Random, n: int) -> int:
    """Exercise each inverse primitive directly against its forward counterpart."""
    fails = 0

    # custom-b64
    for _ in range(n):
        payload = bytes(rng.randint(0, 255) for _ in range(rng.randint(0, 300)))
        if turnstile.custom_b64decode(turnstile.custom_b64encode(payload)) != payload:
            fails += 1
    # LZW (random + JSON-ish text)
    for _ in range(n):
        payload = bytes(rng.randint(0, 255) for _ in range(rng.randint(0, 400)))
        if turnstile._lzw_decompress(bytes(turnstile._lzw_compress(list(payload)))) != payload:
            fails += 1
    for _ in range(n):
        s = '{"' + "".join(rng.choice("abcXYZ0123456789_/+=$.") for _ in range(rng.randint(0, 200))) + '":' + str(rng.randint(0, 10 ** 9)) + "}"
        payload = s.encode()
        if turnstile._lzw_decompress(bytes(turnstile._lzw_compress(list(payload)))) != payload:
            fails += 1
    # XTEA (block-aligned stream, per-block subkey schedule)
    for _ in range(n):
        words = tuple(rng.getrandbits(32) for _ in range(4))
        base_keys = turnstile._xtea_round_keys(words)
        pt = bytes(rng.randint(0, 255) for _ in range(rng.randint(1, 40) * 8))
        if turnstile._xtea_decrypt(turnstile._xtea_encrypt(pt, base_keys), base_keys) != pt:
            fails += 1
    return fails


def _rand_fingerprint(rng: random.Random) -> dict:
    """A map shaped like the recovered /flow/ov plaintext: string keys mapping to
    arrays of property paths, plus a few scalars."""
    obj: dict = {}
    for _ in range(rng.randint(1, 40)):
        key = "".join(rng.choice(string.ascii_letters + string.digits) for _ in range(rng.randint(3, 8)))
        obj[key] = ["".join(rng.choice(string.ascii_letters) for _ in range(rng.randint(1, 10)))
                    for _ in range(rng.randint(0, 6))]
    obj["sitekey"] = "0x4AAAAAAA-nDfU7SyKYs52-"
    obj["n"] = rng.randint(0, 10 ** 9)
    return obj


def main() -> int:
    num = int(sys.argv[1]) if len(sys.argv) > 1 else 300
    rng = random.Random(0xBADC0DE)

    prim_fails = _primitive_roundtrips(rng, num)
    if prim_fails:
        print(f"FAILED: {prim_fails} primitive round-trip(s) diverged")
        return 1
    print(f"OK: custom_b64 / _lzw / _xtea inverse primitives round-trip ({num} cases each)")

    # Full body round-trip across the default alphabet and a couple of swapped
    # per-load alphabets (apply_constants path), to prove the inverse honours the
    # active alphabet exactly like the forward encoder does.
    alphabets = [
        turnstile.ALPHABET,
        "Z0n8WYzBaTI2dk+gXJ5FKjm9h$VRCfUco4uwDSMErlP1NexitsLbqAOH7pQvyG6-3",
    ]
    body_fails = 0
    layers = ["json_bytes", "lzw", "pad", "rsa_block", "blob"]
    saved = turnstile.ALPHABET
    try:
        for alpha in alphabets:
            turnstile.ALPHABET = alpha
            for _ in range(num):
                fp = _rand_fingerprint(rng)
                rb = secrets.token_bytes(turnstile.RSA_KEY_SIZE)
                built = turnstile.build_flow_ov_body(fp, random_buffer=rb)
                parsed = turnstile.parse_flow_ov_body(built["body"], random_buffer=rb, alphabet=alpha)
                if parsed["fingerprint"] != fp or any(parsed[name] != built[name] for name in layers):
                    body_fails += 1
                    if body_fails <= 3:
                        print(f"   MISMATCH fp_ok={parsed['fingerprint'] == fp} "
                              + " ".join(f"{name}={parsed[name] == built[name]}" for name in layers))
    finally:
        turnstile.ALPHABET = saved

    if body_fails:
        print(f"FAILED: {body_fails} body round-trip(s) diverged")
        return 1
    print(f"OK: build_flow_ov_body <-> parse_flow_ov_body round-trip "
          f"({num} cases x {len(alphabets)} alphabets, all layers match)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
