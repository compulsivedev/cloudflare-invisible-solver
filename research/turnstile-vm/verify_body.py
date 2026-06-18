"""Byte-for-byte verification of the Python /flow/ov body builder vs. the JS oracle.

Drives utils.turnstile.build_flow_ov_body and research/turnstile-vm/oracle-run.js
(the surgically-extracted plain-JS body builder `pZ`) with identical random inputs,
then compares every intermediate layer (serialized JSON, LZW, pad, plaintext length,
RSA block, full blob, and the final custom-base64 body string).

Run:  python research/turnstile-vm/verify_body.py [num_cases]
Exit code 0 == all layers match on every case.
"""
from __future__ import annotations

import json
import os
import random
import string
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.abspath(os.path.join(HERE, os.pardir, os.pardir))
sys.path.insert(0, REPO)

from utils import turnstile  # noqa: E402

ORACLE = os.path.join(HERE, "oracle-run.js")
BUILD = os.path.join(HERE, "build-oracle.js")


def _ensure_oracle() -> None:
    """(Re)generate oracle-body.js by surgically extracting the body builder from
    decoded.js, so the harness is runnable without committing the generated file."""
    proc = subprocess.run(["node", BUILD], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if proc.returncode != 0:
        sys.stderr.write(proc.stderr.decode("utf-8", "replace"))
        raise SystemExit(2)

# Characters that exercise every branch of the `an` string serializer:
#   raw ASCII, the named short escapes (\b\t\n\f\r " \), control chars (\u00xx),
#   2-/3-byte UTF-8 (cafe accent, CJK) and a 4-byte astral pair (emoji).
_STR_CHARS = (
    string.ascii_letters
    + string.digits
    + " !#%&'()*,-./:;<=>?@[]^_`{|}~"
    + '"\\'
    + "\b\t\n\f\r\x00\x01\x1f\x7f"
    + "\u00e9\u00fc\u4e2d\u6587\U0001f600\U0001f680"
)


def _rand_string(rng: random.Random) -> str:
    return "".join(rng.choice(_STR_CHARS) for _ in range(rng.randint(0, 12)))


def _rand_scalar(rng: random.Random):
    pick = rng.randint(0, 5)
    if pick == 0:
        return rng.randint(-(10 ** 9), 10 ** 9)
    if pick == 1:
        return _rand_string(rng)
    if pick == 2:
        return rng.choice([True, False])
    if pick == 3:
        return None
    if pick == 4:
        return rng.choice([0, 1, 255, 256, 65535, 65536, -1])
    return rng.choice([1.5, 0.1, -2.25, 3.0, 100.0])


def _rand_value(rng: random.Random, depth: int):
    if depth <= 0 or rng.random() < 0.45:
        return _rand_scalar(rng)
    if rng.random() < 0.5:
        return [_rand_value(rng, depth - 1) for _ in range(rng.randint(0, 5))]
    obj = {}
    for _ in range(rng.randint(0, 5)):
        # non-integer-like string keys so JS for-in order == Python insertion order
        key = "k" + _rand_string(rng).replace("\x00", "")
        obj[key] = _rand_value(rng, depth - 1)
    return obj


def _rand_fingerprint(rng: random.Random) -> dict:
    obj = {}
    for _ in range(rng.randint(1, 8)):
        key = "k" + "".join(rng.choice(string.ascii_letters) for _ in range(rng.randint(1, 6)))
        obj[key] = _rand_value(rng, depth=3)
    return obj


def _big_fingerprint(rng: random.Random) -> dict:
    """A fingerprint whose serialized JSON (>16384B) and compressed+padded plaintext
    (>16384B) both cross the VM's 16384-byte threshold, exercising the oracle's `aG`
    (LZW) and `p4` (XTEA) large-input branches against the Python `av`/`p3` port."""
    alnum = string.ascii_letters + string.digits
    obj = {}
    for i in range(1200):
        obj["k%04d" % i] = "".join(
            rng.choice(alnum) for _ in range(rng.randint(10, 30))
        )
    return obj


def _hex(b: bytes) -> str:
    return b.hex()


def main() -> int:
    num = int(sys.argv[1]) if len(sys.argv) > 1 else 200
    _ensure_oracle()
    rng = random.Random(0xC0FFEE)

    cases = []
    for _ in range(num):
        seed = [rng.randint(0, 255) for _ in range(128)]
        cases.append({"seed": seed, "fp": _rand_fingerprint(rng)})
    # also exercise the large-input branches (aG / p4) on a handful of big maps
    for _ in range(3):
        seed = [rng.randint(0, 255) for _ in range(128)]
        cases.append({"seed": seed, "fp": _big_fingerprint(rng)})

    proc = subprocess.run(
        ["node", ORACLE],
        input=json.dumps(cases).encode("utf-8"),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if proc.returncode != 0:
        sys.stderr.write(proc.stderr.decode("utf-8", "replace"))
        return 2
    oracle_out = json.loads(proc.stdout.decode("utf-8"))

    layers = ["json_hex", "lzw_hex", "pad", "plen", "blob_hex", "pv_hex", "body"]
    mismatches = 0
    for idx, (case, exp) in enumerate(zip(cases, oracle_out)):
        got = turnstile.build_flow_ov_body(
            case["fp"], random_buffer=bytes(case["seed"])
        )
        py = {
            "json_hex": _hex(got["json_bytes"]),
            "lzw_hex": _hex(got["lzw"]),
            "pad": got["pad"],
            "plen": got["plaintext_len"],
            "blob_hex": _hex(got["blob"]),
            "pv_hex": _hex(got["rsa_block"]),
            "body": got["body"],
        }
        for layer in layers:
            if py[layer] != exp[layer]:
                mismatches += 1
                print(f"[case {idx}] MISMATCH on {layer}")
                print(f"   fp     = {json.dumps(case['fp'])[:200]}")
                print(f"   python = {str(py[layer])[:160]}")
                print(f"   oracle = {str(exp[layer])[:160]}")
                break  # first divergent layer is the informative one

    total = len(cases)
    if mismatches:
        print(f"\nFAILED: {mismatches}/{total} cases diverged")
        return 1
    print(f"OK: all {total} cases match byte-for-byte across layers {layers}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
