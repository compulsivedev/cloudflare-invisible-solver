"""Live, HTTP-only Turnstile solve harness (TODO 4 demo + findings).

Exercises the full HTTP path end-to-end against a real Turnstile sitekey:

  1. utils.turnstile_scraper.scrape_turnstile_tokens -> fetch the challenge iframe
     over HTTP (curl_cffi, no browser) and parse the per-load _cf_chl_opt tokens
     (SvTRd8/wKbN9/TJERQ4), the <num>:<ts>:<token> triple, and the inline VM bundle.
  2. utils.turnstile.build_flow_ov_{url,body} -> assemble the /flow/ov request body
     with the verified primitives + captured DEFAULT_CONSTANTS.
  3. POST it to challenges.cloudflare.com and report the server's response.

Documented result (tickpick sitekey 0x4AAAAAAA-nDfU7SyKYs52-, June 2026): step 1
succeeds (HTTP 200, all tokens recovered), but step 3 is rejected with HTTP 400.
Cloudflare re-obfuscates the VM per request -- the served bundle's string table is
re-shuffled each serve (observed table_len 1908 vs the captured bundle's 1821), so
the custom-base64 alphabet and the runtime-assembled KJuRf8 XTEA key differ from
DEFAULT_CONSTANTS and the body this load expects cannot be built statically. The
RSA modulus is the only constant that is stable across loads. Recovering a given
load's alphabet + KJuRf8 key requires executing that bundle's JS (a JS engine with
a DOM env), and invisible-mode Turnstile additionally scores the submission
server-side -- so a synthetic, non-browser body is expected to be rejected.

Run:  python research/turnstile-vm/live_solve.py [sitekey] [page_url]
This makes real network requests to challenges.cloudflare.com.
"""

from __future__ import annotations

import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.abspath(os.path.join(HERE, os.pardir, os.pardir))
sys.path.insert(0, REPO)

from curl_cffi import requests  # noqa: E402

from utils import constants, turnstile  # noqa: E402
from utils.turnstile_scraper import (  # noqa: E402
    TURNSTILE_HOST,
    scrape_turnstile_tokens,
)

# A representative env-probe bucket map. A *passing* token needs a live one collected
# over a real browser (utils.turnstile_fingerprint.collect_fingerprint); this stand-in
# only lets the body builder run so the transport + token wiring can be exercised.
SAMPLE_FINGERPRINT = {
    "object": ["window.navigator", "window.document", "window.location"],
    "function": ["window.fetch", "window.atob", "window.btoa"],
    "3": ["navigator.maxTouchPoints"],
    "true": ["navigator.cookieEnabled"],
    "false": ["navigator.webdriver"],
}

DEFAULT_SITEKEY = "0x4AAAAAAA-nDfU7SyKYs52-"
DEFAULT_PAGE_URL = "https://www.tickpick.com/"


def main() -> int:
    sitekey = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_SITEKEY
    page_url = sys.argv[2] if len(sys.argv) > 2 else DEFAULT_PAGE_URL

    print(f"[1] scraping per-load tokens for {sitekey} (referer {page_url}) ...")
    challenge = scrape_turnstile_tokens(sitekey, page_url=page_url)
    print(f"    mode           = {challenge.mode}")
    print(f"    SvTRd8         = {challenge.sv}")
    print(f"    wKbN9 (ray)    = {challenge.ray}")
    print(f"    TJERQ4         = {challenge.chl[:48]}...")
    print(f"    challenge_token= {challenge.challenge_token}")
    print(f"    bundle bytes   = {len(challenge.bundle)}")

    print("[2] building /flow/ov body with DEFAULT_CONSTANTS ...")
    submit_url = turnstile.build_flow_ov_url(
        TURNSTILE_HOST, challenge.cf_chl_opt, challenge.challenge_token
    )
    body = turnstile.TurnstileSolver(SAMPLE_FINGERPRINT).build_submit_body()
    print(f"    submit_url     = {submit_url[:80]}...")
    print(f"    body_len       = {len(body)}")

    print("[3] POSTing to /flow/ov ...")
    session = requests.Session(impersonate="chrome133a")
    headers = constants.CHALLENGE_HEADERS.copy()
    headers["origin"] = TURNSTILE_HOST
    headers["Referer"] = challenge.iframe_url
    headers.update(challenge.extra_headers)
    response = session.post(submit_url, data=body, headers=headers)
    session.close()

    print(f"    HTTP {response.status_code}, {len(response.text)} bytes")
    print(f"    response: {response.text[:200]}")

    if response.status_code == 200:
        print("\nRESULT: /flow/ov accepted the submission.")
        return 0
    print(
        "\nRESULT: rejected (expected). The captured DEFAULT_CONSTANTS do not match "
        "this load's per-serve re-obfuscated bundle -- see module docstring."
    )
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
