"""HTTP per-load token scraper for the Turnstile ``/flow/ov`` submit path (TODO 4).

:func:`utils.turnstile.build_flow_ov_url` needs the widget's per-load
``_cf_chl_opt`` tokens (``SvTRd8`` / ``wKbN9`` / ``TJERQ4``) and the embedded
``<num>:<ts>:<token>`` challenge triple. Those are minted fresh on every Turnstile
load, so the original :meth:`CfSolver.get_turnstile_solution` made the caller pass
them in by hand. This module fetches the widget's challenge iframe directly over
HTTP -- no browser, same ``curl_cffi`` transport as the rest of the solver -- and
parses them out.

The iframe response also carries the full inline VM bundle (the same source backing
``research/turnstile-vm/vm_raw.js``); it is returned as :attr:`TurnstileChallenge.bundle`
so a caller can run :func:`utils.turnstile.load_constants_from_bundle` against the
*live* bundle. Note Cloudflare re-obfuscates the VM per request (the string table is
re-shuffled each serve), so the custom-base64 alphabet and the runtime-assembled
``KJuRf8`` key in any given load differ from the captured ``DEFAULT_CONSTANTS`` and
generally cannot be recovered without executing that specific bundle.
"""

from __future__ import annotations

import random
import re
import string
from dataclasses import dataclass, field
from typing import Dict, Optional, Tuple

from curl_cffi import requests

# Host that serves every Turnstile widget + its challenge iframe and /flow/ov.
TURNSTILE_HOST = "https://challenges.cloudflare.com"

# `_cf_chl_opt = { key: 'value', key: 123, ... };` -- the per-load option blob the
# iframe inlines (decoded.js reads SvTRd8/wKbN9/TJERQ4 straight off it).
_OPT_RE = re.compile(r"_cf_chl_opt\s*=\s*\{(?P<body>.*?)\};", re.DOTALL)
_OPT_STR_RE = re.compile(r"(\w+)\s*:\s*'((?:[^'\\]|\\.)*)'")
# The challenge token the VM feeds to build_flow_ov_url: <num>:<unix-ts>:<token>.
_TRIPLE_RE = re.compile(r"\b\d{6,}:\d{10}:[A-Za-z0-9._-]{20,}\b")

# curl_cffi browser-impersonation target shared with main.CfSolver._create_session.
DEFAULT_IMPERSONATE = "chrome133a"


@dataclass
class TurnstileChallenge:
    """Per-load tokens scraped from one Turnstile challenge-iframe load."""

    sitekey: str
    sv: str          # _cf_chl_opt.SvTRd8 -- the `/h/<sv>/` path segment (e.g. "b")
    ray: str         # _cf_chl_opt.wKbN9  -- per-load cf-ray
    chl: str         # _cf_chl_opt.TJERQ4 -- per-load token + the cf-chl header value
    challenge_token: str  # the <num>:<ts>:<token> triple embedded in the iframe
    mode: str        # _cf_chl_opt.sVSMo5 -- e.g. "invisible" / "managed"
    widget_id: str   # the random cb minted for this widget load
    iframe_url: str
    bundle: str = field(repr=False)  # full inline VM source from the iframe HTML
    opt: Dict[str, str] = field(default_factory=dict, repr=False)  # raw _cf_chl_opt

    @property
    def cf_chl_opt(self) -> Dict[str, str]:
        """The subset :func:`utils.turnstile.build_flow_ov_url` consumes."""
        return {"SvTRd8": self.sv, "wKbN9": self.ray, "TJERQ4": self.chl}

    @property
    def extra_headers(self) -> Dict[str, str]:
        """Per-load XHR headers the VM sets on the ``/flow/ov`` POST (decoded.js:4844).

        ``cf-chl`` is ``TJERQ4``; ``cf-chl-ra`` is the retry counter ``h`` (0 on the
        first attempt, incremented on each retry).
        """
        return {"cf-chl": self.chl, "cf-chl-ra": "0"}

    def solution_inputs(self) -> Tuple[Dict[str, str], str, Dict[str, str]]:
        """``(cf_chl_opt, challenge_token, extra_headers)`` for get_turnstile_solution."""
        return self.cf_chl_opt, self.challenge_token, self.extra_headers


def _random_widget_id(length: int = 5) -> str:
    alphabet = string.ascii_lowercase + string.digits
    return "".join(random.choice(alphabet) for _ in range(length))


def build_iframe_url(
    sitekey: str,
    *,
    sv: str = "b",
    widget_id: Optional[str] = None,
    theme: str = "light",
    appearance: str = "fbE",
    flow: str = "new",
    size: str = "flexible",
    lang: str = "auto",
) -> str:
    """Assemble the Turnstile challenge-iframe (``/turnstile/f/ov2``) URL.

    Mirrors the request the widget's ``api.js`` issues, observed live as
    ``/cdn-cgi/challenge-platform/h/b/turnstile/f/ov2/av0/rch/<cb>/<sitekey>/light/fbE/new/flexible?lang=auto``.
    """
    cb = widget_id or _random_widget_id()
    return (
        f"{TURNSTILE_HOST}/cdn-cgi/challenge-platform/h/{sv}/turnstile/f/ov2/av0/"
        f"rch/{cb}/{sitekey}/{theme}/{appearance}/{flow}/{size}?lang={lang}"
    )


def _parse_cf_chl_opt(html: str) -> Dict[str, str]:
    match = _OPT_RE.search(html)
    if match is None:
        raise RuntimeError("_cf_chl_opt blob not found in iframe HTML")
    return dict(_OPT_STR_RE.findall(match.group("body")))


def _extract_inline_bundle(html: str) -> str:
    scripts = re.findall(r"<script[^>]*>(.*?)</script>", html, re.DOTALL)
    return max(scripts, key=len) if scripts else ""


def scrape_turnstile_tokens(
    sitekey: str,
    *,
    page_url: str,
    session: Optional[requests.Session] = None,
    sv: str = "b",
    theme: str = "light",
    appearance: str = "fbE",
    flow: str = "new",
    size: str = "flexible",
    lang: str = "auto",
    impersonate: str = DEFAULT_IMPERSONATE,
    timeout: float = 30.0,
) -> TurnstileChallenge:
    """Fetch a Turnstile challenge iframe over HTTP and scrape its per-load tokens.

    Args:
        sitekey: the widget sitekey, e.g. ``0x4AAAAAAA-nDfU7SyKYs52-``.
        page_url: the host page embedding the widget (sent as ``Referer``; the sitekey
            is domain-bound, so this must be an allowlisted origin to get a challenge).
        session: reuse an existing ``curl_cffi`` session; one is created otherwise.
        sv/theme/appearance/flow/size/lang: iframe-URL params (see :func:`build_iframe_url`).
        impersonate: ``curl_cffi`` browser-impersonation target.
        timeout: request timeout in seconds.

    Returns a :class:`TurnstileChallenge`. Raises ``RuntimeError`` on a non-200
    response or if the required tokens cannot be parsed.
    """
    owns_session = session is None
    if session is None:
        session = requests.Session(impersonate=impersonate)

    widget_id = _random_widget_id()
    iframe_url = build_iframe_url(
        sitekey,
        sv=sv,
        widget_id=widget_id,
        theme=theme,
        appearance=appearance,
        flow=flow,
        size=size,
        lang=lang,
    )
    headers = {
        "Referer": page_url,
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "sec-fetch-dest": "iframe",
        "sec-fetch-mode": "navigate",
        "sec-fetch-site": "cross-site",
        "upgrade-insecure-requests": "1",
    }
    try:
        response = session.get(iframe_url, headers=headers, timeout=timeout)
    finally:
        if owns_session:
            session.close()

    if response.status_code != 200:
        raise RuntimeError(
            f"Turnstile iframe fetch failed (HTTP {response.status_code}) for {sitekey}"
        )

    html = response.text
    opt = _parse_cf_chl_opt(html)
    missing = [k for k in ("SvTRd8", "wKbN9", "TJERQ4") if k not in opt]
    if missing:
        raise RuntimeError(f"_cf_chl_opt missing required keys: {missing}")

    triple_match = _TRIPLE_RE.search(html)
    if triple_match is None:
        raise RuntimeError("challenge <num>:<ts>:<token> triple not found in iframe HTML")

    return TurnstileChallenge(
        sitekey=opt.get("kGHQ7", sitekey),
        sv=opt["SvTRd8"],
        ray=opt["wKbN9"],
        chl=opt["TJERQ4"],
        challenge_token=triple_match.group(0),
        mode=opt.get("sVSMo5", ""),
        widget_id=opt.get("widgetId", widget_id),
        iframe_url=iframe_url,
        bundle=_extract_inline_bundle(html),
        opt=opt,
    )
