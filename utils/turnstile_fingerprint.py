"""Live Turnstile env-probe fingerprint collection (closes TODO 2).

The fingerprint that the ``/flow/ov`` body hashes (``utils.turnstile.build_flow_ov_body``)
is the ``aM`` (enumerate) -> ``aP`` (classify) -> bucket map computed over the **real**
browser global graph (window/navigator/document/...). It cannot be hand-authored and
stay correct across UA/version, so it must be collected from a real browser.

This module runs the faithful JS port of that collector
(``research/turnstile-vm/collect-fingerprint.js``) inside an already-running Chromium
over CDP and returns the bucket map in the exact shape ``build_flow_ov_body`` consumes::

    { "<value-or-categoryChar>": ["<prefix><propName>", ...], ... }

The VM driver that selects the enumerated root objects + prefixes is bytecode-driven
(JSVMP dispatch) and not statically recoverable; the collector's ``DEFAULT_ROOTS`` are
reconstructed from the recovered evidence and can be overridden via ``roots``.

``playwright`` is imported lazily, so importing this module (or ``main``) does not
require it -- only :func:`collect_fingerprint` does.
"""
from __future__ import annotations

import ipaddress
import json
import warnings
from pathlib import Path
from typing import Dict, List, Optional
from urllib.parse import urlsplit

DEFAULT_CDP_URL = "http://localhost:29229"
COLLECTOR_JS = (
    Path(__file__).resolve().parents[1]
    / "research"
    / "turnstile-vm"
    / "collect-fingerprint.js"
)

# A fingerprint enumerated over a real browser global graph is large (the live
# capture is ~59 buckets / ~1500 names). A map far below this almost certainly
# means the enumerated root set is wrong/incomplete (e.g. a future VM changed the
# roots, or a bad ``roots`` override), which would silently produce an invalid
# body -- so we warn rather than fail.
MIN_EXPECTED_BUCKETS = 10
MIN_EXPECTED_NAMES = 100

_LOOPBACK_HOSTNAMES = {"localhost", "localhost.localdomain", "ip6-localhost"}


def load_collector_js() -> str:
    """Return the source of the recovered JS fingerprint collector."""
    return COLLECTOR_JS.read_text(encoding="utf-8")


def _is_loopback_host(host: str) -> bool:
    """Return True if ``host`` resolves to a loopback name or address."""
    if not host:
        return False
    host = host.strip("[]").lower()
    if host in _LOOPBACK_HOSTNAMES:
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def _validate_challenge_website(challenge_website: str) -> None:
    """Reject non-http(s) / hostless targets before navigating to them.

    ``challenge_website`` is operator-supplied (the origin you intend to solve),
    but validating the scheme/host keeps an accidental or injected ``file://`` /
    ``javascript:`` / hostless value from being handed to ``page.goto``.
    """
    parts = urlsplit(challenge_website)
    if parts.scheme not in ("http", "https"):
        raise ValueError(
            "challenge_website must use http/https, got %r" % (challenge_website,)
        )
    if not parts.hostname:
        raise ValueError(
            "challenge_website must include a host, got %r" % (challenge_website,)
        )


def _validate_cdp_url(cdp_url: str, *, allow_remote: bool) -> None:
    """Keep the CDP endpoint loopback-only unless explicitly opted out.

    ``connect_over_cdp`` will talk to whatever endpoint it is given; defaulting to
    loopback-only avoids a caller-influenced ``cdp_url`` reaching an internal host.
    """
    parts = urlsplit(cdp_url)
    if parts.scheme not in ("http", "https", "ws", "wss"):
        raise ValueError("cdp_url must be an http(s)/ws(s) URL, got %r" % (cdp_url,))
    if not allow_remote and not _is_loopback_host(parts.hostname or ""):
        raise ValueError(
            "cdp_url %r is not loopback; pass allow_remote=True to target a "
            "non-local DevTools endpoint" % (cdp_url,)
        )


def collect_fingerprint(
    challenge_website: str,
    *,
    cdp_url: str = DEFAULT_CDP_URL,
    roots: Optional[List[Dict[str, str]]] = None,
    wait_until: str = "domcontentloaded",
    timeout_ms: int = 30000,
    reuse_page: bool = True,
    allow_remote: bool = False,
) -> Dict[str, List[str]]:
    """Collect a live env-probe fingerprint from a real Chromium over CDP.

    Connects to an already-running Chrome at ``cdp_url`` (the browser must expose a
    DevTools endpoint, e.g. launched with ``--remote-debugging-port``), navigates to
    ``challenge_website`` so the global graph matches the target origin, injects the
    recovered collector, and returns the ``aM``/``aP``/bucket map.

    Args:
        challenge_website: origin to load before probing, e.g. ``https://example.com``.
        cdp_url: DevTools/CDP endpoint of the running browser.
        roots: optional override of the enumerated ``{path, prefix}`` / ``{obj, prefix}``
            root objects (see ``collect-fingerprint.js`` ``DEFAULT_ROOTS``).
        wait_until: Playwright navigation wait state.
        timeout_ms: navigation timeout in milliseconds.
        reuse_page: reuse the context's first existing page instead of opening a new one.
        allow_remote: permit a non-loopback ``cdp_url`` (default loopback-only).

    Returns the bucket map ready to pass to ``build_flow_ov_body`` /
    ``CfSolver.get_turnstile_solution``. Requires ``playwright``.

    Raises:
        ValueError: if ``challenge_website`` is not http(s)/hostless, or ``cdp_url``
            is non-loopback without ``allow_remote=True``.
    """
    _validate_challenge_website(challenge_website)
    _validate_cdp_url(cdp_url, allow_remote=allow_remote)

    from playwright.sync_api import sync_playwright

    collector = load_collector_js()
    call = "__cfCollectFingerprint(%s)" % ("" if roots is None else json.dumps(roots))

    with sync_playwright() as p:
        browser = p.chromium.connect_over_cdp(cdp_url)
        try:
            ctx = browser.contexts[0] if browser.contexts else browser.new_context()
            page = ctx.pages[0] if (reuse_page and ctx.pages) else ctx.new_page()
            page.goto(challenge_website, wait_until=wait_until, timeout=timeout_ms)
            page.evaluate(collector)
            fingerprint = page.evaluate(call)
        finally:
            browser.close()

    _warn_if_suspiciously_small(fingerprint)
    return fingerprint


def _warn_if_suspiciously_small(fingerprint: Dict[str, List[str]]) -> None:
    """Warn when a collected map looks too small to be a real env probe.

    Guards against a silently-incomplete fingerprint (wrong/changed root set or a
    bad ``roots`` override) producing a body that the VM would reject.
    """
    buckets = len(fingerprint)
    names = sum(len(v) for v in fingerprint.values())
    if buckets < MIN_EXPECTED_BUCKETS or names < MIN_EXPECTED_NAMES:
        warnings.warn(
            "collected fingerprint looks suspiciously small (%d buckets / %d names; "
            "expected >=%d / >=%d) -- the enumerated root set may be wrong or "
            "incomplete" % (buckets, names, MIN_EXPECTED_BUCKETS, MIN_EXPECTED_NAMES),
            stacklevel=2,
        )
