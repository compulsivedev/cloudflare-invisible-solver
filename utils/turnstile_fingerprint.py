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

import json
from pathlib import Path
from typing import Dict, List, Optional

DEFAULT_CDP_URL = "http://localhost:29229"
COLLECTOR_JS = (
    Path(__file__).resolve().parents[1]
    / "research"
    / "turnstile-vm"
    / "collect-fingerprint.js"
)


def load_collector_js() -> str:
    """Return the source of the recovered JS fingerprint collector."""
    return COLLECTOR_JS.read_text(encoding="utf-8")


def collect_fingerprint(
    challenge_website: str,
    *,
    cdp_url: str = DEFAULT_CDP_URL,
    roots: Optional[List[Dict[str, str]]] = None,
    wait_until: str = "domcontentloaded",
    timeout_ms: int = 30000,
    reuse_page: bool = True,
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

    Returns the bucket map ready to pass to ``build_flow_ov_body`` /
    ``CfSolver.get_turnstile_solution``. Requires ``playwright``.
    """
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
            return page.evaluate(call)
        finally:
            browser.close()
