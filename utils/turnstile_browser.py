"""Browser-based Turnstile solver: harvest a real ``cf-turnstile-response`` token.

Invisible-mode Turnstile scores the submission *server-side* on the live browser
environment, so a byte-perfect synthetic ``/flow/ov`` body (see ``utils/turnstile.py``)
is still rejected as a bot. The reliable way to obtain a **valid** token is to let
Cloudflare's own challenge VM run inside a real (stealth) Chrome and read back the
token it issues.

This module drives Chrome via `zendriver <https://github.com/cdpdriver/zendriver>`_
(CDP, no Selenium/WebDriver). It does **not** rely on the page actually hosting the
widget: it intercepts the top-level document request for ``host`` via CDP ``Fetch``
and fulfils it with a minimal page that renders the widget for ``sitekey``. Because
the navigation URL is on ``host``, the iframe's hostname check passes and Cloudflare
binds the issued token to that hostname.

Key environment gotcha: a browser launched with ``--enable-automation`` reports
``navigator.webdriver === true`` and Turnstile fails it with client error ``600010``
("bot behavior detected"). zendriver launches its own instance *without* that flag and
patches ``navigator.webdriver``, which is what makes the challenge pass.
"""

from __future__ import annotations

import asyncio
import base64
import glob
import os
from dataclasses import dataclass, field
from typing import Dict, List, Optional

import zendriver
from zendriver import cdp

DEFAULT_HOST = "www.tickpick.com"
_HARVEST_PATH = "/__cf_turnstile_harvest"

# Minimal page: load Turnstile's api.js and render the widget. The callbacks stash the
# token / error on ``window`` where we poll for them. ``{extra}`` carries optional
# ``data-action`` / ``data-cdata`` attributes some sites bind their token to.
_HARVEST_HTML = """<!DOCTYPE html><html><head><meta charset="utf-8"><title>.</title>
<script src="https://challenges.cloudflare.com/turnstile/v0/api.js" async defer></script>
</head><body>
<div class="cf-turnstile" data-sitekey="{sitekey}"{extra}
     data-callback="__onTok" data-error-callback="__onErr"></div>
<script>
window.__cfToken=null;window.__cfErr=null;
function __onTok(t){{window.__cfToken=t;}}
function __onErr(e){{window.__cfErr=String(e);return true;}}
</script></body></html>"""


def _resolve_chrome() -> Optional[str]:
    """Locate a real Chrome binary zendriver can launch.

    Some environments shadow ``google-chrome`` with a shim that merely opens a tab in
    an already-running instance; launching it yields no debuggable process. Prefer an
    explicit ``CHROME_PATH``/``CHROME_BIN`` override, then a real binary on disk, and
    finally fall back to ``None`` (zendriver auto-detect).
    """
    for env in ("CHROME_PATH", "CHROME_BIN"):
        p = os.environ.get(env)
        if p and os.path.exists(p):
            return p
    candidates: List[str] = []
    candidates += sorted(glob.glob("/opt/.devin/chrome/chrome/*/chrome-linux64/chrome"), reverse=True)
    candidates += [
        "/opt/google/chrome/chrome",
        "/usr/bin/google-chrome-stable",
        "/usr/bin/chromium",
        "/usr/bin/chromium-browser",
    ]
    for c in candidates:
        if os.path.exists(c):
            return c
    return None


@dataclass
class BrowserTurnstileSolver:
    """Harvest a valid ``cf-turnstile-response`` token by running CF's VM in Chrome."""

    chrome_path: Optional[str] = field(default_factory=_resolve_chrome)
    user_data_dir: str = field(
        default_factory=lambda: os.path.expanduser("~/.zendriver_turnstile_profile")
    )
    headless: bool = False
    timeout: float = 60.0

    async def harvest_async(
        self,
        sitekey: str,
        *,
        host: str = DEFAULT_HOST,
        action: Optional[str] = None,
        cdata: Optional[str] = None,
        timeout: Optional[float] = None,
    ) -> str:
        """Launch Chrome, render the widget for ``sitekey`` on ``host``, return token.

        ``action`` / ``cdata`` mirror Turnstile's ``data-action`` / ``data-cdata`` so the
        issued token carries the same metadata the target site binds to (siteverify
        echoes them). Raises :class:`RuntimeError` on Turnstile error / timeout.
        """
        timeout = self.timeout if timeout is None else timeout
        extra = ""
        if action is not None:
            extra += f' data-action="{action}"'
        if cdata is not None:
            extra += f' data-cdata="{cdata}"'
        html = _HARVEST_HTML.format(sitekey=sitekey, extra=extra)
        harvest_url = f"https://{host}{_HARVEST_PATH}"

        browser = await zendriver.start(
            headless=self.headless,
            sandbox=False,
            browser_executable_path=self.chrome_path,
            user_data_dir=self.user_data_dir,
            browser_args=["--disable-dev-shm-usage"],
            browser_connection_timeout=1.0,
            browser_connection_max_tries=40,
        )
        try:
            tab = await browser.get("about:blank")

            async def _on_paused(ev: cdp.fetch.RequestPaused) -> None:
                if _HARVEST_PATH in ev.request.url:
                    await tab.send(
                        cdp.fetch.fulfill_request(
                            request_id=ev.request_id,
                            response_code=200,
                            response_headers=[
                                cdp.fetch.HeaderEntry(
                                    name="Content-Type", value="text/html; charset=utf-8"
                                )
                            ],
                            body=base64.b64encode(html.encode()).decode(),
                        )
                    )
                else:  # pragma: no cover - pattern is scoped, should not fire
                    try:
                        await tab.send(cdp.fetch.continue_request(request_id=ev.request_id))
                    except Exception:
                        pass

            tab.add_handler(cdp.fetch.RequestPaused, _on_paused)
            await tab.send(
                cdp.fetch.enable(
                    patterns=[
                        cdp.fetch.RequestPattern(
                            url_pattern=f"*{_HARVEST_PATH}*",
                            request_stage=cdp.fetch.RequestStage.REQUEST,
                        )
                    ]
                )
            )

            await tab.get(harvest_url)

            deadline = asyncio.get_event_loop().time() + timeout
            last_err: Optional[str] = None
            while asyncio.get_event_loop().time() < deadline:
                token = await tab.evaluate("window.__cfToken")
                if token:
                    return str(token)
                last_err = await tab.evaluate("window.__cfErr")
                await asyncio.sleep(0.5)
            raise RuntimeError(
                f"Turnstile token not issued within {timeout:.0f}s "
                f"(last client error: {last_err!r})"
            )
        finally:
            await browser.stop()

    def harvest(
        self,
        sitekey: str,
        *,
        host: str = DEFAULT_HOST,
        action: Optional[str] = None,
        cdata: Optional[str] = None,
        timeout: Optional[float] = None,
    ) -> str:
        """Synchronous wrapper around :meth:`harvest_async`."""
        return asyncio.run(
            self.harvest_async(
                sitekey, host=host, action=action, cdata=cdata, timeout=timeout
            )
        )


def solve_turnstile_browser(
    sitekey: str,
    *,
    host: str = DEFAULT_HOST,
    action: Optional[str] = None,
    cdata: Optional[str] = None,
    headless: bool = False,
    timeout: float = 60.0,
) -> str:
    """Convenience one-shot: return a valid ``cf-turnstile-response`` token."""
    return BrowserTurnstileSolver(headless=headless, timeout=timeout).harvest(
        sitekey, host=host, action=action, cdata=cdata
    )


if __name__ == "__main__":  # pragma: no cover - manual smoke test
    import argparse
    import json

    ap = argparse.ArgumentParser(description="Harvest a Turnstile token via zendriver.")
    ap.add_argument("sitekey")
    ap.add_argument("--host", default=DEFAULT_HOST)
    ap.add_argument("--action", default=None)
    ap.add_argument("--cdata", default=None)
    ap.add_argument("--headless", action="store_true")
    ap.add_argument("--timeout", type=float, default=60.0)
    args = ap.parse_args()
    tok = solve_turnstile_browser(
        args.sitekey,
        host=args.host,
        action=args.action,
        cdata=args.cdata,
        headless=args.headless,
        timeout=args.timeout,
    )
    print(json.dumps({"token": tok, "len": len(tok)}))
