import random
from typing import Dict, List, Optional, Union

import structlog
from curl_cffi import requests

from utils.fingerprint import create_wb_result
from utils import constants, turnstile, turnstile_scraper
from utils.turnstile_scraper import TurnstileChallenge

logger = structlog.get_logger()


class CfSolver:
    def __init__(self, proxies: Optional[List[str]] = None) -> None:
        self.proxies = proxies

    def _create_session(self) -> requests.Session:
        session = requests.Session(
            impersonate="chrome133a", headers=constants.DEFAULT_HEADERS.copy()
        )
        if self.proxies:
            proxy = "http://" + random.choice(self.proxies)
            session.proxies = {"http": proxy, "https": proxy}
        return session

    def get_solution(self, challenge_url: str) -> Union[bool, str]:
        session = self._create_session()
        challenge_website = challenge_url.split("/cdn-cgi/")[0]
        
        cloudflare_result = session.get(challenge_url)
        cf_ray_id = cloudflare_result.headers["cf-ray"]

        cf_ray_id = cf_ray_id.split("-")[0]


        cfs = cloudflare_result.text

        jsd = cfs.split("/jsd/r/")[1].split(',')[0]

        cloudflare_enc_key = constants.ENC_KEY_RE.search(cfs).group(0)

        challenge_url = (
            f"{challenge_website}/cdn-cgi/challenge-platform/h/b/jsd/r/"
            + jsd
            + cf_ray_id
        )

        wb_result = create_wb_result(
            session.headers["user-agent"],
            cloudflare_enc_key,
            challenge_website
        )

        logger.info(
            "Solving cloudflare challenge.",
            challenge_url=challenge_url[:50] + "...",
            encoded_payload=wb_result[:30] + "..",
        )

        session.headers = constants.CHALLENGE_HEADERS.copy()
        session.headers["origin"] = challenge_website
        response = session.post(challenge_url, data=wb_result)

        if response.status_code == 200:
            logger.info(
                "Cloudflare challenge successfully solved.",
                cf_clearance=session.cookies["cf_clearance"][:50] + "..",
            )
            return session.cookies["cf_clearance"]
        logger.error("Error happened while solving cloudflare.")
        return False

    def collect_turnstile_fingerprint(
        self,
        challenge_website: str,
        *,
        cdp_url: str = "http://localhost:29229",
        roots: Optional[List[Dict[str, str]]] = None,
    ) -> Dict[str, List[str]]:
        """Collect a live env-probe ``fingerprint`` for :meth:`get_turnstile_solution`.

        Runs the recovered ``aM``/``aP``/bucket collector in a real Chromium over CDP
        (see ``utils/turnstile_fingerprint.py``) against ``challenge_website`` and
        returns the bucket map. This replaces hand-authoring the fingerprint (TODO 2):

            fp = solver.collect_turnstile_fingerprint("https://example.com")
            solver.get_turnstile_solution(site, cf_chl_opt, token, fp)

        Requires ``playwright`` and a browser exposing a CDP endpoint at ``cdp_url``.
        """
        from utils import turnstile_fingerprint

        return turnstile_fingerprint.collect_fingerprint(
            challenge_website, cdp_url=cdp_url, roots=roots
        )

    def scrape_turnstile_challenge(
        self,
        sitekey: str,
        page_url: str,
        **kwargs: object,
    ) -> TurnstileChallenge:
        """HTTP-scrape a widget's per-load ``_cf_chl_opt`` tokens + challenge triple (TODO 4).

        Fetches the Turnstile challenge iframe over HTTP (no browser) and returns a
        :class:`~utils.turnstile_scraper.TurnstileChallenge` carrying ``SvTRd8`` /
        ``wKbN9`` / ``TJERQ4``, the ``<num>:<ts>:<token>`` triple, and the ``cf-chl`` /
        ``cf-chl-ra`` headers -- the inputs :meth:`get_turnstile_solution` used to need
        hand-supplied. ``page_url`` is sent as ``Referer`` and must be an origin the
        sitekey is allowlisted for. Extra keyword args pass through to
        :func:`utils.turnstile_scraper.scrape_turnstile_tokens`.
        """
        return turnstile_scraper.scrape_turnstile_tokens(
            sitekey, page_url=page_url, **kwargs
        )

    def solve_turnstile(
        self,
        sitekey: str,
        page_url: str,
        fingerprint: Dict[str, List[str]],
        *,
        challenge: Optional[TurnstileChallenge] = None,
    ) -> Union[bool, str]:
        """End-to-end Turnstile solve: scrape per-load tokens (TODO 4) then submit ``/flow/ov``.

        Wires :meth:`scrape_turnstile_challenge` into :meth:`get_turnstile_solution` so a
        caller only needs the ``sitekey``, the embedding ``page_url``, and a live
        ``fingerprint``. Pass a pre-scraped ``challenge`` to reuse one load. The submit
        target is ``challenges.cloudflare.com`` (where the widget POSTs), not ``page_url``.
        """
        if challenge is None:
            challenge = self.scrape_turnstile_challenge(sitekey, page_url)
        cf_chl_opt, challenge_token, extra_headers = challenge.solution_inputs()
        return self.get_turnstile_solution(
            turnstile_scraper.TURNSTILE_HOST,
            cf_chl_opt,
            challenge_token,
            fingerprint,
            extra_headers=extra_headers,
        )

    def solve_turnstile_browser(
        self,
        sitekey: str,
        *,
        host: str = "www.tickpick.com",
        action: Optional[str] = None,
        cdata: Optional[str] = None,
        headless: bool = False,
        timeout: float = 60.0,
    ) -> str:
        """Return a **valid** ``cf-turnstile-response`` token by running CF's VM in Chrome.

        Invisible Turnstile scores the submission server-side on the live browser
        environment, so the synthetic ``/flow/ov`` body in :meth:`solve_turnstile`
        cannot yield a token that validates. This drives a stealth Chrome via zendriver
        (CDP), renders the widget for ``sitekey`` on ``host`` (the document is injected,
        so the sitekey's hostname check passes), and reads back the issued token. See
        :mod:`utils.turnstile_browser`.
        """
        from utils.turnstile_browser import solve_turnstile_browser

        return solve_turnstile_browser(
            sitekey,
            host=host,
            action=action,
            cdata=cdata,
            headless=headless,
            timeout=timeout,
        )

    def get_turnstile_solution(
        self,
        challenge_website: str,
        cf_chl_opt: Dict[str, str],
        challenge_token: str,
        fingerprint: Dict[str, List[str]],
        *,
        extra_headers: Optional[Dict[str, str]] = None,
    ) -> Union[bool, str]:
        """Turnstile submit pathway, parallel to :meth:`get_solution`.

        Where the JSD path lz-string-encodes the fingerprint and POSTs to ``/jsd/r/``,
        Turnstile serializes -> LZW -> XTEA -> RSA-1024-wraps -> custom-base64-encodes it
        and POSTs to ``/flow/ov`` (see utils/turnstile.py and research/turnstile-vm/). The
        fingerprint model, every crypto primitive, and the byte-exact body builder ``pZ``
        are recovered and verified byte-for-byte (``turnstile.build_flow_ov_body``), so
        this assembles the real request body and submits it.

        The per-load ``cf_chl_opt`` tokens + ``challenge_token`` triple and the VM-set
        ``cf-chl`` / ``cf-chl-ra`` headers (decoded.js:4836) can now be HTTP-scraped via
        :meth:`scrape_turnstile_challenge` -- use :meth:`solve_turnstile` to wire that in
        automatically (TODO 4). A *passing* token additionally needs a live env-probe
        ``fingerprint`` (TODO 2 in utils/turnstile.py) and, because Cloudflare re-obfuscates
        the VM per request, per-load crypto constants (alphabet + ``KJuRf8`` key) that the
        captured ``DEFAULT_CONSTANTS`` will not match for an arbitrary live load.

        Args:
            challenge_website: e.g. ``https://example.com``.
            cf_chl_opt: the page's ``_cf_chl_opt`` (needs ``SvTRd8``/``wKbN9``/``TJERQ4``).
            challenge_token: the per-load ``<num>:<ts>:<token>`` triple embedded in the VM.
            fingerprint: the env-probe bucket map (see TODO 2 in utils/turnstile.py).
            extra_headers: per-load request headers the VM sets on the XHR (e.g.
                ``cf-chl`` / ``cf-chl-ra``), merged onto the challenge headers.

        Returns the ``/flow/ov`` response text on HTTP 200, else ``False``.
        """
        session = self._create_session()
        submit_url = turnstile.build_flow_ov_url(
            challenge_website, cf_chl_opt, challenge_token
        )
        body = turnstile.TurnstileSolver(fingerprint).build_submit_body()

        logger.info(
            "Submitting recovered Turnstile /flow/ov payload.",
            submit_url=submit_url[:50] + "...",
            body=body[:30] + "..",
            body_len=len(body),
        )

        session.headers = constants.CHALLENGE_HEADERS.copy()
        session.headers["origin"] = challenge_website
        if extra_headers:
            session.headers.update(extra_headers)

        response = session.post(submit_url, data=body)
        if response.status_code == 200:
            logger.info(
                "Turnstile challenge submission accepted.",
                status_code=response.status_code,
            )
            return response.text
        logger.error(
            "Error happened while submitting Turnstile challenge.",
            status_code=response.status_code,
        )
        return False


if __name__ == "__main__":
    solver = CfSolver()
    solver.get_solution(
        "https://discord.com/cdn-cgi/challenge-platform/scripts/jsd/main.js"
    )
