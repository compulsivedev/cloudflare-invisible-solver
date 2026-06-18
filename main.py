import random
from typing import Dict, List, Optional, Union

import structlog
from curl_cffi import requests

from utils.fingerprint import create_wb_result
from utils import constants, turnstile

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

        A *passing* token still depends on caller-supplied per-load inputs that cannot be
        recovered statically: a live env-probe ``fingerprint`` (TODO 2 in
        utils/turnstile.py), the page's per-load ``cf_chl_opt`` tokens + ``challenge_token``
        triple (TODO 4), and the VM-set ``cf-chl`` / ``cf-chl-ra`` request headers
        (decoded.js:4836) passed via ``extra_headers``.

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
