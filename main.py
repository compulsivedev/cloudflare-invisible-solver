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

    def get_turnstile_solution(
        self,
        challenge_website: str,
        cf_chl_opt: Dict[str, str],
        challenge_token: str,
        fingerprint: Dict[str, List[str]],
    ) -> Union[bool, str]:
        """Turnstile submit pathway (SCAFFOLD), parallel to :meth:`get_solution`.

        Where the JSD path lz-string-encodes the fingerprint and POSTs to ``/jsd/r/``,
        Turnstile hashes + RSA-wraps + custom-base64-encodes it and POSTs to ``/flow/ov``
        (see utils/turnstile.py and research/turnstile-vm/). The fingerprint model and
        every crypto primitive are recovered and verified, but the byte-exact request
        *body* is assembled by the VM's JSVMP bytecode, so this cannot produce a passing
        token from static recovery alone -- it wires what is recovered and marks the gap.

        Args:
            challenge_website: e.g. ``https://example.com``.
            cf_chl_opt: the page's ``_cf_chl_opt`` (needs ``SvTRd8``/``wKbN9``/``TJERQ4``).
            challenge_token: the per-load ``<num>:<ts>:<token>`` triple embedded in the VM.
            fingerprint: the env-probe bucket map (see TODO 2 in utils/turnstile.py).
        """
        submit_url = turnstile.build_flow_ov_url(
            challenge_website, cf_chl_opt, challenge_token
        )
        recovered = turnstile.TurnstileSolver(fingerprint).build_submit_body()

        logger.info(
            "Assembled recovered Turnstile payload pieces.",
            submit_url=submit_url[:50] + "...",
            hash=recovered["hash"][:16] + "..",
        )

        # TODO(dynamic): the exact /flow/ov request body (field names/order + the
        # symmetric encryption of the fingerprint/telemetry blob) is produced by the
        # JSVMP bytecode interpreter and is not recovered statically. Lifting/executing
        # that bytecode is required before this POST can yield a passing token.
        raise NotImplementedError(
            "Turnstile /flow/ov body assembly is JSVMP-driven; see TODOs in "
            "utils/turnstile.py and research/turnstile-vm/TURNSTILE-ALGORITHM-RECOVERY.md"
        )


if __name__ == "__main__":
    solver = CfSolver()
    solver.get_solution(
        "https://discord.com/cdn-cgi/challenge-platform/scripts/jsd/main.js"
    )
