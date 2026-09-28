"""
JOCKY Remote Agent.

Runs on a target endpoint. Polls the central API for pending jobs,
executes JOCKY scripts locally, and submits results back.

Usage:
    python -m jocky.agent \
        --api-url http://127.0.0.1:8000 \
        --agent-id YOUR_AGENT_ID \
        --agent-token YOUR_AGENT_TOKEN

Or via environment variables:
    JOCKY_API_URL, JOCKY_AGENT_ID, JOCKY_AGENT_TOKEN, JOCKY_POLL_INTERVAL

Security notes:
  - Agent token is never logged
  - Scripts go through the full lexer/parser/interpreter pipeline
    with all existing safety limits (variable cap, nesting cap, allowlist)
  - Connection errors use exponential backoff up to _MAX_BACKOFF seconds
  - TLS verification is enabled by default — set JOCKY_TLS_VERIFY=false
    only in controlled dev environments
"""

import argparse
import logging
import os
import sys
import time
from datetime import datetime, timezone
from typing import Optional

import requests
from dotenv import load_dotenv

load_dotenv()

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [JOCKY-AGENT] %(levelname)s %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger(__name__)

_DEFAULT_POLL_INTERVAL = 10   # seconds between polls when idle
_MAX_BACKOFF           = 120  # ceiling for exponential backoff


# ── Script execution ───────────────────────────────────────────────────────────

def _execute_script(script: str) -> dict:
    """
    Run a JOCKY script through the full pipeline and return a
    serialisable result dict suitable for submission to the API.
    """
    from jocky.language.lexer import tokenize
    from jocky.language.parser import parse
    from jocky.language.interpreter import run_investigation

    tokens = tokenize(script)
    investigation = parse(tokens)

    started_at  = datetime.now(timezone.utc)
    result      = run_investigation(investigation)
    finished_at = datetime.now(timezone.utc)

    return {
        "collector_results": [
            {
                "target": cr.target,
                "status": cr.status,
                "data":   cr.data,
                "error":  cr.error,
            }
            for cr in result.collector_results
        ],
        "findings": [
            {
                "rule_name":        f.rule_name,
                "severity":         f.severity,
                "summary":          f.summary,
                "reason":           f.reason,
                "related_evidence": f.related_evidence,
            }
            for f in result.findings
        ],
        "report_name": result.report_name,
        "started_at":  started_at.isoformat(),
        "finished_at": finished_at.isoformat(),
    }


# ── Agent class ────────────────────────────────────────────────────────────────

class JockyAgent:
    def __init__(
        self,
        api_url:       str,
        agent_id:      str,
        agent_token:   str,
        poll_interval: int  = _DEFAULT_POLL_INTERVAL,
        tls_verify:    bool = True,
    ) -> None:
        self.api_url       = api_url.rstrip("/")
        self.agent_id      = agent_id
        self.poll_interval = poll_interval

        self._session = requests.Session()
        self._session.headers.update({
            "Authorization": f"Bearer {agent_token}",
            "Content-Type":  "application/json",
        })
        self._session.verify = tls_verify

    def _url(self, path: str) -> str:
        return f"{self.api_url}{path}"

    def _poll(self) -> Optional[dict]:
        resp = self._session.get(
            self._url(f"/api/agents/{self.agent_id}/jobs/pending"),
            timeout=10,
        )
        resp.raise_for_status()
        data = resp.json()
        return data if data.get("job_id") else None

    def _submit_result(self, job_id: str, result: dict) -> None:
        resp = self._session.post(
            self._url(f"/api/agents/{self.agent_id}/jobs/{job_id}/result"),
            json=result,
            timeout=30,
        )
        resp.raise_for_status()

    def _submit_error(self, job_id: str, error: str) -> None:
        resp = self._session.post(
            self._url(f"/api/agents/{self.agent_id}/jobs/{job_id}/error"),
            json={"error": error},
            timeout=10,
        )
        resp.raise_for_status()

    def _heartbeat(self) -> None:
        try:
            self._session.post(
                self._url(f"/api/agents/{self.agent_id}/heartbeat"),
                timeout=5,
            )
        except Exception:
            pass  # heartbeat failure is non-fatal

    # ── Main loop ──────────────────────────────────────────────────────────────

    def run(self) -> None:
        log.info(
            "Agent started. API: %s  ID: %s  Poll interval: %ds",
            self.api_url, self.agent_id, self.poll_interval,
        )
        backoff = self.poll_interval

        while True:
            try:
                job = self._poll()

                if job is None:
                    log.debug("No pending job. Sleeping %ds.", backoff)
                    time.sleep(backoff)
                    backoff = self.poll_interval  # reset after successful poll
                    continue

                job_id = job["job_id"]
                script = job["script"]
                log.info("Job claimed: %s — executing investigation...", job_id)

                try:
                    result = _execute_script(script)
                    findings_count = len(result.get("findings", []))
                    log.info(
                        "Job %s complete — %d finding(s). Submitting...",
                        job_id, findings_count,
                    )
                    self._submit_result(job_id, result)
                    log.info("Job %s accepted by API.", job_id)
                except Exception as exc:
                    log.error("Job %s execution failed: %s", job_id, exc)
                    self._submit_error(job_id, str(exc))

                backoff = self.poll_interval

            except KeyboardInterrupt:
                log.info("Shutdown requested. Exiting.")
                break
            except requests.exceptions.ConnectionError:
                log.warning(
                    "Cannot reach API at %s. Retrying in %ds.",
                    self.api_url, backoff,
                )
                time.sleep(backoff)
                backoff = min(backoff * 2, _MAX_BACKOFF)
            except requests.exceptions.HTTPError as exc:
                log.error("HTTP error: %s. Retrying in %ds.", exc, backoff)
                time.sleep(backoff)
                backoff = min(backoff * 2, _MAX_BACKOFF)
            except Exception as exc:
                log.error("Unexpected error: %s. Retrying in %ds.", exc, backoff)
                time.sleep(backoff)
                backoff = min(backoff * 2, _MAX_BACKOFF)


# ── Entry point ────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(description="JOCKY Remote Agent")
    parser.add_argument(
        "--api-url",
        default=os.environ.get("JOCKY_API_URL", ""),
        help="Central API URL (env: JOCKY_API_URL)",
    )
    parser.add_argument(
        "--agent-id",
        default=os.environ.get("JOCKY_AGENT_ID", ""),
        help="Agent ID from registration (env: JOCKY_AGENT_ID)",
    )
    parser.add_argument(
        "--agent-token",
        default=os.environ.get("JOCKY_AGENT_TOKEN", ""),
        help="Agent token from registration (env: JOCKY_AGENT_TOKEN)",
    )
    parser.add_argument(
        "--poll-interval",
        type=int,
        default=int(os.environ.get("JOCKY_POLL_INTERVAL", str(_DEFAULT_POLL_INTERVAL))),
        help=f"Poll interval in seconds (env: JOCKY_POLL_INTERVAL, default: {_DEFAULT_POLL_INTERVAL})",
    )
    parser.add_argument(
        "--no-tls-verify",
        action="store_true",
        default=os.environ.get("JOCKY_TLS_VERIFY", "true").lower() == "false",
        help="Disable TLS certificate verification (dev only)",
    )
    args = parser.parse_args()

    missing = [
        label for label, val in [
            ("--api-url / JOCKY_API_URL",       args.api_url),
            ("--agent-id / JOCKY_AGENT_ID",     args.agent_id),
            ("--agent-token / JOCKY_AGENT_TOKEN", args.agent_token),
        ]
        if not val.strip()
    ]
    if missing:
        print("Error: required arguments not set:")
        for m in missing:
            print(f"  {m}")
        sys.exit(1)

    if args.no_tls_verify:
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        log.warning("TLS verification disabled — dev/test use only.")

    JockyAgent(
        api_url       = args.api_url,
        agent_id      = args.agent_id,
        agent_token   = args.agent_token,
        poll_interval = args.poll_interval,
        tls_verify    = not args.no_tls_verify,
    ).run()


if __name__ == "__main__":
    main()