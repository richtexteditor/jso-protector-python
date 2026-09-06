"""
JSO AI client. Wraps the four /v1/ai/* endpoints documented at
https://javascriptobfuscator.com/docs/aiapi.aspx

Same auth model as the protect API: api_key + api_password (base64
values from the dashboard). Reads JSO_API_KEY / JSO_API_PASSWORD from
the environment if not passed explicitly, matching the protect()
function's behavior in the rest of this package.

Standard library only, no new dependencies.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from typing import Any, Dict, Mapping, Optional
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


DEFAULT_ENDPOINT = "https://javascriptobfuscator.com"
DEFAULT_TIMEOUT  = 30.0   # seconds


class AiError(RuntimeError):
    """Raised on transport-level failures (HTTP 4xx/5xx, network, missing creds).

    Carries an error code in `.code` for the auth_missing / input_invalid /
    bad_payload cases, and an optional `.status` + `.body` for HTTP errors.
    Business-logic failures (the server responded ok=false at HTTP 200)
    do NOT raise — they come back as a normal dict so the caller can
    branch on `result["ok"]`.
    """

    def __init__(self, message: str, *, code: str = "internal_error",
                 status: Optional[int] = None, body: Any = None):
        super().__init__(message)
        self.code = code
        self.status = status
        self.body = body


# ---------- internal helpers ----------------------------------------------

def _resolve_credentials(api_key: Optional[str], api_password: Optional[str]) -> Mapping[str, str]:
    key = (api_key or os.environ.get("JSO_API_KEY") or "").strip()
    pwd = (api_password or os.environ.get("JSO_API_PASSWORD") or "").strip()
    if not key or not pwd:
        raise AiError(
            "JSO AI: api_key / api_password required. Pass them as "
            "arguments or set JSO_API_KEY / JSO_API_PASSWORD environment "
            "variables.",
            code="auth_missing")
    return {"APIKey": key, "APIPwd": pwd}


def _resolve_endpoint(endpoint: Optional[str]) -> str:
    base = (endpoint or os.environ.get("JSO_BASE_URL") or DEFAULT_ENDPOINT)
    return base.rstrip("/")


def _post_json(url: str, body: Mapping[str, Any], timeout: float) -> Dict[str, Any]:
    payload = json.dumps(body).encode("utf-8")
    req = Request(
        url,
        data=payload,
        method="POST",
        headers={
            "Content-Type":   "application/json",
            "Content-Length": str(len(payload)),
            "User-Agent":     "jso-protector-python/ai",
        },
    )
    try:
        with urlopen(req, timeout=timeout) as resp:
            text = resp.read().decode("utf-8")
    except HTTPError as e:
        try:
            error_body = json.loads(e.read().decode("utf-8"))
        except Exception:
            error_body = None
        raise AiError(
            f"HTTP {e.code} from {url}",
            code="http_error",
            status=e.code,
            body=error_body,
        ) from None
    except URLError as e:
        raise AiError(f"Network error contacting {url}: {e.reason}",
                      code="network_error") from None

    try:
        return json.loads(text)
    except json.JSONDecodeError as e:
        raise AiError(f"Non-JSON response from {url}: {e}",
                      code="bad_payload") from None


def _build_body(creds: Mapping[str, str], **extra: Any) -> Dict[str, Any]:
    body: Dict[str, Any] = dict(creds)
    for k, v in extra.items():
        if v is not None:
            body[k] = v
    return body


# ---------- public surface ------------------------------------------------

def usage(*, api_key: Optional[str] = None, api_password: Optional[str] = None,
          endpoint: Optional[str] = None, timeout: float = DEFAULT_TIMEOUT) -> Dict[str, Any]:
    """Read the current-month AI quota counters for this account.

    Free to poll (this endpoint does not count against actionsCap).

        >>> u = ai.usage()
        >>> if u["actionsRemaining"] < 5: print("quota low")
    """
    creds = _resolve_credentials(api_key, api_password)
    return _post_json(
        _resolve_endpoint(endpoint) + "/v1/ai/usage.ashx",
        _build_body(creds),
        timeout)


def preset_suggest(description: str, *,
                   api_key: Optional[str] = None, api_password: Optional[str] = None,
                   endpoint: Optional[str] = None, timeout: float = DEFAULT_TIMEOUT) -> Dict[str, Any]:
    """Ask the preset assistant to suggest a jso.config from a description.

        >>> r = ai.preset_suggest("React SaaS, balanced, lock to example.com")
        >>> json.dump(r["suggestion"]["config"], open("jso.config.json", "w"), indent=2)
    """
    if not description:
        raise AiError("preset_suggest: 'description' is required", code="input_invalid")
    creds = _resolve_credentials(api_key, api_password)
    return _post_json(
        _resolve_endpoint(endpoint) + "/v1/ai/preset-suggest.ashx",
        _build_body(creds, description=description),
        timeout)


def compat_check(source: str, *, framework: Optional[str] = None,
                 api_key: Optional[str] = None, api_password: Optional[str] = None,
                 endpoint: Optional[str] = None, timeout: float = DEFAULT_TIMEOUT) -> Dict[str, Any]:
    """Scan a JS source string for obfuscation-unfriendly patterns.

        >>> r = ai.compat_check(open("src/app.js").read(), framework="react")
        >>> if r["report"]["summary"]["errors"] > 0: sys.exit(1)
    """
    if not source:
        raise AiError("compat_check: 'source' is required", code="input_invalid")
    creds = _resolve_credentials(api_key, api_password)
    return _post_json(
        _resolve_endpoint(endpoint) + "/v1/ai/compat-check.ashx",
        _build_body(creds, source=source, framework=framework),
        timeout)


def explain_error(error: str, *, config: Optional[str] = None,
                  api_key: Optional[str] = None, api_password: Optional[str] = None,
                  endpoint: Optional[str] = None, timeout: float = DEFAULT_TIMEOUT) -> Dict[str, Any]:
    """Diagnose a protected-output runtime error.

        >>> r = ai.explain_error("Uncaught TypeError: api.charge is not a function")
        >>> print(r["explanation"]["transform"], "->", r["explanation"]["fix"])
    """
    if not error:
        raise AiError("explain_error: 'error' is required", code="input_invalid")
    creds = _resolve_credentials(api_key, api_password)
    return _post_json(
        _resolve_endpoint(endpoint) + "/v1/ai/explain-error.ashx",
        _build_body(creds, error=error, config=config),
        timeout)


__all__ = ["AiError", "usage", "preset_suggest", "compat_check", "explain_error"]
