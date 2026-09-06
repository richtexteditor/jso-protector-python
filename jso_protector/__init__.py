"""jso-protector — Python client for the JavaScript Obfuscator HTTP API.

Mirrors the protect() function of the npm `jso-protector` CLI. Pure stdlib
(uses urllib + json), no third-party dependency, no network calls at import
time.

Quick start:

    from jso_protector import protect

    result = protect(
        api_key="<base64-from-dashboard>",
        api_password="<base64-from-dashboard>",
        files={"app.js": open("dist/app.js").read()},
        preset="balanced",
        label="ci-build-7f3a",
    )
    for name, code in result.files.items():
        open(f"dist-protected/{name}", "w").write(code)
    print(f"BuildId: {result.build_id}")
    print(f"Fingerprint: {result.polymorphism_fingerprint}")

The wire format is identical to what the npm CLI and VS Code / JetBrains
extensions send, so behavior stays in lockstep across runtimes.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from typing import Dict, List, Mapping, Optional
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

# JSO AI surface — preset_suggest / compat_check / explain_error / usage.
# Importable as `from jso_protector import ai` or `from jso_protector.ai
# import usage`.
from . import ai  # noqa: F401

# Watermarking helpers. Mirror of jso-protector/watermark.js — same
# wire format, so a marker stamped by either client verifies under the
# other. Importable as `from jso_protector import watermark`.
from . import watermark  # noqa: F401

__version__ = "0.1.0"
__all__ = ["protect", "ProtectResult", "ProtectError", "PRESETS"]

DEFAULT_ENDPOINT = "https://javascriptobfuscator.com/HttpApi.ashx"
USER_AGENT = f"jso-protector-python/{__version__}"

PRESETS: Dict[str, Dict[str, bool]] = {
    "standard": {
        "Compress": True,
        "EncodeStrings": True,
        "MoveStringsIntoArray": True,
        "NameMangling": True,
    },
    "balanced": {
        "Compress": True,
        "EncodeStrings": True,
        "EncryptStrings": True,
        "MoveStringsIntoArray": True,
        "NameMangling": True,
        "DeepObfuscate": True,
        "FlatTransform": True,
        "CodeTransposition": True,
    },
    "maximum": {
        "Compress": True,
        "EncodeStrings": True,
        "EncryptStrings": True,
        "MoveStringsIntoArray": True,
        "NameMangling": True,
        "DeepObfuscate": True,
        "FlatTransform": True,
        "CodeTransposition": True,
        "ProtectMembers": True,
        "RenameGlobals": True,
        "MoveMembers": True,
        "DeadCodeInsertion": True,
    },
}


class ProtectError(RuntimeError):
    """Raised when the JSO API rejects a request or the response is malformed.

    The error message is safe to log: API key / password values are never
    interpolated into it.
    """

    def __init__(self, message: str, *, type_: Optional[str] = None, error_code: Optional[str] = None):
        super().__init__(message)
        self.type = type_
        self.error_code = error_code


@dataclass
class ProtectResult:
    """Outcome of a successful protect() call."""

    #: Map of {filename: protected_source}. Keys match the input filenames.
    files: Dict[str, str] = field(default_factory=dict)
    #: Stable identifier for this protection run. Inject as a global into
    #: your runtime so crash reports carry the matching BuildId.
    build_id: Optional[str] = None
    #: Short SHA-256-derived fingerprint over the protected output. Two
    #: consecutive obfuscations of identical input MUST produce different
    #: fingerprints when polymorphism is engaged.
    polymorphism_fingerprint: Optional[str] = None
    #: The full Report object from the API response: BuildId, identifier
    #: maps, enabled options, compatibility findings, release metadata.
    report: Dict = field(default_factory=dict)
    #: The full raw response body. Use when you need fields not surfaced
    #: on this dataclass yet.
    raw: Dict = field(default_factory=dict)


def protect(
    *,
    api_key: Optional[str] = None,
    api_password: Optional[str] = None,
    files: Mapping[str, str],
    preset: str = "balanced",
    options: Optional[Mapping[str, object]] = None,
    label: Optional[str] = None,
    project_name: str = "python-session",
    endpoint: Optional[str] = None,
    timeout_seconds: float = 180.0,
) -> ProtectResult:
    """Send JavaScript files to JSO and return the protected output.

    Args:
        api_key: Base64 API key from the JSO dashboard. Falls back to the
            JSO_API_KEY / JAVASCRIPT_OBFUSCATOR_API_KEY environment variable.
        api_password: Base64 API password from the dashboard. Falls back to
            the JSO_API_PASSWORD / JAVASCRIPT_OBFUSCATOR_API_PASSWORD env
            variable.
        files: Map of {filename: source_text}. At least one entry required.
        preset: One of "standard", "balanced", "maximum" — see PRESETS.
        options: Optional dict of additional HTTP API options that override
            or extend the preset. Use snake/Pascal keys exactly as the API
            documents them (e.g. {"LockDate": True, "LockDomain": True}).
        label: Optional release label tagged on the request as
            ReleaseLabel. Use the commit SHA for CI runs.
        project_name: Audit-log project name. Default "python-session".
        endpoint: Override the API endpoint URL. Default is the production
            HttpApi.ashx URL; override only for staging or self-hosted.
        timeout_seconds: HTTP request timeout. Default 180s (3 minutes) —
            generous enough for large multi-file projects.

    Returns:
        ProtectResult with the protected files plus BuildId / fingerprint /
        full Report.

    Raises:
        ProtectError: If the API returns a non-Succeed Type, the response
            is malformed JSON, or the HTTP connection fails. The error
            message never contains the API key or password.
    """
    resolved_key = _resolve(api_key, "JSO_API_KEY", "JAVASCRIPT_OBFUSCATOR_API_KEY")
    resolved_pwd = _resolve(api_password, "JSO_API_PASSWORD", "JAVASCRIPT_OBFUSCATOR_API_PASSWORD")
    if not resolved_key or not resolved_pwd:
        raise ProtectError(
            "JSO API credentials not configured. Pass api_key/api_password "
            "or export JSO_API_KEY / JSO_API_PASSWORD."
        )

    if not files:
        raise ProtectError("At least one file is required.")

    preset_name = preset.lower()
    if preset_name not in PRESETS:
        raise ProtectError(
            f"Unknown preset {preset!r}. Pick one of {sorted(PRESETS)}."
        )

    payload: Dict[str, object] = {
        "APIKey": resolved_key,
        "APIPwd": resolved_pwd,
        "Name": project_name,
        "Items": [
            {"FileName": name, "FileCode": code}
            for name, code in files.items()
        ],
    }
    if label:
        payload["ReleaseLabel"] = label
    # Preset first, explicit options override.
    for k, v in PRESETS[preset_name].items():
        payload[k] = v
    if options:
        for k, v in options.items():
            payload[k] = v

    body = json.dumps(payload).encode("utf-8")
    url = endpoint or DEFAULT_ENDPOINT
    req = Request(
        url,
        data=body,
        headers={
            "Content-Type": "text/json",
            "Content-Length": str(len(body)),
            "User-Agent": USER_AGENT,
        },
        method="POST",
    )

    try:
        with urlopen(req, timeout=timeout_seconds) as resp:
            text = resp.read().decode("utf-8", errors="replace")
    except HTTPError as e:
        # Truncate the error body so we never echo back leaked credentials
        # if the server foolishly mirrored them.
        snippet = e.read().decode("utf-8", errors="replace")[:200] if hasattr(e, "read") else str(e)
        raise ProtectError(f"HTTP {e.code}: {snippet}") from None
    except URLError as e:
        raise ProtectError(f"Connection failed: {e.reason}") from None

    try:
        parsed = json.loads(text)
    except json.JSONDecodeError as e:
        raise ProtectError(f"Malformed JSON in response: {e.msg}") from None

    type_ = parsed.get("Type")
    if type_ != "Succeed":
        msg = parsed.get("Message") or parsed.get("ErrorCode") or "API request failed"
        raise ProtectError(msg, type_=type_, error_code=parsed.get("ErrorCode"))

    items = parsed.get("Items") or []
    protected: Dict[str, str] = {}
    for item in items:
        name = item.get("FileName")
        code = item.get("FileCode")
        if name and isinstance(code, str):
            protected[name] = code
    if not protected:
        raise ProtectError("API response did not include any protected files.")

    report = parsed.get("Report") or {}
    return ProtectResult(
        files=protected,
        build_id=report.get("BuildId"),
        polymorphism_fingerprint=report.get("PolymorphismFingerprint"),
        report=report,
        raw=parsed,
    )


def _resolve(arg: Optional[str], *env_var_names: str) -> Optional[str]:
    if arg and arg.strip():
        return arg.strip()
    for name in env_var_names:
        v = os.environ.get(name)
        if v and v.strip():
            return v.strip()
    return None
