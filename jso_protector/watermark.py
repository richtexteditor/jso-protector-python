"""
Watermarking for jso-protector (Python).

Mirror of packages/jso-protector/watermark.js so an artifact signed
by either client verifies under the other. The header-comment format
is identical:

    /*! __jso_watermark_v1
     * tag: <base64url>
     * sig: <base64url HMAC-SHA256(tag, key)>
     */

The goal is letting Python customers either:

    - prepend a watermark to source before sending it to the JSO
      obfuscation API (the obfuscator's KeepComment option preserves
      the block through every transform); or

    - verify a protected file produced by any pipeline (Node, Python,
      shell + curl) by checking the embedded HMAC.

Standard library only — uses hmac + hashlib + base64. No third-party
dependency, matching the rest of jso-protector-python's "pure stdlib"
promise.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import re
from typing import Optional, NamedTuple


MARKER = "__jso_watermark_v1"

# The regex must match the format buildHeader() produces in BOTH
# clients. Keep this in sync with watermark.js MARKER_RE.
_MARKER_RE = re.compile(
    r"/\*!?\s*__jso_watermark_v1\s+"
    r"\*\s*tag:\s*([A-Za-z0-9_-]+)\s+"
    r"\*\s*sig:\s*([A-Za-z0-9_-]+)\s*"
    r"\*/"
)


def _b64url(data: bytes) -> str:
    """Encode bytes as base64url (no padding)."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64url_decode(s: str) -> bytes:
    """Decode base64url, tolerant of missing padding."""
    s = s.encode("ascii") if isinstance(s, str) else s
    pad = (-len(s)) % 4
    return base64.urlsafe_b64decode(s + b"=" * pad)


def sign_tag(tag: str, key: str) -> str:
    """Return the canonical base64url HMAC-SHA256(tag, key).

    Both arguments are required; raises ValueError on missing inputs.
    The tag is UTF-8 encoded before signing, matching watermark.js so
    cross-language verification works on non-ASCII tags.
    """
    if not tag:
        raise ValueError("watermark: tag is required")
    if not key:
        raise ValueError("watermark: key is required")
    digest = hmac.new(
        key.encode("utf-8") if isinstance(key, str) else key,
        tag.encode("utf-8") if isinstance(tag, str) else tag,
        hashlib.sha256,
    ).digest()
    return _b64url(digest)


def build_header(tag: str, key: str) -> str:
    """Build the header-comment block. Caller prepends to source."""
    tag_b64 = _b64url((tag if isinstance(tag, str) else str(tag)).encode("utf-8"))
    sig_b64 = sign_tag(tag, key)
    return (
        "/*! " + MARKER + "\n"
        " * tag: " + tag_b64 + "\n"
        " * sig: " + sig_b64 + "\n"
        " */\n"
    )


def inject_into(source: str, tag: str, key: str) -> str:
    """Return source with a watermark header prepended.

    The block goes at byte zero. Use-strict directives that follow on
    line 1 still apply: comments are part of the directive prologue
    rules and don't break "use strict" hoisting.
    """
    return build_header(tag, key) + (source or "")


class VerifyResult(NamedTuple):
    """Result of verify(). Mirrors the JS module's return shape.

    Attributes:
        present:  True iff the marker block was found at all.
        tag:      The decoded tag string (empty if marker missing).
        sig:      The embedded base64url signature.
        valid:    True iff HMAC(tag, key) matches sig (constant time).
                  Always False when present=False or key=None.
        error:    Human-readable failure reason, or "".
    """
    present: bool
    tag: str
    sig: str
    valid: bool
    error: str


def verify(protected_source: str, key: Optional[str] = None) -> VerifyResult:
    """Scan a protected source string for the watermark marker.

    When ``key`` is supplied, runs a constant-time HMAC compare to
    confirm the signature was produced with that key. When ``key`` is
    None, returns the parsed tag without validating (lookup-only mode
    for forensic / inventory tooling).
    """
    if protected_source is None:
        protected_source = ""
    m = _MARKER_RE.search(protected_source)
    if not m:
        return VerifyResult(
            present=False, tag="", sig="", valid=False,
            error="watermark: marker not found in input",
        )
    tag_b64, sig_b64 = m.group(1), m.group(2)
    try:
        tag = _b64url_decode(tag_b64).decode("utf-8")
    except (UnicodeDecodeError, ValueError) as e:
        return VerifyResult(
            present=True, tag="", sig=sig_b64, valid=False,
            error="watermark: tag is not valid base64url utf-8 ({})".format(e),
        )

    if not key:
        # Lookup-only: return the tag, don't validate.
        return VerifyResult(present=True, tag=tag, sig=sig_b64, valid=False, error="")

    expected = sign_tag(tag, key)
    # hmac.compare_digest is the canonical constant-time string
    # compare in Python stdlib. Use it defensively even though we're
    # comparing base64url strings of fixed length (HMAC-SHA256 -> 43
    # chars after base64url-no-padding).
    valid = hmac.compare_digest(expected, sig_b64)
    return VerifyResult(present=True, tag=tag, sig=sig_b64, valid=valid, error="")


__all__ = [
    "MARKER",
    "sign_tag",
    "build_header",
    "inject_into",
    "verify",
    "VerifyResult",
]
