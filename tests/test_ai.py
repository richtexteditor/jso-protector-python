"""
Tests for jso_protector.ai.

Stands up a tiny mock HTTP server with http.server, points the ai module
at it via the `endpoint` argument, then asserts the request body shape
and how each function unpacks the response envelope.
"""

from __future__ import annotations

import json
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Any, Dict, Optional

from jso_protector import ai


class _MockState:
    """Captured request + the next response to send back."""

    def __init__(self) -> None:
        self.captured_path: Optional[str] = None
        self.captured_body: Optional[Dict[str, Any]] = None
        self.captured_user_agent: Optional[str] = None
        self.response_status: int = 200
        self.response_body: Dict[str, Any] = {}


def _make_handler(state: _MockState):
    class Handler(BaseHTTPRequestHandler):
        def do_POST(self) -> None:    # noqa: N802
            length = int(self.headers.get("Content-Length", "0"))
            raw = self.rfile.read(length).decode("utf-8") if length else ""
            try:
                state.captured_body = json.loads(raw) if raw else None
            except json.JSONDecodeError:
                state.captured_body = None
            state.captured_path = self.path
            state.captured_user_agent = self.headers.get("User-Agent")
            body = json.dumps(state.response_body).encode("utf-8")
            self.send_response(state.response_status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        # Suppress access-log noise during test runs.
        def log_message(self, *args, **kwargs) -> None:    # noqa: N802
            pass

    return Handler


def _start_mock(state: _MockState) -> HTTPServer:
    server = HTTPServer(("127.0.0.1", 0), _make_handler(state))
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    return server


class AiClientTests(unittest.TestCase):

    def setUp(self) -> None:
        self.state = _MockState()
        self.server = _start_mock(self.state)
        host, port = self.server.server_address
        self.endpoint = f"http://{host}:{port}"

    def tearDown(self) -> None:
        self.server.shutdown()
        self.server.server_close()

    # -- usage ---------------------------------------------------------------

    def test_usage_sends_credentials_and_parses_envelope(self) -> None:
        self.state.response_body = {
            "ok": True, "previewMode": True,
            "tier": "FreeTrial", "billingMonth": "2026-05-01",
            "actionsUsed": 0, "actionsCap": 10, "actionsRemaining": 10,
            "tokensUsed": 0, "tokensCap": 0, "tokensRemaining": 0,
            "approxCostCents": 0, "costCapCents": 200, "costRemainingCents": 200,
            "quotaRejections": 0, "asOfUtc": "2026-05-26T00:00:00Z",
        }
        r = ai.usage(api_key="k1", api_password="p1", endpoint=self.endpoint)
        self.assertEqual(self.state.captured_path, "/v1/ai/usage.ashx")
        self.assertEqual(self.state.captured_body, {"APIKey": "k1", "APIPwd": "p1"})
        self.assertTrue(r["ok"])
        self.assertEqual(r["tier"], "FreeTrial")
        self.assertEqual(r["actionsRemaining"], 10)

    # -- preset_suggest ------------------------------------------------------

    def test_preset_suggest_sends_description(self) -> None:
        self.state.response_body = {
            "ok": True, "previewMode": True, "provider": "rule-based",
            "tokensIn": 0, "tokensOut": 0,
            "suggestion": {
                "previewMode": True, "source": "rule-based",
                "config": {"preset": "balanced"},
                "signals": ["sig a", "sig b"],
            },
        }
        r = ai.preset_suggest("React SaaS, balanced",
                              api_key="k", api_password="p", endpoint=self.endpoint)
        self.assertEqual(self.state.captured_body["description"], "React SaaS, balanced")
        self.assertEqual(r["suggestion"]["config"]["preset"], "balanced")
        self.assertEqual(len(r["suggestion"]["signals"]), 2)

    def test_preset_suggest_empty_description_raises_input_invalid(self) -> None:
        with self.assertRaises(ai.AiError) as ctx:
            ai.preset_suggest("", api_key="k", api_password="p", endpoint=self.endpoint)
        self.assertEqual(ctx.exception.code, "input_invalid")

    # -- compat_check --------------------------------------------------------

    def test_compat_check_sends_source_and_framework(self) -> None:
        self.state.response_body = {
            "ok": True, "previewMode": True, "provider": "rule-based",
            "tokensIn": 0, "tokensOut": 0,
            "report": {
                "previewMode": True, "source": "rule-based",
                "summary": {"errors": 1, "warnings": 0, "infos": 0},
                "findings": [
                    {"category": "dynamic-eval", "severity": "error",
                     "line": 1, "column": 1, "message": "eval", "suggestedFix": "fix"},
                ],
            },
        }
        r = ai.compat_check("eval('x');", framework="react",
                            api_key="k", api_password="p", endpoint=self.endpoint)
        self.assertEqual(self.state.captured_body["source"], "eval('x');")
        self.assertEqual(self.state.captured_body["framework"], "react")
        self.assertEqual(r["report"]["summary"]["errors"], 1)

    def test_compat_check_omits_framework_when_none(self) -> None:
        self.state.response_body = {"ok": True, "report": {"summary": {"errors": 0, "warnings": 0, "infos": 0}, "findings": []}}
        ai.compat_check("x = 1;", api_key="k", api_password="p", endpoint=self.endpoint)
        # framework field absent from request when not provided.
        self.assertNotIn("framework", self.state.captured_body)

    # -- explain_error -------------------------------------------------------

    def test_explain_error_sends_error_and_unpacks(self) -> None:
        self.state.response_body = {
            "ok": True, "previewMode": True, "provider": "rule-based",
            "tokensIn": 0, "tokensOut": 0,
            "explanation": {
                "previewMode": True, "source": "rule-based",
                "cause": "name-mangling", "transform": "Name Mangling",
                "confidence": "high", "explanation": "x", "fix": "y",
                "docsUrl": "/Docs/VariableExclusionList.aspx",
            },
        }
        r = ai.explain_error("Uncaught TypeError",
                             api_key="k", api_password="p", endpoint=self.endpoint)
        self.assertEqual(self.state.captured_body["error"], "Uncaught TypeError")
        self.assertEqual(r["explanation"]["cause"], "name-mangling")
        self.assertEqual(r["explanation"]["confidence"], "high")

    # -- auth + env-var fallback --------------------------------------------

    def test_auth_missing_raises_when_no_env_and_no_args(self) -> None:
        import os
        saved = {k: os.environ.pop(k, None) for k in ("JSO_API_KEY", "JSO_API_PASSWORD")}
        try:
            with self.assertRaises(ai.AiError) as ctx:
                ai.usage(endpoint=self.endpoint)
            self.assertEqual(ctx.exception.code, "auth_missing")
        finally:
            for k, v in saved.items():
                if v is not None:
                    os.environ[k] = v

    def test_env_var_fallback_picks_up_credentials(self) -> None:
        import os
        self.state.response_body = {"ok": True, "tier": "FreeTrial"}
        saved = {k: os.environ.get(k) for k in ("JSO_API_KEY", "JSO_API_PASSWORD")}
        try:
            os.environ["JSO_API_KEY"]      = "envkey"
            os.environ["JSO_API_PASSWORD"] = "envpwd"
            ai.usage(endpoint=self.endpoint)
            self.assertEqual(self.state.captured_body["APIKey"], "envkey")
            self.assertEqual(self.state.captured_body["APIPwd"], "envpwd")
        finally:
            for k, v in saved.items():
                if v is None: os.environ.pop(k, None)
                else: os.environ[k] = v

    # -- error paths --------------------------------------------------------

    def test_http_4xx_raises_aierror_with_status_and_body(self) -> None:
        self.state.response_status = 429
        self.state.response_body   = {"ok": False, "error": "rate_limited", "message": "Retry after 30s."}
        with self.assertRaises(ai.AiError) as ctx:
            ai.usage(api_key="k", api_password="p", endpoint=self.endpoint)
        self.assertEqual(ctx.exception.code, "http_error")
        self.assertEqual(ctx.exception.status, 429)
        self.assertEqual(ctx.exception.body["error"], "rate_limited")

    def test_business_logic_ok_false_returns_normal_dict(self) -> None:
        self.state.response_status = 200
        self.state.response_body   = {"ok": False, "error": "auth_failed", "message": "Bad APIKey."}
        r = ai.usage(api_key="bad", api_password="bad", endpoint=self.endpoint)
        self.assertFalse(r["ok"])
        self.assertEqual(r["error"], "auth_failed")

    # -- User-Agent ---------------------------------------------------------

    def test_user_agent_advertises_package(self) -> None:
        self.state.response_body = {"ok": True}
        ai.usage(api_key="k", api_password="p", endpoint=self.endpoint)
        self.assertIn("jso-protector-python/ai", self.state.captured_user_agent or "")


if __name__ == "__main__":
    unittest.main()
