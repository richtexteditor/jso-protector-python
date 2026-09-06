"""Tests for jso_protector.protect — mocks the HTTP layer via urllib monkeypatch.

Run with: python -m unittest discover -s tests -p 'test_*.py'
"""

import json
import unittest
from unittest.mock import patch, MagicMock

from jso_protector import PRESETS, ProtectError, protect


class _FakeResponse:
    """Minimal context-manager stand-in for urllib.request.urlopen()."""

    def __init__(self, body: bytes, status: int = 200):
        self._body = body
        self.status = status

    def read(self):
        return self._body

    def __enter__(self):
        return self

    def __exit__(self, *_):
        return False


class ProtectTests(unittest.TestCase):
    def _make_fake_urlopen(self, captured: dict, response: dict):
        def fake_urlopen(request, timeout=None):
            # urllib request data is bytes; decode for inspection.
            captured["body"] = json.loads(request.data.decode("utf-8"))
            captured["url"] = request.full_url
            captured["headers"] = dict(request.header_items())
            return _FakeResponse(json.dumps(response).encode("utf-8"))
        return fake_urlopen

    def test_label_propagates_as_release_label(self):
        captured = {}
        fake_response = {
            "Type": "Succeed",
            "Items": [{"FileName": "app.js", "FileCode": "PROTECTED;"}],
            "Report": {"BuildId": "rel-1", "PolymorphismFingerprint": "abc123"}
        }
        with patch("jso_protector.urlopen", self._make_fake_urlopen(captured, fake_response)):
            result = protect(
                api_key="k",
                api_password="p",
                files={"app.js": "let x = 1;"},
                preset="balanced",
                label="ci-build-7f3a",
            )
        self.assertEqual(captured["body"]["ReleaseLabel"], "ci-build-7f3a")
        self.assertEqual(captured["body"]["APIKey"], "k")
        self.assertEqual(captured["body"]["APIPwd"], "p")
        self.assertEqual(len(captured["body"]["Items"]), 1)
        # Preset must include the balanced defaults.
        self.assertTrue(captured["body"].get("FlatTransform"))
        self.assertTrue(captured["body"].get("EncryptStrings"))
        self.assertEqual(result.build_id, "rel-1")
        self.assertEqual(result.polymorphism_fingerprint, "abc123")
        self.assertEqual(result.files, {"app.js": "PROTECTED;"})

    def test_explicit_options_override_preset(self):
        captured = {}
        fake_response = {
            "Type": "Succeed",
            "Items": [{"FileName": "x.js", "FileCode": "OK;"}],
        }
        with patch("jso_protector.urlopen", self._make_fake_urlopen(captured, fake_response)):
            protect(
                api_key="k", api_password="p",
                files={"x.js": "let y = 2;"},
                preset="balanced",
                options={"FlatTransform": False, "LockDomain": True, "LockDomainList": "example.com"},
            )
        # Balanced default was True; explicit override wins.
        self.assertFalse(captured["body"]["FlatTransform"])
        self.assertTrue(captured["body"]["LockDomain"])
        self.assertEqual(captured["body"]["LockDomainList"], "example.com")

    def test_env_var_fallback_for_credentials(self):
        captured = {}
        fake_response = {
            "Type": "Succeed",
            "Items": [{"FileName": "a.js", "FileCode": "OK;"}],
        }
        with patch("jso_protector.urlopen", self._make_fake_urlopen(captured, fake_response)), \
             patch.dict("os.environ", {"JSO_API_KEY": "env-key", "JSO_API_PASSWORD": "env-pwd"}, clear=False):
            protect(files={"a.js": "let z = 3;"})
        self.assertEqual(captured["body"]["APIKey"], "env-key")
        self.assertEqual(captured["body"]["APIPwd"], "env-pwd")

    def test_missing_credentials_raises(self):
        with patch.dict("os.environ", {}, clear=True):
            with self.assertRaises(ProtectError) as ctx:
                protect(files={"a.js": "x"})
        # Message must not leak any provided value (none provided here).
        self.assertIn("credentials", str(ctx.exception).lower())

    def test_unknown_preset_raises(self):
        with self.assertRaises(ProtectError) as ctx:
            protect(api_key="k", api_password="p", files={"a.js": "x"}, preset="elephant")
        self.assertIn("preset", str(ctx.exception).lower())

    def test_empty_files_raises(self):
        with self.assertRaises(ProtectError) as ctx:
            protect(api_key="k", api_password="p", files={})
        self.assertIn("file", str(ctx.exception).lower())

    def test_non_succeed_type_raises_with_message(self):
        captured = {}
        fake_response = {"Type": "Error", "Message": "Invalid API key", "ErrorCode": "AUTH_FAIL"}
        with patch("jso_protector.urlopen", self._make_fake_urlopen(captured, fake_response)):
            with self.assertRaises(ProtectError) as ctx:
                protect(api_key="k", api_password="p", files={"a.js": "x"})
        self.assertIn("Invalid API key", str(ctx.exception))
        self.assertEqual(ctx.exception.type, "Error")
        self.assertEqual(ctx.exception.error_code, "AUTH_FAIL")

    def test_preset_table_has_expected_entries(self):
        # Defensive: if someone removes a preset by accident the import test
        # will catch it via this assertion.
        self.assertIn("standard", PRESETS)
        self.assertIn("balanced", PRESETS)
        self.assertIn("maximum", PRESETS)
        self.assertGreater(len(PRESETS["maximum"]), len(PRESETS["standard"]))


if __name__ == "__main__":
    unittest.main()
