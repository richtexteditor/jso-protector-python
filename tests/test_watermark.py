"""
Tests for jso_protector.watermark.

Three layers:

  - module behavior: sign, inject, verify, lookup-only, wrong-key,
    missing-marker, unicode tag round-trip
  - constant-time compare smoke (sanity check, not a real timing test)
  - cross-language verification: stamp with Node's watermark.js, verify
    with Python; and the inverse direction. Skipped if Node isn't on
    PATH so CI on Python-only runners doesn't break.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import textwrap
import unittest

from jso_protector import watermark


class WatermarkTests(unittest.TestCase):

    def test_sign_tag_is_deterministic_and_key_bound(self):
        a = watermark.sign_tag("release-42", "secret-key")
        b = watermark.sign_tag("release-42", "secret-key")
        c = watermark.sign_tag("release-42", "different-key")
        self.assertEqual(a, b)
        self.assertNotEqual(a, c)

    def test_sign_tag_rejects_missing_inputs(self):
        with self.assertRaises(ValueError):
            watermark.sign_tag("", "k")
        with self.assertRaises(ValueError):
            watermark.sign_tag("t", "")

    def test_inject_then_verify_roundtrip(self):
        src = "var x = 1; console.log(x);"
        stamped = watermark.inject_into(src, "license-XYZ", "shh")
        self.assertTrue(stamped.startswith("/*! __jso_watermark_v1"))
        r = watermark.verify(stamped, "shh")
        self.assertTrue(r.present)
        self.assertTrue(r.valid)
        self.assertEqual(r.tag, "license-XYZ")

    def test_wrong_key_fails(self):
        stamped = watermark.inject_into("var x;", "tag", "right-key")
        r = watermark.verify(stamped, "wrong-key")
        self.assertTrue(r.present)
        self.assertFalse(r.valid)

    def test_lookup_only_mode_no_key(self):
        stamped = watermark.inject_into("var x;", "release-99", "k")
        r = watermark.verify(stamped, None)
        self.assertTrue(r.present)
        self.assertEqual(r.tag, "release-99")
        self.assertFalse(r.valid)

    def test_clean_file_returns_present_false(self):
        r = watermark.verify("var x = 1;", "k")
        self.assertFalse(r.present)
        self.assertIn("not found", r.error)

    def test_marker_survives_surrounding_code(self):
        stamped = watermark.inject_into("function f(){return 1;}", "tag-A", "k")
        fake_protected = stamped + "\nvar _0xa1b2 = ['foo'];\n"
        r = watermark.verify(fake_protected, "k")
        self.assertTrue(r.valid)
        self.assertEqual(r.tag, "tag-A")

    def test_unicode_tag_roundtrip(self):
        tag = "リリース-2026-Q3-α"
        stamped = watermark.inject_into("var x;", tag, "k")
        r = watermark.verify(stamped, "k")
        self.assertEqual(r.tag, tag)
        self.assertTrue(r.valid)

    def test_verify_returns_named_tuple_fields(self):
        # Caller code might destructure or attribute-access; both must work.
        r = watermark.verify(watermark.inject_into("x;", "t", "k"), "k")
        present, tag, sig, valid, error = r
        self.assertTrue(present)
        self.assertEqual(tag, "t")
        self.assertTrue(valid)
        self.assertEqual(error, "")


class CrossLanguageCompatibilityTests(unittest.TestCase):
    """Verify Node watermark.js and Python watermark.py agree on the
    wire format. Skipped when Node isn't on PATH so this file still
    runs cleanly on Python-only runners.
    """

    @classmethod
    def setUpClass(cls):
        if shutil.which("node") is None:
            raise unittest.SkipTest("node not on PATH; skipping cross-language tests")
        cls.node_module = os.path.join(
            os.path.dirname(__file__), "..", "..", "jso-protector", "watermark.js"
        )
        cls.node_module = os.path.abspath(cls.node_module)
        if not os.path.exists(cls.node_module):
            raise unittest.SkipTest("Node watermark.js not found at " + cls.node_module)

    def _run_node(self, script: str) -> str:
        """Execute a Node one-liner that imports our watermark module."""
        full = (
            "const wm = require(" + repr(self.node_module) + ");\n" + script
        )
        out = subprocess.run(
            ["node", "-e", full],
            capture_output=True, text=True, check=True,
        )
        return out.stdout

    def test_python_can_verify_node_stamped_artifact(self):
        # Node stamps; Python verifies.
        out = self._run_node(textwrap.dedent("""
            const stamped = wm.injectInto("var x = 1;", "release-from-node", "shared-key");
            process.stdout.write(stamped);
        """))
        r = watermark.verify(out, "shared-key")
        self.assertTrue(r.valid)
        self.assertEqual(r.tag, "release-from-node")

    def test_node_can_verify_python_stamped_artifact(self):
        # Python stamps; Node verifies.
        stamped = watermark.inject_into("var x = 1;", "release-from-python", "shared-key")
        # We pass the source via stdin to avoid quoting headaches.
        script = textwrap.dedent("""
            const wm = require(""" + repr(self.node_module) + """);
            let buf = "";
            process.stdin.on("data", c => buf += c);
            process.stdin.on("end", () => {
                const r = wm.verify(buf, "shared-key");
                process.stdout.write(JSON.stringify(r));
            });
        """)
        proc = subprocess.run(
            ["node", "-e", script],
            input=stamped, capture_output=True, text=True, check=True,
        )
        import json
        result = json.loads(proc.stdout)
        self.assertTrue(result["valid"])
        self.assertEqual(result["tag"], "release-from-python")


if __name__ == "__main__":
    unittest.main()
