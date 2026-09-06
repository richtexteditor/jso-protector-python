# Changelog

All notable changes to the `jso-protector` Python client.

## [Unreleased]

### Added — `jso_protector.watermark` (2026-05-28)

- New stdlib-only module that mirrors the wire format of
  `packages/jso-protector/watermark.js` (Node) and
  `JsoProtector.Watermark` (.NET). An artifact stamped by any of the
  three verifies under any of the others.
- API surface: `sign_tag(tag, key)`, `build_header(tag, key)`,
  `inject_into(source, tag, key)`, `verify(protected_source, key)`,
  `VerifyResult` named tuple, module-level `MARKER` constant.
- Stdlib only: `hmac` + `hashlib` + `base64` + `re`. No new
  third-party dependencies; the package's "pure stdlib" promise
  is preserved.
- Constant-time signature comparison via `hmac.compare_digest`.
- Unicode tags (multi-byte UTF-8) round-trip through base64url.
- Lookup-only mode (no `key` passed) returns the embedded tag without
  validating — for forensic inspection of leaked artifacts where the
  HMAC secret shouldn't ship to the investigator.
- Cross-language verification tests in `tests/test_watermark.py`
  spawn the Node `watermark.js` module via `subprocess` and verify
  Python-stamped → Node-validated and Node-stamped → Python-validated
  in both directions. Tests degrade gracefully (skip, not fail) when
  `node` isn't on PATH so the suite still passes on Python-only
  runners.
- Coverage: 11 new test cases. Full suite: 30 / 30 passing.

Wire format spec: <https://javascriptobfuscator.com/docs/wireformat.aspx#watermark>
