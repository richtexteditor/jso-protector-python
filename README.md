> **This repository has moved to [javascriptobfuscator-com/jso-protector-python](https://github.com/javascriptobfuscator-com/jso-protector-python).** It is archived and no longer updated.

# jso-protector — Python client

Python client for the [JavaScript Obfuscator](https://javascriptobfuscator.com/) HTTP API. Mirrors the protect() surface of the [npm `jso-protector` CLI](https://javascriptobfuscator.com/docs/npmcli.aspx) so behavior stays in lockstep across runtimes.

Pure stdlib — uses `urllib` and `json`. No third-party dependency.

## Install

```bash
pip install jso-protector
```

## Quick start

```python
from jso_protector import protect

result = protect(
    # Credentials default to JSO_API_KEY / JSO_API_PASSWORD env vars.
    files={"app.js": open("dist/app.js").read()},
    preset="balanced",
    label="ci-build-7f3a",   # tags the request with this release label
)

for name, code in result.files.items():
    with open(f"dist-protected/{name}", "w") as fh:
        fh.write(code)

print("BuildId:", result.build_id)
print("Fingerprint:", result.polymorphism_fingerprint)
```

## Credentials

The client reads `JSO_API_KEY` / `JSO_API_PASSWORD` (or the long-form `JAVASCRIPT_OBFUSCATOR_API_KEY` / `JAVASCRIPT_OBFUSCATOR_API_PASSWORD`) from the environment before falling back to the `api_key=` / `api_password=` keyword arguments. Use env vars on shared / CI machines so the keys never appear in source.

## Presets

| Preset | Notes |
|---|---|
| `standard` | Core string encoding, string-array move, name mangling, compression. |
| `balanced` | Adds string encryption, deep obfuscation, flat transform, code transposition. |
| `maximum` | Adds member rename, global rename, member move, dead-code insertion. |

For fine-grained control pass `options={...}` with the same Pascal-case keys the [HTTP API](https://javascriptobfuscator.com/docs/) documents — e.g. `options={"LockDate": True, "LockDomain": True, "LockDomainList": "example.com"}`. Explicit options override preset defaults.

## Returned data

`ProtectResult` is a dataclass with five fields:

| Field | Type | Notes |
|---|---|---|
| `files` | `dict[str, str]` | Protected source keyed by input filename. |
| `build_id` | `str \| None` | Stable identifier for this protection run. Inject as a global so production crash reports carry the matching BuildId. |
| `polymorphism_fingerprint` | `str \| None` | Short fingerprint over the protected output. Auditors use this to prove builds genuinely diverge. |
| `report` | `dict` | Full Report object — identifier maps, enabled options, compatibility findings, release metadata. |
| `raw` | `dict` | The complete raw response body. Use when a field hasn't been surfaced on the dataclass yet. |

## Error handling

```python
from jso_protector import protect, ProtectError

try:
    result = protect(files={"app.js": code})
except ProtectError as e:
    # e.message is safe to log — API key / password are never interpolated.
    # e.type and e.error_code carry the API's Type / ErrorCode when present.
    print(f"JSO protection failed: {e}")
```

## Watermarking — anti-piracy / dispute proof

The `jso_protector.watermark` module embeds an HMAC-SHA256-signed marker into source before it goes to the obfuscation API. The obfuscator's `KeepComment` option preserves the marker through every transform, so the watermark survives in the protected output. Holders of the secret can verify; everyone else sees an opaque comment block.

```python
from jso_protector import protect, watermark

# Stamp during build:
source = open("dist/app.js").read()
stamped = watermark.inject_into(source, tag="release-2026-Q3", key=os.environ["JSO_WATERMARK_KEY"])
result = protect(files={"app.js": stamped}, preset="balanced",
                 options={"KeepComment": True})    # required so the marker survives

# Verify a protected artifact later:
r = watermark.verify(open("dist-protected/app.js").read(), key=os.environ["JSO_WATERMARK_KEY"])
if r.valid:
    print(f"Valid build, tag={r.tag}")
elif r.present:
    print(f"Watermark present (tag={r.tag}) but signature does NOT match the supplied key.")
else:
    print("No watermark in this file.")
```

Wire format is identical to the Node (`packages/jso-protector/watermark.js`) and .NET (`JsoProtector.Watermark`) clients — an artifact stamped by any of the three verifies under any of the others. Tests in `tests/test_watermark.py` include cross-language verification with the Node implementation (skipped when `node` isn't on PATH). Spec: <https://javascriptobfuscator.com/docs/wireformat.aspx#watermark>.

Lookup-only mode (no key supplied) extracts the embedded tag without validating — useful for forensic inspection of leaked artifacts where the secret shouldn't ship to the investigator. Constant-time HMAC compare via `hmac.compare_digest`.

## Stack-trace symbolication

Persist `result.report` (or just `result.report["GlobalIdentifierMap"]` and `result.report["MemberIdentifierMap"]`) alongside the protected dist. When a production crash arrives, demangle locally with the [`jso-symbolicate` npm package](https://javascriptobfuscator.com/docs/symbolication.aspx) — or, for a Python-only pipeline, the identifier map is plain JSON that you can iterate over and substitute against the stack text yourself.

## License

UNLICENSED. Provided as a free companion to the JSO service. An active JSO account is required to make API calls.
