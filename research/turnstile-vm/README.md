# Turnstile challenge-VM recovery

Reverse-engineering artifacts for the Cloudflare **Turnstile** challenge VM — the
obfuscated `<script>` served inside the challenge **iframe** (not `api.js`, which
is only the loader/orchestrator).

See **[`TURNSTILE-ALGORITHM-RECOVERY.md`](./TURNSTILE-ALGORITHM-RECOVERY.md)** for the
full write-up (obfuscation layers, fingerprint model, crypto primitives, endpoints,
and the verification results).

## Files

| File | What it is |
|------|------------|
| `TURNSTILE-ALGORITHM-RECOVERY.md` | The analysis / algorithm write-up. |
| `vm_raw.js` | Raw obfuscated source captured from the iframe HTML (213 KB). Provenance only. |
| `final.js` | Output of the `ast-deobfuscation` skill's generic pipeline on `vm_raw.js` (pretty-printed, string table still encoded + **rotated**). |
| `decoded.js` | `final.js` after inlining the string-table decoder **with the runtime rotation applied** — the readable artifact. |
| `decode-strings.js` | The decode pass: detects + executes the self-defending shuffler to derive the rotation, then inlines all `p(idx)` calls. |
| `derive-rotation.js` | Standalone harness that runs the obfuscator's own checksum loop to prove the rotation offset (= 421). |
| `verify-primitives.js` | Executes the recovered custom-base64 + RSA-2048 against test vectors. |

## Reproduce

Requires `@babel/parser|traverse|generator|types` (preinstalled in this repo's Devin
environment; otherwise `npm i @babel/parser @babel/traverse @babel/generator @babel/types`).

```bash
# 1. derive the load-time string-table rotation (prints rotations: 421)
node derive-rotation.js final.js

# 2. regenerate decoded.js from final.js (byte-identical to the committed file)
node decode-strings.js final.js decoded.js

# 3. validate the recovered crypto primitives
node verify-primitives.js
```

`final.js` itself is regenerated from `vm_raw.js` via the bundled skill:

```bash
node ../../.agents/skills/ast-deobfuscation/scripts/run-pipeline.js vm_raw.js out
```

## Caveats

- The bundle is **version-pinned** and embeds per-load tokens (`_cf_chl_opt`). The
  algorithm is stable across loads; the RSA modulus, alphabet, and string table (and
  its rotation) change per version.
- A residual **JSVMP** layer (`runProgram` / `V3`) interprets base64 bytecode that drives
  the exact `/flow/ov` body assembly; the fingerprint model + crypto primitives are fully
  recovered and verified, but a byte-exact request body would require lifting/executing
  that bytecode. See §5 of the write-up.
