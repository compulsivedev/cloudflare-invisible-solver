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
| `build-oracle.js` | Surgically extracts the plain-JS body builder `pZ` (+ `an`/`av`/`aG`/`p0`-`p4`) from `decoded.js` into a runnable, parameterizable oracle (`oracle-body.js`, generated). |
| `oracle-run.js` | Drives the oracle over stdin test cases, emitting every intermediate layer as hex. |
| `verify_body.py` | Byte-for-byte check of the Python `/flow/ov` body builder (`utils/turnstile.build_flow_ov_body`) against the JS oracle, including the large-input `aG`/`p4` branches. |

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

# 4. verify the Python /flow/ov body builder byte-for-byte vs the JS oracle
#    (regenerates oracle-body.js, then compares 200 small + 3 large random cases)
python verify_body.py 200
```

`final.js` itself is regenerated from `vm_raw.js` via the bundled skill:

```bash
node ../../.agents/skills/ast-deobfuscation/scripts/run-pipeline.js vm_raw.js out
```

## Caveats

- The bundle is **version-pinned** and embeds per-load tokens (`_cf_chl_opt`). The
  algorithm is stable across loads; the RSA modulus, alphabet, and string table (and
  its rotation) change per version.
- **Body-assembly gap is now closed.** The `/flow/ov` body is built by a plain-JS
  function `pZ` (decoded.js:2746-2937); the `runProgram`/`V3` JSVMP at line 8410 only
  returns the closure that *calls* `pZ` and fires the XHR. `pZ` is fully recovered,
  ported to `utils/turnstile.py` (`build_flow_ov_body`), and verified byte-for-byte by
  `verify_body.py` across the serialize -> LZW -> pad -> XTEA -> RSA-prepend -> custom-b64
  chain (both the small `av`/`p3` and large `aG`/`p4` branches).
- **`KJuRf8`** (decoded.js:2884) — the 16-byte transform on the XTEA key slice — is
  **resolved**: a repeating-key XOR whose key is assembled at runtime from the string
  table (so it is not statically greppable in the bundle), recovered live by calling
  `KJuRf8(new Uint8Array(16))` over CDP and verified against two independent `/flow/ov`
  captures (both decrypt to identical, coherent LZW/JSON plaintext). The port carries
  the captured key as `KJURF8_KEY` (`make_kjurf8`) and still exposes it as an injectable
  hook so a new deployment can be re-probed.
