# Turnstile challenge VM — fingerprinting + payload-generation algorithm recovery

**Target:** the inline `<script>` served inside the Turnstile challenge **iframe**
(`https://challenges.cloudflare.com/cdn-cgi/challenge-platform/h/b/turnstile/f/ov2/av0/rch/dlkoc/0x4AAAAAAA-nDfU7SyKYs52-/light/fbE/new/flexible?lang=auto`).
This is the real engine the `api.js` loader injects — **not** `api.js` itself (which, as established earlier, is only the loader/orchestrator).

**Method:** ast-deobfuscation skill (generic layered pipeline) + a custom string-table decode pass.
**Artifacts:**
- `vm_raw.js` — 213.7 KB obfuscated source extracted from the iframe HTML.
- `out/final.js` — pipeline output (pretty-printed, 13,136 lines).
- `out/decoded.js` — after inlining the string-table decoder (**4,580** `decoder(idx)` calls replaced, 0 remaining), **with the runtime array rotation applied** (see L1).
- `decode-strings.js` — the decode pass (detects + executes the self-defending shuffler to derive the rotation).
- `derive-rotation.js` — standalone harness that runs the obfuscator's own checksum loop to prove the rotation offset.
- `verify-primitives.js` — executes the recovered base64 + RSA against test vectors.

> **Accuracy note (correction to the first draft):** the initial decode indexed the **static** string table and was therefore off by the load-time rotation, mislabeling a number of strings (e.g. `aE` resolved to junk instead of `0xff`). The decode pass now **executes the real shuffler IIFE** (`final.js:161-184`) and derives a rotation of **421**; all anchors then resolve to real identifiers. Every string-derived claim below is from the corrected `decoded.js`.

---

## 1. Obfuscation layers

| Layer | Mechanism | Status |
|-------|-----------|--------|
| L1 String table | `a()` returns a 1,821-entry array from `'…'.split(';')`; decoder `p(i) = table[i-114]`; **a load-time shuffler IIFE (`final.js:161-184`) rotates the array by `arr.push(arr.shift())` until an obfuscated checksum equals `489459` — derived rotation = 421**; ~384 aliases (`lC=p`, `ZB=lC`, `Zh=lC`, …); per-function numeric const-objects (`ko={V:435,…}`) used as `Zh(ko.V)` | **Decoded** (all 4,580 sites, rotation applied) |
| L2 "Scrambler" helper objects | per-function `Z["<rand>"]=function(a,b){return a==b}` then `Z["<rand>"](x,y)`; random-label keys (mixed into the same string table) | Identified; values readable |
| L3 Master natives registry | params `l`/`R`; random-label keys map to real globals — e.g. `l["Array"]["isArray"](H)` = `Array.isArray(H)` | Identified |
| L4 Control-flow flattening | `for(;;){ switch(seq[i++]){ case '0': … continue } }` with permuted case orders | Present (does not block algorithm recovery) |
| L5 JSVMP (bytecode interpreter) | `R["runProgram"](program)` (`decoded.js:3063`) builds `new V3(program)` — a register-based VM (`vm.h` register file, `vm.g` PC, XOR-masked register indices) with a fetch-decode-execute loop; invoked with large base64 bytecode blobs (e.g. `decoded.js:8410`) | **Boundary** — see §3/§5 |

The decode pass (L1) is the key unlock: it exposes the SHA-256 constants, the RSA modulus, the 65-char alphabet, the API/property strings, and the type-classifier. **However**, part of the high-level orchestration (including how the final flow body is assembled and when it is sent) executes inside the **L5 JSVMP** as interpreted bytecode, so the *primitives and fingerprint model* are fully recovered while the exact byte-level assembly of the `/flow/ov` body is partly behind the VM (see §5).

---

## 2. Fingerprinting algorithm

Two functions form the core. Both operate on the **global object graph**.

### 2a. Property enumerator — `aM(obj)` (`decoded.js:8202`)
Walks the whole prototype chain collecting **enumerable own keys** at every level:
```js
function aM(obj) {
  var names = [];
  for (; obj !== null; ) {
    names = names.concat(Object.keys(obj));   // enumerable own keys
    obj = Object.getPrototypeOf(obj);         // walk up the prototype chain
  }
  return names;
}
```
The **caller** (§2c) then unions `Object.getOwnPropertyNames(H)` (own, incl. non-enumerable) onto this list and de-dupes.
*(Corrected: the enumerator uses `Object.keys`, not `getOwnPropertyNames` — the first draft mislabeled these due to the rotation bug.)*

### 2b. Value type-classifier — `aP(natives, value)` (`decoded.js:7025`)
Maps each property's **value** to a single category char (helper-object calls inlined):
```js
function aP(natives, v) {
  if (v == null)            return v === undefined ? 'u' : 'x';   // undefined / null
  var t = typeof v;
  if (t === 'object') {                                           // Promise instance?
    try { if (natives.Promise && v instanceof natives.Promise) { v.catch(()=>{}); return 'p'; } } catch (e) {}
  }
  return Array.isArray(v)      ? 'a'                               // array
       : v === natives.Array   ? 'D'                               // the Array constructor itself
       : v === true            ? 'T'
       : v === false           ? 'F'
       : t === 'function'                                         // native vs user-defined function
           ? (v instanceof natives.Function
              && natives.Function.prototype.toString.call(v).indexOf('[native code]') > 0 ? 'N' : 'f')
       : (aK[t] || '?');                                          // else: typeof-keyed table (aK)
}
// aK (typeof → char), decoded.js:2553-2559:
//   object→'o'   string→'s'   undefined→'u'   symbol→'z'   number→'n'   bigint→'I'
```

**Category legend (corrected):**

| char | meaning | char | meaning |
|------|---------|------|---------|
| `u` | `undefined` | `o` | object (non-Promise, non-array, non-null) |
| `x` | `null` | `s` | string |
| `p` | Promise instance | `z` | symbol |
| `a` | array (`Array.isArray`) | `n` | number |
| `D` | the `Array` constructor itself | `I` | bigint |
| `T` / `F` | boolean `true` / `false` | `i` | inaccessible (getter threw — set in §2c) |
| `N` | **native** function (`[native code]`) | `?` | unknown `typeof` |
| `f` | non-native (user) function | | |

*(Corrected from the first draft: `N` is a native function and `f` a user function — not `Number`/generic-object; and `s/z/n/I` were missing.)*

### 2c. Collection loop (`decoded.js:2618-2666`)
```js
var keys = aM(H);                                  // enumerable keys up the prototype chain (§2a)
if (Object.getOwnPropertyNames)                    // + own (incl. non-enumerable) names of H
  keys = keys.concat(Object.getOwnPropertyNames(H));
keys = Array.from(new Set(keys));                  // dedupe (Set, or a sort+splice fallback)
var out = {};
for (var name of keys) {
  try {
    var v   = H[name];
    var cat = aP(natives, v);                       // classify the value (§2b)   ← decoded.js:2641
    if (cat === 'n' || cat === 's' || cat === 'a') {            // ["n","s","a"].includes(cat)
      var num = +v, isNumericString = (cat === 's') && (num === num);
      if (name === 'd.cookie')   bucket(name, cat);             // cookie: bucket by category only
      else if (!isNumericString) bucket(name, v);               // else bucket under the LITERAL value
      // (numeric-looking strings are dropped)
    } else {
      bucket(name, cat);                            // bucket under the category char
    }
  } catch (e) { bucket(name, 'i'); }                // inaccessible getter → 'i'
}
// bucket(name, key): out[key] = out[key] || []; out[key].push(name)   (decoded.js:2660)
return out;                                         // { <value-or-category> : [propName…] }
```
A companion pass (`R["aPlZu"]`, `decoded.js:2670`) builds the baseline/expected map and prefixes the object bucket with `'o.'` (`decoded.js:2692`).

**Result shape:** `{ "<value-or-categoryChar>": ["<propName>", …], … }`. Crucially, the bucket **key** is the value's *category char* for most types, but the **literal value** itself for numbers/arrays/non-numeric strings (e.g. `outerWidth` buckets under `"158"`, `n.vendor` under `"Google Inc."`). This is exactly the structure — and the value-keyed quirk — of the repo's JSD `wb_result` in `utils/fingerprint.py`.

---

## 3. Payload generation pipeline

Globals set at `decoded.js:2697-2745`:

| Symbol | Value | Meaning |
|--------|-------|---------|
| `aj` | `D9nyKPm+ZdgzraW-e3NEo4Hp76GXsU52jIVuRtwcxlfi$YC10QkqMOSFbvBTA8LhJ` (65 chars) | custom base64/lz alphabet — matches repo regex `[a-zA-Z0-9+\-$]{65}` |
| `ag` | `BigInt('0x00e9d3dca1328a49…ebfb')` (1024-bit) | **RSA modulus N** |
| `ae` | `BigInt(65537)` | **RSA public exponent e** (0x10001) |
| SHA-256 K[64] | `[1116352408, 1899447441, …]` (`decoded.js:9662`) | SHA-256 round constants |
| SHA-256 H[8] | `[1779033703, 3144134277, …]` (`decoded.js:9663`) | SHA-256 init state |

### Step 1 — assemble + serialize
Fingerprint map (§2) → `JSON.stringify` (`stringify` present in table).

### Step 2 — SHA-256 (`decoded.js:~9650-9740`)
UTF-8 encode the string → SHA-256 → **hex** digest. Standard implementation (sigma funcs `x>>>2^x>>>13^x>>>22`, `x>>>6^x>>>11^x>>>25` visible at `decoded.js:9723`). Used for integrity/keying. No leading-zero/difficulty loop was found, so this is **hashing, not classic PoW**.

### Step 3 — RSA hybrid key transport (`decoded.js:2713-2744`)
```js
var rnd = new Uint8Array(128);
crypto.getRandomValues(rnd);            // "CUCsp"
rnd[0] = 1;
var m = 0n; for (b of rnd) m = (m << 8n) | BigInt(b);   // 1024-bit message
// c = m^e mod N  (square-and-multiply)
var base = m % N, e = 65537n, c = 1n;
for (; e > 0n; e >>= 1n) { if (e & 1n) c = c*base % N; base = base*base % N; }
var bytes = toBigEndian128(c);          // 128-byte ciphertext  (decoded.js:2736-2744)
```
i.e. **RSA-1024 encryption of a random 128-byte buffer** — public-key key/nonce transport.

### Step 4 — custom-alphabet base64 (`decoded.js:2900-2937`)
Classic 3-byte→4-symbol base64 over `aj`, packing each 3 bytes into a 24-bit int then emitting 4 sextets (decimals like `& 63.42` are `ToInt32`-truncated no-ops), with the standard 1-/2-byte tail handling at `decoded.js:2925-2936`:
```js
for (i = 0; i < n3; i += 3) {
  var g = H[i] << 16 | H[i+1] << 8 | H[i+2];     // decoded.js:2918
  out.push(aj[g>>18 & 63], aj[g>>12 & 63], aj[g>>6 & 63], aj[g & 63]);  // 2919-2922
}
```
Encodes the RSA ciphertext bytes (and other binary blobs) for transport.

### Step 5 — submit (`decoded.js` XHR path)
`XMLHttpRequest` + `setRequestHeader("cf-chl", …)` + `setRequestHeader("cf-chl-ra", …)` (`decoded.js:4836-4845`) → **POST**. The `/flow/ov` URL is assembled at `decoded.js:8404` as:
```
"/cdn-cgi/challenge-platform/h/" + _cf_chl_opt.SvTRd8 + "/flow/ov" + "1"
  + "/<num>:<ts>:<challengeToken>/" + _cf_chl_opt.wKbN9 + "/" + _cf_chl_opt.TJERQ4 + …
```
i.e. `…/flow/ov1/<token-triple>/<ray>/…`. A sibling `…/b/ov1/<token-triple>/<ray>/` POST is built at `decoded.js:2311`. The resulting token is posted back to the parent `api.js` via `postMessage`.

**Pipeline (primitives, recovered + verified):** `fingerprintMap → JSON → SHA-256(hex)` and `RSA-1024(random 128-byte buffer) → custom-base64`. **Orchestration boundary:** the exact field-by-field assembly of the `/flow/ov` body and its dispatch are driven by the **L5 JSVMP bytecode** (`runProgram`, `decoded.js:8410`) plus encrypted-string telemetry events (`R["XbnH2"]('<b64>$<b64>')`, `R["qcNv7"](…)`); these are not fully reducible to static JS without executing/lifting the bytecode (see §5).

---

## 4. Comparison with the repo's JSD implementation

| Aspect | Repo JSD (`utils/fingerprint.py`, `utils/encryption.py`) | Turnstile VM (recovered) |
|--------|----------------------------------------------------------|--------------------------|
| Fingerprint model | env-probe map `{categoryChar: [propNames]}` (`create_wb_result`) | **same** — `aM` enumerate → `aP` classify → bucket |
| Category chars | `0-9, o, F, x, u, T, N, E, s, …` | overlapping: `u, x, T, F, N, a, f, o, p, D, i` |
| Object bucket | `"o": [...]` | `'o.' + name` prefix (`decoded.js:2692`) |
| Alphabet | 65-char `[a-zA-Z0-9+\-$]{65}` per challenge | **same family** — `aj` (65 chars, incl. `+ - $`) |
| Transport encoding | **lz-string LZW**, 6-bit codes via `key[code]` (`_lzw_encode_to_key_chars`) | **custom-alphabet base64** for the crypto bytes (lz-string-style compression of the JSON is likely present too; same alphabet family) |
| Crypto | none beyond the lz encode | **adds RSA-1024 (e=65537)** key transport + **SHA-256** hashing |
| Endpoint | `/cdn-cgi/challenge-platform/h/b/jsd/r/<jsd><ray>` | `/cdn-cgi/challenge-platform/h/<b>/flow/ov…` |

**Bottom line:** Turnstile's fingerprinting is the *same algorithm family* as the JSD code already in the repo (enumerate → type-classify → bucket → 65-char-alphabet encode). The material **difference** is the payload-protection layer: Turnstile wraps the result with **SHA-256 + RSA-1024 hybrid encryption** and submits over **XHR to `/flow/ov`**, whereas the repo's JSD path lz-string-encodes and posts to `/jsd/r/`.

---

## 5. Verification (what was executed, not just read)

Run `node derive-rotation.js out/final.js` and `node verify-primitives.js`:

| Check | Method | Result |
|-------|--------|--------|
| String-table rotation | Reconstructed memoized `a()` + decoder `p()`, executed the **real** shuffler IIFE verbatim until checksum `=== 489459` | converges at **421** rotations; anchors resolve: `1094→getRandomValues`, `194→getPrototypeOf`, `769→slice`, `776→toString`, `1084→keys`, `1528→concat`, `1054→0xff` |
| Custom base64 | Faithful transcription of the encoder tail; encode then decode with the inverse alphabet | **round-trips** to input; only indices 0-63 of the 65-char `aj` are used |
| Float-noise (`>>18.89`, `&63.42`, `128.22<<`) | 100k random trials vs. integer ops | **identical** (operands coerce via `ToInt32`) |
| RSA modexp + serialization | Transcribed square-and-multiply vs. an independent `modpow`; 128-byte big-endian round-trip | **matches** reference; `c < N`; BE round-trips |
| SHA-256 | Constant + structure match | `K[64]`/`H[8]` are the canonical SHA-256 constants; padding `0x80 << (24 - len%32)` and length placement match `binb_sha256` |

## 6. Caveats / boundaries
- **L5 JSVMP is the main boundary.** `runProgram`/`V3` interpret base64 bytecode; the high-level *orchestration* (exact `/flow/ov` body field order, timing, and which telemetry events fire) lives in that bytecode and in encrypted string events (`XbnH2`/`qcNv7`). The **fingerprint model and crypto primitives** (this report) are fully recovered and verified, but a byte-exact reproduction of the request body would require lifting the bytecode or running the VM in an instrumented browser env.
- The captured bundle is **version-pinned** and embeds per-load tokens (`_cf_chl_opt`: `SvTRd8`, ray `wKbN9`, `TJERQ4`, ts). The algorithm is stable across loads; constants (RSA `N`, alphabet, string table + its rotation) change per version.
- L2/L3/L4 indirection remains in `decoded.js`; some method names on the natives registry are still random labels, but the classifier + crypto constants are unambiguous.
- The earlier `aE` artifact is **resolved**: with the rotation applied it decodes to `BigInt("0xff")` (the byte mask in `Number(0xFF & x)` at `decoded.js:2742`).
