// build-oracle.js
// Surgically extract the pure body-assembly functions from decoded.js (the
// deobfuscated Turnstile challenge VM) and assemble a self-contained Node
// oracle that reproduces the exact /flow/ov request-body byte stream, so the
// Python port in utils/turnstile.py can be verified byte-for-byte.
//
// Strategy: the crypto/serialization functions (an, av, aG, p0, p1, p2, p3,
// p4, po) are PURE (no `this`, DOM, or `R`/window access) -- they only touch
// their own inline helper objects plus a handful of module constants
// (aj, ao, aS, aE, am, az, ad, ag, ae) and the dead canary `lC`. We extract
// each by brace-matching from its `function NAME(` declaration, then wrap them
// with deterministic constants and a faithful reimplementation of the pZ
// encoder body (decoded.js lines 2746-end).
'use strict';
const fs = require('fs');
const path = require('path');

const SRC = fs.readFileSync(path.join(__dirname, 'decoded.js'), 'utf8');

function extractFunction(name) {
  const re = new RegExp('\\n\\s*function ' + name + '\\s*\\(');
  const m = re.exec(SRC);
  if (!m) throw new Error('function not found: ' + name);
  // start at the `function` keyword
  const start = SRC.indexOf('function ' + name, m.index);
  // find first `{` after the signature
  let i = SRC.indexOf('{', start);
  let depth = 0;
  let inStr = null;
  for (; i < SRC.length; i++) {
    const c = SRC[i];
    if (inStr) {
      if (c === '\\') { i++; continue; }
      if (c === inStr) inStr = null;
      continue;
    }
    if (c === '"' || c === "'" || c === '`') { inStr = c; continue; }
    if (c === '{') depth++;
    else if (c === '}') {
      depth--;
      if (depth === 0) { return SRC.slice(start, i + 1); }
    }
  }
  throw new Error('unterminated function: ' + name);
}

const NAMES = ['an', 'av', 'aG', 'p0', 'p1', 'p2', 'p3', 'p4', 'po'];
const bodies = NAMES.map(extractFunction).join('\n\n');

const prelude = `'use strict';
// ---- deterministic stand-ins for the per-load / per-request closure state ----
var lC = 0;                       // dead anti-tamper canary (assigned, never read)
var p = 0;                        // string-table accessor; only used as a dead canary in these fns
var Math_pow = Math.pow;

// custom base64 alphabet (aj) -- decoded.js:2697
var aj = 'D9nyKPm+ZdgzraW-e3NEo4Hp76GXsU52jIVuRtwcxlfi$YC10QkqMOSFbvBTA8LhJ';

// JSON string-escape map (ao) -- decoded.js:2705-2712
var ao = [];
ao[8] = 98; ao[9] = 116; ao[10] = 110; ao[12] = 102; ao[13] = 114; ao[34] = 34; ao[92] = 92;

// BigInt constants -- decoded.js:2698-2704
var ag = BigInt('0x00e9d3dca1328a49ad3403e4badda37a6a13610b608b5099839e1074e720f5a33b2ebd8c2ffd12c09be0015a4635aa9d2022d8f72f90ed11610c3742b0baef5b7da73d7e79aff6cdbdeab72492ce0a858e4c1f4c27a14ebbb4ce3beacfda982fe74463e76f654aab0c597d5e73686ea149023e8f60ae6365a30055fe2c5eb2ebfb');
var ae = BigInt(65537);
var ad = BigInt(0);
var az = BigInt(1);
var am = BigInt(2);
var aS = BigInt(8);
var aE = BigInt('0xff');

// KJuRf8 -- transform applied to the XTEA key slice (decoded.js:2884). RESOLVED:
// it is a repeating-key XOR  out[i] = in[i] ^ s.charCodeAt(i % s.length).  The key
// s is assembled at runtime from the obfuscator string-table (not a static literal
// in the bundle); it was recovered live by calling the global KJuRf8(new
// Uint8Array(16)) over CDP and verified against two independent /flow/ov captures.
// Both sides (this oracle + utils.turnstile.make_kjurf8) use the same key so the
// byte-for-byte harness validates the real transform. Override via KJURF8_KEY env.
var KJURF8_KEY = process.env.KJURF8_KEY || 'ENdhiMvjWPEYrXrp';
var KJuRf8 = function (a) {
  var out = new Uint8Array(a.length);
  for (var i = 0; i < a.length; i++) out[i] = a[i] ^ KJURF8_KEY.charCodeAt(i % KJURF8_KEY.length);
  return out;
};

// ---- deterministic per-request random buffer p5 (normally crypto.getRandomValues) ----
// Fixed so the oracle is reproducible. p5[0] forced to 1 then 0 exactly as the bundle does.
var p5 = new Uint8Array(128);
for (var _i = 0; _i < 128; _i++) p5[_i] = (_i * 37 + 11) & 255;

// allow the Python verifier to inject an exact p5 (array of 128 byte values)
function reseedP5(arr) {
  for (var i = 0; i < 128; i++) p5[i] = arr[i] & 255;
  pV = buildPV();
}

// ---- RSA key-transport block pV (decoded.js:2713-2744) ----
// p6 = bigint(p5 with p5[0]=1); p8 = p6^e mod N; pV = 128-byte BE of p8.
function buildPV() {
  p5[0] = 1;
  var p6 = ad;
  for (var i = 0; i < p5.length; i++) p6 = (p6 << aS) | BigInt(p5[i]);
  var p9 = p6 % ag, pa = ae, pp = az;
  for (; pa > ad;) {
    if (pa % am === az) pp = (pp * p9) % ag;
    pa >>= az;
    p9 = (p9 * p9) % ag;
  }
  var p8 = pp;
  var pV = []; pV.length = 128;
  var pl = 127, pH = p8;
  for (; pH > ad;) { pV[pl--] = Number(aE & pH); pH >>= aS; }
  p5[0] = 0;
  return pV;
}
var pV = buildPV();

// ---- pZ: the body encoder (faithful transcription of decoded.js:2746-2945) ----
// Input V = the fingerprint object. Returns the custom-base64 /flow/ov body string.
// We also stash intermediate layers on pZ.__layers for evidence.
function pZ(V) {
  var H = [];
  V = an(V, H, 0);
  H[V++] = Number(aS << am);   // append 0x20
  H.length = V;
  var jsonBytes = H.slice();

  if (H.length < 16384) V = av(H); else V = aG(H);
  var lzw = V.slice();

  var Z = (8 - (V.length % 8)) % 8;
  V.length += Z;
  var I = V.length;
  var padCount = Z;

  H = pV.slice();
  H[128] = Z;
  var Y = 129;
  H.length += I;

  Z = 9 * Z + 40;
  var V5 = p5.slice(Z, Z + 16);
  V5 = KJuRf8(V5);
  Z = [];
  p0(
    (V5[3] | (V5[2] << 8 | (V5[0] << 24 | V5[1] << 16))) >>> 0,
    (V5[4] << 24 | V5[5] << 16 | V5[6] << 8 | V5[7]) >>> 0,
    (V5[8] << 24 | V5[9] << 16 | V5[10] << 8 | V5[11]) >>> 0,
    (V5[12] << 24 | V5[13] << 16 | V5[14] << 8 | V5[15]) >>> 0,
    Z, 0
  );
  V5 = [];
  var V6 = I >= 16384;
  if (V6) {
    var V7 = I >>> 3; if (V7 >= 256) V7 = 256;
    for (var V8 = 0; V8 < V7; V8++) p1(Z, V8, V5, V8 * 64);
  }
  if (V6) Y = p4(V, I, V5, H, Y);
  else Y = p3(V, I, Z, H, Y);
  H.length = Y;
  var blob = H.slice();

  // custom base64 over aj (decoded.js:2909-2945)
  var out = [];
  var II = 0;
  var ZZ = H.length;
  var YY = ZZ % 3;
  ZZ -= YY;
  out.length = ((ZZ / 3) * 4) + (YY ? YY + 1 : 0);
  for (var V5b = 0; V5b < ZZ; V5b += 3) {
    var V6b = (H[V5b] << 16 | H[V5b + 1] << 8) | H[V5b + 2];
    out[II++] = aj[(V6b >> 18) & 63];
    out[II++] = aj[V6b >> 12 & 63];
    out[II++] = aj[(V6b >> 6) & 63];
    out[II++] = aj[V6b & 63];
  }
  if (YY === 1) {
    var Hh = H[ZZ] << 16;
    out[II++] = aj[(Hh >> 18) & 63];
    out[II++] = aj[(Hh >> 12) & 63];
  } else if (YY === 2) {
    var Hh2 = (H[ZZ] << 16) | (H[ZZ + 1] << 8);
    out[II++] = aj[(Hh2 >> 18) & 63];
    out[II++] = aj[(Hh2 >> 12) & 63];
    out[II++] = aj[(Hh2 >> 6) & 63];
  }
  var body = out.join('');

  pZ.__layers = {
    jsonBytes: jsonBytes,
    lzw: lzw,
    padCount: padCount,
    plaintextLen: I,
    blob: blob,
    body: body
  };
  return body;
}

module.exports = { pZ: pZ, p5: p5, get pV() { return pV; }, reseedP5: reseedP5 };
`;

const runner = `
// ---- runner ----
if (require.main === module) {
  var fp = {
    "navigator.userAgent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    "navigator.language": "en-US",
    "navigator.hardwareConcurrency": 8,
    "screen.width": 1920,
    "screen.height": 1080,
    "window.devicePixelRatio": 1,
    "n": [1, 2, 3, true, false, null, "x"],
    "nested": { "a": 1, "b": "two", "c": [3, 4] }
  };
  var body = pZ(fp);
  var L = pZ.__layers;
  function hex(a){ return Array.prototype.map.call(a, function(b){ return (b&255).toString(16).padStart(2,'0'); }).join(''); }
  console.log(JSON.stringify({
    jsonBytes_hex: hex(L.jsonBytes),
    jsonText: Buffer.from(L.jsonBytes).toString('latin1'),
    lzw_hex: hex(L.lzw),
    lzw_len: L.lzw.length,
    padCount: L.padCount,
    plaintextLen: L.plaintextLen,
    blob_hex: hex(L.blob),
    blob_len: L.blob.length,
    body: body,
    body_len: body.length
  }, null, 2));
}
`;

const oracle = prelude + '\n\n' + bodies + '\n\n' + runner;
fs.writeFileSync(path.join(__dirname, 'oracle-body.js'), oracle);
console.log('wrote oracle-body.js (', oracle.length, 'bytes ) with functions:', NAMES.join(', '));
