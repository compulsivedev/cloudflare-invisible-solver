// oracle-run.js
// Drive the extracted Turnstile body oracle (oracle-body.js) over a batch of
// test cases supplied on stdin as JSON: [{ "seed": [..128 bytes..], "fp": <obj> }, ...]
// Emits, per case, the exact intermediate layers as hex so the Python port in
// utils/turnstile.py can be checked byte-for-byte.
'use strict';
const oracle = require('./oracle-body.js');

// NOTE: pV/blob are sparse arrays -- buildPV fills the 128-byte RSA block from the
// tail, leaving holes at the front when the ciphertext has leading zero bytes. The VM
// consumes those holes as 0 in the base64 packer (`undefined << 16 === 0`), so we index
// by position (not Array.prototype.map, which skips holes) and coerce undefined -> 0.
function hex(a) {
  let s = '';
  for (let i = 0; i < a.length; i++) s += ((a[i] | 0) & 255).toString(16).padStart(2, '0');
  return s;
}

const input = JSON.parse(require('fs').readFileSync(0, 'utf8'));
const out = input.map(tc => {
  oracle.reseedP5(tc.seed);
  const body = oracle.pZ(tc.fp);
  const L = oracle.pZ.__layers;
  return {
    json_hex: hex(L.jsonBytes),
    lzw_hex: hex(L.lzw),
    pad: L.padCount,
    plen: L.plaintextLen,
    blob_hex: hex(L.blob),
    pv_hex: hex(oracle.pV),
    body: body,
  };
});
process.stdout.write(JSON.stringify(out));
