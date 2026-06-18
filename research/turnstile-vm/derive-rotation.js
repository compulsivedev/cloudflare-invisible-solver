// Faithfully derive the runtime rotation of the Turnstile string table by
// executing the REAL shuffler IIFE (verbatim from final.js:161-184) against a
// reconstructed memoized array-provider `a` and decoder `p`.
const fs = require("fs");
const src = fs.readFileSync(process.argv[2] || "final.js", "utf8");

// 1. extract the static table exactly as the source builds it
const m = src.match(/'((?:[^'\\]|\\.)*)'\.split\('(;)'\)/);
if (!m) throw new Error("table literal not found");
const STATIC = m[1].split(";");
const OFFSET = 114;

// 2. reconstruct memoized provider + decoder (same semantics as source)
let Jm = STATIC.slice();
let a = function () {
  a = function () {
    return Jm;
  };
  return a();
};
function p(V) {
  V = V - OFFSET;
  const H = a();
  return H[V];
}

const beforeFirst = a()[1180 - OFFSET]; // sanity: pre-rotation value at checksum idx

// 3. run the EXACT shuffler IIFE (verbatim), counting rotations
let rotations = 0;
(function (V, l, NT, lY, H, Z) {
  NT = { V: 1180, l: 1690, H: 537, Z: 1253, I: 217, Y: 1013, V5: 827, V6: 415, V7: 1538, V8: 1216, V9: 1830, Va: 143 };
  lY = p;
  H = V();
  for (; !![]; ) try {
    Z = -parseInt(lY(NT.V)) / 1 * (-parseInt(lY(NT.l)) / 2) + -parseInt(lY(NT.H)) / 3 * (parseInt(lY(NT.Z)) / 4) + parseInt(lY(NT.I)) / 5 * (-parseInt(lY(NT.Y)) / 6) + parseInt(lY(NT.V5)) / 7 * (-parseInt(lY(NT.V6)) / 8) + -parseInt(lY(NT.V7)) / 9 * (-parseInt(lY(NT.V8)) / 10) + -parseInt(lY(NT.V9)) / 11 + parseInt(lY(NT.Va)) / 12;
    if (l === Z) break;
    else {
      H.push(H.shift());
      rotations++;
    }
  } catch (I) {
    H.push(H.shift());
    rotations++;
  }
})(a, 489459);

const rotated = a();
// rotated[j] === STATIC[(j + rotations) % N]
const N = STATIC.length;
let K = (STATIC.indexOf(rotated[0]) % N + N) % N; // shift amount

const anchors = { 1094: "getRandomValues", 1084: "keys", 194: "getPrototypeOf", 1528: "concat", 1054: "0xff", 769: null, 776: null };
const dec = (ci) => rotated[ci - OFFSET];
console.log(JSON.stringify({
  tableLen: N,
  rotations,
  derivedShift_K: K,
  preRotationAtChecksumIdx: beforeFirst,
  anchorChecks: Object.fromEntries(Object.keys(anchors).map((ci) => [ci, dec(+ci)])),
}, null, 2));

// expose for reuse
module.exports = { STATIC, rotations, OFFSET, decode: (ci) => rotated[ci - OFFSET], rotated };
