// Validate the recovered Turnstile crypto primitives by faithful transcription
// + test vectors. Float decimals in the source (e.g. `>>18.89`, `&63.42`) are
// obfuscator noise: bitwise operators coerce operands to int32, so they equal
// the integer forms. We transcribe to integer ops and prove equivalence.
const aj = "D9nyKPm+ZdgzraW-e3NEo4Hp76GXsU52jIVuRtwcxlfi$YC10QkqMOSFbvBTA8LhJ";

// ---------- 1. custom-alphabet base64 (faithful transcription of pZ tail) ----------
function b64enc(bytes) {
  const out = [];
  let i = 0;
  let n = bytes.length;
  const rem = n % 3;
  n -= rem;
  for (; i < n; i += 3) {
    const g = (bytes[i] << 16) | (bytes[i + 1] << 8) | bytes[i + 2];
    out.push(aj[(g >> 18) & 63], aj[(g >> 12) & 63], aj[(g >> 6) & 63], aj[g & 63]);
  }
  if (rem === 1) {
    const g = bytes[n] << 16;
    out.push(aj[(g >> 18) & 63], aj[(g >> 12) & 63]);
  } else if (rem === 2) {
    const g = (bytes[n] << 16) | (bytes[n + 1] << 8);
    out.push(aj[(g >> 18) & 63], aj[(g >> 12) & 63], aj[(g >> 6) & 63]);
  }
  return out.join("");
}
// inverse, to prove round-trip (alphabet is a bijection over 6-bit symbols)
function b64dec(str) {
  const map = {};
  for (let i = 0; i < aj.length; i++) map[aj[i]] = i;
  const bytes = [];
  let bits = 0;
  let acc = 0;
  for (const ch of str) {
    acc = (acc << 6) | map[ch];
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      bytes.push((acc >> bits) & 0xff);
    }
  }
  return bytes;
}
// prove float-noise equivalence: g>>18.89 === g>>18, g&63.42 === g&63
const fuzz = (() => {
  for (let t = 0; t < 100000; t++) {
    const g = (Math.random() * 0xffffff) | 0;
    if ((g >> 18.89) !== (g >> 18)) return false;
    if ((g & 63.42) !== (g & 63)) return false;
    if ((128.22 << (t % 24)) !== (128 << (t % 24))) return false;
  }
  return true;
})();
const sample = Array.from({ length: 20 }, (_, i) => (i * 37 + 11) & 0xff);
const enc = b64enc(sample);
const rt = b64dec(enc);
const rtOk = JSON.stringify(rt) === JSON.stringify(sample);

// ---------- 2. RSA-2048 modexp (faithful transcription of the square-and-multiply) ----------
const N = BigInt(
  "0x00e9d3dca1328a49ad3403e4badda37a6a13610b608b5099839e1074e720f5a33b2ebd8c2ffd12c09be0015a4635aa9d2022d8f72f90ed11610c3742b0baef5b7da73d7e79aff6cdbdeab72492ce0a858e4c1f4c27a14ebbb4ce3beacfda982fe74463e76f654aab0c597d5e73686ea149023e8f60ae6365a30055fe2c5eb2ebfb"
);
const e = BigInt(65537);
// recovered loop: pp=1; base%=N; while(exp>0){ if(exp&1) pp=pp*base%N; exp>>=1; base=base*base%N; }
function modpowRecovered(base, exp, mod) {
  let pp = 1n;
  base %= mod;
  while (exp > 0n) {
    if (exp % 2n === 1n) pp = (pp * base) % mod;
    exp >>= 1n;
    base = (base * base) % mod;
  }
  return pp;
}
// reference modpow (independent formulation)
function modpowRef(b, ex, m) {
  let r = 1n;
  b %= m;
  while (ex > 0n) {
    if (ex & 1n) r = (r * b) % m;
    b = (b * b) % m;
    ex >>= 1n;
  }
  return r;
}
// recovered serialization: 128-byte big-endian buffer, pV[127..]=Number(0xff & x); x>>=8
function toBE128(x) {
  const v = new Array(128).fill(0);
  let p = 127;
  while (x > 0n) {
    v[p--] = Number(0xffn & x);
    x >>= 8n;
  }
  return v;
}
// build m from a 128-byte buffer big-endian (p6 = p6<<8 | byte), matching source
function fromBE(bytes) {
  let x = 0n;
  for (const b of bytes) x = (x << 8n) | BigInt(b);
  return x;
}
const msgBytes = Array.from({ length: 128 }, (_, i) => (i * 7 + 3) & 0xff);
msgBytes[0] = 0; // source sets p5[0]=0 so m < N
const m = fromBE(msgBytes);
const cRec = modpowRecovered(m, e, N);
const cRef = modpowRef(m, e, N);
const rsaOk = cRec === cRef && cRec < N;
const beRoundTrip = fromBE(toBE128(cRec)) === cRec;

console.log(
  JSON.stringify(
    {
      base64: { alphabetLen: aj.length, floatNoiseEquivToInt: fuzz, sampleEnc: enc, roundTripsToInput: rtOk },
      rsa: {
        recoveredEqualsReference: rsaOk,
        cipherLessThanModulus: cRec < N,
        be128RoundTrips: beRoundTrip,
        cipherHexHead: cRec.toString(16).slice(0, 24) + "...",
      },
    },
    null,
    2
  )
);
