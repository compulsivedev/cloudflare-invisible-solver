// Per-load constant extractor for the Turnstile challenge VM bundle.
//
// The body-critical constants rotate every Turnstile version and must be
// re-read from a fresh bundle rather than hardcoded. This script takes a RAW
// (still-obfuscated) bundle -- e.g. the `vm_raw.js` captured from
// `challenges.cloudflare.com/.../turnstile/.../<sitekey>/...` -- and recovers,
// without executing the page's network/DOM code:
//
//   * aj          -- the 65-char custom-base64 alphabet            (build_flow_ov_body)
//   * ag          -- the RSA modulus N (1024-bit, key transport)   (rsa_block)
//   * ae          -- the RSA public exponent e (normally 65537)    (rsa_block)
//   * rotation K  -- the load-time string-table rotation, derived by executing
//                    the obfuscator's own self-defending shuffler (lets you
//                    decode any table-stored string; not needed for the three
//                    body constants above, which are inline literals in this
//                    bundle family, but reported for completeness).
//
// In this bundle family `aj`/`ag`/`ae` are inline string/BigInt literals (only
// small constants like 0xff go through the string table), so they are read by
// AST shape -- NOT by the variable names `aj`/`ag`/`ae`, which the minifier
// rotates per version. Output is JSON on stdout:
//
//   { alphabet, rsa_n_hex, rsa_e, rotation_k, table_len, decoder_offset, warnings }
//
// Usage:  node extract-constants.js <raw-bundle.js>
// Reuse:  const { extractConstants } = require("./extract-constants");

const fs = require("fs");
const vm = require("vm");
const parser = require("@babel/parser");
const traverse = require("@babel/traverse").default;
const generate = require("@babel/generator").default;
const t = require("@babel/types");

// 65 symbols over the JSD/Turnstile alphabet charset (utils/constants.py ENC_KEY_RE).
const ALPHABET_RE = /^[A-Za-z0-9+\-$]{65}$/;
// Public exponents we recognise; 65537 is near-universal for RSA key transport.
const KNOWN_EXPONENTS = new Set([3, 5, 17, 257, 65537]);

function bigIntArgValue(node) {
  // BigInt('0x..') / BigInt('123') / BigInt(123) -> BigInt, else null.
  if (!t.isCallExpression(node) || !t.isIdentifier(node.callee, { name: "BigInt" })) {
    return null;
  }
  if (node.arguments.length !== 1) return null;
  const arg = node.arguments[0];
  try {
    if (t.isStringLiteral(arg)) return BigInt(arg.value);
    if (t.isNumericLiteral(arg)) return BigInt(arg.value);
  } catch (_) {
    return null;
  }
  return null;
}

function extractAlphabet(ast, warnings) {
  const hits = new Set();
  traverse(ast, {
    StringLiteral(path) {
      if (ALPHABET_RE.test(path.node.value)) hits.add(path.node.value);
    },
  });
  if (hits.size === 0) {
    warnings.push("alphabet: no 65-char [A-Za-z0-9+-$] literal found");
    return null;
  }
  if (hits.size > 1) {
    warnings.push("alphabet: multiple 65-char candidates: " + JSON.stringify([...hits]));
  }
  return [...hits][0];
}

function extractRsa(ast, warnings) {
  // Collect every BigInt(...) call with a constant argument, in source order.
  const calls = [];
  traverse(ast, {
    CallExpression(path) {
      const v = bigIntArgValue(path.node);
      if (v === null) return;
      const arg = path.node.arguments[0];
      calls.push({
        value: v,
        start: typeof path.node.start === "number" ? path.node.start : Infinity,
        isString: t.isStringLiteral(arg),
      });
    },
  });
  calls.sort((a, b) => a.start - b.start);

  // Modulus = the largest BigInt built from a string literal (1024-bit RSA N is
  // ~309 decimal / 256 hex digits; dwarfs every other constant in the bundle).
  let modulus = null;
  for (const c of calls) {
    if (c.isString && (modulus === null || c.value > modulus.value)) modulus = c;
  }
  if (modulus === null) {
    warnings.push("rsa: no BigInt(<string>) modulus candidate found");
    return { nHex: null, e: null };
  }
  if (modulus.value.toString(2).length < 512) {
    warnings.push("rsa: modulus is only " + modulus.value.toString(2).length + " bits (<512)");
  }

  // Exponent = the first BigInt(<numeric>) at/after the modulus position that is
  // a plausible public exponent (odd, >1). RSA emits `N` then `e` adjacently
  // (`ag=BigInt('0x..'),ae=BigInt(65537)`). Fall back to a known-exponent scan.
  const numerics = calls.filter((c) => !c.isString);
  const plausible = (v) => v > 1n && (v & 1n) === 1n;
  let exponent = null;
  for (const c of numerics) {
    if (c.start >= modulus.start && plausible(c.value)) {
      exponent = c.value;
      break;
    }
  }
  if (exponent === null) {
    const known = numerics.find((c) => KNOWN_EXPONENTS.has(Number(c.value)));
    if (known) exponent = known.value;
  }
  if (exponent === null) {
    warnings.push("rsa: no plausible public exponent found; defaulting to 65537");
    exponent = 65537n;
  } else if (!KNOWN_EXPONENTS.has(Number(exponent))) {
    warnings.push("rsa: unusual public exponent " + exponent.toString());
  }

  return { nHex: "0x" + modulus.value.toString(16), e: Number(exponent) };
}

// Derive the load-time string-table rotation by locating and EXECUTING the
// obfuscator's self-defending shuffler IIFE -- never guessed. Mirrors the logic
// in decode-strings.js so the two stay consistent.
function deriveRotation(ast, warnings) {
  let table = null;
  traverse(ast, {
    CallExpression(path) {
      const { callee, arguments: args } = path.node;
      if (
        t.isMemberExpression(callee) &&
        t.isStringLiteral(callee.object) &&
        t.isIdentifier(callee.property, { name: "split" }) &&
        args.length === 1 &&
        t.isStringLiteral(args[0])
      ) {
        const arr = callee.object.value.split(args[0].value);
        if (arr.length > 500 && (!table || arr.length > table.length)) table = arr;
      }
    },
  });
  if (!table) {
    warnings.push("rotation: string table not found");
    return { rotationK: null, tableLen: null, offset: null };
  }

  // Candidate decoder offsets: every `X = X - N` subtraction constant used by a
  // small array-indexing function. The decoder shape `function(i){i=i-N;return
  // table[i]}` is duplicated/aliased, so the real N tends to recur; we collect
  // all candidates and let the checksum decide which is correct (below). Trying
  // the wrong N makes the shuffler's self-checksum never converge.
  const offsetCounts = new Map();
  traverse(ast, {
    Function(path) {
      if (!path.get("body").isBlockStatement()) return;
      let sub = null;
      path.traverse({
        AssignmentExpression(p) {
          const r = p.node.right;
          if (t.isBinaryExpression(r) && r.operator === "-" && t.isIdentifier(r.left) && t.isNumericLiteral(r.right)) sub = r.right.value;
        },
        VariableDeclarator(p) {
          const r = p.node.init;
          if (r && t.isBinaryExpression(r) && r.operator === "-" && t.isIdentifier(r.left) && t.isNumericLiteral(r.right)) sub = r.right.value;
        },
      });
      if (sub !== null && path.node.body.body.length <= 6) {
        const code = generate(path.node).code;
        if (/\[\s*[A-Za-z_$][\w$]*\s*\]/.test(code)) offsetCounts.set(sub, (offsetCounts.get(sub) || 0) + 1);
      }
    },
  });
  // Order: most-recurring first, then larger constants (obfuscator offsets are
  // typically 3-digit, e.g. 114) ahead of incidental `x - 1` style indexers.
  const candidateOffsets = [...offsetCounts.keys()].sort((x, y) => {
    const c = (offsetCounts.get(y) || 0) - (offsetCounts.get(x) || 0);
    return c !== 0 ? c : y - x;
  });
  if (candidateOffsets.length === 0) candidateOffsets.push(0);

  let shufflerCode = null;
  let shufflerTarget = null;
  traverse(ast, {
    CallExpression(path) {
      const { callee, arguments: args } = path.node;
      if (
        t.isFunctionExpression(callee) &&
        args.length === 2 &&
        t.isIdentifier(args[0]) &&
        t.isNumericLiteral(args[1]) &&
        shufflerCode === null
      ) {
        const code = generate(callee).code;
        if (/\.\s*push\s*\(\s*\w+\s*\.\s*shift\s*\(\s*\)\s*\)/.test(code)) {
          shufflerCode = code;
          shufflerTarget = args[1].value;
          path.stop();
        }
      }
    },
  });
  if (shufflerCode === null) {
    warnings.push("rotation: shuffler IIFE not found; table may be unrotated");
    return { rotationK: 0, tableLen: table.length, offset: candidateOffsets[0] };
  }

  // Execute the obfuscator's own self-defending shuffler to DERIVE the rotation
  // (never guessed). It loops `arr.push(arr.shift())` until a checksum over the
  // decoded strings equals a target; with the wrong decoder offset that checksum
  // never matches and the loop spins forever, so we run it in a vm sandbox with
  // a wall-clock timeout and treat "completed without timing out" as the signal
  // that this offset is correct.
  for (const offset of candidateOffsets) {
    const Jm = table.slice();
    const before = Jm.slice();
    const sandbox = { Jm, parseInt, String, Number, isNaN };
    const runner = `
      var __a = function () { return Jm; };
      var p = function (V) { V = V - ${offset}; return __a()[V]; };
      (${shufflerCode})(__a, ${shufflerTarget});
    `;
    try {
      vm.runInNewContext(runner, sandbox, { timeout: 1500 });
    } catch (err) {
      // Timeout (wrong offset -> checksum never converges) or runtime error.
      continue;
    }
    const rotationK = ((before.indexOf(sandbox.Jm[0]) % table.length) + table.length) % table.length;
    return { rotationK, tableLen: table.length, offset };
  }
  warnings.push("rotation: no candidate offset converged the shuffler checksum");
  return { rotationK: null, tableLen: table.length, offset: candidateOffsets[0] };
}

function extractConstants(src) {
  const ast = parser.parse(src, { sourceType: "script" });
  const warnings = [];
  const alphabet = extractAlphabet(ast, warnings);
  const { nHex, e } = extractRsa(ast, warnings);
  const { rotationK, tableLen, offset } = deriveRotation(ast, warnings);
  return {
    alphabet,
    rsa_n_hex: nHex,
    rsa_e: e,
    rotation_k: rotationK,
    table_len: tableLen,
    decoder_offset: offset,
    warnings,
  };
}

module.exports = { extractConstants };

if (require.main === module) {
  const inPath = process.argv[2];
  if (!inPath) {
    console.error("Usage: node extract-constants.js <raw-bundle.js>");
    process.exit(1);
  }
  const out = extractConstants(fs.readFileSync(inPath, "utf8"));
  process.stdout.write(JSON.stringify(out, null, 2) + "\n");
}
