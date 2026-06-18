// Faithful port of the Turnstile env-probe fingerprint collector
// (aM enumerate -> aP classify -> gpLd0 bucket), recovered from
// research/turnstile-vm/decoded.js:
//   * aM      -> decoded.js:8202  (Object.keys up the prototype chain)
//   * aP      -> decoded.js:7025  (value -> single category char)
//   * gpLd0   -> decoded.js:2561-2666 (per-root collection loop)
//   * aK      -> decoded.js:2553-2559 (typeof -> char table)
//
// The VM runs gpLd0 once PER ROOT object, accumulating into a single map; the
// driver that chooses the root set + prefix is bytecode-driven (JSVMP dispatch)
// and is NOT statically recoverable, so the root set below is reconstructed from
// the recovered evidence ("d.cookie" => document="d.", n.vendor => navigator="n.",
// outerWidth bucketed unprefixed => window=""). Override by passing your own list.
//
// Usage (in a real browser / via CDP Runtime.evaluate):
//   __cfCollectFingerprint()                 // default roots
//   __cfCollectFingerprint([{path:"navigator",prefix:"n."}, ...])
// Returns { "<value-or-categoryChar>": ["<prefix><propName>", ...], ... }.

(function (globalScope) {
  var DEFAULT_ROOTS = [
    { path: "window", prefix: "" },
    { path: "navigator", prefix: "n." },
    { path: "document", prefix: "d." },
    { path: "screen", prefix: "s." },
    { path: "location", prefix: "l." },
    { path: "history", prefix: "h." },
  ];

  function aM(obj) {
    // decoded.js:8202 -- enumerable own keys up the whole prototype chain.
    var names = [];
    while (obj !== null && obj !== undefined) {
      names = names.concat(Object.keys(obj));
      obj = Object.getPrototypeOf(obj);
    }
    return names;
  }

  // decoded.js:2553-2559 -- typeof -> category char.
  var aK = {
    object: "o",
    string: "s",
    undefined: "u",
    symbol: "z",
    number: "n",
    bigint: "I",
  };

  function aP(N, v) {
    // decoded.js:7025 -- classify a value to one category char.
    if (v === null || v === undefined) return v === undefined ? "u" : "x";
    var t = typeof v;
    if (t === "object") {
      try {
        if (N.Promise && v instanceof N.Promise) {
          v.catch(function () {});
          return "p";
        }
      } catch (e) {}
    }
    return Array.isArray(v)
      ? "a"
      : v === N.Array
      ? "D"
      : v === true
      ? "T"
      : v === false
      ? "F"
      : t === "function"
      ? v instanceof N.Function &&
        N.Function.prototype.toString.call(v).indexOf("[native code]") > 0
        ? "N"
        : "f"
      : aK[t] || "?";
  }

  function bucket(out, name, key) {
    // decoded.js:2660 -- out[key] = out[key] || []; out[key].push(name).
    key = String(key);
    if (!Object.prototype.hasOwnProperty.call(out, key)) out[key] = [];
    out[key].push(name);
  }

  function collect(N, H, prefix, out) {
    // decoded.js:2618-2666 -- the per-root collection loop (gpLd0 body).
    if (H === null || H === undefined) return out;
    var keys = aM(H);
    if (N.Object.getOwnPropertyNames) {
      keys = keys.concat(N.Object.getOwnPropertyNames(H));
    }
    keys =
      N.Array.from && N.Set
        ? N.Array.from(new N.Set(keys))
        : keys
            .sort()
            .filter(function (v, i, a) {
              return i === 0 || v !== a[i - 1];
            });
    var numeric = ["n", "s", "a"]; // 'nAsAa'.split('A')
    for (var i = 0; i < keys.length; i++) {
      var name = keys[i];
      var full = prefix + name;
      try {
        var v = H[name];
        var cat = aP(N, v);
        if (numeric.indexOf(cat) !== -1) {
          var num = +v;
          var isNumericString = cat === "s" && num === num;
          if (full === "d.cookie") {
            bucket(out, full, cat); // cookie: bucket by category only
          } else if (!isNumericString) {
            bucket(out, full, v); // else bucket under the LITERAL value
          }
          // numeric-looking strings are dropped
        } else {
          bucket(out, full, cat); // bucket under the category char
        }
      } catch (e) {
        bucket(out, full, "i"); // inaccessible getter
      }
    }
    return out;
  }

  function collectFingerprint(roots) {
    var N = globalScope;
    roots = roots || DEFAULT_ROOTS;
    var out = {};
    for (var r = 0; r < roots.length; r++) {
      var spec = roots[r];
      var obj = spec.obj;
      if (obj === undefined && spec.path) {
        try {
          obj = spec.path.split(".").reduce(function (acc, k) {
            return acc == null ? acc : acc[k];
          }, N);
        } catch (e) {
          obj = undefined;
        }
      }
      collect(N, obj, spec.prefix || "", out);
    }
    return out;
  }

  collectFingerprint.DEFAULT_ROOTS = DEFAULT_ROOTS;
  globalScope.__cfCollectFingerprint = collectFingerprint;
  if (typeof module !== "undefined" && module.exports) {
    module.exports = collectFingerprint;
  }
  return collectFingerprint;
})(typeof window !== "undefined" ? window : globalThis);
