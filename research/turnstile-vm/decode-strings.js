// Decode Cloudflare Turnstile VM string-table obfuscation.
// Pattern: decoder p(i) = table[i - OFFSET]; many aliases (lC=p, ZB=lC, Zh=lC...).
// Usage sites: ALIAS(obj.key) where obj = {V:435,...} is a per-function numeric const-object,
//              or ALIAS(<numericLiteral>).
const fs = require("fs");
const parser = require("@babel/parser");
const traverse = require("@babel/traverse").default;
const generate = require("@babel/generator").default;
const t = require("@babel/types");

const inPath = process.argv[2];
const outPath = process.argv[3];
const src = fs.readFileSync(inPath, "utf8");
const ast = parser.parse(src, { sourceType: "script" });

// ---- 1. Extract the string table: <bigString>.split(';') ----
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
if (!table) throw new Error("string table not found");

// ---- 2. Find decoder offset: function with `X = X - N` then returns table[X] ----
let offset = null;
traverse(ast, {
  Function(path) {
    const body = path.get("body");
    if (!body.isBlockStatement()) return;
    let sub = null;
    path.traverse({
      AssignmentExpression(p) {
        const r = p.node.right;
        if (
          t.isBinaryExpression(r) &&
          r.operator === "-" &&
          t.isIdentifier(r.left) &&
          t.isNumericLiteral(r.right)
        )
          sub = r.right.value;
      },
      VariableDeclarator(p) {
        const r = p.node.init;
        if (
          r &&
          t.isBinaryExpression(r) &&
          r.operator === "-" &&
          t.isIdentifier(r.left) &&
          t.isNumericLiteral(r.right)
        )
          sub = r.right.value;
      },
    });
    // heuristic: decoder body is tiny and contains a member-index return
    if (sub !== null && path.node.body.body.length <= 6) {
      const code = generate(path.node).code;
      if (/\[\s*[A-Za-z_$][\w$]*\s*\]/.test(code) && offset === null) offset = sub;
    }
  },
});
if (offset === null) offset = 114;

// ---- 2b. Rotate the table to its runtime order by executing the self-defending
// shuffler IIFE verbatim. obfuscator.io ships a `(function(){... arr.push(arr.shift())
// until checksum===target ...})(arrayProvider, target)` that rotates the array at load
// time; decoding against the static order is off by that rotation. We reconstruct a
// memoized provider `a` + decoder `p` and run the REAL shuffler so the rotation is
// derived, never guessed.
let rotation = 0;
{
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
  if (shufflerCode !== null) {
    let Jm = table; // mutate this array object in place
    const a = function () {
      return Jm;
    };
    // decoder used by the checksum; mirrors source `p(i){i=i-offset;return a()[i];}`
    // eslint-disable-next-line no-unused-vars
    const p = function (V) {
      V = V - offset;
      return a()[V];
    };
    const before = Jm.slice();
    // direct eval: the reconstructed shuffler closes over local `p`/`parseInt`
    // eslint-disable-next-line no-eval
    const runShuffler = eval("(" + shufflerCode + ")");
    runShuffler(a, shufflerTarget);
    rotation = (before.indexOf(Jm[0]) % table.length + table.length) % table.length;
  }
}

const decode = (i) => table[i - offset];

// ---- 3. Build decoder alias set (fixpoint over `name = <aliasIdent>`) ----
const decoderFnNames = new Set();
// the function that owns the subtraction+index is the root decoder; also seed common 'p'
traverse(ast, {
  Function(path) {
    if (!path.node.id) return;
    const code = generate(path.node).code;
    if (new RegExp("-\\s*" + offset + "\\b").test(code) && /\[[A-Za-z_$][\w$]*\]/.test(code))
      decoderFnNames.add(path.node.id.name);
  },
});
const aliases = new Set(decoderFnNames);
let changed = true;
while (changed) {
  changed = false;
  traverse(ast, {
    AssignmentExpression(p) {
      if (
        t.isIdentifier(p.node.left) &&
        t.isIdentifier(p.node.right) &&
        aliases.has(p.node.right.name) &&
        !aliases.has(p.node.left.name)
      ) {
        aliases.add(p.node.left.name);
        changed = true;
      }
    },
    VariableDeclarator(p) {
      if (
        t.isIdentifier(p.node.id) &&
        p.node.init &&
        t.isIdentifier(p.node.init) &&
        aliases.has(p.node.init.name) &&
        !aliases.has(p.node.id.name)
      ) {
        aliases.add(p.node.id.name);
        changed = true;
      }
    },
  });
}

// ---- 4. Record numeric const-objects keyed by their binding ----
const objMaps = new Map(); // binding -> {propName: number}
function recordObj(namePath, objExpr, scope) {
  if (!t.isObjectExpression(objExpr)) return;
  const m = {};
  for (const prop of objExpr.properties) {
    if (!t.isObjectProperty(prop)) return;
    const key = t.isIdentifier(prop.key)
      ? prop.key.name
      : t.isStringLiteral(prop.key)
      ? prop.key.value
      : null;
    if (key === null) return;
    if (t.isNumericLiteral(prop.value)) m[key] = prop.value.value;
    else return; // not a pure-numeric const object
  }
  const binding = scope.getBinding(namePath);
  if (binding) objMaps.set(binding, m);
}
traverse(ast, {
  AssignmentExpression(p) {
    if (t.isIdentifier(p.node.left) && t.isObjectExpression(p.node.right))
      recordObj(p.node.left.name, p.node.right, p.scope);
  },
  VariableDeclarator(p) {
    if (t.isIdentifier(p.node.id) && p.node.init && t.isObjectExpression(p.node.init))
      recordObj(p.node.id.name, p.node.init, p.scope);
  },
});

// ---- 5. Replace ALIAS(arg) with decoded string literal ----
let replaced = 0;
let remaining = 0;
traverse(ast, {
  CallExpression(path) {
    const { callee, arguments: args } = path.node;
    if (!t.isIdentifier(callee) || !aliases.has(callee.name)) return;
    if (args.length !== 1) return;
    let idx = null;
    const arg = args[0];
    if (t.isNumericLiteral(arg)) {
      idx = arg.value;
    } else if (t.isMemberExpression(arg) && !arg.computed && t.isIdentifier(arg.object) && t.isIdentifier(arg.property)) {
      const binding = path.scope.getBinding(arg.object.name);
      const m = binding && objMaps.get(binding);
      if (m && Object.prototype.hasOwnProperty.call(m, arg.property.name)) idx = m[arg.property.name];
    }
    if (idx === null) {
      remaining++;
      return;
    }
    const val = decode(idx);
    if (typeof val !== "string") {
      remaining++;
      return;
    }
    path.replaceWith(t.stringLiteral(val));
    replaced++;
  },
});

const out = generate(ast, { jsescOption: { minimal: true } }).code;
fs.writeFileSync(outPath, out);
console.log(
  JSON.stringify(
    {
      tableLen: table.length,
      offset,
      rotation,
      decoderFnNames: [...decoderFnNames],
      aliasCount: aliases.size,
      constObjects: objMaps.size,
      replaced,
      remainingDecoderCalls: remaining,
    },
    null,
    2
  )
);
