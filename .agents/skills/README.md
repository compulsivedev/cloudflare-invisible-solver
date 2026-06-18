# Agent skills

Reverse-engineering skills available to coding agents (Devin, Claude Code, Codex,
Cursor, etc.) when working in this repo. Each skill is a directory with a
`SKILL.md` (YAML frontmatter + prompt) plus its own `references/`, `scripts/`,
and `assets/`. Agents that support `.agents/skills/` auto-discover these and can
invoke them by name.

## Skills

- **`ast-deobfuscation`** — Layered, reversible Babel-AST deobfuscation for
  obfuscated JavaScript: `_0x` identifiers, string tables, self-decoding
  wrappers, dispatcher objects, fake branches, `while/for + switch` control-flow
  flattening, and `if (literal === opcode)` dispatch chains, with detectors and
  site-specific pipelines.
- **`web-reverse-algorithm`** — Pure-algorithm / protocol analysis for header &
  cookie signatures, mixed encryption, JSVMP/VMP, Wasm, PoW, response
  decryption, captcha parameter recovery, and challenge/verify flows; works
  backward from the final request to writer → builder → entry → source.
- **`web-reverse-env`** — Browser environment patching (补环境): Proxy-based
  environment probing, prototype-chain repair, native `toString` protection,
  descriptor guards, and modular `navigator` / `document` / `storage` /
  `canvas` / `WebGL` / `crypto` / `performance` / `WebRTC` / `Worker` builders.

These map directly onto the work this repo does — deobfuscating and reproducing
Cloudflare's challenge JavaScript.

## Attribution

These skills are vendored from [lwjjike/xbsReverseSkill](https://github.com/lwjjike/xbsReverseSkill)
and distributed under the MIT License. See [`LICENSE`](./LICENSE) for the
upstream copyright notice. Most skill content and reference docs are in Chinese.
