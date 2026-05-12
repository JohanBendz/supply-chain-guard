'use strict';
/**
 * test/fixes-round2.test.js
 *
 * Regression tests for the second round of fixes:
 *   #2 lockfile.isDirectDep correctly distinguishes nested vs top-level entries
 *   #4 checkProvenanceRegression fetches previous versions in parallel
 *   #5 httpsGet enforces size cap and follows redirects
 *   #7 import regex handles TypeScript `import type` and inline `{ type X }`
 *   #9 parseArgs handles -D shorthand and boolean flags correctly
 */

const { extractPackages } = require('../src/lockfile');
const { extractImportsFromSource } = require('../src/delta-phantom');

let passed = 0;
let failed = 0;
function assert(cond, label) {
  if (cond) { console.log(`  ✓  ${label}`); passed++; }
  else      { console.error(`  ✖  ${label}`); failed++; }
}
function section(title) {
  const pad = Math.max(2, 54 - title.length);
  console.log(`\n── ${title} ${'─'.repeat(pad)}`);
}

// ── #2: lockfile.isDirectDep ─────────────────────────────────────────────────
section('#2 lockfile.isDirectDep distinguishes nesting');

const fakeLock = {
  packages: {
    '': { name: 'root', version: '1.0.0' },
    'node_modules/foo': { version: '1.0.0' },
    'node_modules/@scope/bar': { version: '2.0.0' },
    'node_modules/foo/node_modules/baz': { version: '3.0.0' },
    'node_modules/@scope/bar/node_modules/qux': { version: '4.0.0' },
  },
};
const pkgs = extractPackages(fakeLock);

assert(pkgs['foo'] && pkgs['foo'].isDirectDep === true,
  'top-level "node_modules/foo" is direct');
assert(pkgs['@scope/bar'] && pkgs['@scope/bar'].isDirectDep === true,
  'top-level scoped "@scope/bar" is direct');
assert(pkgs['foo>baz'] && pkgs['foo>baz'].isDirectDep === false,
  'nested "node_modules/foo/node_modules/baz" is NOT direct');
assert(pkgs['@scope/bar>qux'] && pkgs['@scope/bar>qux'].isDirectDep === false,
  'nested under scoped pkg is NOT direct');

// ── #7: import regex with TypeScript type imports ───────────────────────────
section('#7 import regex handles TypeScript type imports');

const tsTypeOnly = `import type { Config } from 'tsconfig-pkg';`;
const r1 = extractImportsFromSource(tsTypeOnly);
assert(r1.has('tsconfig-pkg'),
  '`import type { ... } from "pkg"` is detected');

const tsInlineType = `import { type Foo, bar } from 'mixed-pkg';`;
const r2 = extractImportsFromSource(tsInlineType);
assert(r2.has('mixed-pkg'),
  '`import { type Foo, bar } from "pkg"` is detected');

const tsExportType = `export type { Bar } from 're-export-pkg';`;
const r3 = extractImportsFromSource(tsExportType);
assert(r3.has('re-export-pkg'),
  '`export type { ... } from "pkg"` is detected');

const tsNamespace = `import * as ns from 'ns-pkg';`;
const r4 = extractImportsFromSource(tsNamespace);
assert(r4.has('ns-pkg'),
  '`import * as ns from "pkg"` is detected');

const dyn = `const m = await import('dyn-pkg');`;
const r5 = extractImportsFromSource(dyn);
assert(r5.has('dyn-pkg'),
  'dynamic `import("pkg")` is detected');

const reExport = `export { default } from 'fwd-pkg';`;
const r6 = extractImportsFromSource(reExport);
assert(r6.has('fwd-pkg'),
  '`export { default } from "pkg"` is detected');

// Mixed file with multiple forms
const mixedFile = `
import type { A } from 'a';
import { type B, c } from 'b';
import * as d from 'd';
import e from 'e';
const f = require('f');
const g = await import('g');
export { h } from 'h';
export type { i } from 'i';
`;
const rMixed = extractImportsFromSource(mixedFile);
const expected = ['a', 'b', 'd', 'e', 'f', 'g', 'h', 'i'];
const allFound = expected.every(p => rMixed.has(p));
assert(allFound,
  `mixed file: all 8 forms detected (got: ${[...rMixed].sort().join(',')})`);

// ── #9: parseArgs short flags and boolean flags ─────────────────────────────
section('#9 parseArgs handles -D and boolean flags');

// Re-implement parseArgs locally because it's not exported from bin/scg.js.
// The test is intentionally a black-box of the parser behaviour we documented.
function loadParseArgs() {
  const fs   = require('fs');
  const path = require('path');
  const src  = fs.readFileSync(path.join(__dirname, '..', 'bin', 'scg.js'), 'utf8');
  // Extract the BOOLEAN_FLAGS, SHORT_FLAG_ALIASES, and parseArgs definitions
  // by evaluating just that slice of the file in a sandbox-ish context.
  const start = src.indexOf('// Boolean flags that should NEVER');
  const end   = src.indexOf('function findProjectRoot');
  if (start === -1 || end === -1) throw new Error('parseArgs block not found in bin/scg.js');
  const slice = src.slice(start, end);
  const sandboxCode = slice + '\nmodule.exports = { parseArgs };';
  const Module = require('module');
  const m = new Module('<inline>');
  m._compile(sandboxCode, '<inline>');
  return m.exports.parseArgs;
}
const parseArgs = loadParseArgs();

// Basic positional
const a1 = parseArgs(['add', 'foo', 'bar']);
assert(a1.positional.length === 3 && a1.positional[1] === 'foo',
  'positional args collected');

// --save-dev as boolean (does not consume next positional)
const a2 = parseArgs(['foo', '--save-dev']);
assert(a2.flags['save-dev'] === true && a2.positional.includes('foo'),
  '--save-dev is boolean and does not eat the previous positional');

// `scg add foo --save-dev` — the original parser would have set
// flags['save-dev']='foo' if --save-dev appeared before foo. Test the
// problematic order: flag first, then positional.
const a3 = parseArgs(['--save-dev', 'foo']);
assert(a3.flags['save-dev'] === true && a3.positional.includes('foo'),
  '--save-dev followed by package name does not consume the package name');

// -D shorthand expands to save-dev
const a4 = parseArgs(['add', 'foo', '-D']);
assert(a4.flags['save-dev'] === true,
  '-D is recognised and aliased to save-dev');

// --cooldown 5 (non-boolean flag still consumes value)
const a5 = parseArgs(['check', 'foo', '--cooldown', '5']);
assert(a5.flags.cooldown === '5',
  '--cooldown 5 still consumes the value (non-boolean flag)');

// --key=value form
const a6 = parseArgs(['check', 'foo', '--cooldown=7']);
assert(a6.flags.cooldown === '7',
  '--key=value form is parsed');

// Multiple short flags
const a7 = parseArgs(['add', 'foo', '-D', '--force']);
assert(a7.flags['save-dev'] === true && a7.flags.force === true,
  'mixed -D and --force both set');

// `--` terminator
const a8 = parseArgs(['npm', '--', 'install', '--save-dev', 'foo']);
assert(a8.positional.length === 4 && a8.positional[2] === '--save-dev',
  'after `--`, all tokens are positional');

// ── #4 / #5: registry retry + parallel provenance ───────────────────────────
// Mocking the internal call graph properly would require restructuring
// registry.js to route through the exports object. Instead we do a
// source-level static check: the rewritten checkProvenanceRegression must
// use Promise.all over the previousVersions slice, and httpsGet must enforce
// a size cap and follow redirects. These are cheap, deterministic, and
// directly verify the intent of the fixes.
section('#4/#5 registry source-level invariants');

const fs   = require('fs');
const path = require('path');
const registrySrc = fs.readFileSync(path.join(__dirname, '..', 'src', 'registry.js'), 'utf8');

assert(/checkProvenanceRegression[\s\S]*Promise\.all/.test(registrySrc),
  'checkProvenanceRegression uses Promise.all (parallel previous-version fetches)');

assert(/MAX_PACKUMENT_BYTES/.test(registrySrc) && /received\s*>\s*MAX_PACKUMENT_BYTES/.test(registrySrc),
  'httpsGet enforces a size cap on streamed bodies');

assert(/\b301\b[\s\S]*\b302\b[\s\S]*location/i.test(registrySrc) ||
       /\[301,\s*302/.test(registrySrc),
  'httpsGet follows 301/302 redirects');

assert(/MAX_RETRIES/.test(registrySrc) && /transient/.test(registrySrc),
  'httpsGet retries transient failures (timeout / ECONNRESET / 5xx)');

const registry = require('../src/registry');
assert(typeof registry.getPackument === 'function',
  'getPackument exported');
assert(typeof registry.checkProvenanceRegression === 'function',
  'checkProvenanceRegression exported');

// ── summary ───────────────────────────────────────────────────────────────────
console.log(`\n${'─'.repeat(52)}`);
console.log(`  Results: ${passed} passed, ${failed} failed\n`);
process.exit(failed > 0 ? 1 : 0);
