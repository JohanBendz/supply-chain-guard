'use strict';
/**
 * test/js-lexer.test.js
 *
 * Tests the lexer's ability to correctly classify CODE vs non-CODE regions.
 * The acceptance criterion is: extractCode(src) preserves require()/import
 * statements that are real code, and removes those that live inside strings,
 * templates, regexes, or comments. The four evasion classes from the design
 * doc each have explicit tests below.
 */

const { tokenize, extractCode } = require('../src/js-lexer');

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

// Helper: does extractCode(src) contain `marker`?
function codeHas(src, marker) {
  return extractCode(src).includes(marker);
}

// ── Baseline: ordinary JS works correctly ────────────────────────────────────
section('baseline — ordinary JavaScript');

assert(codeHas(`const x = require('real-pkg');`, "require('real-pkg')"),
  'plain require call is preserved as code');

assert(codeHas(`import foo from 'real-pkg';`, "from 'real-pkg'"),
  'plain ES import is preserved');

assert(!codeHas(`// require('commented-out')`, "require('commented-out')"),
  'line-commented require is removed');

assert(!codeHas(`/* require('blocked') */`, "require('blocked')"),
  'block-commented require is removed');

// ── Evasion class (a): block comment syntax INSIDE template literal ──────────
section('evasion (a) — block-comment syntax in template literal');

const evasionA = [
  'const sql = `',
  '  SELECT * FROM users',
  '  /* this is SQL, not JS */',
  '`;',
  "require('real-pkg-after-template');",
].join('\n');

assert(codeHas(evasionA, "require('real-pkg-after-template')"),
  'template literal containing /* */ does NOT swallow following require');

assert(!codeHas(evasionA, 'SELECT'),
  'template literal contents are NOT classified as code');

// More aggressive variant: SQL-style comment terminator looks like JS-end
const evasionA2 = [
  'const sql = `SELECT /* not a JS comment */ FROM x`;',
  "require('still-real');",
].join('\n');
assert(codeHas(evasionA2, "require('still-real')"),
  'aggressive variant: inline /* */ inside template does not break following code');

// ── Evasion class (b): line-comment syntax inside string literal ─────────────
section('evasion (b) — line-comment syntax in string literal');

const evasionB = [
  "const url = 'https://example.com//path/to/thing';",
  "require('real-pkg-after-string');",
].join('\n');

assert(codeHas(evasionB, "require('real-pkg-after-string')"),
  '// inside string does NOT trigger line-comment strip');

// Note: under the v2 design, string literals stay in CODE so the
// require() argument is matchable. The string CONTENTS are therefore
// visible in extractCode output — that's intentional. What matters
// is that the // sequence inside the string didn't swallow the
// following require(), which the previous assertion already covers.
assert(codeHas(evasionB, 'example.com'),
  'string contents stay in code (so require() argument is matchable)');

// Variant with double quotes
const evasionB2 = [
  'const path = "/usr/local//bin";',
  "const x = require('real');",
].join('\n');
assert(codeHas(evasionB2, "require('real')"),
  'double-quoted string with // is handled correctly');

// ── Evasion class (c): regex literal containing comment-like sequences ───────
section('evasion (c) — regex literal with comment-like content');

const evasionC = [
  'const re = /\\/\\*.*?\\*\\//;',
  "require('real-after-regex');",
].join('\n');

assert(codeHas(evasionC, "require('real-after-regex')"),
  'regex literal containing /* */ pattern does not break following require');

// Regex literal with // inside char class
const evasionC2 = [
  'const re = /[/\\/]+/g;',
  "const x = require('real');",
].join('\n');
assert(codeHas(evasionC2, "require('real')"),
  'regex literal with / inside char class is handled');

// Division must NOT be misread as regex
const division = `const a = 10; const b = a / 2; const c = require('real');`;
assert(codeHas(division, "require('real')"),
  'division operator is not misread as regex literal opening');

// Regex after return keyword
const regexAfterReturn = [
  'function f() { return /foo/.test("bar"); }',
  "require('real');",
].join('\n');
assert(codeHas(regexAfterReturn, "require('real')"),
  'regex after `return` is handled correctly');

// ── Evasion class (d): string pair bracketing real code with fake markers ────
section('evasion (d) — string pair bracketing fake comment markers');

// The classic attack: place "/*" and "*/" as separate string literals so
// the old regex strip eats everything between them.
const evasionD = [
  'const a = "/*";',
  "require('hidden-by-naive-strip');",
  'const b = "*/";',
].join('\n');

assert(codeHas(evasionD, "require('hidden-by-naive-strip')"),
  'fake "/*" and "*/" string literals do not hide code between them');

// Same with single quotes
const evasionD2 = [
  "const a = '/*';",
  "require('still-visible');",
  "const b = '*/';",
].join('\n');
assert(codeHas(evasionD2, "require('still-visible')"),
  'single-quoted variant of evasion (d)');

// Mixed: template literal containing fake markers
const evasionD3 = [
  'const a = `/*`;',
  "require('template-variant');",
  'const b = `*/`;',
].join('\n');
assert(codeHas(evasionD3, "require('template-variant')"),
  'template literal variant of evasion (d)');

// ── Template literal interpolation ───────────────────────────────────────────
section('template literal interpolation');

const tplInterp = [
  'const x = `result: ${require("real-from-interpolation")}`;',
].join('\n');
assert(codeHas(tplInterp, 'require("real-from-interpolation")'),
  'require() inside ${...} interpolation IS preserved as code');

// Nested template inside interpolation
const nestedTpl = [
  'const x = `outer ${`inner ${require("deeply-nested")}`}`;',
].join('\n');
assert(codeHas(nestedTpl, 'require("deeply-nested")'),
  'require() inside nested ${...} template interpolation is preserved');

// Interpolation that contains an object literal — `{` braces inside ${...}
// must not prematurely close the interpolation.
const interpWithObj = [
  'const x = `${ {a: require("inside-object")} }`;',
  "require('after');",
].join('\n');
assert(codeHas(interpWithObj, 'require("inside-object")') &&
       codeHas(interpWithObj, "require('after')"),
  'object literal inside ${...} does not confuse brace tracking');

// Pure template, no interpolation, no require — should produce no false positives
const pureTpl = "const x = `require('fake-from-template')`;";
assert(!codeHas(pureTpl, "require('fake-from-template')"),
  'require() text inside a plain template literal is NOT classified as code');

// ── String escape sequences ──────────────────────────────────────────────────
section('string escape sequences');

// Escaped quote inside string must not terminate the string early
const escapedQuote = [
  `const a = 'it\\'s a test with require(\\'fake\\') in it';`,
  `require('real');`,
].join('\n');
assert(codeHas(escapedQuote, "require('real')") &&
       !codeHas(escapedQuote, "require('fake')"),
  'escaped quotes inside strings do not terminate early; fake require not seen');

// Backslash at end of escape
const escapedBackslash = [
  `const a = "ends with backslash \\\\";`,
  `require('real');`,
].join('\n');
assert(codeHas(escapedBackslash, "require('real')"),
  'backslash escape sequences are handled');

// ── Comments inside strings, strings inside comments ─────────────────────────
section('cross-context content');

// Real require inside a block comment that contains a fake string
const blockWithString = [
  '/* this comment has "require(\'fake\')" inside a string-like sequence */',
  "require('real-after');",
].join('\n');
assert(codeHas(blockWithString, "require('real-after')") &&
       !codeHas(blockWithString, "require('fake')"),
  'string-like content inside block comments is not extracted as code');

// Multi-line block comment
const multilineBlock = [
  '/*',
  ' * Multi-line block comment',
  " * with require('faker') reference",
  ' */',
  "require('real');",
].join('\n');
assert(codeHas(multilineBlock, "require('real')") &&
       !codeHas(multilineBlock, "require('faker')"),
  'multi-line block comment is fully suppressed');

// ── Real-world TypeScript examples ───────────────────────────────────────────
section('TypeScript edge cases');

const tsTypeImport = [
  "import type { Config } from 'ts-pkg';",
  "import { type Foo, real } from 'real-pkg';",
].join('\n');
assert(codeHas(tsTypeImport, "from 'ts-pkg'") && codeHas(tsTypeImport, "from 'real-pkg'"),
  'TypeScript type imports are preserved as code');

// Decorator (TypeScript / Stage 3)
const decorator = [
  "@SomeDecorator({ provider: require('real') })",
  'class X {}',
].join('\n');
assert(codeHas(decorator, "require('real')"),
  'require inside decorator argument is preserved');

// ── Position preservation ────────────────────────────────────────────────────
section('extractCode preserves length and line numbers');

const src1 = "const x = 'foo';\nrequire('bar');\n";
const out1 = extractCode(src1);
assert(out1.length === src1.length,
  'extractCode output has same length as input');
assert(out1.split('\n').length === src1.split('\n').length,
  'newline count is preserved (line numbers stay aligned)');

// ── Robustness: unterminated and malformed input ─────────────────────────────
section('unterminated / malformed input does not throw');

let didThrow = false;
try {
  extractCode("const x = 'unterminated\n");
  extractCode("const x = `unterminated template");
  extractCode("const x = /unterminated regex");
  extractCode("/* unterminated block");
  extractCode("");
  extractCode(null);
} catch (e) {
  // Some of these (null) are expected to fail; we just want non-string
  // string inputs to not crash. null/undefined we don't claim to support.
  if (!/Cannot read|null|undefined/.test(e.message)) {
    didThrow = true;
    console.error('   unexpected throw:', e.message);
  }
}
assert(!didThrow, 'unterminated literals are handled gracefully');

// Empty input
assert(extractCode('') === '', 'empty string input returns empty string');

// ── Mixed evasion + real code, the realistic attack scenario ─────────────────
section('realistic attack scenario — multiple evasions in one file');

const attackFile = [
  '/**',
  ' * @module fake-module',
  " * @example require('looks-real-1')",
  ' */',
  "const a = '/*';",                           // evasion (d)
  'const sql = `',                             // evasion (a)
  '  SELECT * /* sql comment */ FROM users',
  '`;',
  "const url = 'https://example.com//path';",  // evasion (b)
  'const re = /\\/\\*.*\\*\\//;',              // evasion (c)
  'const b = "*/";',                            // closes evasion (d)
  '',
  '// The only real require:',
  "const real = require('actually-imported-package');",
  '',
  '// Phantom test: this name should NOT appear in extractCode output',
  "// require('phantom-name-in-comment')",
].join('\n');

const extracted = extractCode(attackFile);
assert(extracted.includes("require('actually-imported-package')"),
  'real require survives the gauntlet');

const phantomNames = [
  'looks-real-1',
  'phantom-name-in-comment',
];
const noPhantomLeaked = phantomNames.every(p => !extracted.includes(p));
assert(noPhantomLeaked,
  'none of the phantom names embedded in comments/strings appear as code');

// ── Summary ───────────────────────────────────────────────────────────────────
console.log(`\n${'─'.repeat(52)}`);
console.log(`  Results: ${passed} passed, ${failed} failed\n`);
process.exit(failed > 0 ? 1 : 0);
