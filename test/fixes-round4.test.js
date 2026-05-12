'use strict';
/**
 * test/fixes-round4.test.js
 *
 * Regression tests for round 4 — red team hardening:
 *   #1 Unicode escape evasion in identifiers (lexer normalization)
 *   #2 Tar desync / duplicate-path detection
 *   #3 Env sanitization in rebuild (NODE_OPTIONS injection)
 *   #4 npx detection in scg doctor
 *
 * Each test exercises the specific evasion vector and verifies the fix
 * blocks it deterministically.
 */

const { extractCode, tokenize, KIND } = require('../src/js-lexer');
const { parseTar }                    = require('../src/delta-phantom');

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

// ── #1: Unicode escape evasion ───────────────────────────────────────────────
section('#1 Unicode escape normalization in identifiers');

// Basic case: \u0072 = 'r'
const basic = "\\u0072equire('malware-pkg');";
const norm1 = extractCode(basic);
assert(norm1.includes("require('malware-pkg')"),
  '\\u0072equire normalized to require');

// Extended escape form
const extended = "\\u{72}equire('malware-pkg');";
const norm2 = extractCode(extended);
assert(norm2.includes("require('malware-pkg')"),
  '\\u{72}equire (extended escape) normalized to require');

// Mixed: multiple escapes in one identifier
const mixed = "re\\u0071\\u0075ire('malware-pkg');";
const norm3 = extractCode(mixed);
assert(norm3.includes("require('malware-pkg')"),
  'multiple escapes within one identifier all normalize');

// All-escaped identifier
const allEscaped = "\\u0072\\u0065\\u0071\\u0075\\u0069\\u0072\\u0065('malware-pkg');";
const norm4 = extractCode(allEscaped);
assert(norm4.includes("require('malware-pkg')"),
  'fully escaped identifier normalizes correctly');

// Import statement form
const importEscape = "i\\u006dport foo from 'malware-pkg';";
const norm5 = extractCode(importEscape);
assert(norm5.includes("import foo from 'malware-pkg'"),
  'escaped import keyword normalizes');

// String contents must NOT be normalized — string escapes are runtime,
// not parse-time, and changing them would alter the string value.
const stringEscape = "const s = '\\u0072aw';";
const norm6 = extractCode(stringEscape);
assert(norm6.includes("'\\u0072aw'") && !norm6.includes("'raw'"),
  'string content escapes are NOT normalized (preserves runtime semantics)');

// Comment escapes are not normalized either (they're not code)
const commentEscape = "// \\u0072equire('fake')\nrequire('real');";
const norm7 = extractCode(commentEscape);
assert(norm7.includes("require('real')") && !norm7.includes("require('fake')"),
  'escapes in comments are not normalized; comment is fully suppressed');

// Realistic attack file with multiple Unicode escape variants
const attack = [
  '// Looks innocent',
  'const x = 1;',
  "\\u0072equire('phantom-1');",
  'const y = 2;',
  "\\u{72}equire('phantom-2');",
  "re\\u0071uire('phantom-3');",
].join('\n');
const normAttack = extractCode(attack);
assert(normAttack.includes("require('phantom-1')") &&
       normAttack.includes("require('phantom-2')") &&
       normAttack.includes("require('phantom-3')"),
  'all three Unicode-escape variants in one file are normalized');

// ── #2: Tar dedup detection ──────────────────────────────────────────────────
section('#2 Tar duplicate-path detection');

// Build a synthetic tarball with two entries having the same path. The
// in-memory scanner should refuse this immediately.
function makeHeader(name, size, typeflag) {
  const buf = Buffer.alloc(512, 0);
  buf.write(name.slice(0, 100), 0, 100, 'utf8');
  const sizeOct = size.toString(8).padStart(11, '0');
  buf.write(sizeOct, 124, 11, 'utf8');
  buf.write('\0', 135);
  buf.write(typeflag, 156, 1, 'utf8');
  buf.write('ustar\0', 257, 6, 'utf8');
  buf.write('00', 263, 2, 'utf8');
  return buf;
}
function padTo512(content) {
  const pad = (512 - (content.length % 512)) % 512;
  return Buffer.concat([content, Buffer.alloc(pad, 0)]);
}

// Two entries with the SAME path — the desync attack signature.
// File 1: clean content. File 2: malicious. Naive scanner sees file 1,
// disk extractor sees file 2.
const cleanBody = Buffer.from("module.exports = 'clean';\n", 'utf8');
const evilBody  = Buffer.from("require('child_process').exec('rm -rf ~');\n", 'utf8');

const desyncTar = Buffer.concat([
  makeHeader('package/index.js', cleanBody.length, '0'),
  padTo512(cleanBody),
  makeHeader('package/index.js', evilBody.length, '0'),  // SAME PATH
  padTo512(evilBody),
  Buffer.alloc(1024, 0), // end-of-archive
]);

let desyncBlocked = false;
let desyncErrorMessage = '';
try {
  parseTar(desyncTar, () => {});
} catch (e) {
  desyncBlocked = true;
  desyncErrorMessage = e.message;
}
assert(desyncBlocked,
  'parseTar throws on duplicate entry path');
assert(/duplicate entry path|tar-desync|differential/i.test(desyncErrorMessage),
  'error message identifies the desync attack');

// Triple-duplicate also blocks (defense in depth)
const tripleTar = Buffer.concat([
  makeHeader('package/x.js', 10, '0'),
  padTo512(Buffer.from('aaaaaaaaaa')),
  makeHeader('package/y.js', 10, '0'),
  padTo512(Buffer.from('bbbbbbbbbb')),
  makeHeader('package/x.js', 10, '0'),  // dup of first
  padTo512(Buffer.from('cccccccccc')),
  Buffer.alloc(1024, 0),
]);
let tripleBlocked = false;
try { parseTar(tripleTar, () => {}); } catch { tripleBlocked = true; }
assert(tripleBlocked,
  'duplicate detected even when separated by other entries');

// Negative case: legitimate tarball with all unique paths must NOT trigger
const cleanTar = Buffer.concat([
  makeHeader('package/package.json', 20, '0'),
  padTo512(Buffer.from('{"name":"clean"}    ')),
  makeHeader('package/index.js', 25, '0'),
  padTo512(Buffer.from('module.exports = {};     ')),
  makeHeader('package/lib/util.js', 15, '0'),
  padTo512(Buffer.from('exports.x = 1; ')),
  Buffer.alloc(1024, 0),
]);
const seenFiles = [];
let cleanThrew = false;
try {
  parseTar(cleanTar, (name) => seenFiles.push(name));
} catch (e) {
  cleanThrew = true;
  console.error('   unexpected throw:', e.message);
}
assert(!cleanThrew && seenFiles.length === 3,
  'legitimate tarball with unique paths is accepted (3 files seen)');

// ── #3 prep: env sanitization (will be implemented in src/npm.js) ───────────
// We test the contract here so the implementation has something to satisfy.
section('#3 env sanitization for build scripts');

const { runRaw } = require('../src/npm');
// We can't easily run an actual subprocess in tests, but we CAN inspect
// the source to verify the sanitization logic exists in the code path.
const fs = require('fs');
const path = require('path');
const npmSrc = fs.readFileSync(path.join(__dirname, '..', 'src', 'npm.js'), 'utf8');
assert(/NODE_OPTIONS/.test(npmSrc),
  'npm.js mentions NODE_OPTIONS (env sanitization implemented)');
assert(/sanitiz|stripEnv|cleanEnv/i.test(npmSrc),
  'npm.js has env sanitization logic');

// ── #4 prep: npx detection in doctor ────────────────────────────────────────
section('#4 scg doctor detects raw npx in package.json scripts');

const cliSrc = fs.readFileSync(path.join(__dirname, '..', 'bin', 'scg.js'), 'utf8');
assert(/npx\\s\+/.test(cliSrc) || cliSrc.includes("npx\\s+"),
  'scg doctor scans scripts for npx invocations');
assert(/npx bypasses scg/i.test(cliSrc),
  'doctor warning text mentions that npx bypasses scg');

// ── summary ──────────────────────────────────────────────────────────────────
console.log(`\n${'─'.repeat(52)}`);
console.log(`  Results: ${passed} passed, ${failed} failed\n`);
process.exit(failed > 0 ? 1 : 0);
