'use strict';
/**
 * test/fixes.test.js
 *
 * Regression tests for the four prioritized fixes in this revision:
 *   #1  phantom-check uses real per-package previous-version diff
 *   #6  parseTar handles PaxHeader and GNU longlink long filenames
 *   #8  extractImportsFromSource strips comments before regex scanning
 *   #10 hashScripts canonicalizes key order properly
 */

const { runPhantomCheck }                  = require('../src/phantom-check');
const { extractImportsFromSource, parseTar } = require('../src/delta-phantom');
const { hashScripts }                      = require('../src/policy');
const registry                             = require('../src/registry');

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

(async () => {

// ── #10: hashScripts canonical key order ─────────────────────────────────────
section('#10 hashScripts is order-independent');

const h1 = hashScripts({ postinstall: 'a', preinstall: 'b' });
const h2 = hashScripts({ preinstall: 'b', postinstall: 'a' });
assert(h1 === h2, 'same scripts in different key order produce same hash');

const h3 = hashScripts({ postinstall: 'a', preinstall: 'c' });
assert(h1 !== h3, 'different script content produces different hash');

const h4 = hashScripts({});
assert(/^sha256:[0-9a-f]{64}$/.test(h4), 'empty scripts still produces valid sha256 hash');

// ── #8: comment stripping in import extraction ───────────────────────────────
section('#8 extractImportsFromSource strips comments');

const blockCommentEvasion = `
// Legitimate file
const x = 1;
/* require('plain-crypto-js') */
module.exports = { x };
`;
const r1 = extractImportsFromSource(blockCommentEvasion);
assert(!r1.has('plain-crypto-js'),
  'fake require() inside /* */ block does NOT count as used (evasion blocked)');

const lineCommentEvasion = `
// require('plain-crypto-js')
const x = 1;
`;
const r2 = extractImportsFromSource(lineCommentEvasion);
assert(!r2.has('plain-crypto-js'),
  'fake require() inside // line comment does NOT count as used');

const realRequire = `
const crypto = require('plain-crypto-js');
module.exports = crypto;
`;
const r3 = extractImportsFromSource(realRequire);
assert(r3.has('plain-crypto-js'),
  'real require() outside any comment IS detected');

const mixedComments = `
/* old code:
   const a = require('removed-pkg');
*/
const b = require('real-pkg');
`;
const r4 = extractImportsFromSource(mixedComments);
assert(!r4.has('removed-pkg') && r4.has('real-pkg'),
  'commented-out require ignored, live require detected');

// ── #6: parseTar handles PaxHeader long filenames ────────────────────────────
section('#6 parseTar handles PaxHeader extended headers');

// Build a synthetic tar buffer with a PaxHeader entry preceding a regular file.
// We use a short ustar name and override it via the pax 'path' record so the
// onFile callback should receive the long name, not the truncated one.
function makeHeader(name, size, typeflag) {
  const buf = Buffer.alloc(512, 0);
  buf.write(name.slice(0, 100), 0, 100, 'utf8');
  // size in octal, 11 chars + null
  const sizeOct = size.toString(8).padStart(11, '0');
  buf.write(sizeOct, 124, 11, 'utf8');
  buf.write('\0', 135);
  buf.write(typeflag, 156, 1, 'utf8');
  // ustar magic so most parsers accept it (not strictly required by ours)
  buf.write('ustar\0', 257, 6, 'utf8');
  buf.write('00', 263, 2, 'utf8');
  return buf;
}
function padTo512(content) {
  const pad = (512 - (content.length % 512)) % 512;
  return Buffer.concat([content, Buffer.alloc(pad, 0)]);
}

// Build a pax record: "<len> path=<longname>\n" where len is total record length
const longName = 'package/' + 'very-long-directory-name/'.repeat(6) + 'file.js';
const recordBody = `path=${longName}\n`;
// length must include the length-prefix itself plus the leading space
// Iterate to find self-consistent length
let recLen = recordBody.length + 4; // initial guess
for (let i = 0; i < 5; i++) {
  recLen = String(recLen).length + 1 + recordBody.length;
}
const paxPayload = Buffer.from(`${recLen} ${recordBody}`, 'utf8');

const fileBody = Buffer.from("require('real-import-from-long-path');\n", 'utf8');

const tarBuf = Buffer.concat([
  makeHeader('PaxHeader/longpath', paxPayload.length, 'x'),
  padTo512(paxPayload),
  makeHeader('package/short.js', fileBody.length, '0'), // short ustar name (overridden)
  padTo512(fileBody),
  Buffer.alloc(1024, 0), // end-of-archive
]);

const seenFiles = [];
parseTar(tarBuf, (name, content) => {
  seenFiles.push({ name, content: content.toString('utf8') });
});

assert(seenFiles.length === 1, 'parseTar yielded exactly one regular file');
assert(seenFiles[0] && seenFiles[0].name === longName,
  'PaxHeader path override applied to following entry (long name preserved)');
assert(seenFiles[0] && seenFiles[0].content.includes('real-import-from-long-path'),
  'file content correctly attached to long-name entry');

// GNU longlink ('L') variant
const gnuLongName = 'package/another-' + 'long-segment/'.repeat(8) + 'file.js';
const gnuPayload = Buffer.from(gnuLongName + '\0', 'utf8');
const gnuBody    = Buffer.from("import x from 'gnu-long-pkg';\n", 'utf8');

const gnuBuf = Buffer.concat([
  makeHeader('././@LongLink', gnuPayload.length, 'L'),
  padTo512(gnuPayload),
  makeHeader('package/short2.js', gnuBody.length, '0'),
  padTo512(gnuBody),
  Buffer.alloc(1024, 0),
]);

const gnuSeen = [];
parseTar(gnuBuf, (name, content) => {
  gnuSeen.push({ name, content: content.toString('utf8') });
});

assert(gnuSeen.length === 1, 'GNU longlink: one regular file yielded');
assert(gnuSeen[0] && gnuSeen[0].name === gnuLongName,
  'GNU longlink name applied to following entry');

// ── #1: phantom-check uses real previous-version manifest diff ───────────────
section('#1 phantom-check fetches previous version manifest');

const originalGetVersionMeta = registry.getVersionMeta;

// Scenario: axios goes 1.14.0 → 1.14.1 and 1.14.1 adds plain-crypto-js.
// plain-crypto-js ALSO already exists in the global tree (used legitimately
// by some other package). Old logic missed this; new logic catches it because
// it asks "what deps did axios@1.14.0 declare?" not "is the name anywhere?".

const before = {
  'axios':            { version: '1.14.0', hasInstallScript: false, scripts: {} },
  'plain-crypto-js':  { version: '1.0.0',  hasInstallScript: false, scripts: {} },
  'some-other-pkg':   { version: '1.0.0',  hasInstallScript: false, scripts: {} },
};
const after = {
  'axios':            { version: '1.14.1', hasInstallScript: false, scripts: {} },
  'plain-crypto-js':  { version: '1.0.0',  hasInstallScript: false, scripts: {} },
  'some-other-pkg':   { version: '1.0.0',  hasInstallScript: false, scripts: {} },
};

registry.getVersionMeta = async (name, version) => {
  if (name === 'axios' && version === '1.14.0') {
    return {
      name: 'axios', version: '1.14.0',
      dependencies: { 'follow-redirects': '^1.15.0' },
      main: 'index.js', readme: 'Promise based HTTP client',
    };
  }
  if (name === 'axios' && version === '1.14.1') {
    return {
      name: 'axios', version: '1.14.1',
      // Newly added 'plain-crypto-js' that is NOT referenced anywhere
      dependencies: { 'follow-redirects': '^1.15.0', 'plain-crypto-js': '^1.0.0' },
      main: 'index.js', readme: 'Promise based HTTP client',
      files: ['index.js', 'lib/'],
    };
  }
  return null;
};

const phantomResults = await runPhantomCheck(before, after);
const axiosFinding = phantomResults.find(r => r.package.startsWith('axios'));
assert(axiosFinding != null,
  'axios update produces a phantom-check entry');
assert(axiosFinding && axiosFinding.newDeps.includes('plain-crypto-js'),
  'plain-crypto-js identified as NEW dep of axios (not masked by global tree presence)');
assert(axiosFinding && !axiosFinding.newDeps.includes('follow-redirects'),
  'follow-redirects NOT flagged (it was already in axios@1.14.0)');

// Scenario: previous version manifest unfetchable → fallback treats all deps as new.
registry.getVersionMeta = async (name, version) => {
  if (name === 'foo' && version === '2.0.0') {
    return { name: 'foo', version: '2.0.0', dependencies: { 'bar': '^1.0.0' }, main: 'index.js' };
  }
  return null; // foo@1.0.0 unfetchable
};

const fallbackBefore = { 'foo': { version: '1.0.0', hasInstallScript: false, scripts: {} } };
const fallbackAfter  = { 'foo': { version: '2.0.0', hasInstallScript: false, scripts: {} } };
const fallbackRes = await runPhantomCheck(fallbackBefore, fallbackAfter);
const fooFinding = fallbackRes.find(r => r.package.startsWith('foo'));
// In conservative fallback mode all currentDeps are treated as new, so 'bar'
// (not referenced in main/readme) shows up as a phantom candidate.
assert(fooFinding && fooFinding.newDeps.includes('bar'),
  'fallback path: when previous manifest unavailable, all current deps treated as new');

registry.getVersionMeta = originalGetVersionMeta;

// ── summary ───────────────────────────────────────────────────────────────────
console.log(`\n${'─'.repeat(52)}`);
console.log(`  Results: ${passed} passed, ${failed} failed\n`);
process.exit(failed > 0 ? 1 : 0);

})().catch(e => { console.error('async error:', e.message, e.stack); process.exit(2); });
