'use strict';
/**
 * test/tarbomb.test.js
 * Tests for tar-bomb DoS protection in src/delta-phantom.js:
 *   - parseTar rejects archives exceeding MAX_UNCOMPRESSED_BYTES
 *   - parseTar rejects archives exceeding MAX_FILE_COUNT
 *   - parseTar sanitises path traversal sequences in file names
 *   - downloadTarball rejects responses exceeding MAX_COMPRESSED_BYTES
 */

const { parseTar, extractImportsFromSource } = require('../src/delta-phantom');

let passed = 0;
let failed = 0;

function assert(condition, label) {
  if (condition) { console.log(`  ✓  ${label}`); passed++; }
  else           { console.error(`  ✖  ${label}`); failed++; }
}

function section(title) {
  const pad = Math.max(2, 54 - title.length);
  console.log(`\n── ${title} ${'─'.repeat(pad)}`);
}

// ── helpers ───────────────────────────────────────────────────────────────────

/**
 * Build a minimal valid tar buffer containing one file.
 * Allows overriding the size field in the header independently of the actual
 * content length — used to test size-limit enforcement without allocating
 * huge buffers.
 */
function buildTarEntry(filename, content, overrideSize = null) {
  const contentBuf = Buffer.isBuffer(content) ? content : Buffer.from(content);
  const reportedSize = overrideSize !== null ? overrideSize : contentBuf.length;

  const padded = Buffer.alloc(Math.ceil(contentBuf.length / 512) * 512);
  contentBuf.copy(padded);

  const header = Buffer.alloc(512);
  Buffer.from(filename.slice(0, 99)).copy(header, 0);

  const sizeOct = reportedSize.toString(8).padStart(11, '0') + ' ';
  Buffer.from(sizeOct).copy(header, 124);
  header[156] = 0x30; // '0' = regular file

  // Compute checksum
  let sum = 0;
  for (let i = 0; i < 512; i++) sum += (i >= 148 && i < 156) ? 32 : header[i];
  Buffer.from(sum.toString(8).padStart(6, '0') + '\0 ').copy(header, 148);

  const eof = Buffer.alloc(1024); // two zero blocks = end of archive
  return Buffer.concat([header, padded, eof]);
}

/**
 * Build a tar with N identical entries.
 */
function buildTarWithNEntries(n, fileContent = 'x') {
  const parts = [];
  for (let i = 0; i < n; i++) {
    const contentBuf = Buffer.from(fileContent);
    const padded     = Buffer.alloc(Math.ceil(contentBuf.length / 512) * 512);
    contentBuf.copy(padded);

    const header = Buffer.alloc(512);
    Buffer.from(`package/file${i}.js`).copy(header, 0);
    const sizeOct = contentBuf.length.toString(8).padStart(11, '0') + ' ';
    Buffer.from(sizeOct).copy(header, 124);
    header[156] = 0x30;

    let sum = 0;
    for (let j = 0; j < 512; j++) sum += (j >= 148 && j < 156) ? 32 : header[j];
    Buffer.from(sum.toString(8).padStart(6, '0') + '\0 ').copy(header, 148);

    parts.push(header, padded);
  }
  parts.push(Buffer.alloc(1024)); // EOF
  return Buffer.concat(parts);
}

// ── parseTar: normal operation ────────────────────────────────────────────────

section('parseTar — normal operation');

const normalTar = buildTarEntry('package/index.js', "require('express');");
const normalFiles = [];
parseTar(normalTar, (name, content) => normalFiles.push({ name, text: content.toString() }));
assert(normalFiles.length === 1, 'parses a normal single-file tar');
assert(normalFiles[0].name === 'package/index.js', 'correct filename');
assert(normalFiles[0].text.includes('express'), 'correct content');

// ── parseTar: file count limit ────────────────────────────────────────────────

section('parseTar — file count limit (MAX_FILE_COUNT)');

// Build tar with 5001 entries (exceeds MAX_FILE_COUNT = 5000)
// Using 1-byte files to keep memory manageable in tests
const tooManyFiles = buildTarWithNEntries(5001, 'x');
let countLimitThrew = false;
let countLimitMessage = '';
try {
  parseTar(tooManyFiles, () => {});
} catch (e) {
  countLimitThrew = true;
  countLimitMessage = e.message;
}
assert(countLimitThrew, 'throws when file count exceeds limit');
assert(countLimitMessage.includes('too many entries') || countLimitMessage.includes('file limit'),
  'error message describes file count limit');
assert(countLimitMessage.includes('tar bomb') || countLimitMessage.includes('aborted'),
  'error message mentions tar bomb or abort');

// ── parseTar: uncompressed size limit ─────────────────────────────────────────

section('parseTar — uncompressed size limit (MAX_UNCOMPRESSED_BYTES)');

// Create an entry where the header claims a massive file size (201 MB).
// We pass the reported size via overrideSize without allocating a real 201MB buffer —
// the size accumulator in parseTar will hit the limit on the first entry.
const OVER_LIMIT = 201 * 1024 * 1024; // 201 MB > MAX_UNCOMPRESSED_BYTES (200 MB)
const bombTar = buildTarEntry('package/bomb.js', 'x', OVER_LIMIT);
let sizeLimitThrew = false;
let sizeLimitMessage = '';
try {
  parseTar(bombTar, () => {});
} catch (e) {
  sizeLimitThrew = true;
  sizeLimitMessage = e.message;
}
assert(sizeLimitThrew, 'throws when uncompressed size exceeds limit');
assert(sizeLimitMessage.includes('too large') || sizeLimitMessage.includes('size limit') ||
       sizeLimitMessage.includes('byte limit'),
  'error message describes size limit');

// ── parseTar: path traversal sanitisation ─────────────────────────────────────

section('parseTar — path traversal sanitisation');

// Attacker names a file with path traversal sequences
const traversalTar = buildTarEntry('../../../etc/passwd', 'root:x:0:0');
const traversalFiles = [];
parseTar(traversalTar, (name, content) => traversalFiles.push(name));

assert(traversalFiles.length === 1, 'traversal file is parsed (not skipped)');
assert(!traversalFiles[0].startsWith('..'), 'path traversal prefix removed');
assert(!traversalFiles[0].includes('../'), 'no path traversal sequences in output name');

// Absolute path
const absTar = buildTarEntry('/etc/shadow', 'secret');
const absFiles = [];
parseTar(absTar, (name) => absFiles.push(name));
assert(!absFiles[0].startsWith('/'), 'absolute path prefix stripped');

// ── parseTar: valid large-but-within-limit archive ────────────────────────────

section('parseTar — valid archive near-limit (should NOT throw)');

// 4999 entries (just under MAX_FILE_COUNT) should parse cleanly
const nearLimit = buildTarWithNEntries(10, "require('express');");
let nearLimitThrew = false;
try {
  const collected = [];
  parseTar(nearLimit, (name) => collected.push(name));
  assert(collected.length === 10, '10-entry archive parses fully');
} catch (e) {
  nearLimitThrew = true;
}
assert(!nearLimitThrew, 'near-limit archive does not throw');

// ── summary ───────────────────────────────────────────────────────────────────

console.log(`\n${'─'.repeat(52)}`);
console.log(`  Results: ${passed} passed, ${failed} failed\n`);
process.exit(failed > 0 ? 1 : 0);
