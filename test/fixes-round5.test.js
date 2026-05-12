'use strict';
/**
 * test/fixes-round5.test.js
 *
 * Regression tests for round 5 — comprehensive audit findings:
 *   #1 Approver identity sanitization (XSS via GITHUB_ACTOR)
 *   #2 Path traversal in readInstalledMeta
 *   #3 URL injection via malformed package names
 *   #4 URL injection via malformed version specs
 */

let passed = 0;
let failed = 0;
function assert(cond, label) {
  if (cond) { console.log(`  \u2713  ${label}`); passed++; }
  else      { console.error(`  \u2716  ${label}`); failed++; }
}
function section(title) {
  const pad = Math.max(2, 54 - title.length);
  console.log(`\n\u2500\u2500 ${title} ${'\u2500'.repeat(pad)}`);
}

const fs = require('fs');
const os = require('os');
const path = require('path');

// ── #1: Approver identity sanitization ──────────────────────────────────────
section('#1 approver identity is sanitized before writing to policy');

const origActor = process.env.GITHUB_ACTOR;
process.env.GITHUB_ACTOR = "evil<script>alert(1)</script>\"quotes'too";

// Clear require cache so policy.js picks up the new env
delete require.cache[require.resolve('../src/policy')];
const { approveBuild, loadPolicy } = require('../src/policy');

const tmp1 = fs.mkdtempSync(path.join(os.tmpdir(), 'scg-r5-'));
approveBuild(tmp1, 'test-pkg', '1.0.0', { postinstall: 'echo hi' });
const policy = loadPolicy(tmp1);
const storedApprover = policy.approvedBuilds['test-pkg@1.0.0'].approvedBy;

assert(!storedApprover.includes('<'),
  'stored approver contains no angle brackets');
assert(!storedApprover.includes('"'),
  'stored approver contains no quotes');
assert(!storedApprover.includes("'"),
  'stored approver contains no apostrophes');
assert(storedApprover.startsWith('github:'),
  'prefix preserved despite sanitization');
assert(storedApprover.length <= 136,
  'sanitized value is length-bounded (<= 128 + "github:" prefix)');

fs.rmSync(tmp1, { recursive: true, force: true });
if (origActor === undefined) delete process.env.GITHUB_ACTOR;
else process.env.GITHUB_ACTOR = origActor;

// ── #2: Path traversal in readInstalledMeta ─────────────────────────────────
section('#2 readInstalledMeta rejects path-traversal in package names');

delete require.cache[require.resolve('../src/install-inspector')];
const { readInstalledMeta } = require('../src/install-inspector');

const tmp2 = fs.mkdtempSync(path.join(os.tmpdir(), 'scg-r5-'));

// Create a fake legitimate package
fs.mkdirSync(path.join(tmp2, 'node_modules', 'real-pkg'), { recursive: true });
fs.writeFileSync(
  path.join(tmp2, 'node_modules', 'real-pkg', 'package.json'),
  '{"name":"real-pkg","version":"1.0.0"}'
);

// Legitimate read should work
assert(readInstalledMeta(tmp2, 'real-pkg')?.version === '1.0.0',
  'legitimate package names still resolve');

// Path traversal attempts should return null WITHOUT reading outside node_modules
assert(readInstalledMeta(tmp2, '../../../etc/passwd') === null,
  'simple ../ traversal returns null');
assert(readInstalledMeta(tmp2, 'foo/../../etc/passwd') === null,
  'embedded ../ traversal returns null');
assert(readInstalledMeta(tmp2, '..') === null,
  'lone .. returns null');
assert(readInstalledMeta(tmp2, '/absolute/path') === null,
  'absolute path returns null');
assert(readInstalledMeta(tmp2, 'foo\x00bar') === null,
  'null byte injection returns null');

fs.rmSync(tmp2, { recursive: true, force: true });

// ── #3: URL injection via package names ─────────────────────────────────────
section('#3 registry URL construction rejects unsafe names');

delete require.cache[require.resolve('../src/registry')];
const registry = require('../src/registry');

// We don't actually hit the network — we just verify getPackument/getVersionMeta
// throw on unsafe names before constructing the URL. Tricky because these are
// async; we test via promise rejection.
(async () => {
  let threw;

  threw = false;
  try { await registry.getPackument('foo?evil=1'); } catch { threw = true; }
  assert(threw, 'getPackument rejects "foo?evil=1" (query injection attempt)');

  threw = false;
  try { await registry.getPackument('foo/../../admin'); } catch { threw = true; }
  assert(threw, 'getPackument rejects path-traversal in name');

  threw = false;
  try { await registry.getPackument('foo bar'); } catch { threw = true; }
  assert(threw, 'getPackument rejects whitespace in name');

  threw = false;
  try { await registry.getPackument('foo\r\nHost: evil.com'); } catch { threw = true; }
  assert(threw, 'getPackument rejects CRLF injection (header smuggling)');

  threw = false;
  try { await registry.getVersionMeta('valid-name', '1.0.0/../../admin'); } catch { threw = true; }
  assert(threw, 'getVersionMeta rejects path-traversal in version');

  threw = false;
  try { await registry.getVersionMeta('valid-name', 'latest?x=1'); } catch { threw = true; }
  assert(threw, 'getVersionMeta rejects query-string in version');

  // ── Summary ────────────────────────────────────────────────────────────────
  console.log(`\n${'\u2500'.repeat(52)}`);
  console.log(`  Results: ${passed} passed, ${failed} failed\n`);
  process.exit(failed > 0 ? 1 : 0);
})();
