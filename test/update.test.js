'use strict';
/**
 * test/update.test.js
 * Tests for scg update command — blocking without explicit targets.
 */

const fs   = require('fs');
const path = require('path');
const os   = require('os');
const { spawnSync } = require('child_process');

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

const SCG_BIN = path.resolve(__dirname, '../bin/scg.js');

function runScg(args, cwd) {
  const r = spawnSync(process.execPath, [SCG_BIN, ...args], {
    cwd, encoding: 'utf8', timeout: 10000,
  });
  return { status: r.status ?? 2, stdout: r.stdout || '', stderr: r.stderr || '' };
}

function makeProject() {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'scg-upd-test-'));
  fs.writeFileSync(path.join(root, 'package.json'),
    JSON.stringify({ name: 'test', version: '1.0.0', dependencies: {} }, null, 2));
  return root;
}
function cleanup(dir) { fs.rmSync(dir, { recursive: true, force: true }); }

// ── scg update without args → blocked ────────────────────────────────────────

section('scg update without args -- blocked');

const rootA = makeProject();
const resA  = runScg(['update'], rootA);
assert(resA.status === 1, 'exits 1 when no package targets given');
assert(resA.stdout.includes('Tell scg which packages') ||
       resA.stdout.includes('preflight'), 'explains why it was blocked');
assert(resA.stdout.includes('scg update lodash') ||
       resA.stdout.includes('scg update <pkg>'), 'shows correct usage');
cleanup(rootA);

// ── scg update <pkg> → allowed (with preflight) ───────────────────────────────

section('scg update <pkg> -- accepted syntax (registry may be unavailable in test)');

const rootB = makeProject();
// We just test that the command is accepted and doesn't immediately exit with the
// "blocked" message. It may fail later due to no lockfile/network, that's fine.
const resB  = runScg(['update', 'lodash', '--dry-run'], rootB);
// Should NOT show the "requires explicit" error
assert(!resB.stdout.includes('requires an explicit package list'),
  'single package target is accepted');
cleanup(rootB);

// ── scg update --all → opt-in for mass update ─────────────────────────────────

section('scg update --all -- accepted as explicit opt-in');

const rootC = makeProject();
const resC  = runScg(['update', '--all', '--dry-run'], rootC);
assert(!resC.stdout.includes('requires an explicit package list'),
  '--all flag bypasses the block');
cleanup(rootC);

// ── scg update --dry-run without args → blocked ───────────────────────────────

section('scg update --dry-run without targets -- still blocked');

const rootD = makeProject();
const resD  = runScg(['update', '--dry-run'], rootD);
assert(resD.status === 1, '--dry-run alone does not bypass the requirement for targets');
cleanup(rootD);

// ── help text mentions update correctly ───────────────────────────────────────

section('scg update -- correct syntax in help');

const rootE = makeProject();
const resE  = runScg(['help'], rootE);
assert(resE.stdout.includes('scg update'), 'update in help');
assert(resE.stdout.includes('--all'), '--all documented in help');
cleanup(rootE);

// ── summary ───────────────────────────────────────────────────────────────────

console.log(`\n${'─'.repeat(52)}`);
console.log(`  Results: ${passed} passed, ${failed} failed\n`);
process.exit(failed > 0 ? 1 : 0);
