'use strict';
/**
 * test/policy.test.js
 * Tests for src/policy.js — repo-local .scg-policy.json management.
 */

const fs   = require('fs');
const path = require('path');
const os   = require('os');

const {
  loadPolicy, savePolicy, initPolicy,
  approveBuild, denyBuild, listApprovedBuilds,
  isBuildApproved, isBuildDenied,
  buildKey, POLICY_FILE,
} = require('../src/policy');

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

// ── fixture helpers ───────────────────────────────────────────────────────────

function makeTmpDir() {
  const d = fs.mkdtempSync(path.join(os.tmpdir(), 'scg-policy-test-'));
  // policy.js needs a package.json to recognise the project root in some flows,
  // but loadPolicy just needs the dir — write a minimal one for safety
  fs.writeFileSync(path.join(d, 'package.json'), '{"name":"test","version":"1.0.0"}');
  return d;
}

function cleanup(dir) {
  fs.rmSync(dir, { recursive: true, force: true });
}

// ── tests ─────────────────────────────────────────────────────────────────────

section('initPolicy');

const tmpA = makeTmpDir();
const created = initPolicy(tmpA);
assert(created === true, 'returns true when creating fresh policy');
assert(fs.existsSync(path.join(tmpA, POLICY_FILE)), 'creates .scg-policy.json');

const created2 = initPolicy(tmpA);
assert(created2 === false, 'returns false when policy already exists');
cleanup(tmpA);

section('loadPolicy — defaults');

const tmpB = makeTmpDir();
const policy = loadPolicy(tmpB);
assert(policy.version === 1, 'version field is 1');
assert(typeof policy.approvedBuilds === 'object', 'approvedBuilds is object');
assert(typeof policy.deniedBuilds   === 'object', 'deniedBuilds is object');
assert(policy.settings.cooldownDays === 3, 'default cooldownDays = 3');
assert(policy.settings.failOn       === 'HIGH', 'default failOn = HIGH');
cleanup(tmpB);

section('loadPolicy — reads existing file');

const tmpC = makeTmpDir();
savePolicy(tmpC, {
  version: 1,
  approvedBuilds: { 'esbuild@0.21.5': { approvedAt: '2026-01-01', approvedBy: 'ci', scripts: {} } },
  deniedBuilds: {},
  settings: { cooldownDays: 7, failOn: 'CRITICAL' },
});
const loaded = loadPolicy(tmpC);
assert(loaded.approvedBuilds['esbuild@0.21.5'] !== undefined, 'reads existing approved build');
assert(loaded.settings.cooldownDays === 7, 'reads custom cooldownDays');
cleanup(tmpC);

section('approveBuild');

const tmpD = makeTmpDir();
initPolicy(tmpD);

const key = approveBuild(tmpD, 'esbuild', '0.21.5', { postinstall: 'node install.js' });
assert(key === 'esbuild@0.21.5', 'returns correct key');

const p2 = loadPolicy(tmpD);
assert(p2.approvedBuilds['esbuild@0.21.5'] !== undefined, 'persists to file');
assert(p2.approvedBuilds['esbuild@0.21.5'].scripts.postinstall === 'node install.js', 'stores scripts');
assert(typeof p2.approvedBuilds['esbuild@0.21.5'].approvedAt === 'string', 'stores approvedAt');

// Approving removes from deniedBuilds if present
savePolicy(tmpD, { ...p2, deniedBuilds: { 'esbuild@0.21.5': { reason: 'test' } } });
approveBuild(tmpD, 'esbuild', '0.21.5', {});
const p3 = loadPolicy(tmpD);
assert(p3.deniedBuilds['esbuild@0.21.5'] === undefined, 'approval removes from deniedBuilds');
cleanup(tmpD);

section('denyBuild');

const tmpE = makeTmpDir();
initPolicy(tmpE);
approveBuild(tmpE, 'blocked-dep', '1.0.0', { postinstall: 'node build-native.js' });
denyBuild(tmpE, 'blocked-dep', '1.0.0', 'unapproved-script');
const p4 = loadPolicy(tmpE);
assert(p4.deniedBuilds['blocked-dep@1.0.0'] !== undefined, 'persists denial');
assert(p4.deniedBuilds['blocked-dep@1.0.0'].reason === 'unapproved-script', 'stores reason');
assert(p4.approvedBuilds['blocked-dep@1.0.0'] === undefined, 'denial removes approval');
cleanup(tmpE);

section('isBuildApproved / isBuildDenied');

const tmpF = makeTmpDir();
initPolicy(tmpF);
approveBuild(tmpF, 'sharp', '0.33.0', {});
denyBuild(tmpF, 'bad-dep', '9.9.9', 'unapproved');
const p5 = loadPolicy(tmpF);

assert(isBuildApproved(p5, 'sharp', '0.33.0'), 'exact version approved');
assert(!isBuildApproved(p5, 'sharp', '0.34.0'), 'different version not approved');
assert(isBuildDenied(p5, 'bad-dep', '9.9.9'), 'exact version denied');
assert(!isBuildDenied(p5, 'sharp', '0.33.0'), 'approved pkg not denied');

// bare-name approval (no version)
approveBuild(tmpF, 'bcrypt', null, {});
const p6 = loadPolicy(tmpF);
assert(isBuildApproved(p6, 'bcrypt', '5.1.1'), 'bare-name approval matches any version');
cleanup(tmpF);

section('listApprovedBuilds');

const tmpG = makeTmpDir();
initPolicy(tmpG);
approveBuild(tmpG, 'a', '1.0.0', {});
approveBuild(tmpG, 'b', '2.0.0', {});
const p7 = loadPolicy(tmpG);
const list = listApprovedBuilds(p7);
assert(list.length === 2, 'lists 2 approved builds');
assert(list.every(e => typeof e.key === 'string'), 'each entry has key');
cleanup(tmpG);

section('legacy whitelist fallback');

// Simulate old ~/.scg-whitelist.json being absent — should not throw
const tmpH = makeTmpDir();
const fallbackPolicy = loadPolicy(tmpH);
assert(typeof fallbackPolicy.approvedBuilds === 'object', 'loads without legacy whitelist');
cleanup(tmpH);

// ── summary ───────────────────────────────────────────────────────────────────

console.log(`\n${'─'.repeat(52)}`);
console.log(`  Results: ${passed} passed, ${failed} failed\n`);
process.exit(failed > 0 ? 1 : 0);
