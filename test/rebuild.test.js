'use strict';
/**
 * test/rebuild.test.js
 * Tests for src/rebuild.js
 *
 * Uses dry-run throughout — no real npm rebuild calls.
 */

const fs   = require('fs');
const path = require('path');
const os   = require('os');

const { rebuildApproved } = require('../src/rebuild');
const { initPolicy, approveBuild, denyBuild } = require('../src/policy');

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

function makeProject(installedPkgs = {}) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'scg-rb-test-'));
  fs.writeFileSync(path.join(root, 'package.json'), '{"name":"test","version":"1.0.0"}');
  const nm = path.join(root, 'node_modules');
  fs.mkdirSync(nm);
  for (const [name, meta] of Object.entries(installedPkgs)) {
    const pkgDir = path.join(nm, name);
    fs.mkdirSync(pkgDir, { recursive: true });
    fs.writeFileSync(path.join(pkgDir, 'package.json'), JSON.stringify({
      name, version: meta.version || '1.0.0', scripts: meta.scripts || {},
    }));
  }
  return root;
}

function cleanup(dir) { fs.rmSync(dir, { recursive: true, force: true }); }

// ── tests ─────────────────────────────────────────────────────────────────────

section('no approved builds — nothing to rebuild');

const rootA = makeProject({ 'esbuild': { version: '0.21.5' } });
initPolicy(rootA);
const resA = rebuildApproved(rootA, [], { dryRun: true });
assert(resA.rebuilt.length === 0, 'nothing rebuilt when policy empty');
assert(resA.skipped.length === 0, 'nothing skipped either');
cleanup(rootA);

section('rebuild all approved');

const rootB = makeProject({
  'esbuild': { version: '0.21.5', scripts: { postinstall: 'node install.js' } },
  'sharp':   { version: '0.33.0', scripts: { install: 'node-pre-gyp install' } },
});
initPolicy(rootB);
// Approve with the ACTUAL scripts so the hash matches at rebuild time
approveBuild(rootB, 'esbuild', '0.21.5', { postinstall: 'node install.js' });
approveBuild(rootB, 'sharp',   '0.33.0', { install: 'node-pre-gyp install' });

const resB = rebuildApproved(rootB, [], { dryRun: true });
assert(resB.rebuilt.length === 2, 'both approved packages rebuilt');
assert(resB.skipped.length === 0, 'nothing skipped');
assert(resB.denied.length  === 0, 'nothing denied');
cleanup(rootB);

section('rebuild specific package only');

const rootC = makeProject({
  'esbuild': { version: '0.21.5', scripts: { postinstall: 'node install.js' } },
  'sharp':   { version: '0.33.0', scripts: { install: 'node-pre-gyp install' } },
});
initPolicy(rootC);
approveBuild(rootC, 'esbuild', '0.21.5', { postinstall: 'node install.js' });
approveBuild(rootC, 'sharp',   '0.33.0', { install: 'node-pre-gyp install' });

const resC = rebuildApproved(rootC, ['esbuild@0.21.5'], { dryRun: true });
assert(resC.rebuilt.length === 1, 'only specified package rebuilt');
assert(resC.rebuilt[0] === 'esbuild@0.21.5', 'correct package');
cleanup(rootC);

section('skip unapproved package');

const rootD = makeProject({
  'esbuild': { version: '0.21.5', scripts: { postinstall: 'node install.js' } },
  'sharp':   { version: '0.33.0', scripts: { install: 'node-pre-gyp install' } },
});
initPolicy(rootD);
approveBuild(rootD, 'esbuild', '0.21.5', { postinstall: 'node install.js' });
// sharp is NOT approved

const resD = rebuildApproved(rootD, ['sharp@0.33.0'], { dryRun: true });
assert(resD.rebuilt.length === 0, 'unapproved package not rebuilt');
assert(resD.skipped.length === 1, 'unapproved package in skipped');
cleanup(rootD);

section('blocked by denial');

const rootE = makeProject({
  'bad-dep': { version: '1.0.0', scripts: { postinstall: 'node build-native.js' } },
});
initPolicy(rootE);
// Approve first, then deny — deny wins
approveBuild(rootE, 'bad-dep', '1.0.0', {});
denyBuild(rootE, 'bad-dep', '1.0.0', 'unapproved');

const resE = rebuildApproved(rootE, ['bad-dep@1.0.0'], { dryRun: true });
assert(resE.denied.length  === 1, 'denied package goes to denied list');
assert(resE.rebuilt.length === 0, 'denied package not rebuilt');
cleanup(rootE);

section('package not installed — skipped');

const rootF = makeProject({}); // empty node_modules
initPolicy(rootF);
approveBuild(rootF, 'esbuild', '0.21.5', {});

const resF = rebuildApproved(rootF, ['esbuild@0.21.5'], { dryRun: true });
assert(resF.skipped.length === 1, 'skipped when not installed');
assert(resF.rebuilt.length === 0, 'not rebuilt when not installed');
cleanup(rootF);


section('hash mismatch blocks rebuild');

const rootHM = makeProject({
  'esbuild': { version: '0.21.5', scripts: { postinstall: 'node install.js' } },
});
initPolicy(rootHM);
// Approve with original script
approveBuild(rootHM, 'esbuild', '0.21.5', { postinstall: 'node install.js' });

// Now simulate the package being compromised: the installed script changed
// Overwrite node_modules/esbuild/package.json with a different postinstall
const pkgDir = require('path').join(rootHM, 'node_modules', 'esbuild');
require('fs').writeFileSync(
  require('path').join(pkgDir, 'package.json'),
  JSON.stringify({ name: 'esbuild', version: '0.21.5',
    scripts: { postinstall: 'node build-native.js' } })  // different!
);

const resHM = rebuildApproved(rootHM, ['esbuild@0.21.5'], { dryRun: true });
assert(resHM.hashMismatch.length === 1, 'hash mismatch detected');
assert(resHM.rebuilt.length    === 0, 'compromised package not rebuilt');
assert(resHM.hashMismatch[0].message.includes('re-run'), 'message guides to re-approve');
cleanup(rootHM);

section('hash match allows rebuild');

const rootHOK = makeProject({
  'sharp': { version: '0.33.0', scripts: { install: 'node-pre-gyp install' } },
});
initPolicy(rootHOK);
// Approve with exact matching script
approveBuild(rootHOK, 'sharp', '0.33.0', { install: 'node-pre-gyp install' });

const resHOK = rebuildApproved(rootHOK, ['sharp@0.33.0'], { dryRun: true });
assert(resHOK.hashMismatch.length === 0, 'matching hash: no mismatch');
assert(resHOK.rebuilt.length      === 1, 'package rebuilt when hash matches');
cleanup(rootHOK);

section('rebuild result includes hashMismatch field');

// Verify the return shape always has hashMismatch even when empty
const rootShape = makeProject({});
initPolicy(rootShape);
const resShape = rebuildApproved(rootShape, [], { dryRun: true });
assert(Array.isArray(resShape.hashMismatch), 'hashMismatch is always an array');
cleanup(rootShape);

// ── summary ───────────────────────────────────────────────────────────────────

console.log(`\n${'─'.repeat(52)}`);
console.log(`  Results: ${passed} passed, ${failed} failed\n`);
process.exit(failed > 0 ? 1 : 0);
