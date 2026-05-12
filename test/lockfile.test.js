'use strict';
/**
 * test/lockfile.test.js
 * Tests for src/lockfile.js
 */

const fs   = require('fs');
const path = require('path');
const os   = require('os');

const { readLockfile, extractPackages, diffLockfilePackages } = require('../src/lockfile');

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

function makeTmpDir() {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'scg-lf-test-'));
}

function writeLockfile(dir, content) {
  fs.writeFileSync(path.join(dir, 'package-lock.json'), JSON.stringify(content, null, 2));
}

function cleanup(dir) {
  fs.rmSync(dir, { recursive: true, force: true });
}

// ── readLockfile ──────────────────────────────────────────────────────────────

section('readLockfile');

const tmpA = makeTmpDir();
assert(readLockfile(tmpA) === null, 'returns null when no lockfile');

writeLockfile(tmpA, { lockfileVersion: 3, packages: {} });
assert(readLockfile(tmpA) !== null, 'reads existing lockfile');
cleanup(tmpA);

// ── extractPackages — v3 format ───────────────────────────────────────────────

section('extractPackages (v3)');

const v3lockfile = {
  lockfileVersion: 3,
  packages: {
    '': { name: 'myapp', version: '1.0.0' }, // root — should be skipped
    'node_modules/follow-redirects': {
      version: '1.15.0',
      resolved: 'https://registry.npmjs.org/follow-redirects/-/follow-redirects-1.15.0.tgz',
      hasInstallScript: false,
      scripts: {},
    },
    'node_modules/mock-unapproved-dep': {
      version: '4.2.1',
      resolved: 'https://registry.npmjs.org/mock-unapproved-dep/-/mock-unapproved-dep-4.2.1.tgz',
      hasInstallScript: true,
      scripts: { postinstall: 'node postinstall-hook.js' },
    },
    'node_modules/@scope/utils': {
      version: '2.0.0',
      resolved: 'https://example.com/@scope/utils-2.0.0.tgz',
    },
  },
};

const pkgs = extractPackages(v3lockfile);

assert(!pkgs[''],                         'root package excluded');
assert(pkgs['follow-redirects']           !== undefined, 'extracts plain package');
assert(pkgs['follow-redirects'].version   === '1.15.0', 'correct version');
assert(pkgs['follow-redirects'].hasInstallScript === false, 'no install script on clean pkg');
assert(pkgs['mock-unapproved-dep']            !== undefined, 'extracts pkg with scripts');
assert(pkgs['mock-unapproved-dep'].hasInstallScript === true, 'hasInstallScript=true from lockfile');
assert(pkgs['mock-unapproved-dep'].scripts.postinstall === 'node postinstall-hook.js', 'script text preserved');
assert(pkgs['@scope/utils']               !== undefined, 'extracts scoped package');
assert(pkgs['@scope/utils'].version       === '2.0.0', 'scoped pkg version correct');

// hasInstallScript derived from scripts when flag not set
const v3NoFlag = {
  lockfileVersion: 3,
  packages: {
    'node_modules/native-mod': {
      version: '1.0.0',
      scripts: { postinstall: 'node-gyp rebuild' },
      // hasInstallScript NOT explicitly set — should be derived
    },
  },
};
const pkgs2 = extractPackages(v3NoFlag);
assert(pkgs2['native-mod'].hasInstallScript === true, 'hasInstallScript derived from scripts field');

// ── extractPackages — v1 format ───────────────────────────────────────────────

section('extractPackages (v1 fallback)');

const v1lockfile = {
  lockfileVersion: 1,
  dependencies: {
    express: {
      version: '4.18.0',
      resolved: 'https://registry.npmjs.org/express/-/express-4.18.0.tgz',
      dependencies: {
        'body-parser': { version: '1.20.0' },
      },
    },
    'sharp': {
      version: '0.33.0',
      scripts: { postinstall: 'node-pre-gyp install' },
    },
  },
};

const pkgsV1 = extractPackages(v1lockfile);
assert(pkgsV1['express'] !== undefined, 'extracts v1 package');
assert(pkgsV1['express'].version === '4.18.0', 'v1 version correct');
assert(pkgsV1['body-parser'] !== undefined, 'extracts nested v1 deps');
assert(pkgsV1['sharp'].hasInstallScript === true, 'v1 scripts → hasInstallScript');

// ── diffLockfilePackages ──────────────────────────────────────────────────────

section('diffLockfilePackages');

const before = {
  'follow-redirects': { version: '1.15.0', hasInstallScript: false, scripts: {} },
  'axios':            { version: '1.14.0', hasInstallScript: false, scripts: {} },
};

const after = {
  'follow-redirects': { version: '1.15.0', hasInstallScript: false, scripts: {} }, // unchanged
  'axios':            { version: '1.14.1', hasInstallScript: false, scripts: {} }, // updated
  'mock-unapproved-dep':  { version: '4.2.1',  hasInstallScript: true,  scripts: { postinstall: 'node postinstall-hook.js' } }, // new
};

const diff = diffLockfilePackages(before, after);

assert(diff.added.length === 1, 'detects 1 added package');
assert(diff.added[0].name === 'mock-unapproved-dep', 'correct added package');
assert(diff.updated.length === 1, 'detects 1 updated package');
assert(diff.updated[0].name === 'axios', 'correct updated package');
assert(diff.updated[0].from === '1.14.0', 'from version correct');
assert(diff.updated[0].to   === '1.14.1', 'to version correct');
assert(diff.removed.length === 0, 'no removals');
assert(diff.newWithScripts.length === 1, 'newWithScripts identifies mock-unapproved-dep');
assert(diff.newWithScripts[0].name === 'mock-unapproved-dep', 'correct newWithScripts entry');

// Removal test
const afterRemoved = {
  'follow-redirects': { version: '1.15.0', hasInstallScript: false, scripts: {} },
};
const diffRm = diffLockfilePackages(before, afterRemoved);
assert(diffRm.removed.length === 1, 'detects removal');
assert(diffRm.removed[0].name === 'axios', 'correct removed package');

// Update that adds new scripts
const beforeNoScripts = { 'mymod': { version: '1.0.0', hasInstallScript: false, scripts: {} } };
const afterNewScripts  = { 'mymod': { version: '1.1.0', hasInstallScript: true, scripts: { postinstall: 'node build.js' } } };
const diffScripts = diffLockfilePackages(beforeNoScripts, afterNewScripts);
assert(diffScripts.updatesWithNewScripts.length === 1, 'detects update that adds new scripts');
assert(diffScripts.updatesWithNewScripts[0].scriptsAdded.includes('postinstall'), 'identifies added script key');

// ── summary ───────────────────────────────────────────────────────────────────

console.log(`\n${'─'.repeat(52)}`);
console.log(`  Results: ${passed} passed, ${failed} failed\n`);
process.exit(failed > 0 ? 1 : 0);
