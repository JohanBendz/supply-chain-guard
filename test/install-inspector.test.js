'use strict';
/**
 * test/install-inspector.test.js
 * Tests for src/install-inspector.js
 *
 * Builds fake node_modules + lockfile structures in tmp dirs to test
 * the full policy enforcement pipeline without running npm.
 */

const fs   = require('fs');
const path = require('path');
const os   = require('os');

const { inspectInstall }       = require('../src/install-inspector');
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

// ── fixture builders ──────────────────────────────────────────────────────────

function makeProject(packages = {}) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'scg-ii-test-'));
  fs.writeFileSync(path.join(root, 'package.json'), JSON.stringify({ name: 'test', version: '1.0.0' }));

  // Build node_modules
  const nm = path.join(root, 'node_modules');
  fs.mkdirSync(nm);

  // Build lockfile v3
  const lockPkgs = {};
  for (const [name, meta] of Object.entries(packages)) {
    // Write node_modules/<name>/package.json
    const pkgDir = path.join(nm, name);
    fs.mkdirSync(pkgDir, { recursive: true });
    fs.writeFileSync(path.join(pkgDir, 'package.json'), JSON.stringify({
      name, version: meta.version || '1.0.0', scripts: meta.scripts || {},
    }));

    lockPkgs[`node_modules/${name}`] = {
      version: meta.version || '1.0.0',
      hasInstallScript: !!(meta.scripts && Object.keys(meta.scripts).length > 0),
      scripts: meta.scripts || {},
    };
  }

  fs.writeFileSync(
    path.join(root, 'package-lock.json'),
    JSON.stringify({ lockfileVersion: 3, packages: { '': {}, ...lockPkgs } }, null, 2),
  );

  return root;
}

function cleanup(dir) {
  fs.rmSync(dir, { recursive: true, force: true });
}

// ── tests ─────────────────────────────────────────────────────────────────────

section('clean install — no scripts');

const rootClean = makeProject({
  'follow-redirects': { version: '1.15.0' },
  'form-data':        { version: '4.0.1' },
});
initPolicy(rootClean);

const clean = inspectInstall(rootClean, { beforeLockfile: null });
assert(clean.blocked.length       === 0, 'no blocked packages');
assert(clean.needsApproval.length === 0, 'no packages needing approval');
assert(clean.isClean              === true, 'isClean is true');
cleanup(rootClean);

section('new package with postinstall — needs approval');

const rootNeeds = makeProject({
  'follow-redirects': { version: '1.15.0' },
  'mock-unapproved-dep':  { version: '4.2.1', scripts: { postinstall: 'node postinstall-hook.js' } },
});
initPolicy(rootNeeds);

const beforePkgs = {
  'follow-redirects': { version: '1.15.0', hasInstallScript: false, scripts: {} },
  // mock-unapproved-dep not present before
};

const needsReport = inspectInstall(rootNeeds, { beforeLockfile: beforePkgs });
assert(needsReport.needsApproval.length === 1, 'one package needs approval');
assert(needsReport.needsApproval[0].name === 'mock-unapproved-dep', 'correct package flagged');
assert(needsReport.blocked.length === 0, 'nothing blocked yet');
assert(needsReport.isClean === false, 'isClean is false');
cleanup(rootNeeds);

section('approved package — moves to approved list');

const rootApproved = makeProject({
  'esbuild': { version: '0.21.5', scripts: { postinstall: 'node install.js' } },
});
initPolicy(rootApproved);
approveBuild(rootApproved, 'esbuild', '0.21.5', { postinstall: 'node install.js' });

const approvedReport = inspectInstall(rootApproved, { beforeLockfile: {} });
assert(approvedReport.needsApproval.length === 0, 'approved pkg not in needsApproval');
assert(approvedReport.approved.length === 1, 'in approved list');
assert(approvedReport.approved[0].name === 'esbuild', 'correct approved package');
assert(approvedReport.blocked.length   === 0, 'not blocked');
cleanup(rootApproved);

section('denied package — moves to blocked list');

const rootDenied = makeProject({
  'bad-dep': { version: '9.9.9', scripts: { postinstall: 'node build-native.js' } },
});
initPolicy(rootDenied);
denyBuild(rootDenied, 'bad-dep', '9.9.9', 'unapproved-script');

const deniedReport = inspectInstall(rootDenied, { beforeLockfile: {} });
assert(deniedReport.blocked.length    === 1, 'one blocked package');
assert(deniedReport.blocked[0].name   === 'bad-dep', 'correct blocked package');
assert(deniedReport.blocked[0].reason === 'unapproved-script', 'reason preserved');
assert(deniedReport.isClean           === false, 'isClean false when blocked');
cleanup(rootDenied);

section('bare-name denial — blocks any version');

const rootBaredeny = makeProject({
  'always-bad': { version: '2.0.0', scripts: { postinstall: 'node cleanup.js' } },
});
initPolicy(rootBaredeny);
// Deny bare name (no version) — should match any version
denyBuild(rootBaredeny, 'always-bad', null, 'always block this package');

const bareDenyReport = inspectInstall(rootBaredeny, { beforeLockfile: {} });
assert(bareDenyReport.blocked.length === 1, 'bare-name denial blocks any version');
cleanup(rootBaredeny);

section('no beforeLockfile — inspects all packages with scripts');

const rootAll = makeProject({
  'clean-pkg': { version: '1.0.0' },
  'scripted-pkg': { version: '1.0.0', scripts: { postinstall: 'echo hi' } },
});
initPolicy(rootAll);

const allReport = inspectInstall(rootAll, { beforeLockfile: null });
// With no before lockfile, we scan everything with scripts
assert(allReport.needsApproval.length === 1, 'finds the one unapproved scripted pkg');
assert(allReport.needsApproval[0].name === 'scripted-pkg', 'correct package');
cleanup(rootAll);

section('mixed — approved + denied + pending');

const rootMixed = makeProject({
  'esbuild':     { version: '0.21.5', scripts: { postinstall: 'node install.js' } },
  'bad-dep':    { version: '1.0.0',  scripts: { postinstall: 'node build-native.js' } },
  'new-mystery': { version: '1.0.0',  scripts: { install: 'node-gyp build' } },
});
initPolicy(rootMixed);
approveBuild(rootMixed, 'esbuild', '0.21.5', { postinstall: 'node install.js' });
denyBuild(rootMixed, 'bad-dep', '1.0.0', 'suspicious');

const mixedReport = inspectInstall(rootMixed, { beforeLockfile: {} });
assert(mixedReport.approved.length      === 1, 'one approved');
assert(mixedReport.blocked.length       === 1, 'one blocked');
assert(mixedReport.needsApproval.length === 1, 'one pending approval');
assert(mixedReport.isClean              === false, 'not clean');
cleanup(rootMixed);

// ── summary ───────────────────────────────────────────────────────────────────

console.log(`\n${'─'.repeat(52)}`);
console.log(`  Results: ${passed} passed, ${failed} failed\n`);
process.exit(failed > 0 ? 1 : 0);
