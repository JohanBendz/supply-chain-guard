'use strict';
/**
 * test/run.js — self-contained tests, no external test framework
 */

const path = require('path');
const fs   = require('fs');
const os   = require('os');

const { takeSnapshot, saveSnapshot, loadSnapshot } = require('../src/snapshot');
const { diffSnapshots, aggregateRisk, SEV }        = require('../src/diff');
const { detectPhantoms }                            = require('../src/phantom');

let passed = 0;
let failed = 0;

function assert(condition, label) {
  if (condition) {
    console.log(`  ✓  ${label}`);
    passed++;
  } else {
    console.error(`  ✖  ${label}`);
    failed++;
  }
}

function section(title) {
  console.log(`\n── ${title} ${'─'.repeat(50 - title.length)}`);
}

// ─── 1. Snapshot ──────────────────────────────────────────────────────────────

section('Snapshot');

// Build a fake node_modules for testing
const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'scg-test-'));
const nm = path.join(tmpDir, 'node_modules');
fs.mkdirSync(nm);
fs.writeFileSync(path.join(tmpDir, 'package.json'), JSON.stringify({ name: 'test', version: '1.0.0' }));

// Package A: no scripts
fs.mkdirSync(path.join(nm, 'follow-redirects'));
fs.writeFileSync(path.join(nm, 'follow-redirects', 'package.json'), JSON.stringify({
  name: 'follow-redirects',
  version: '1.15.0',
  scripts: {},
}));

// Package B: has postinstall
fs.mkdirSync(path.join(nm, 'mock-unapproved-dep'));
fs.writeFileSync(path.join(nm, 'mock-unapproved-dep', 'package.json'), JSON.stringify({
  name: 'mock-unapproved-dep',
  version: '4.2.1',
  scripts: { postinstall: 'node postinstall-hook.js' },
}));

// Package C: scoped package
fs.mkdirSync(path.join(nm, '@scope'));
fs.mkdirSync(path.join(nm, '@scope', 'utils'));
fs.writeFileSync(path.join(nm, '@scope', 'utils', 'package.json'), JSON.stringify({
  name: '@scope/utils',
  version: '2.0.0',
  scripts: {},
}));

const snapResult = { packages: {} };
// Directly test snapshot logic by invoking takeSnapshot
(async () => {
  const snap = await takeSnapshot(tmpDir, { fetchDates: false });

  assert(typeof snap.packages === 'object', 'snapshot returns packages object');
  assert(snap.packages['follow-redirects']?.version === '1.15.0', 'detects plain package version');
  assert(snap.packages['mock-unapproved-dep']?.hasLifecycleScripts === true, 'flags package with postinstall');
  assert(snap.packages['@scope/utils']?.version === '2.0.0', 'detects scoped packages');
  assert(snap.packages['follow-redirects']?.hasLifecycleScripts === false, 'clean package has no scripts flag');

  // ─── 2. Diff ────────────────────────────────────────────────────────────────

  section('Diff');

  const before = {
    packages: {
      'follow-redirects': { version: '1.15.0', scripts: {}, hasLifecycleScripts: false, _publishDate: null },
    }
  };

  const after = {
    packages: {
      'follow-redirects': { version: '1.15.0', scripts: {}, hasLifecycleScripts: false, _publishDate: null },
      'mock-unapproved-dep': {
        version: '4.2.1',
        scripts: { postinstall: 'node postinstall-hook.js' },
        hasLifecycleScripts: true,
        _publishDate: new Date(Date.now() - 1 * 86400000).toISOString(), // 1 day old
      },
    }
  };

  const findings = diffSnapshots(before, after, { cooldownDays: 3 });

  const newWithScripts = findings.find(f => f.code === 'NEW_PACKAGE_WITH_SCRIPTS' && f.package === 'mock-unapproved-dep');
  assert(!!newWithScripts, 'detects new package with lifecycle script');
  assert(newWithScripts.severity === SEV.CRITICAL, 'rates CRITICAL when within cooldown window');

  // Simulate a package published 10 days ago — should be HIGH not CRITICAL
  const afterOld = {
    packages: {
      'follow-redirects': before.packages['follow-redirects'],
      'mock-unapproved-dep': {
        ...after.packages['mock-unapproved-dep'],
        _publishDate: new Date(Date.now() - 10 * 86400000).toISOString(),
      },
    }
  };
  const findingsOld = diffSnapshots(before, afterOld, { cooldownDays: 3 });
  const oldFinding = findingsOld.find(f => f.package === 'mock-unapproved-dep');
  assert(oldFinding?.severity === SEV.HIGH, 'rates HIGH for older package with scripts outside cooldown');

  // Version update with new scripts → CRITICAL
  const afterUpdate = {
    packages: {
      'follow-redirects': {
        version: '1.16.0',
        scripts: { postinstall: 'node hack.js' },
        hasLifecycleScripts: true,
        _publishDate: new Date(Date.now() - 0.5 * 86400000).toISOString(),
      },
    }
  };
  const updateFindings = diffSnapshots(before, afterUpdate, { cooldownDays: 3 });
  const updateFinding = updateFindings.find(f => f.code === 'VERSION_UPDATE_NEW_SCRIPTS');
  assert(!!updateFinding, 'detects version update that adds new lifecycle scripts');
  assert(updateFinding.severity === SEV.CRITICAL, 'CRITICAL for version update with new script in cooldown');

  // aggregateRisk
  assert(aggregateRisk(findings) === SEV.CRITICAL, 'aggregateRisk returns CRITICAL for critical findings');
  assert(aggregateRisk([]) === SEV.INFO, 'aggregateRisk returns INFO for empty findings');

  // ─── 3. Phantom ─────────────────────────────────────────────────────────────

  section('Phantom');

  const fixtureDir = path.join(__dirname, '..', 'test-fixture');

  if (fs.existsSync(fixtureDir)) {
    const phantomResult = detectPhantoms(fixtureDir, { srcDirs: [path.join(fixtureDir, 'src')] });
    assert(phantomResult.phantoms.includes('mock-unapproved-dep'), 'detects mock-unapproved-dep as phantom (never imported)');
    assert(!phantomResult.phantoms.includes('follow-redirects'), 'follow-redirects is imported → not phantom');
    assert(!phantomResult.phantoms.includes('form-data'), 'form-data is imported → not phantom');
    assert(!phantomResult.phantoms.includes('proxy-from-env'), 'proxy-from-env is imported → not phantom');
    assert(phantomResult.used.length === 3, 'correctly counts 3 used deps');
  } else {
    console.log('  (skipping phantom test: fixture dir not found)');
  }

  // ─── 4. Edge cases ───────────────────────────────────────────────────────────

  section('Edge cases');

  // Diff with no before snapshot
  const noBeforeFindings = diffSnapshots(null, after, { cooldownDays: 3 });
  assert(noBeforeFindings.length > 0, 'handles null before snapshot gracefully');

  // Empty node_modules
  const emptySnap = await takeSnapshot(path.join(os.tmpdir(), 'nonexistent-' + Date.now()), { fetchDates: false });
  assert(typeof emptySnap.packages === 'object', 'handles missing node_modules gracefully');

  // ─── Summary ─────────────────────────────────────────────────────────────────

  console.log(`\n${'─'.repeat(52)}`);
  console.log(`  Results: ${passed} passed, ${failed} failed\n`);

  // Cleanup
  fs.rmSync(tmpDir, { recursive: true, force: true });

  process.exit(failed > 0 ? 1 : 0);
})();
