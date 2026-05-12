'use strict';
/**
 * test/npm.test.js
 * Tests for src/npm.js — --ignore-scripts enforcement.
 *
 * We use dry-run mode throughout so no real npm calls are made.
 */

const { runSafe, runRaw, SAFE_COMMANDS, ignoreFlagNotice } = require('../src/npm');

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

// ── SAFE_COMMANDS set ─────────────────────────────────────────────────────────

section('SAFE_COMMANDS coverage');
assert(SAFE_COMMANDS.has('install'), 'install is a safe command');
assert(SAFE_COMMANDS.has('ci'),      'ci is a safe command');
assert(SAFE_COMMANDS.has('update'),  'update is a safe command');
assert(SAFE_COMMANDS.has('i'),       'i alias is a safe command');
assert(SAFE_COMMANDS.has('uninstall'), 'uninstall is a safe command');
assert(SAFE_COMMANDS.has('remove'),  'remove is a safe command');
assert(!SAFE_COMMANDS.has('publish'), 'publish is NOT a safe command');
assert(!SAFE_COMMANDS.has('run'),     'run is NOT a safe command');

// ── --ignore-scripts injection ────────────────────────────────────────────────

section('runSafe -- ignore-scripts injection');

// install: should inject
let r = runSafe(['install'], { dryRun: true });
assert(r.command.includes('--ignore-scripts'), 'inject --ignore-scripts for install');
assert(r.dryRun === true, 'dryRun flag preserved');

// ci: should inject
r = runSafe(['ci'], { dryRun: true });
assert(r.command.includes('--ignore-scripts'), 'inject --ignore-scripts for ci');

// update: should inject
r = runSafe(['update', 'lodash'], { dryRun: true });
assert(r.command.includes('--ignore-scripts'), 'inject for update');
assert(r.command.includes('lodash'), 'package name preserved');

// install with explicit --save-dev flag: preserved
r = runSafe(['install', 'express', '--save-dev'], { dryRun: true });
assert(r.command.includes('--save-dev'), '--save-dev flag preserved');
assert(r.command.includes('--ignore-scripts'), '--ignore-scripts still injected');

// already has --ignore-scripts: not duplicated
r = runSafe(['install', '--ignore-scripts'], { dryRun: true });
const count = (r.command.match(/--ignore-scripts/g) || []).length;
assert(count === 1, '--ignore-scripts not duplicated when already present');

// non-dependency-changing commands: no injection
r = runSafe(['run', 'build'], { dryRun: true });
assert(!r.command.includes('--ignore-scripts'), 'no injection for non-dep commands (run)');

r = runSafe(['publish'], { dryRun: true });
assert(!r.command.includes('--ignore-scripts'), 'no injection for publish');

// ── runRaw -- no injection ────────────────────────────────────────────────────

section('runRaw -- passthrough without injection');

r = runRaw(['install', 'lodash'], { dryRun: true });
assert(!r.command.includes('--ignore-scripts'), 'runRaw does NOT inject --ignore-scripts');
assert(r.command.includes('install'), 'command preserved in runRaw');
assert(r.dryRun === true, 'dryRun works in runRaw');

// ── ignoreFlagNotice ──────────────────────────────────────────────────────────

section('ignoreFlagNotice');
const notice = ignoreFlagNotice();
assert(typeof notice === 'string', 'returns a string');
assert(notice.includes('ignore-scripts'), 'mentions ignore-scripts');


section('runSafe -- SCG_ACTIVE injected into subprocess env');

// Verify that runSafe passes SCG_ACTIVE=1 to the npm environment.
// We can't inspect the env of a spawned process directly, but we can
// test that SCG_ACTIVE is present in spawnOpts by reading the source
// or by using a dry-run with env inspection via a test script.
// Instead: verify the contract via the npm.js source itself.
const npmSrc = require('fs').readFileSync(
  require('path').join(__dirname, '../src/npm.js'), 'utf8');
assert(npmSrc.includes('SCG_ACTIVE'), 'SCG_ACTIVE present in npm.js source');
assert(npmSrc.includes('SCG_ACTIVE:'), 'SCG_ACTIVE key present in env merge');
assert(!npmSrc.includes("SCG_ACTIVE: '1'"), "SCG_ACTIVE is NOT a static '1' (dynamic token)");
assert(npmSrc.indexOf('SCG_ACTIVE') < npmSrc.indexOf('function runRaw'),
  'SCG_ACTIVE injection is in runSafe, not runRaw');

// runRaw must NOT set SCG_ACTIVE (escape hatch = no protection)
const runRawSection = npmSrc.slice(npmSrc.indexOf('function runRaw'));
assert(!runRawSection.includes('SCG_ACTIVE'), 'runRaw does NOT set SCG_ACTIVE');

// ── summary ───────────────────────────────────────────────────────────────────

console.log(`\n${'─'.repeat(52)}`);
console.log(`  Results: ${passed} passed, ${failed} failed\n`);
process.exit(failed > 0 ? 1 : 0);
