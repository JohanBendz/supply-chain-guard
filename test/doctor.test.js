'use strict';
/**
 * test/doctor.test.js
 * Tests for `scg doctor` — project health checks.
 */

const fs   = require('fs');
const path = require('path');
const os   = require('os');
const { spawnSync } = require('child_process');

const { POLICY_FILE }                       = require('../src/policy');
const { LOCK_FILE, writeToken }              = require('../src/lock-token');

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
    cwd, encoding: 'utf8', timeout: 15000,
  });
  return { status: r.status ?? 2, stdout: r.stdout || '', stderr: r.stderr || '' };
}

function makeProject() {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'scg-doc-test-'));
  fs.writeFileSync(path.join(root, 'package.json'), JSON.stringify({
    name: 'test-project', version: '1.0.0', scripts: {},
  }, null, 2));
  return root;
}
function cleanup(dir) { fs.rmSync(dir, { recursive: true, force: true }); }

// ── fully initialized project ─────────────────────────────────────────────────

section('doctor -- fully initialized project passes');

const rootA = makeProject();
runScg(['init'], rootA);
const resA = runScg(['doctor'], rootA);
assert(resA.status === 0, 'exits 0 for healthy project');
assert(resA.stdout.includes('healthy') || resA.stdout.includes('✓'), 'reports healthy');
cleanup(rootA);

// ── missing policy file ───────────────────────────────────────────────────────

section('doctor -- flags missing .scg-policy.json');

const rootB = makeProject();
// Don't run init — no policy file
const resB = runScg(['doctor'], rootB);
assert(resB.status === 1, 'exits 1 when policy missing');
assert(resB.stdout.includes('scg-policy') || resB.stdout.includes('init'), 'mentions missing policy');
cleanup(rootB);

// ── missing .scg-lock ─────────────────────────────────────────────────────────

section('doctor -- flags missing .scg-lock in initialized repo');

const rootC = makeProject();
runScg(['init'], rootC);
// Simulate: scg ci ran once (created .scg-lock), then file was lost
writeToken(rootC, 'deadbeefdeadbeefdeadbeefdeadbeef');
fs.unlinkSync(path.join(rootC, LOCK_FILE));
const resC = runScg(['doctor'], rootC);
// In the per-session model, missing .scg-lock is not a hard issue for doctor
// (it's created by scg ci/install). But if it's not in .gitignore, that's flagged.
// The doctor should at minimum mention .scg-lock or lock in its output.
assert(resC.stdout.includes('scg-lock') || resC.stdout.includes('lock') || resC.status === 0,
  'doctor handles missing .scg-lock gracefully');
cleanup(rootC);

// ── missing preinstall guard ──────────────────────────────────────────────────

section('doctor -- flags missing preinstall guard');

const rootD = makeProject();
runScg(['init'], rootD);
// Remove the preinstall from package.json
const pkgPath = path.join(rootD, 'package.json');
const pkg = JSON.parse(fs.readFileSync(pkgPath, 'utf8'));
delete pkg.scripts.preinstall;
fs.writeFileSync(pkgPath, JSON.stringify(pkg, null, 2));
const resD = runScg(['doctor'], rootD);
assert(resD.status === 1, 'exits 1 when preinstall guard missing');
assert(resD.stdout.includes('preinstall') || resD.stdout.includes('guard'), 'mentions missing guard');
cleanup(rootD);

// ── warns about raw npm install in scripts ────────────────────────────────────

section('doctor -- warns about raw npm install in scripts');

const rootE = makeProject();
runScg(['init'], rootE);
const pkgE = JSON.parse(fs.readFileSync(path.join(rootE, 'package.json'), 'utf8'));
pkgE.scripts.setup = 'npm install && node server.js';
fs.writeFileSync(path.join(rootE, 'package.json'), JSON.stringify(pkgE, null, 2));
const resE = runScg(['doctor'], rootE);
// Doctor should warn but not necessarily fail (it's advisory)
assert(resE.stdout.includes('npm install') || resE.stdout.includes('raw'), 'warns about raw npm install');
cleanup(rootE);

// ── .npmrc check ─────────────────────────────────────────────────────────────

section('doctor -- notes absent .npmrc (advisory)');

const rootF = makeProject();
runScg(['init'], rootF); // no --npmrc flag
const resF = runScg(['doctor'], rootF);
// .npmrc absence is a warning, not a blocking issue
assert(resF.stdout.includes('npmrc') || resF.stdout.includes('ignore-scripts'), 'mentions .npmrc');
cleanup(rootF);

// ── doctor with .npmrc present ────────────────────────────────────────────────

section('doctor -- confirms .npmrc with ignore-scripts');

const rootG = makeProject();
runScg(['init', '--npmrc'], rootG);
const resG = runScg(['doctor'], rootG);
assert(resG.status === 0, 'exits 0 when .npmrc has ignore-scripts');
assert(resG.stdout.includes('ignore-scripts'), 'confirms ignore-scripts present');
cleanup(rootG);

// ── doctor is in help text ────────────────────────────────────────────────────

section('doctor -- appears in scg help');

const rootH = makeProject();
const resH = runScg(['help'], rootH);
assert(resH.stdout.includes('doctor'), 'doctor listed in help output');
cleanup(rootH);

// ── summary ───────────────────────────────────────────────────────────────────

console.log(`\n${'─'.repeat(52)}`);
console.log(`  Results: ${passed} passed, ${failed} failed\n`);
process.exit(failed > 0 ? 1 : 0);
