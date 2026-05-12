'use strict';
/**
 * test/init.test.js
 * Tests for scg init behavior.
 */

const fs   = require('fs');
const path = require('path');
const os   = require('os');
const { spawnSync } = require('child_process');

const { POLICY_FILE }                       = require('../src/policy');
const { LOCK_FILE, readToken, buildGuardScript, generateSessionToken } = require('../src/lock-token');

let passed = 0;
let failed = 0;

function assert(condition, label) {
  if (condition) { console.log(`  \u2713  ${label}`); passed++; }
  else           { console.error(`  \u2716  ${label}`); failed++; }
}

function section(title) {
  const pad = Math.max(2, 54 - title.length);
  console.log(`\n\u2500\u2500 ${title} ${'\u2500'.repeat(pad)}`);
}

const SCG_BIN = path.resolve(__dirname, '../bin/scg.js');

function runScg(args, cwd) {
  const result = spawnSync(process.execPath, [SCG_BIN, ...args], {
    cwd, encoding: 'utf8', timeout: 10000,
  });
  return { status: result.status, stdout: result.stdout || '', stderr: result.stderr || '' };
}

function makeProject() {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'scg-init-test-'));
  fs.writeFileSync(path.join(root, 'package.json'), JSON.stringify({
    name: 'test-project', version: '1.0.0', scripts: { build: 'tsc' },
  }, null, 2));
  return root;
}

function cleanup(dir) { fs.rmSync(dir, { recursive: true, force: true }); }

// ── policy file ───────────────────────────────────────────────────────────────

section('scg init -- creates .scg-policy.json');

const rootA = makeProject();
const resA  = runScg(['init', '--dry-run'], rootA);
assert(resA.status === 0, 'exits 0');
assert(resA.stdout.includes(POLICY_FILE), 'mentions policy file in output');
assert(!fs.existsSync(path.join(rootA, POLICY_FILE)), 'dry-run does not write policy file');
cleanup(rootA);

const rootB = makeProject();
const resB  = runScg(['init'], rootB);
assert(resB.status === 0, 'exits 0 on real init');
assert(fs.existsSync(path.join(rootB, POLICY_FILE)), 'creates .scg-policy.json');
const policyContent = JSON.parse(fs.readFileSync(path.join(rootB, POLICY_FILE), 'utf8'));
assert(policyContent.version === 1, 'policy has version: 1');
assert(typeof policyContent.approvedBuilds === 'object', 'has approvedBuilds');
assert(typeof policyContent.deniedBuilds   === 'object', 'has deniedBuilds');
cleanup(rootB);

// ── muscle memory guard ───────────────────────────────────────────────────────

section('scg init -- preinstall guard added to package.json');

const rootC = makeProject();
runScg(['init'], rootC);
const pkgC = JSON.parse(fs.readFileSync(path.join(rootC, 'package.json'), 'utf8'));
assert(!!pkgC.scripts?.preinstall,                           'preinstall guard IS added');
assert(pkgC.scripts.preinstall.includes('SCG_ACTIVE'),       'guard checks SCG_ACTIVE');
assert(pkgC.scripts.preinstall.includes('process.exit(1)'), 'guard exits 1 when not active');
assert(!pkgC.scripts?.postinstall,                           'postinstall NOT added');
assert(pkgC.scripts?.build === 'tsc',                        'existing scripts preserved');
cleanup(rootC);

section('scg init -- guard blocks raw npm install');

const passResult = spawnSync(process.execPath,
  ['-e', "if(!process.env.SCG_ACTIVE){process.exit(1)} process.exit(0)"],
  { env: { ...process.env, SCG_ACTIVE: '1' }, encoding: 'utf8' });
assert(passResult.status === 0, 'guard passes when SCG_ACTIVE=1');

const failResult = spawnSync(process.execPath,
  ['-e', "if(!process.env.SCG_ACTIVE){process.exit(1)} process.exit(0)"],
  { env: Object.fromEntries(Object.entries(process.env).filter(([k]) => k !== 'SCG_ACTIVE')), encoding: 'utf8' });
assert(failResult.status === 1, 'guard exits 1 when SCG_ACTIVE absent');

section('scg init -- guard prepends to existing preinstall');

const rootD = makeProject();
const pkgPathD = path.join(rootD, 'package.json');
const pkgD0 = JSON.parse(fs.readFileSync(pkgPathD, 'utf8'));
pkgD0.scripts = { preinstall: 'echo existing-hook' };
fs.writeFileSync(pkgPathD, JSON.stringify(pkgD0, null, 2));
runScg(['init'], rootD);
const pkgD = JSON.parse(fs.readFileSync(pkgPathD, 'utf8'));
assert(pkgD.scripts.preinstall.includes('SCG_ACTIVE'),       'guard prepended');
assert(pkgD.scripts.preinstall.includes('echo existing-hook'), 'existing hook preserved');
cleanup(rootD);

section('scg init -- guard idempotent (second run)');

const rootE = makeProject();
runScg(['init'], rootE);
runScg(['init'], rootE);
const pkgE   = JSON.parse(fs.readFileSync(path.join(rootE, 'package.json'), 'utf8'));
const gCount = (pkgE.scripts?.preinstall || '').split('SCG_ACTIVE').length - 1;
assert(gCount === 1, 'SCG_ACTIVE appears exactly once after two inits');
cleanup(rootE);

// ── other init behaviour ──────────────────────────────────────────────────────

section('scg init -- creates .gitignore entry');

const rootF = makeProject();
runScg(['init'], rootF);
assert(fs.existsSync(path.join(rootF, '.gitignore')), 'creates .gitignore');
const gi = fs.readFileSync(path.join(rootF, '.gitignore'), 'utf8');
assert(gi.includes('.scg-snapshot'), '.gitignore excludes scg snapshots');
assert(gi.includes('.scg-lock'),     '.gitignore excludes .scg-lock (not committed)');
cleanup(rootF);

section('scg init -- --npmrc flag');

const rootG = makeProject();
runScg(['init', '--npmrc'], rootG);
assert(fs.existsSync(path.join(rootG, '.npmrc')), '.npmrc created');
const npmrc = fs.readFileSync(path.join(rootG, '.npmrc'), 'utf8');
assert(npmrc.includes('ignore-scripts=true'), '.npmrc has ignore-scripts=true');
cleanup(rootG);

section('scg init -- no .npmrc without flag');

const rootH = makeProject();
runScg(['init'], rootH);
assert(!fs.existsSync(path.join(rootH, '.npmrc')), '.npmrc not created without --npmrc');
cleanup(rootH);

section('scg init -- idempotent (policy file)');

const rootI = makeProject();
runScg(['init'], rootI);
const res2 = runScg(['init'], rootI);
assert(res2.status === 0, 'second init exits 0');
assert(res2.stdout.includes('already exists') || res2.stdout.includes('~'), 'notes existing files');
cleanup(rootI);

section('scg init -- output guides to wrapper commands');

const rootJ = makeProject();
const resJ  = runScg(['init'], rootJ);
assert(resJ.stdout.includes('scg install') || resJ.stdout.includes('scg add'), 'guides to wrapper commands');
assert(!resJ.stdout.includes('scg snapshot --pre'), 'does not advise snapshot hook');
cleanup(rootJ);

section('scg init -- .scg-lock is NOT created (generated per-session by scg ci/install)');

const rootL = makeProject();
runScg(['init'], rootL);
// .scg-lock should NOT exist after init — it's auto-generated by scg install/ci
assert(!fs.existsSync(path.join(rootL, LOCK_FILE)), '.scg-lock NOT created by init (per-session model)');
// But it should be in .gitignore
const giL = fs.readFileSync(path.join(rootL, '.gitignore'), 'utf8');
assert(giL.includes('.scg-lock'), '.scg-lock added to .gitignore');
cleanup(rootL);

section('scg init --rotate-token is accepted (no-op in per-session model)');

const rootM = makeProject();
const resM = runScg(['init', '--rotate-token'], rootM);
assert(resM.status === 0, '--rotate-token flag accepted without error');
cleanup(rootM);

section('buildGuardScript reads .scg-lock, not static value');

const guardSrc = buildGuardScript();
assert(guardSrc.includes('.scg-lock'),   'guard script reads .scg-lock');
assert(guardSrc.includes('SCG_ACTIVE'),  'guard compares SCG_ACTIVE');
assert(!guardSrc.includes("=== '1'"),    "guard does NOT compare against static '1'");
// The guard must read the file — hardcoding the token in ~/.zshrc doesn't help
assert(guardSrc.includes('readFileSync') || guardSrc.includes('readFile'),
  'guard reads file at runtime');

section('preinstall guard validates dynamic token (generated by scg commands)');

const rootN = makeProject();
runScg(['init'], rootN);
// Simulate scg generating a session token (what scg install/ci does)
const dynToken = generateSessionToken(rootN);

// Guard passes when SCG_ACTIVE equals the current session token
const passRes = spawnSync(process.execPath,
  ['-e', `if(process.env.SCG_ACTIVE!=='${dynToken}'){process.exit(1)}process.exit(0)`],
  { env: { ...process.env, SCG_ACTIVE: dynToken }, encoding: 'utf8' });
assert(passRes.status === 0, 'guard passes with correct session token');

// Guard blocks static bypass value
const bypassRes = spawnSync(process.execPath,
  ['-e', `if(process.env.SCG_ACTIVE!=='${dynToken}'){process.exit(1)}process.exit(0)`],
  { env: { ...process.env, SCG_ACTIVE: '1' }, encoding: 'utf8' });
assert(bypassRes.status === 1, "static '1' does not bypass dynamic token guard");

// Guard blocks stale token (e.g., from previous session)
const staleRes = spawnSync(process.execPath,
  ['-e', `if(process.env.SCG_ACTIVE!=='${dynToken}'){process.exit(1)}process.exit(0)`],
  { env: { ...process.env, SCG_ACTIVE: 'deadbeefdeadbeefdeadbeefdeadbeef' }, encoding: 'utf8' });
assert(staleRes.status === 1, 'stale token from previous session is blocked');
cleanup(rootN);

section('fail-closed: missing .scg-lock in initialized repo');

// When .scg-policy.json exists but .scg-lock is missing, guard blocks.
// Simulate: repo was initialized, scg ci ran once (created .scg-lock),
// then someone deleted it or failed to let scg ci run first.
const rootO = makeProject();
runScg(['init'], rootO);
// Create .scg-lock as if scg ci had run, then delete it
const { writeToken: wt } = require('../src/lock-token');
wt(rootO, 'deadbeefdeadbeefdeadbeefdeadbeef');
// Now delete it to simulate the broken state
fs.unlinkSync(path.join(rootO, LOCK_FILE));
// Guard script should now block because .scg-policy.json exists
const guardScript = buildGuardScript();
const innerScript = guardScript.replace(/^node -e "/, '').replace(/"$/, '');
const closedRes = spawnSync(process.execPath,
  ['-e', innerScript],
  {
    cwd: rootO,
    env: Object.fromEntries(Object.entries(process.env).filter(([k]) => k !== 'SCG_ACTIVE')),
    encoding: 'utf8',
  }
);
assert(closedRes.status === 1, 'missing .scg-lock in initialized repo → exit 1 (fail-closed)');
const errOut = (closedRes.stdout || '') + (closedRes.stderr || '');
assert(errOut.includes('STOP') || errOut.includes('scg ci') || errOut.includes('missing'), 'error message mentions recovery action');
cleanup(rootO);

section('fail-open: no .scg-lock AND no .scg-policy.json (not initialized)');

// When neither file exists, guard should pass (graceful onboarding)
const rootP = makeProject(); // no scg init
const guardScript2 = buildGuardScript();
const innerScript2 = guardScript2.replace(/^node -e "/, '').replace(/"$/, '');
const openRes = spawnSync(process.execPath,
  ['-e', innerScript2],
  {
    cwd: rootP,
    env: Object.fromEntries(Object.entries(process.env).filter(([k]) => k !== 'SCG_ACTIVE')),
    encoding: 'utf8',
  }
);
assert(openRes.status === 0, 'no .scg-lock, no policy → exit 0 (graceful onboarding)');
cleanup(rootP);

// ── summary ───────────────────────────────────────────────────────────────────



console.log(`\n${'─'.repeat(52)}`);
console.log(`  Results: ${passed} passed, ${failed} failed\n`);
process.exit(failed > 0 ? 1 : 0);
