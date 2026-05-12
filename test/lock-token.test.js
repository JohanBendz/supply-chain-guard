'use strict';
/**
 * test/lock-token.test.js
 * Tests for src/lock-token.js — dynamic repo-specific SCG_ACTIVE token.
 */

const fs   = require('fs');
const path = require('path');
const os   = require('os');
const { spawnSync } = require('child_process');

const {
  LOCK_FILE, lockFilePath, generateToken,
  readToken, writeToken, ensureToken, buildGuardScript,
} = require('../src/lock-token');

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

function makeTmp() {
  const d = fs.mkdtempSync(path.join(os.tmpdir(), 'scg-token-test-'));
  fs.writeFileSync(path.join(d, 'package.json'), '{"name":"test","version":"1.0.0"}');
  return d;
}

function cleanup(dir) { fs.rmSync(dir, { recursive: true, force: true }); }

// ── generateToken ─────────────────────────────────────────────────────────────

section('generateToken');

const t1 = generateToken();
const t2 = generateToken();
assert(typeof t1 === 'string', 'returns a string');
assert(t1.length === 32, 'token is 32 hex chars (128 bits)');
assert(/^[0-9a-f]+$/.test(t1), 'token is lowercase hex');
assert(t1 !== t2, 'each call generates a unique token');

// ── readToken / writeToken ────────────────────────────────────────────────────

section('readToken / writeToken');

const dirA = makeTmp();
assert(readToken(dirA) === null, 'returns null when .scg-lock missing');

writeToken(dirA, 'abc123');
assert(readToken(dirA) === 'abc123', 'reads back written token');
assert(fs.existsSync(lockFilePath(dirA)), '.scg-lock file created');

// Whitespace trimmed
fs.writeFileSync(lockFilePath(dirA), '  def456  \n');
assert(readToken(dirA) === 'def456', 'reads token with whitespace trimmed');
cleanup(dirA);

// ── ensureToken ───────────────────────────────────────────────────────────────

section('ensureToken');

const dirB = makeTmp();
const r1 = ensureToken(dirB);
assert(r1.created === true, 'created=true for new token');
assert(typeof r1.token === 'string' && r1.token.length === 32, 'token is 32-char hex');

const r2 = ensureToken(dirB);
assert(r2.created === false, 'created=false when token already exists');
assert(r2.token === r1.token, 'same token returned on second call');
cleanup(dirB);

// ── buildGuardScript ──────────────────────────────────────────────────────────

section('buildGuardScript — structure');

const guard = buildGuardScript();
assert(typeof guard === 'string', 'returns a string');
assert(guard.startsWith('node -e'), 'starts with node -e');
assert(guard.includes('.scg-lock'), 'reads .scg-lock file');
assert(guard.includes('SCG_ACTIVE'), 'compares SCG_ACTIVE env var');
assert(guard.includes('process.exit(1)'), 'exits 1 on mismatch');

section('buildGuardScript — runtime behaviour');

// Write a .scg-lock with a known token
const dirC = makeTmp();
const testToken = 'testtoken1234567890abcdef12345678';
writeToken(dirC, testToken);
const guardScript = buildGuardScript();
// Extract the -e argument
const eArg = guardScript.replace(/^node -e /, '');

// Run guard with correct SCG_ACTIVE=<token> — should pass
const passResult = spawnSync(process.execPath, ['-e', eArg], {
  cwd: dirC,
  env: { ...process.env, SCG_ACTIVE: testToken },
  encoding: 'utf8',
});
assert(passResult.status === 0, 'guard passes with correct token');

// Run guard with wrong SCG_ACTIVE — should fail
const wrongResult = spawnSync(process.execPath, ['-e', eArg], {
  cwd: dirC,
  env: { ...process.env, SCG_ACTIVE: 'wrongtoken' },
  encoding: 'utf8',
});
assert(wrongResult.status === 1, 'guard fails with wrong token');
assert(wrongResult.stderr.includes('STOP') || wrongResult.stdout.includes('STOP'),
  'error output mentions STOP');

// Run guard without SCG_ACTIVE — should fail
const noTokenEnv = Object.fromEntries(
  Object.entries(process.env).filter(([k]) => k !== 'SCG_ACTIVE'),
);
const noTokenResult = spawnSync(process.execPath, ['-e', eArg], {
  cwd: dirC, env: noTokenEnv, encoding: 'utf8',
});
assert(noTokenResult.status === 1, 'guard fails without SCG_ACTIVE');

// Run guard without .scg-lock file — should fail (empty string !== anything)
const dirD = makeTmp();
const noLockResult = spawnSync(process.execPath, ['-e', eArg], {
  cwd: dirD,
  env: { ...process.env, SCG_ACTIVE: testToken },
  encoding: 'utf8',
});
assert(noLockResult.status === 1, 'guard fails when .scg-lock absent');
cleanup(dirC);
cleanup(dirD);

section('token uniqueness — cannot be globally hardcoded');

// The bypass: developer adds `export SCG_ACTIVE=1` to ~/.zshrc.
// With the old static value, this would bypass the guard permanently.
// With the dynamic token, the guard reads .scg-lock at runtime.
// Even if SCG_ACTIVE is set in the environment, it must match the file.

const dirE = makeTmp();
const uniqueToken = ensureToken(dirE).token;
const scriptE = buildGuardScript();
const eArgE = scriptE.replace(/^node -e /, '');

// Simulate `export SCG_ACTIVE=1` in ~/.zshrc — should FAIL because token !== '1'
const zshrcBypassResult = spawnSync(process.execPath, ['-e', eArgE], {
  cwd: dirE,
  env: { ...process.env, SCG_ACTIVE: '1' }, // old static value
  encoding: 'utf8',
});
assert(zshrcBypassResult.status === 1, 'static SCG_ACTIVE=1 cannot bypass token guard');
cleanup(dirE);

// ── summary ───────────────────────────────────────────────────────────────────

console.log(`\n${'─'.repeat(52)}`);
console.log(`  Results: ${passed} passed, ${failed} failed\n`);
process.exit(failed > 0 ? 1 : 0);
