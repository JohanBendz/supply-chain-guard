'use strict';
/**
 * test/fixes-080.test.js
 * Regression tests for v0.8.0 release blockers:
 *   - npm wrapper flags are preserved for install/ci/remove dry runs
 *   - nested package metadata is read via the lockfile path, not pkgName.split('>')[0]
 *   - installed package.json scripts are inspected even when lockfile metadata is missing
 *   - approved script hash mismatches are surfaced during post-install inspection
 */

const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawnSync } = require('child_process');

const { inspectInstall, readInstalledMeta } = require('../src/install-inspector');
const { initPolicy, approveBuild } = require('../src/policy');

let passed = 0;
let failed = 0;
function assert(cond, label) {
  if (cond) { console.log(`  ✓  ${label}`); passed++; }
  else      { console.error(`  ✖  ${label}`); failed++; }
}
function section(title) {
  const pad = Math.max(2, 54 - title.length);
  console.log(`\n── ${title} ${'─'.repeat(pad)}`);
}
function makeRoot(prefix = 'scg-080-') {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), prefix));
  fs.writeFileSync(path.join(root, 'package.json'), JSON.stringify({ name: 't', version: '1.0.0' }, null, 2));
  fs.mkdirSync(path.join(root, 'node_modules'), { recursive: true });
  return root;
}
function writePkg(root, rel, meta) {
  const dir = path.join(root, rel);
  fs.mkdirSync(dir, { recursive: true });
  fs.writeFileSync(path.join(dir, 'package.json'), JSON.stringify(meta, null, 2));
}
function cleanup(root) { fs.rmSync(root, { recursive: true, force: true }); }

section('npm wrapper preserves npm flags');

const cliRoot = makeRoot();
let r = spawnSync(process.execPath, [path.join(__dirname, '../bin/scg.js'), 'install', '--omit=dev', '--legacy-peer-deps', '--dry-run'], {
  cwd: cliRoot,
  encoding: 'utf8',
});
const out = `${r.stdout}\n${r.stderr}`;
assert(r.status === 0, 'scg install --dry-run exits cleanly');
assert(out.includes('npm install --omit=dev --legacy-peer-deps --ignore-scripts'), 'install preserves npm flags and strips SCG dry-run');

r = spawnSync(process.execPath, [path.join(__dirname, '../bin/scg.js'), 'ci', '--workspace', 'app', '--dry-run'], {
  cwd: cliRoot,
  encoding: 'utf8',
});
const outCi = `${r.stdout}\n${r.stderr}`;
assert(r.status === 0, 'scg ci --dry-run exits cleanly');
assert(outCi.includes('npm ci --workspace app --ignore-scripts'), 'ci preserves npm flags with values');
cleanup(cliRoot);

section('nested package metadata uses lockfile path');

const nestedRoot = makeRoot();
writePkg(nestedRoot, 'node_modules/foo', { name: 'foo', version: '1.0.0' });
writePkg(nestedRoot, 'node_modules/foo/node_modules/bar', {
  name: 'bar', version: '2.0.0', scripts: { postinstall: 'node nested.js' },
});
const nestedMeta = readInstalledMeta(nestedRoot, 'foo>bar', {
  _lockfilePath: 'node_modules/foo/node_modules/bar',
});
assert(nestedMeta?.name === 'bar', 'nested metadata reads bar, not parent foo');
assert(nestedMeta?.scripts?.postinstall === 'node nested.js', 'nested scripts are visible');
cleanup(nestedRoot);

section('inspector reads disk scripts even if lockfile omits them');

const missingLockRoot = makeRoot();
writePkg(missingLockRoot, 'node_modules/native-pkg', {
  name: 'native-pkg', version: '1.0.0', scripts: { postinstall: 'node install.js' },
});
fs.writeFileSync(path.join(missingLockRoot, 'package-lock.json'), JSON.stringify({
  lockfileVersion: 3,
  packages: {
    '': {},
    'node_modules/native-pkg': { version: '1.0.0' },
  },
}, null, 2));
initPolicy(missingLockRoot);
const missingReport = inspectInstall(missingLockRoot, { beforeLockfile: {} });
assert(missingReport.needsApproval.length === 1, 'script package is detected from node_modules/package.json');
assert(missingReport.needsApproval[0].name === 'native-pkg', 'correct package flagged');
cleanup(missingLockRoot);

section('approved script changes are reported immediately');

const changedRoot = makeRoot();
writePkg(changedRoot, 'node_modules/esbuild', {
  name: 'esbuild', version: '0.21.5', scripts: { postinstall: 'node install.js' },
});
fs.writeFileSync(path.join(changedRoot, 'package-lock.json'), JSON.stringify({
  lockfileVersion: 3,
  packages: {
    '': {},
    'node_modules/esbuild': { version: '0.21.5', hasInstallScript: true },
  },
}, null, 2));
initPolicy(changedRoot);
approveBuild(changedRoot, 'esbuild', '0.21.5', { postinstall: 'node install.js' });
writePkg(changedRoot, 'node_modules/esbuild', {
  name: 'esbuild', version: '0.21.5', scripts: { postinstall: 'node changed.js' },
});
const changedReport = inspectInstall(changedRoot, { beforeLockfile: {} });
assert(changedReport.approvedChanged.length === 1, 'approvedChanged contains hash mismatch');
assert(changedReport.isClean === false, 'hash mismatch makes report unclean');
cleanup(changedRoot);

console.log(`\n${'─'.repeat(52)}`);
console.log(`  Results: ${passed} passed, ${failed} failed\n`);
process.exit(failed > 0 ? 1 : 0);
