'use strict';
/**
 * postinstall-guard.js
 *
 * Reads the current project's lockfile (package-lock.json or yarn.lock)
 * and node_modules to build a complete picture of all packages that
 * declare lifecycle scripts.
 *
 * Also manages a persistent whitelist (~/.scg-whitelist.json) so that
 * previously-approved scripts don't generate noise on every run.
 */

const fs   = require('fs');
const path = require('path');
const os   = require('os');

const WHITELIST_PATH = path.join(os.homedir(), '.scg-whitelist.json');
const LIFECYCLE_KEYS = ['preinstall', 'install', 'postinstall', 'prepare', 'prepack', 'postpack'];

// ─── whitelist ────────────────────────────────────────────────────────────────

function loadWhitelist() {
  try {
    if (fs.existsSync(WHITELIST_PATH)) {
      return JSON.parse(fs.readFileSync(WHITELIST_PATH, 'utf8'));
    }
  } catch {}
  return {};
}

function saveWhitelist(wl) {
  fs.writeFileSync(WHITELIST_PATH, JSON.stringify(wl, null, 2));
}

/**
 * Whitelist key: "<name>@<version>:<scriptKey>=<fingerprint>"
 * Fingerprint = first 40 chars of script value — catches edits even within same version.
 */
function whitelistKey(name, version, scriptKey, scriptValue) {
  const fp = scriptValue.slice(0, 40).replace(/\s+/g, ' ');
  return `${name}@${version}:${scriptKey}=${fp}`;
}

function isWhitelisted(wl, name, version, scriptKey, scriptValue) {
  return !!wl[whitelistKey(name, version, scriptKey, scriptValue)];
}

function addToWhitelist(name, version, scriptKey, scriptValue) {
  const wl = loadWhitelist();
  wl[whitelistKey(name, version, scriptKey, scriptValue)] = {
    approvedAt: new Date().toISOString(),
    package: name,
    version,
    scriptKey,
  };
  saveWhitelist(wl);
}

// ─── lockfile reader ──────────────────────────────────────────────────────────

/** Parse package-lock.json v2/v3 */
function readLockfileScripts(lockfilePath) {
  let lock;
  try { lock = JSON.parse(fs.readFileSync(lockfilePath, 'utf8')); }
  catch { return null; }

  const result = {};

  // v2/v3: packages map
  if (lock.packages) {
    for (const [pkgPath, meta] of Object.entries(lock.packages)) {
      if (!pkgPath || pkgPath === '') continue; // root
      if (!meta.scripts) continue;

      const name = pkgPath.replace(/^node_modules\//, '').replace(/\/node_modules\//, ' > ');
      const version = meta.version || '?';
      const scripts = {};
      for (const k of LIFECYCLE_KEYS) {
        if (meta.scripts[k]) scripts[k] = meta.scripts[k];
      }
      if (Object.keys(scripts).length > 0) {
        result[name] = { version, scripts };
      }
    }
  }

  return result;
}

// ─── node_modules reader ──────────────────────────────────────────────────────

function readNodeModulesScripts(nodeModulesDir) {
  const result = {};
  if (!fs.existsSync(nodeModulesDir)) return result;

  function scanDir(dir, prefix = '') {
    let entries;
    try { entries = fs.readdirSync(dir, { withFileTypes: true }); }
    catch { return; }

    for (const entry of entries) {
      if (!entry.isDirectory()) continue;
      if (entry.name.startsWith('.') || entry.name === '.bin') continue;

      if (entry.name.startsWith('@')) {
        scanDir(path.join(dir, entry.name), entry.name + '/');
        continue;
      }

      const pkgJsonPath = path.join(dir, entry.name, 'package.json');
      let pkg;
      try { pkg = JSON.parse(fs.readFileSync(pkgJsonPath, 'utf8')); }
      catch { continue; }

      if (!pkg.scripts) continue;
      const scripts = {};
      for (const k of LIFECYCLE_KEYS) {
        if (pkg.scripts[k]) scripts[k] = pkg.scripts[k];
      }
      if (Object.keys(scripts).length > 0) {
        result[prefix + entry.name] = { version: pkg.version || '?', scripts };
      }
    }
  }

  scanDir(nodeModulesDir);
  return result;
}

// ─── audit ────────────────────────────────────────────────────────────────────

/**
 * Audit all lifecycle scripts in the project, segmented by whitelist status.
 *
 * @returns {{
 *   approved: Array,
 *   pending: Array,    ← new, not yet whitelisted
 *   source: 'lockfile'|'node_modules'
 * }}
 */
function auditLifecycleScripts(projectRoot) {
  const lockfilePath    = path.join(projectRoot, 'package-lock.json');
  const nodeModulesDir  = path.join(projectRoot, 'node_modules');

  let scriptsMap;
  let source;

  const lockfileData = readLockfileScripts(lockfilePath);
  if (lockfileData && Object.keys(lockfileData).length > 0) {
    scriptsMap = lockfileData;
    source = 'lockfile';
  } else {
    scriptsMap = readNodeModulesScripts(nodeModulesDir);
    source = 'node_modules';
  }

  const wl = loadWhitelist();
  const approved = [];
  const pending  = [];

  for (const [name, { version, scripts }] of Object.entries(scriptsMap)) {
    for (const [scriptKey, scriptValue] of Object.entries(scripts)) {
      const entry = { package: name, version, scriptKey, scriptValue };
      if (isWhitelisted(wl, name, version, scriptKey, scriptValue)) {
        approved.push(entry);
      } else {
        pending.push(entry);
      }
    }
  }

  return { approved, pending, source };
}

module.exports = {
  auditLifecycleScripts,
  addToWhitelist,
  loadWhitelist,
  WHITELIST_PATH,
};
