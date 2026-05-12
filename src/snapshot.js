'use strict';
/**
 * snapshot.js
 * Reads node_modules and produces a serialisable map of every installed
 * package: version, publish-date (from registry), and lifecycle scripts.
 * No external dependencies — pure Node.js.
 */

const fs   = require('fs');
const path = require('path');
const https = require('https');

// ─── helpers ────────────────────────────────────────────────────────────────

function readJSON(filePath) {
  try { return JSON.parse(fs.readFileSync(filePath, 'utf8')); }
  catch { return null; }
}

/** Fetch publish timestamp for a specific package@version from npm registry */
function fetchPublishDate(name, version) {
  return new Promise((resolve) => {
    const encoded = name.startsWith('@')
      ? name.replace('/', '%2F')
      : name;
    const url = `https://registry.npmjs.org/${encoded}/${version}`;
    const req = https.get(url, { timeout: 6000 }, (res) => {
      let body = '';
      res.on('data', d => body += d);
      res.on('end', () => {
        try {
          const data = JSON.parse(body);
          resolve(data.time ? data.time.created || null : null);
        } catch { resolve(null); }
      });
    });
    req.on('error', () => resolve(null));
    req.on('timeout', () => { req.destroy(); resolve(null); });
  });
}

/** Walk node_modules (top-level + scoped) */
function collectInstalledPackages(nodeModulesDir) {
  const pkgs = {};

  if (!fs.existsSync(nodeModulesDir)) return pkgs;

  const entries = fs.readdirSync(nodeModulesDir, { withFileTypes: true });

  for (const entry of entries) {
    if (!entry.isDirectory() && !entry.isSymbolicLink()) continue;

    if (entry.name.startsWith('@')) {
      // scoped packages
      const scopeDir = path.join(nodeModulesDir, entry.name);
      try {
        for (const scoped of fs.readdirSync(scopeDir, { withFileTypes: true })) {
          if (!scoped.isDirectory()) continue;
          const pkgName = `${entry.name}/${scoped.name}`;
          const pkgJson = readJSON(path.join(scopeDir, scoped.name, 'package.json'));
          if (pkgJson) pkgs[pkgName] = extractMeta(pkgJson);
        }
      } catch {}
      continue;
    }

    if (entry.name.startsWith('.') || entry.name === '.bin') continue;

    const pkgJson = readJSON(path.join(nodeModulesDir, entry.name, 'package.json'));
    if (pkgJson) pkgs[entry.name] = extractMeta(pkgJson);
  }

  return pkgs;
}

function extractMeta(pkgJson) {
  const scripts = pkgJson.scripts || {};
  const lifecycleKeys = ['preinstall','install','postinstall','prepare','prepack','postpack'];
  const lifecycleScripts = {};
  for (const k of lifecycleKeys) {
    if (scripts[k]) lifecycleScripts[k] = scripts[k];
  }

  return {
    version: pkgJson.version || 'unknown',
    scripts: lifecycleScripts,
    hasLifecycleScripts: Object.keys(lifecycleScripts).length > 0,
    dependencies: Object.keys(pkgJson.dependencies || {}),
    _publishDate: null, // filled in by enrichWithDates if requested
  };
}

/** Enrich snapshot with publish dates (requires network, optional) */
async function enrichWithDates(snapshot) {
  const entries = Object.entries(snapshot);
  const concurrency = 8;

  for (let i = 0; i < entries.length; i += concurrency) {
    const batch = entries.slice(i, i + concurrency);
    await Promise.all(batch.map(async ([name, meta]) => {
      meta._publishDate = await fetchPublishDate(name, meta.version);
    }));
  }
  return snapshot;
}

// ─── public API ─────────────────────────────────────────────────────────────

/**
 * Take a snapshot of the current node_modules state.
 * @param {string} projectRoot  - path containing node_modules
 * @param {object} opts
 * @param {boolean} opts.fetchDates - whether to hit npm registry for publish dates
 */
async function takeSnapshot(projectRoot, opts = {}) {
  const nodeModulesDir = path.join(projectRoot, 'node_modules');
  const snapshot = collectInstalledPackages(nodeModulesDir);

  if (opts.fetchDates) {
    process.stderr.write('  Fetching publish dates from registry...\n');
    await enrichWithDates(snapshot);
  }

  return {
    timestamp: new Date().toISOString(),
    projectRoot,
    packages: snapshot,
  };
}

/**
 * Save a snapshot to disk.
 */
function saveSnapshot(snapshot, filePath) {
  fs.writeFileSync(filePath, JSON.stringify(snapshot, null, 2));
}

/**
 * Load a snapshot from disk.
 */
function loadSnapshot(filePath) {
  if (!fs.existsSync(filePath)) return null;
  return readJSON(filePath);
}

module.exports = { takeSnapshot, saveSnapshot, loadSnapshot, extractMeta };
