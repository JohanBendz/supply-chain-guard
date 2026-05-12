'use strict';
/**
 * install-inspector.js
 *
 * After `npm install --ignore-scripts`, inspect the result:
 *   1. Read package-lock.json for hasInstallScript / scripts
 *   2. Cross-check installed package.json files in node_modules
 *   3. Cross-reference against policy (approved/denied builds)
 *   4. Return a structured report: { blocked, needsApproval, approved, clean }
 *
 * This is the enforcement layer that runs after every SCG wrapper command.
 */

const fs   = require('fs');
const path = require('path');

const { readLockfile, extractPackages }  = require('./lockfile');
const { loadPolicy, isBuildApproved, isBuildDenied, verifyScriptHash } = require('./policy');
const { SEV } = require('./diff');

const LIFECYCLE_KEYS = ['preinstall', 'install', 'postinstall', 'prepare'];

// ─── read installed package.json ─────────────────────────────────────────────

/**
 * Read the actual installed package.json for a given package name,
 * looking in node_modules (handles scoped packages).
 * Returns null if not found.
 */
function readInstalledMeta(projectRoot, pkgName, lockEntry = null) {
  const NAME_RE = /^(?:@[a-z0-9][a-z0-9._-]*\/)?[a-z0-9][a-z0-9._-]*$/i;

  function safePackagePathFromLock(entry) {
    if (!entry || !entry._lockfilePath) return null;
    const rel = String(entry._lockfilePath).replace(/\\/g, '/');
    if (!rel.startsWith('node_modules/') || rel.includes('..') || path.isAbsolute(rel)) return null;
    return path.join(projectRoot, rel, 'package.json');
  }

  let pkgJsonPath = safePackagePathFromLock(lockEntry);
  if (!pkgJsonPath) {
    // If no lockfile path was provided, only resolve direct packages by name.
    // Never collapse nested keys like "foo>bar" to "foo" — that reads the
    // wrong package. Callers that need nested packages must pass lockEntry.
    if (String(pkgName).includes('>')) return null;
    if (!NAME_RE.test(pkgName) || String(pkgName).includes('..')) return null;
    pkgJsonPath = path.join(projectRoot, 'node_modules', pkgName, 'package.json');
  }

  try {
    return JSON.parse(fs.readFileSync(pkgJsonPath, 'utf8'));
  } catch {
    return null;
  }
}
/**
 * Extract lifecycle scripts from an installed package.json.
 */
function extractScriptsFromMeta(meta) {
  if (!meta || !meta.scripts) return {};
  const result = {};
  for (const k of LIFECYCLE_KEYS) {
    if (meta.scripts[k]) result[k] = meta.scripts[k];
  }
  return result;
}

// ─── main inspection ─────────────────────────────────────────────────────────

/**
 * Inspect the project after an `npm install --ignore-scripts` run.
 *
 * @param {string}   projectRoot
 * @param {object}   opts
 * @param {object}   opts.beforeLockfile  - lockfile packages snapshot before install (or null)
 * @returns {InspectionReport}
 */
function inspectInstall(projectRoot, opts = {}) {
  const { beforeLockfile = null } = opts;

  const lockfile     = readLockfile(projectRoot);
  const afterPkgs    = lockfile ? extractPackages(lockfile) : {};
  const beforePkgs   = beforeLockfile ? beforeLockfile : {};
  const policy       = loadPolicy(projectRoot);

  const blocked        = [];  // denied in policy
  const needsApproval  = [];  // has scripts, not in policy
  const approved       = [];  // has scripts, explicitly approved
  const approvedChanged = []; // approved in policy but script hash changed
  const clean          = [];  // no scripts at all

  // Only inspect packages that changed or are new
  // (when no before-lockfile provided, inspect everything with scripts)
  const toInspect = beforeLockfile
    ? getChangedPackages(beforePkgs, afterPkgs)
    : getPackagesWithScripts(afterPkgs);

  for (const [name, lockEntry] of Object.entries(toInspect)) {
    // Read actual installed scripts (more reliable than lockfile alone)
    const installedMeta    = readInstalledMeta(projectRoot, name, lockEntry);
    const installedScripts = extractScriptsFromMeta(installedMeta);
    const lockfileScripts  = lockEntry.scripts || {};

    // Union of scripts from both sources
    const allScripts = Object.assign({}, lockfileScripts, installedScripts);
    const hasScripts = Object.keys(allScripts).length > 0 || lockEntry.hasInstallScript;

    if (!hasScripts) {
      clean.push({ name, version: lockEntry.version });
      continue;
    }

    const version = lockEntry.version || (installedMeta && installedMeta.version) || 'unknown';

    if (isBuildDenied(policy, name, version)) {
      blocked.push({
        severity: SEV.CRITICAL,
        name,
        version,
        scripts: allScripts,
        reason: policy.deniedBuilds[`${name}@${version}`]?.reason
             || policy.deniedBuilds[name]?.reason
             || 'denied in .scg-policy.json',
      });
    } else if (isBuildApproved(policy, name, version)) {
      const exactKey = `${name}@${version}`;
      const policyEntry = policy.approvedBuilds[exactKey] || policy.approvedBuilds[name];
      if (policyEntry && policyEntry.scriptHash) {
        const check = verifyScriptHash(policyEntry.scriptHash, allScripts);
        if (!check.ok) {
          approvedChanged.push({
            severity: SEV.CRITICAL,
            name,
            version,
            scripts: allScripts,
            recorded: check.recorded,
            actual: check.actual,
            reason: 'approved build script changed since policy approval',
          });
          continue;
        }
      }
      approved.push({ name, version, scripts: allScripts });
    } else {
      needsApproval.push({
        severity: SEV.HIGH,
        name,
        version,
        scripts: allScripts,
        hasInstallScript: lockEntry.hasInstallScript,
      });
    }
  }

  return {
    blocked,
    needsApproval,
    approved,
    approvedChanged,
    clean,
    totalInspected: Object.keys(toInspect).length,
    isClean: blocked.length === 0 && needsApproval.length === 0 && approvedChanged.length === 0,
  };
}

// ─── helpers ──────────────────────────────────────────────────────────────────

function getChangedPackages(before, after) {
  const result = {};
  for (const [name, entry] of Object.entries(after)) {
    const prev = before[name];
    if (!prev || prev.version !== entry.version) {
      // New or version-changed — inspect the actual installed package.json too.
      // Lockfiles can omit script metadata; fail safe by checking disk.
      result[name] = entry;
    }
  }
  return result;
}
function getPackagesWithScripts(pkgs) {
  // Full audit mode: inspect every package so missing/stale lockfile script
  // metadata cannot hide lifecycle scripts present on disk.
  return Object.assign({}, pkgs);
}

module.exports = {
  inspectInstall,
  readInstalledMeta,
  extractScriptsFromMeta,
};
