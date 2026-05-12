'use strict';
/**
 * lockfile.js
 *
 * Reads package-lock.json (v2/v3 format) and extracts:
 *   - flat package list with resolved versions
 *   - hasInstallScript flag per package (npm v7+ sets this explicitly)
 *   - lifecycle scripts embedded in the lockfile entries
 *   - diff between two lockfile snapshots
 */

const fs   = require('fs');
const path = require('path');

const LIFECYCLE_KEYS = ['preinstall', 'install', 'postinstall', 'prepare', 'prepack', 'postpack'];

// ─── readers ──────────────────────────────────────────────────────────────────

/**
 * Read and parse package-lock.json from projectRoot.
 * Returns null if not found or unparseable.
 */
function readLockfile(projectRoot) {
  const file = path.join(projectRoot, 'package-lock.json');
  if (!fs.existsSync(file)) return null;
  try {
    return JSON.parse(fs.readFileSync(file, 'utf8'));
  } catch {
    return null;
  }
}

/**
 * Extract a flat map of all packages from a lockfile.
 *
 * Each entry: {
 *   name:             string,
 *   version:          string,
 *   resolved:         string | undefined,
 *   hasInstallScript: boolean,   // from lockfile field (npm v7+)
 *   scripts:          object,    // lifecycle scripts if present
 *   isDirectDep:      boolean,
 * }
 */
function extractPackages(lockfile) {
  if (!lockfile) return {};
  const result = {};

  // v2/v3: packages map (preferred, most complete)
  if (lockfile.packages) {
    for (const [rawPkgPath, entry] of Object.entries(lockfile.packages)) {
      if (rawPkgPath === '') continue; // root package

      // Normalise POSIX/Windows separators up-front so every downstream check
      // (direct-dep detection, pkgPathToName, display) works on the same form.
      const pkgPath = rawPkgPath.replace(/\\/g, '/');

      // Derive a clean package name from the path
      // "node_modules/foo"                  → "foo"
      // "node_modules/@scope/foo"            → "@scope/foo"
      // "node_modules/foo/node_modules/bar"  → "foo>bar" (nested)
      const name = pkgPathToName(pkgPath);

      const scripts = {};
      if (entry.scripts) {
        for (const k of LIFECYCLE_KEYS) {
          if (entry.scripts[k]) scripts[k] = entry.scripts[k];
        }
      }

      // npm v7+ sets hasInstallScript=true when the package has lifecycle scripts
      // even if the scripts field isn't present in the lockfile entry
      const hasInstallScript = !!(
        entry.hasInstallScript ||
        Object.keys(scripts).length > 0
      );

      result[name] = {
        name,
        version:          entry.version || 'unknown',
        resolved:         entry.resolved || null,
        hasInstallScript,
        scripts,
        // A direct dep lives at "node_modules/<name>" with no further nesting.
        // The previous check passed the second argument as a length offset to
        // String.includes, which is actually a *start position* — making the
        // check incorrect for genuinely nested entries like
        // "node_modules/foo/node_modules/bar". Slicing past the leading
        // "node_modules/" and looking for any further "/node_modules/" gives
        // the right semantics.
        isDirectDep:      !pkgPath.slice('node_modules/'.length).includes('/node_modules/'),
        _lockfilePath:    pkgPath,
      };
    }
    return result;
  }

  // v1 fallback: dependencies map (less reliable for hasInstallScript)
  if (lockfile.dependencies) {
    flattenV1Deps(lockfile.dependencies, result, false);
  }

  return result;
}

function pkgPathToName(pkgPath) {
  // Lockfile paths from npm are always POSIX-style ("node_modules/foo"),
  // even on Windows — npm normalises them. However, if a caller constructs
  // a fake lockfile or a future npm version changes behaviour, we accept
  // backslashes too and normalise everything through forward slashes first
  // so the rest of the logic stays POSIX-only.
  let p = pkgPath.replace(/\\/g, '/');
  // Strip leading "node_modules/"
  p = p.replace(/^node_modules\//, '');
  // Collapse nested paths to use ">" separator for clarity
  p = p.replace(/\/node_modules\//g, '>');
  return p;
}

function flattenV1Deps(deps, result, nested) {
  for (const [name, entry] of Object.entries(deps)) {
    if (result[name]) continue; // already seen (take first occurrence)

    const scripts = {};
    if (entry.scripts) {
      for (const k of LIFECYCLE_KEYS) {
        if (entry.scripts[k]) scripts[k] = entry.scripts[k];
      }
    }

    result[name] = {
      name,
      version:          entry.version || 'unknown',
      resolved:         entry.resolved || null,
      hasInstallScript: !!(entry.hasInstallScript || Object.keys(scripts).length > 0),
      scripts,
      isDirectDep:      !nested,
      _lockfilePath:    `dependencies.${name}`,
    };

    if (entry.dependencies) {
      flattenV1Deps(entry.dependencies, result, true);
    }
  }
}

// ─── diff ─────────────────────────────────────────────────────────────────────

/**
 * Compare two lockfile package maps and return changes.
 *
 * Returns {
 *   added:   [{ name, version, hasInstallScript, scripts }],
 *   removed: [{ name, version }],
 *   updated: [{ name, from, to, scriptsAdded }],
 *   newWithScripts: [ subset of added where hasInstallScript===true ],
 *   updatesWithNewScripts: [ subset of updated ],
 * }
 */
function diffLockfilePackages(before, after) {
  const added   = [];
  const removed = [];
  const updated = [];

  for (const [name, entry] of Object.entries(after)) {
    // Ensure name is always present on returned entries (entries from hand-built
    // maps or v1 lockfiles may not have it; extractPackages always sets it)
    const withName = entry.name ? entry : { name, ...entry };
    if (!before[name]) {
      added.push(withName);
    } else if (before[name].version !== entry.version) {
      // Check whether new scripts appeared
      const prevScriptKeys = new Set(Object.keys(before[name].scripts || {}));
      const newScriptKeys  = Object.keys(entry.scripts || {}).filter(k => !prevScriptKeys.has(k));
      updated.push({
        name,
        from:          before[name].version,
        to:            entry.version,
        hasInstallScript: entry.hasInstallScript,
        scripts:       entry.scripts,
        scriptsAdded:  newScriptKeys,
      });
    }
  }

  for (const name of Object.keys(before)) {
    if (!after[name]) removed.push({ name, version: before[name].version });
  }

  return {
    added,
    removed,
    updated,
    newWithScripts:        added.filter(e => e.hasInstallScript),
    updatesWithNewScripts: updated.filter(e => e.scriptsAdded.length > 0),
  };
}

module.exports = {
  readLockfile,
  extractPackages,
  diffLockfilePackages,
  LIFECYCLE_KEYS,
};
