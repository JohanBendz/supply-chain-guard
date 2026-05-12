'use strict';
/**
 * policy.js
 *
 * Manages the repo-local .scg-policy.json file.
 * This is the primary trust source for SCG — replaces the old user-global
 * ~/.scg-whitelist.json for all enforcement purposes.
 *
 * Policy schema:
 * {
 *   "version": 1,
 *   "approvedBuilds": {
 *     "esbuild@0.21.5": {
 *       "approvedAt": "2026-04-02T...",
 *       "approvedBy": "git-user-or-ci",
 *       "scripts": { "postinstall": "node install.js" }
 *     }
 *   },
 *   "deniedBuilds": {
 *     "mock-unapproved-dep": { "reason": "unapproved-script" }
 *   },
 *   "settings": {
 *     "cooldownDays": 3,
 *     "failOn": "HIGH"
 *   }
 * }
 */

const fs     = require('fs');
const crypto = require('crypto');
const path = require('path');
const os   = require('os');

const POLICY_FILE    = '.scg-policy.json';
const LEGACY_WL_FILE = path.join(os.homedir(), '.scg-whitelist.json');

const DEFAULT_POLICY = {
  version: 1,
  approvedBuilds: {},
  deniedBuilds: {},
  settings: {
    cooldownDays: 3,
    failOn: 'HIGH',
  },
};

// ─── helpers ──────────────────────────────────────────────────────────────────

function policyPath(projectRoot) {
  return path.join(projectRoot, POLICY_FILE);
}

/**
 * Normalise a package spec to a lookup key.
 * "esbuild@0.21.5"  → "esbuild@0.21.5"
 * "esbuild"         → "esbuild" (matches any version if no version in table)
 */
function buildKey(name, version) {
  return version ? `${name}@${version}` : name;
}

// ─── load / save ──────────────────────────────────────────────────────────────

/**
 * Load .scg-policy.json from projectRoot.
 * Falls back to reading the legacy ~/.scg-whitelist.json and converting it,
 * but never writes the converted content back automatically.
 *
 * Returns a fully-hydrated policy object (never null).
 */
function loadPolicy(projectRoot) {
  const file = policyPath(projectRoot);

  if (fs.existsSync(file)) {
    try {
      const raw = JSON.parse(fs.readFileSync(file, 'utf8'));
      return Object.assign({}, DEFAULT_POLICY, raw, {
        approvedBuilds: raw.approvedBuilds || {},
        deniedBuilds:   raw.deniedBuilds   || {},
        settings:       Object.assign({}, DEFAULT_POLICY.settings, raw.settings || {}),
      });
    } catch (e) {
      throw new Error(`Failed to parse ${file}: ${e.message}`);
    }
  }

  // No repo-local policy — read legacy whitelist as fallback (read-only)
  const policy = JSON.parse(JSON.stringify(DEFAULT_POLICY));
  if (fs.existsSync(LEGACY_WL_FILE)) {
    try {
      const legacy = JSON.parse(fs.readFileSync(LEGACY_WL_FILE, 'utf8'));
      // Legacy format: { "<name>@<version>:<key>=<fp>": { approvedAt, ... } }
      for (const [legacyKey, entry] of Object.entries(legacy)) {
        const match = legacyKey.match(/^(.+?)@([^:]+):(\w+)=(.*)$/);
        if (match) {
          const pkgKey = buildKey(match[1], match[2]);
          if (!policy.approvedBuilds[pkgKey]) {
            policy.approvedBuilds[pkgKey] = {
              approvedAt: entry.approvedAt || null,
              approvedBy: 'legacy-whitelist',
              scripts: {},
              _fromLegacy: true,
            };
          }
          policy.approvedBuilds[pkgKey].scripts[match[3]] = match[4];
        }
      }
    } catch {
      // Legacy whitelist corrupt — ignore silently
    }
  }

  return policy;
}

/**
 * Save policy to .scg-policy.json in projectRoot.
 * Creates the file if it doesn't exist.
 */
function savePolicy(projectRoot, policy) {
  const file = policyPath(projectRoot);
  fs.writeFileSync(file, JSON.stringify(policy, null, 2) + '\n');
}

/**
 * Initialise a fresh .scg-policy.json if one doesn't exist.
 * Returns true if created, false if already present.
 */
function initPolicy(projectRoot) {
  const file = policyPath(projectRoot);
  if (fs.existsSync(file)) return false;
  savePolicy(projectRoot, JSON.parse(JSON.stringify(DEFAULT_POLICY)));
  return true;
}


// ─── script hashing ───────────────────────────────────────────────────────────

/**
 * Compute a SHA-256 hash of a script string (or object of scripts).
 * Stored in policy at approval time; verified at rebuild time.
 * Format: "sha256:<hex>" — mirrors Subresource Integrity (SRI) convention.
 */
function hashScripts(scripts) {
  // Build a canonical representation: sort keys, then JSON.stringify the
  // reconstructed object. The previous implementation passed the sorted-keys
  // array as the second argument to JSON.stringify, which is a *replacer
  // filter*, not a key sorter — it preserved insertion order, which meant two
  // identically-keyed objects with different declaration order produced
  // different hashes. Reconstructing via Object.fromEntries on a sorted entry
  // list guarantees a stable canonical form regardless of source order.
  const sorted = Object.fromEntries(
    Object.entries(scripts || {}).sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))
  );
  const canonical = JSON.stringify(sorted);
  const digest    = crypto.createHash('sha256').update(canonical).digest('hex');
  return `sha256:${digest}`;
}

/**
 * Verify that the scripts currently on disk match the hash recorded at
 * approval time. Returns { ok, recorded, actual }.
 */
function verifyScriptHash(recordedHash, currentScripts) {
  if (!recordedHash) return { ok: false, recorded: null, actual: null, missing: true };
  const actualHash = hashScripts(currentScripts);
  return {
    ok:       recordedHash === actualHash,
    recorded: recordedHash,
    actual:   actualHash,
  };
}

// ─── approval queries ─────────────────────────────────────────────────────────

/**
 * Check whether a package@version is approved for rebuild.
 * Looks up exact "pkg@ver" first, then falls back to bare "pkg".
 */
function isBuildApproved(policy, name, version) {
  const exactKey = buildKey(name, version);
  const bareKey  = name;
  return !!(policy.approvedBuilds[exactKey] || policy.approvedBuilds[bareKey]);
}

/**
 * Check whether a package is explicitly denied.
 */
function isBuildDenied(policy, name, version) {
  const exactKey = buildKey(name, version);
  const bareKey  = name;
  return !!(policy.deniedBuilds[exactKey] || policy.deniedBuilds[bareKey]);
}

/**
 * Approve a package@version for rebuild.
 * scripts: { postinstall: "node install.js", ... } — actual scripts from the package
 */
function approveBuild(projectRoot, name, version, scripts = {}, approvedBy = null) {
  const policy = loadPolicy(projectRoot);
  const key    = buildKey(name, version);

  // Remove from denied if it was there
  delete policy.deniedBuilds[buildKey(name, version)];
  delete policy.deniedBuilds[name];

  policy.approvedBuilds[key] = {
    approvedAt:  new Date().toISOString(),
    approvedBy:  approvedBy || detectApprover(),
    scripts,
    // SRI-style hash of the approved scripts object.
    // If the installed scripts change (e.g. package compromised after approval),
    // verifyScriptHash() will return ok=false and rebuild will be blocked.
    scriptHash:  hashScripts(scripts),
  };

  savePolicy(projectRoot, policy);
  return key;
}

/**
 * Explicitly deny a package (overrides any approval).
 */
function denyBuild(projectRoot, name, version, reason = '') {
  const policy = loadPolicy(projectRoot);
  const key    = buildKey(name, version);

  delete policy.approvedBuilds[key];
  delete policy.approvedBuilds[name];

  policy.deniedBuilds[key] = {
    deniedAt: new Date().toISOString(),
    reason,
  };

  savePolicy(projectRoot, policy);
  return key;
}

/**
 * Return all approved build entries as a list.
 */
function listApprovedBuilds(policy) {
  return Object.entries(policy.approvedBuilds).map(([key, entry]) => ({
    key,
    ...entry,
  }));
}

// ─── helper ───────────────────────────────────────────────────────────────────

function detectApprover() {
  // Try to identify who's approving (CI env or git user).
  // We sanitize the resulting string aggressively: the value is written
  // verbatim into .scg-policy.json, which may later be rendered by a
  // dashboard, diff viewer, or log aggregator that doesn't escape HTML.
  // Policy files are committed to git, so a compromised env var (or a
  // poisoned git config) could persist a stored-XSS payload across the
  // whole team. We strip anything that isn't a printable identifier.
  function clean(s) {
    return String(s || '').replace(/[^\w.@:\-/]/g, '').slice(0, 128) || 'unknown';
  }
  if (process.env.GITHUB_ACTOR) return `github:${clean(process.env.GITHUB_ACTOR)}`;
  if (process.env.CI)           return 'ci';
  try {
    const { execSync } = require('child_process');
    const name = execSync('git config user.name', { encoding: 'utf8', stdio: ['pipe','pipe','pipe'] }).trim();
    if (name) return `git:${clean(name)}`;
  } catch {}
  return clean(process.env.USER || process.env.USERNAME || 'unknown');
}

module.exports = {
  hashScripts,
  verifyScriptHash,
  POLICY_FILE,
  policyPath,
  loadPolicy,
  savePolicy,
  initPolicy,
  isBuildApproved,
  isBuildDenied,
  approveBuild,
  denyBuild,
  listApprovedBuilds,
  buildKey,
};
