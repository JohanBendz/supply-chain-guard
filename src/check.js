'use strict';
/**
 * check.js
 *
 * Pre-flight risk scorer for `scg check axios@1.14.1`.
 * Runs BEFORE npm install and surfaces signals that would catch
 * attacks like the axios/mock-unapproved-dep compromise.
 *
 * Scoring model: each signal adds a risk score.
 * Signals are independent and composable.
 */

const { getVersionRiskProfile, getVersionMeta } = require('./registry');
const { SEV }                    = require('./diff');
const { analyseNewDeps, analysePhantom } = require('./delta-phantom');

// ─── signal definitions ───────────────────────────────────────────────────────

const SIGNALS = {
  // Delta-phantom signal (manifest heuristic — LOW confidence)
  LIKELY_PHANTOM_DEP: {
    sev: SEV.HIGH,
    code: 'LIKELY_PHANTOM_DEP',
    fmt: (dep, reason) =>
      `New dependency '${dep}' appears phantom (not referenced in parent source): ${reason}`,
  },
  // Phantom-injection signals
  NEW_DEP_WITH_SCRIPTS: {
    sev: SEV.CRITICAL,
    code: 'NEW_DEP_WITH_SCRIPTS',
    fmt: (dep, profile) =>
      `New dependency '${dep}@${profile.version}' has lifecycle scripts: ` +
      Object.keys(profile.scripts).join(', '),
  },
  NEW_DEP_BRAND_NEW_PACKAGE: {
    sev: SEV.CRITICAL,
    code: 'NEW_DEP_BRAND_NEW_PACKAGE',
    fmt: (dep, profile) =>
      `New dependency '${dep}' is a brand-new package ` +
      `(first published ${profile.packageAgeDays}d ago, ${profile.totalVersions} total versions)`,
  },
  NEW_DEP_ADDED: {
    sev: SEV.HIGH,
    code: 'NEW_DEP_ADDED',
    fmt: (dep) => `Version adds new dependency '${dep}' not present in previous version`,
  },

  // Provenance signals
  PROVENANCE_REGRESSION: {
    sev: SEV.CRITICAL,
    code: 'PROVENANCE_REGRESSION',
    fmt: () => `Previous versions used OIDC trusted-publishing; this version was published manually (stolen token pattern)`,
  },
  NO_PROVENANCE: {
    sev: SEV.HIGH,
    code: 'NO_PROVENANCE',
    fmt: (detail) => `No OIDC provenance attestation (${detail})`,
  },

  // Age signals
  VERSION_VERY_NEW: {
    sev: SEV.HIGH,
    code: 'VERSION_VERY_NEW',
    fmt: (days) => `Version published only ${days}d ago (below cooldown threshold)`,
  },
  VERSION_VERY_NEW_WITH_SCRIPTS: {
    sev: SEV.CRITICAL,
    code: 'VERSION_VERY_NEW_WITH_SCRIPTS',
    fmt: (days) => `Version published only ${days}d ago AND has lifecycle scripts`,
  },

  // General
  PACKAGE_NOT_FOUND: {
    sev: SEV.WARN,
    code: 'PACKAGE_NOT_FOUND',
    fmt: (name) => `Package '${name}' not found in npm registry`,
  },
  SINGLE_VERSION_PACKAGE: {
    sev: SEV.HIGH,
    code: 'SINGLE_VERSION_PACKAGE',
    fmt: (dep) => `New dependency '${dep}' has only 1 published version (created for this attack?)`,
  },
};

// ─── scorer ───────────────────────────────────────────────────────────────────

/**
 * Score a pre-fetched risk profile and return an array of triggered signals.
 * @param {object} profile  - from getVersionRiskProfile()
 * @param {object} opts
 * @param {number} opts.cooldownDays
 */
function scoreProfile(profile, opts = {}) {
  const { cooldownDays = 3 } = opts;
  const triggered = [];

  function emit(signal, ...args) {
    triggered.push({
      severity: signal.sev,
      code: signal.code,
      message: signal.fmt(...args),
    });
  }

  // ── 1. New dependency signals ─────────────────────────────────────────────
  if (profile.depDiff && profile.depDiff.added.length > 0) {
    for (const dep of profile.depDiff.added) {
      const depProfile = profile.newDepProfiles?.[dep];

      emit(SIGNALS.NEW_DEP_ADDED, dep);

      if (depProfile && !depProfile.error) {
        // New dep with lifecycle scripts → CRITICAL
        if (depProfile.hasLifecycleScripts) {
          emit(SIGNALS.NEW_DEP_WITH_SCRIPTS, dep, depProfile);
        }

        // New dep that's a brand-new package (< 7 days since first publish, ≤ 3 versions)
        const isNew = depProfile.packageAgeDays !== null && depProfile.packageAgeDays < 7;
        const fewVersions = depProfile.totalVersions !== null && depProfile.totalVersions <= 3;
        if (isNew || fewVersions) {
          emit(SIGNALS.NEW_DEP_BRAND_NEW_PACKAGE, dep, depProfile);
        }

        // Single-version package
        if (depProfile.totalVersions === 1) {
          emit(SIGNALS.SINGLE_VERSION_PACKAGE, dep);
        }
      }
    }
  }

  // ── 2. Provenance signals ─────────────────────────────────────────────────
  if (profile.provenance) {
    if (profile.provenance.regression) {
      emit(SIGNALS.PROVENANCE_REGRESSION);
    } else if (!profile.provenance.currentHasProvenance && profile.provenance.previousUsedProvenance === false) {
      // Package never used provenance — lower signal
      emit(SIGNALS.NO_PROVENANCE, profile.provenance.currentDetail || '');
    }
  }

  // ── 3. Age signals ────────────────────────────────────────────────────────
  if (profile.ageDays !== null && profile.ageDays < cooldownDays) {
    if (profile.hasLifecycleScripts) {
      emit(SIGNALS.VERSION_VERY_NEW_WITH_SCRIPTS, profile.ageDays);
    } else {
      emit(SIGNALS.VERSION_VERY_NEW, profile.ageDays);
    }
  }

  return triggered;
}

/**
 * Full pre-flight check for a package@version.
 * Fetches registry data, scores, returns structured result.
 */
async function checkPackage(name, version, opts = {}) {
  const { deepPhantom = false } = opts;
  const profile    = await getVersionRiskProfile(name, version);
  const signals    = scoreProfile(profile, opts);

  // Delta-phantom analysis: manifest-level check for newly introduced deps.
  // Run when the version adds new dependencies (always fast — no network).
  // Surfaced as HIGH rather than CRITICAL: manifest heuristic is LOW confidence.
  if (profile.depDiff && profile.depDiff.added.length > 0) {
    try {
      const parentMeta  = await getVersionMeta(name, version).catch(() => null);
      const depResults = deepPhantom
        ? await Promise.all(profile.depDiff.added.map(dep => analysePhantom(parentMeta, dep, {
            tarball: true,
            tarballUrl: parentMeta?.dist?.tarball,
          })))
        : analyseNewDeps(parentMeta, profile.depDiff.added);
      for (const r of depResults) {
        if (r.verdict === 'LIKELY_PHANTOM') {
          signals.push({
            severity: SEV.HIGH,
            code:     SIGNALS.LIKELY_PHANTOM_DEP.code,
            message:  SIGNALS.LIKELY_PHANTOM_DEP.fmt(r.dep, r.reason),
            _phantomConfidence: r.confidence,
            _phantomLayer: r.layer,
          });
        }
      }
    } catch { /* delta-phantom errors are non-fatal */ }
  }

  const riskLevel = signals.length === 0
    ? SEV.INFO
    : signals.some(s => s.severity === SEV.CRITICAL) ? SEV.CRITICAL
    : signals.some(s => s.severity === SEV.HIGH) ? SEV.HIGH
    : signals.some(s => s.severity === SEV.WARN) ? SEV.WARN
    : SEV.INFO;

  return { profile, signals, riskLevel };
}

module.exports = { checkPackage, scoreProfile, SIGNALS };
