'use strict';
/**
 * diff.js
 * Compares a "before" and "after" snapshot and produces a structured
 * risk report with categorised findings.
 */

// ─── types ───────────────────────────────────────────────────────────────────
// Finding severity levels
const SEV = { CRITICAL: 'CRITICAL', HIGH: 'HIGH', WARN: 'WARN', INFO: 'INFO' };

// ─── helpers ─────────────────────────────────────────────────────────────────

function daysSince(isoDate) {
  if (!isoDate) return null;
  const ms = Date.now() - new Date(isoDate).getTime();
  return Math.floor(ms / 86_400_000);
}

function scriptsSummary(scripts) {
  return Object.entries(scripts)
    .map(([k, v]) => `${k}: "${v}"`)
    .join(', ');
}

// ─── core diff ───────────────────────────────────────────────────────────────

/**
 * Diff two snapshots. Returns an array of findings.
 *
 * Each finding: { severity, code, package, version, message, detail }
 */
function diffSnapshots(before, after, opts = {}) {
  const {
    cooldownDays = 3,      // warn if package published within N days
    warnOnNewScripts = true,
    failOnPhantom = false, // phantom is detected separately; here we flag new lifecycle scripts on known packages
  } = opts;

  const findings = [];
  const beforePkgs = (before && before.packages) ? before.packages : {};
  const afterPkgs  = after.packages;

  // ── 1. New packages ────────────────────────────────────────────────────────
  for (const [name, meta] of Object.entries(afterPkgs)) {
    if (beforePkgs[name]) continue; // existed before

    const age = daysSince(meta._publishDate);
    const ageLabel = age !== null ? `published ${age}d ago` : 'publish date unknown';

    // New package with lifecycle scripts → HIGH/CRITICAL
    if (meta.hasLifecycleScripts) {
      const severity = (age !== null && age < cooldownDays) ? SEV.CRITICAL : SEV.HIGH;
      findings.push({
        severity,
        code: 'NEW_PACKAGE_WITH_SCRIPTS',
        package: name,
        version: meta.version,
        message: `New package with lifecycle scripts (${ageLabel})`,
        detail: scriptsSummary(meta.scripts),
      });
    } else {
      // New package without scripts — still worth noting
      const severity = (age !== null && age < cooldownDays) ? SEV.HIGH : SEV.INFO;
      findings.push({
        severity,
        code: 'NEW_PACKAGE',
        package: name,
        version: meta.version,
        message: `New package introduced (${ageLabel})`,
        detail: null,
      });
    }
  }

  // ── 2. Removed packages ───────────────────────────────────────────────────
  for (const [name, meta] of Object.entries(beforePkgs)) {
    if (!afterPkgs[name]) {
      findings.push({
        severity: SEV.INFO,
        code: 'REMOVED_PACKAGE',
        package: name,
        version: meta.version,
        message: 'Package removed',
        detail: null,
      });
    }
  }

  // ── 3. Version changes ────────────────────────────────────────────────────
  for (const [name, afterMeta] of Object.entries(afterPkgs)) {
    const beforeMeta = beforePkgs[name];
    if (!beforeMeta || beforeMeta.version === afterMeta.version) continue;

    const age = daysSince(afterMeta._publishDate);
    const ageLabel = age !== null ? `published ${age}d ago` : 'publish date unknown';

    // Version changed AND new lifecycle scripts added
    const newScripts = {};
    for (const [k, v] of Object.entries(afterMeta.scripts)) {
      if (!beforeMeta.scripts[k]) newScripts[k] = v;
    }

    if (Object.keys(newScripts).length > 0) {
      const severity = (age !== null && age < cooldownDays) ? SEV.CRITICAL : SEV.HIGH;
      findings.push({
        severity,
        code: 'VERSION_UPDATE_NEW_SCRIPTS',
        package: name,
        version: `${beforeMeta.version} → ${afterMeta.version}`,
        message: `Version updated and new lifecycle scripts added (${ageLabel})`,
        detail: scriptsSummary(newScripts),
      });
    } else if (warnOnNewScripts) {
      // Version changed, no new scripts — lower risk
      const severity = (age !== null && age < cooldownDays) ? SEV.HIGH : SEV.INFO;
      findings.push({
        severity,
        code: 'VERSION_UPDATE',
        package: name,
        version: `${beforeMeta.version} → ${afterMeta.version}`,
        message: `Version updated (${ageLabel})`,
        detail: null,
      });
    }
  }

  // ── 4. Cooldown violations (existing packages, newly refreshed) ────────────
  for (const [name, meta] of Object.entries(afterPkgs)) {
    if (!beforePkgs[name]) continue; // already handled as new
    if (beforePkgs[name].version !== meta.version) continue; // handled as update
    const age = daysSince(meta._publishDate);
    if (age !== null && age < cooldownDays && meta.hasLifecycleScripts) {
      findings.push({
        severity: SEV.WARN,
        code: 'COOLDOWN_VIOLATION',
        package: name,
        version: meta.version,
        message: `Package with scripts published only ${age}d ago`,
        detail: scriptsSummary(meta.scripts),
      });
    }
  }

  return findings;
}

/**
 * Classify the aggregate risk level from a list of findings.
 */
function aggregateRisk(findings) {
  if (findings.some(f => f.severity === SEV.CRITICAL)) return SEV.CRITICAL;
  if (findings.some(f => f.severity === SEV.HIGH))     return SEV.HIGH;
  if (findings.some(f => f.severity === SEV.WARN))     return SEV.WARN;
  return SEV.INFO;
}

module.exports = { diffSnapshots, aggregateRisk, SEV };
