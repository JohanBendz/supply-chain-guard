'use strict';
/**
 * rebuild.js
 *
 * Runs `npm rebuild` for explicitly approved packages only.
 * This is how native modules (esbuild, sharp, bcrypt, etc.) get their
 * build scripts executed after a --ignore-scripts install.
 *
 * Only packages listed in .scg-policy.json approvedBuilds will be rebuilt.
 */

const { loadPolicy, isBuildApproved, isBuildDenied,
        verifyScriptHash }                           = require('./policy');
const { runRaw }    = require('./npm');
const { readInstalledMeta } = require('./install-inspector');
const { parseSpec } = require('./spec');

/**
 * Rebuild approved packages.
 *
 * @param {string}   projectRoot
 * @param {string[]} pkgNames      - specific packages to rebuild; empty = all approved
 * @param {object}   opts
 * @param {boolean}  opts.dryRun   - print what would happen without executing
 * @returns {{ rebuilt: string[], skipped: string[], denied: string[] }}
 */
function rebuildApproved(projectRoot, pkgNames = [], opts = {}) {
  const { dryRun = false } = opts;
  const policy  = loadPolicy(projectRoot);

  // Determine which packages to attempt rebuilding
  let targets;
  if (pkgNames.length > 0) {
    targets = pkgNames;
  } else {
    // All approved builds
    targets = Object.keys(policy.approvedBuilds);
  }

  const rebuilt      = [];
  const skipped      = [];
  const denied       = [];
  const hashMismatch = [];  // script changed since approval — must re-approve

  for (const spec of targets) {
    // spec may be "name@version", "@scope/name@version", or just a name.
    // Use the shared parser so scoped packages are handled correctly.
    const { name, version } = parseSpec(spec);

    if (isBuildDenied(policy, name, version)) {
      denied.push(spec);
      continue;
    }

    if (!isBuildApproved(policy, name, version)) {
      skipped.push(spec);
      continue;
    }

    // Verify the package is actually installed
    const meta = readInstalledMeta(projectRoot, name);
    if (!meta) {
      skipped.push(`${spec} (not installed)`);
      continue;
    }

    // SRI: verify installed scripts match hash recorded at approval time.
    // Block rebuild if scripts changed after approval (e.g. compromised update).
    const policyEntry = policy.approvedBuilds[`${name}@${version}`]
                     || policy.approvedBuilds[name];
    if (policyEntry && policyEntry.scriptHash) {
      const cur = {};
      if (meta && meta.scripts) {
        for (const k of ['preinstall','install','postinstall','prepare']) {
          if (meta.scripts[k]) cur[k] = meta.scripts[k];
        }
      }
      const { ok } = verifyScriptHash(policyEntry.scriptHash, cur);
      if (!ok) {
        hashMismatch.push({ spec,
          message: `Script changed since approval — re-run: scg policy approve-build ${spec}` });
        continue;
      }
    }

    // Run npm rebuild <name>
    // sanitizeEnv: true defeats the confused-deputy attack where a
    // non-script package's functional code may have set NODE_OPTIONS
    // (or similar) to inject ./payload.js into spawned Node processes.
    // Stripping NODE_* vectors from the inherited env closes that vector.
    const result = runRaw(['rebuild', name], {
      cwd: projectRoot,
      dryRun,
      sanitizeEnv: true,
    });

    if (result.status === 0 || dryRun) {
      rebuilt.push(spec);
    } else {
      // rebuild failed — don't throw, surface in report
      skipped.push(`${spec} (rebuild exited ${result.status})`);
    }
  }

  return { rebuilt, skipped, denied, hashMismatch };
}

module.exports = { rebuildApproved };
