'use strict';
/**
 * phantom-check.js
 *
 * Runs delta-phantom analysis as part of `scg add` and `scg update` flows.
 * Operates on newly-introduced or updated packages only (not the full tree).
 *
 * Two modes:
 *   manifest   — offline, fast, LOW confidence (always runs)
 *   tarball    — network, HIGH confidence (opt-in via policy or --deep flag)
 *
 * Integration point: called after npm install --ignore-scripts succeeds,
 * before the post-install inspection report is printed.
 */

const registry                           = require('./registry');
const { analysePhantom, analyseNewDeps } = require('./delta-phantom');
const { diffLockfilePackages }   = require('./lockfile');

// ─── types ────────────────────────────────────────────────────────────────────
// PhantomCheckResult {
//   package:  string,           // parent package that changed
//   newDeps:  string[],         // newly introduced dependencies
//   results:  DeltaPhantomResult[],
//   hasHighConfidencePhantom: boolean,
//   hasLowConfidencePhantom:  boolean,
// }

// ─── main entry point ─────────────────────────────────────────────────────────

/**
 * Run delta-phantom analysis for packages that changed between two lockfile
 * package maps.
 *
 * @param {object}   beforePkgs     - from extractPackages(beforeLockfile)
 * @param {object}   afterPkgs      - from extractPackages(afterLockfile)
 * @param {object}   opts
 * @param {boolean}  opts.deep      - download tarballs for HIGH confidence (slower)
 * @param {number}   opts.maxDeepScans - cap tarball downloads (default 3)
 * @returns {Promise<PhantomCheckResult[]>}
 */
async function runPhantomCheck(beforePkgs, afterPkgs, opts = {}) {
  const { deep = false, maxDeepScans = 3 } = opts;
  const results = [];
  let deepScansUsed = 0;

  // Identify packages that changed version (new deps may have been injected)
  const changedPackages = [];
  for (const [name, afterEntry] of Object.entries(afterPkgs)) {
    const beforeEntry = beforePkgs[name];
    if (!beforeEntry || beforeEntry.version !== afterEntry.version) {
      changedPackages.push({ name, version: afterEntry.version, isNew: !beforeEntry });
    }
  }

  if (changedPackages.length === 0) return results;

  for (const { name, version, isNew } of changedPackages) {
    // Fetch the published manifest for this version
    let parentMeta = null;
    try {
      parentMeta = await registry.getVersionMeta(name, version);
    } catch {
      // Registry unavailable — skip this package
      continue;
    }
    if (!parentMeta) continue;

    const currentDeps = Object.keys(parentMeta.dependencies || {});

    // Determine which deps are new for THIS package (per-package, not global).
    // Correct comparison: declared deps in the current published manifest minus
    // declared deps in the previous published manifest of the same package.
    // This catches the axios attack pattern even if the injected dep name happens
    // to already exist somewhere else in the global tree.
    let newDeps;
    if (isNew) {
      // Brand-new package — all its deps are "new" from our perspective
      newDeps = currentDeps;
    } else {
      // Updated package — fetch previous version's manifest from registry and
      // compute the real per-package dep diff.
      const prevVersion = beforePkgs[name]?.version;
      let prevDeps = null;
      if (prevVersion && prevVersion !== version) {
        try {
          const prevMeta = await registry.getVersionMeta(name, prevVersion);
          if (prevMeta) {
            prevDeps = new Set(Object.keys(prevMeta.dependencies || {}));
          }
        } catch {
          // Previous version unfetchable — fall back below
        }
      }
      if (prevDeps) {
        newDeps = currentDeps.filter(dep => !prevDeps.has(dep));
      } else {
        // Fallback: previous manifest unavailable. Be conservative — treat every
        // currently declared dep as potentially new. Worse for noise, better for
        // safety than the previous global-tree approximation.
        newDeps = currentDeps;
      }
    }

    if (newDeps.length === 0) continue;

    // Run analysis for each new dep
    const depResults = [];
    for (const dep of newDeps) {
      let result;
      const useDeep = deep && deepScansUsed < maxDeepScans;

      if (useDeep && parentMeta.dist?.tarball) {
        result = await analysePhantom(parentMeta, dep, {
          tarball: true,
          tarballUrl: parentMeta.dist.tarball,
        });
        deepScansUsed++;
      } else {
        result = await analysePhantom(parentMeta, dep, { tarball: false });
      }
      depResults.push(result);
    }

    const hasHighConfidencePhantom = depResults.some(
      r => r.verdict === 'LIKELY_PHANTOM' && r.confidence === 'HIGH'
    );
    const hasLowConfidencePhantom = depResults.some(
      r => r.verdict === 'LIKELY_PHANTOM' && r.confidence === 'LOW'
    );

    if (hasHighConfidencePhantom || hasLowConfidencePhantom) {
      results.push({
        package: `${name}@${version}`,
        newDeps,
        results: depResults,
        hasHighConfidencePhantom,
        hasLowConfidencePhantom,
      });
    }
  }

  return results;
}

/**
 * Format phantom check results for terminal output.
 */
function formatPhantomResults(phantomResults, R) {
  if (phantomResults.length === 0) return;

  console.log(`\n  ${R.C.yellow}${R.C.bold}Delta phantom analysis:${R.C.reset}`);

  for (const pkg of phantomResults) {
    const worstConf = pkg.hasHighConfidencePhantom ? 'HIGH' : 'LOW';
    const icon = worstConf === 'HIGH'
      ? `${R.C.red}✖ PHANTOM (HIGH confidence)${R.C.reset}`
      : `${R.C.yellow}! LIKELY PHANTOM (LOW confidence)${R.C.reset}`;

    console.log(`\n  ${icon}  ${R.C.bold}${pkg.package}${R.C.reset}`);

    for (const r of pkg.results) {
      if (r.verdict !== 'LIKELY_PHANTOM') continue;
      console.log(`    dep: ${R.C.bold}${r.dep}${R.C.reset}  [${r.confidence} confidence, ${r.layer} scan]`);
      console.log(`    ${R.C.dim}${r.reason}${R.C.reset}`);
    }
  }
}

module.exports = { runPhantomCheck, formatPhantomResults };
