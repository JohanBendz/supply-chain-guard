'use strict';
/**
 * supply-chain-guard — public API
 */
const { takeSnapshot, saveSnapshot, loadSnapshot }   = require('./snapshot');
const { diffSnapshots, aggregateRisk, SEV }          = require('./diff');
const { detectPhantoms }                              = require('./phantom');
const { auditLifecycleScripts, addToWhitelist }      = require('./postinstall-guard');
const { checkPackage }                                = require('./check');
const { resolveVersion }                              = require('./registry');
const { loadPolicy, savePolicy, initPolicy,
        approveBuild, denyBuild, isBuildApproved }   = require('./policy');
const { runSafe, runRaw }                             = require('./npm');
const { readLockfile, extractPackages,
        diffLockfilePackages }                        = require('./lockfile');
const { inspectInstall }                              = require('./install-inspector');
const { rebuildApproved }                             = require('./rebuild');
const { analyseNewDeps, analysePhantom }              = require('./delta-phantom');
const { getCached, setCached, invalidate,
        clearDiskCache, stats: cacheStats }          = require('./registry-cache');
const { ensureToken, rotateToken, readToken,
        buildGuardScript, LOCK_FILE }                  = require('./lock-token');

module.exports = {
  takeSnapshot, saveSnapshot, loadSnapshot,
  diffSnapshots, aggregateRisk,
  detectPhantoms,
  checkPackage, resolveVersion,
  loadPolicy, savePolicy, initPolicy, approveBuild, denyBuild, isBuildApproved,
  runSafe, runRaw,
  readLockfile, extractPackages, diffLockfilePackages,
  inspectInstall,
  rebuildApproved,
  analyseNewDeps, analysePhantom,
  getCached, setCached, invalidate, clearDiskCache, cacheStats,
  ensureToken, rotateToken, readToken, buildGuardScript, LOCK_FILE,
  SEV,
  auditLifecycleScripts, addToWhitelist,
};
