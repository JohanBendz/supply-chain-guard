#!/usr/bin/env node
'use strict';

const path = require('path');
const fs   = require('fs');

const { takeSnapshot, saveSnapshot, loadSnapshot } = require('../src/snapshot');
const { diffSnapshots, aggregateRisk, SEV }        = require('../src/diff');
const { detectPhantoms }                            = require('../src/phantom');
const { auditLifecycleScripts }                     = require('../src/postinstall-guard');
const { checkPackage }                              = require('../src/check');
const {
  loadPolicy, initPolicy,
  approveBuild, denyBuild, listApprovedBuilds,
  POLICY_FILE,
}                                                   = require('../src/policy');
const { runSafe, runRaw, ignoreFlagNotice }         = require('../src/npm');
const { readLockfile, extractPackages }             = require('../src/lockfile');
const { inspectInstall, readInstalledMeta,
        extractScriptsFromMeta }                    = require('../src/install-inspector');
const { rebuildApproved }                           = require('../src/rebuild');
const { runPhantomCheck, formatPhantomResults }      = require('../src/phantom-check');
const { generateSessionToken, rotateToken, buildGuardScript,
        readToken, LOCK_FILE: SCG_LOCK }               = require('../src/lock-token');
const R                                             = require('../src/reporter');

// ── utilities ─────────────────────────────────────────────────────────────────

// Boolean flags that should NEVER consume the next token as a value, even
// if that token doesn't start with a dash. Without this list, calls like
// `scg add foo --save-dev` would parse as `flags['save-dev']='foo'` (wrong:
// `foo` is a positional package name) because the lookahead is purely
// syntactic.
const BOOLEAN_FLAGS = new Set([
  // SCG boolean flags
  'force', 'dry-run', 'all', 'force-all', 'deep', 'json', 'npmrc', 'gha',
  'rotate-token', 'pre', 'post', 'fetch-dates', 'help',

  // Common npm boolean flags. Keeping these here prevents the compatibility
  // parser from accidentally swallowing the package name that follows them
  // (for example: scg add --save-exact lodash). The raw argv is still used
  // for npm passthrough; this only protects SCG's own positional view.
  'save-dev', 'D', 'save-optional', 'O', 'save-peer', 'P', 'save-prod',
  'save-exact', 'E', 'global', 'g', 'legacy-peer-deps', 'strict-peer-deps',
  'audit', 'no-audit', 'fund', 'no-fund', 'package-lock', 'no-package-lock',
  'package-lock-only', 'foreground-scripts', 'ignore-scripts', 'prefer-offline',
  'prefer-online', 'offline', 'workspaces', 'ws', 'include-workspace-root',
  'install-links', 'omit-lockfile-registry-resolved',
]);

// Short-flag aliases. `-D` is the standard npm shorthand for `--save-dev`,
// and the original parser dropped it on the floor because it only handled
// `--` prefixes. We expand short flags to their long form during parse so
// downstream commands can read them under one canonical name.
const SHORT_FLAG_ALIASES = {
  'D': 'save-dev',
  'O': 'save-optional',
  'P': 'save-prod',
  'E': 'save-exact',
  'g': 'global',
  'h': 'help',
};

function parseArgs(argv) {
  const args = { flags: {}, positional: [], raw: [...argv] };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--') { args.positional.push(...argv.slice(i + 1)); break; }
    if (a.startsWith('--')) {
      // --key=value form
      const eq = a.indexOf('=');
      if (eq !== -1) {
        args.flags[a.slice(2, eq)] = a.slice(eq + 1);
        continue;
      }
      const key  = a.slice(2);
      // Boolean flags never consume a following token; everything else may
      // consume the next token if it isn't itself a flag.
      if (BOOLEAN_FLAGS.has(key)) {
        args.flags[key] = true;
        continue;
      }
      const next = argv[i + 1];
      if (next && !next.startsWith('-')) { args.flags[key] = next; i++; }
      else                                { args.flags[key] = true; }
    } else if (a.startsWith('-') && a.length > 1) {
      // Short flag(s). We handle single-letter aliases only — clusters like
      // `-Dv` are not currently supported but could be expanded if needed.
      const short = a.slice(1);
      const long  = SHORT_FLAG_ALIASES[short] || short;
      args.flags[long] = true;
    } else {
      args.positional.push(a);
    }
  }
  return args;
}

function findProjectRoot() {
  let dir = process.cwd();
  while (dir !== path.dirname(dir)) {
    if (fs.existsSync(path.join(dir, 'package.json'))) return dir;
    dir = path.dirname(dir);
  }
  return process.cwd();
}

function snapshotPath(root, label) {
  return path.join(root, `.scg-snapshot-${label}.json`);
}

function printFindings(findings) {
  const order  = ['CRITICAL', 'HIGH', 'WARN', 'INFO'];
  const sorted = [...findings].sort((a, b) => order.indexOf(a.severity) - order.indexOf(b.severity));
  R.printFindings(sorted);
}

// ── post-install report ───────────────────────────────────────────────────────

function printInspectionReport(report) {
  if (report.blocked.length > 0) {
    console.log(`\n  ${R.C.red}${R.C.bold}BLOCKED (denied in policy):${R.C.reset}`);
    for (const b of report.blocked) {
      console.log(`    ${R.C.red}x${R.C.reset}  ${R.C.bold}${b.name}@${b.version}${R.C.reset}  -- ${b.reason}`);
    }
  }
  if (report.approvedChanged && report.approvedChanged.length > 0) {
    console.log(`\n  ${R.C.red}${R.C.bold}APPROVED SCRIPT CHANGED (re-approval required):${R.C.reset}`);
    for (const c of report.approvedChanged) {
      console.log(`    ${R.C.red}x${R.C.reset}  ${R.C.bold}${c.name}@${c.version}${R.C.reset}  -- ${c.reason}`);
      if (c.recorded && c.actual) {
        console.log(`       ${R.C.dim}recorded: ${c.recorded}${R.C.reset}`);
        console.log(`       ${R.C.dim}actual:   ${c.actual}${R.C.reset}`);
      }
    }
  }
  if (report.needsApproval.length > 0) {
    console.log(`\n  ${R.C.yellow}${R.C.bold}Packages with install scripts (unapproved -- scripts did NOT run):${R.C.reset}`);
    console.log(`  ${R.C.dim}Approve: scg policy approve-build <pkg>@<ver>  then: scg rebuild-approved${R.C.reset}\n`);
    for (const n of report.needsApproval) {
      console.log(`    ${R.C.yellow}!${R.C.reset}  ${R.C.bold}${n.name}@${n.version}${R.C.reset}`);
      for (const [k, v] of Object.entries(n.scripts)) {
        const vs = String(v);
        console.log(`       ${R.C.dim}${k}: ${vs.slice(0, 100)}${vs.length > 100 ? '...' : ''}${R.C.reset}`);
      }
    }
  }
  if (report.approved.length > 0) {
    console.log(`\n  ${R.C.dim}Approved (suppressed, rebuild manually): ${report.approved.map(a => a.name).join(', ')}${R.C.reset}`);
  }
}

async function runPostInstallPipeline(root, beforePkgs, dryRun, pipelineOpts = {}) {
  if (dryRun) return;

  const afterLockfile = readLockfile(root);
  const afterPkgs     = afterLockfile ? extractPackages(afterLockfile) : {};

  // Delta phantom analysis for changed packages (manifest mode, fast)
  if (beforePkgs && Object.keys(beforePkgs).length > 0) {
    try {
      const deepMode = !!pipelineOpts.deep;
      const phantomResults = await runPhantomCheck(beforePkgs, afterPkgs, { deep: deepMode });
      formatPhantomResults(phantomResults, R);
    } catch (e) {
      // Phantom check failure is non-fatal — log and continue
      console.log(`  ${R.C.dim}(phantom check skipped: ${e.message})${R.C.reset}`);
    }
  }

  // Post-install policy inspection
  const report = inspectInstall(root, { beforeLockfile: beforePkgs });
  if (report.totalInspected === 0 && report.blocked.length === 0) {
    console.log(`\n  ${R.C.green}No new install-script packages${R.C.reset}`);
    return;
  }
  printInspectionReport(report);
  if (report.blocked.length > 0 || (report.approvedChanged && report.approvedChanged.length > 0)) {
    console.log(`\n${R.C.red}${R.C.bold}  INSTALL BLOCKED -- policy requires review${R.C.reset}\n`);
    process.exit(1);
  }
  if (!report.isClean) {
    console.log(`\n  ${R.C.yellow}Install complete with warnings.${R.C.reset} Review above, then run ${R.C.cyan}scg rebuild-approved${R.C.reset}.\n`);
  } else {
    console.log(`\n  ${R.C.green}Install clean${R.C.reset}\n`);
  }
}

// ── wrapper commands ──────────────────────────────────────────────────────────

/**
 * Resolve the latest dist-tag version for a package name via the npm registry.
 * Returns null if the registry is unavailable.
 */
async function resolveLatestVersion(name) {
  try {
    const { getPackument } = require('../src/registry');
    const packument = await getPackument(name);
    return packument?.['dist-tags']?.latest || null;
  } catch { return null; }
}

// ── shared command helpers ────────────────────────────────────────────────────

const { parseSpec } = require('../src/spec');
const { resolveVersion } = require('../src/registry');
const RISK_ORDER = ['INFO', 'WARN', 'HIGH', 'CRITICAL'];
const SCG_WRAPPER_FLAGS = new Set(['dry-run', 'deep', 'cooldown', 'fail-on', 'force', 'all', 'force-all']);
const SCG_VALUE_FLAGS = new Set(['cooldown', 'fail-on']);

function policySettings(root) {
  const policy = loadPolicy(root);
  return Object.assign({ cooldownDays: 3, failOn: 'HIGH' }, policy.settings || {});
}

function cooldownFromPolicyOrFlags(root, flags) {
  const value = flags.cooldown ?? policySettings(root).cooldownDays ?? 3;
  const parsed = parseInt(value, 10);
  return Number.isFinite(parsed) && parsed >= 0 ? parsed : 3;
}

function failOnFromPolicyOrFlags(root, flags) {
  const value = String(flags['fail-on'] || policySettings(root).failOn || 'HIGH').toUpperCase();
  return RISK_ORDER.includes(value) ? value : 'HIGH';
}

function riskAtOrAbove(riskLevel, failOn) {
  const riskIdx = RISK_ORDER.indexOf(riskLevel);
  const failIdx = RISK_ORDER.indexOf(failOn);
  return riskIdx !== -1 && failIdx !== -1 && riskIdx >= failIdx && riskLevel !== 'INFO';
}

function stripScgWrapperFlags(rawArgs) {
  const out = [];
  for (let i = 0; i < rawArgs.length; i++) {
    const token = rawArgs[i];
    if (token === '--') {
      out.push(...rawArgs.slice(i));
      break;
    }
    if (token.startsWith('--')) {
      const body = token.slice(2);
      const eq = body.indexOf('=');
      const key = eq === -1 ? body : body.slice(0, eq);
      if (SCG_WRAPPER_FLAGS.has(key)) {
        if (eq === -1 && SCG_VALUE_FLAGS.has(key) && rawArgs[i + 1] && !rawArgs[i + 1].startsWith('-')) i++;
        continue;
      }
    }
    out.push(token);
  }
  return out;
}

/**
 * Run pre-flight risk check for a single package spec.
 * Resolves "latest"/"next"/unversioned specs via the registry first.
 *
 * Returns { riskLevel, hasHighRisk, resolved } where:
 *   - riskLevel: one of 'INFO' | 'WARN' | 'HIGH' | 'CRITICAL' | 'UNKNOWN'
 *   - hasHighRisk: true if this spec should block the install (when !force)
 *   - resolved: the concrete version that was checked (or null if skipped)
 *
 * Output is streamed to stdout as it happens so the user sees progress.
 * A registry failure during resolution is treated as "unknown risk" — the
 * caller decides whether to continue or abort based on its own policy.
 */
async function preflightOne(spec, opts = {}) {
  const { cooldown = 3, failOn = 'HIGH' } = opts;
  const { name } = parseSpec(spec);
  let { version } = parseSpec(spec);

  process.stdout.write(`  Resolving ${spec}... `);
  try {
    version = await resolveVersion(name, version || 'latest');
    if (!version) {
      process.stdout.write(`${R.C.yellow}(unable to resolve — skipping preflight)${R.C.reset}\n`);
      return { riskLevel: 'UNKNOWN', shouldBlock: false, resolved: null };
    }
    process.stdout.write(`${R.C.dim}${name}@${version}${R.C.reset}\n`);
  } catch (e) {
    process.stdout.write(`${R.C.yellow}(resolve error: ${e.message} — skipping preflight)${R.C.reset}\n`);
    return { riskLevel: 'UNKNOWN', shouldBlock: false, resolved: null };
  }

  process.stdout.write(`  Pre-flight: ${name}@${version}... `);
  try {
    const { signals, riskLevel } = await checkPackage(name, version, { cooldownDays: cooldown });
    if (riskLevel === 'INFO') {
      process.stdout.write(`${R.C.green}clean${R.C.reset}\n`);
      return { riskLevel, shouldBlock: false, resolved: version };
    }
    process.stdout.write(`${R.C.red}${riskLevel}${R.C.reset}\n`);
    printFindings(signals);
    return { riskLevel, shouldBlock: riskAtOrAbove(riskLevel, failOn), resolved: version };
  } catch (e) {
    process.stdout.write(`${R.C.yellow}(check error: ${e.message} — treat with caution)${R.C.reset}\n`);
    return { riskLevel: 'UNKNOWN', shouldBlock: false, resolved: version };
  }
}
/**
 * Run pre-flight for every spec in `specs`. Returns true if any spec had
 * a HIGH or CRITICAL risk level — the caller should exit 1 unless --force.
 */
async function preflightAll(specs, opts = {}) {
  let anyBlocked = false;
  for (const spec of specs) {
    const { shouldBlock } = await preflightOne(spec, opts);
    if (shouldBlock) anyBlocked = true;
  }
  return anyBlocked;
}

/**
 * Shared execution path for all wrapper commands (add / install / ci / update).
 *
 * Steps:
 *   1. (optional) Run pre-flight on the provided specs.
 *   2. Snapshot the lockfile (before).
 *   3. Run `npm <npmArgs> --ignore-scripts` via runSafe.
 *   4. Run the post-install pipeline (phantom delta + policy inspection).
 *
 * All four wrapper commands previously duplicated this logic with small
 * variations. The helper keeps them to ~10 lines each.
 */
async function runNpmWrapper({
  root, label, npmArgs,
  preflightSpecs = null,   // if set, run preflightAll(preflightSpecs, ...)
  cooldown = 3, failOn = 'HIGH', force = false,
  dryRun = false, deep = false,
  preflightBlockedMessage = 'Pre-flight failed. Use --force to proceed (not recommended).',
}) {
  R.header(label);
  console.log(`  Enforcing: ${ignoreFlagNotice()}\n`);

  if (preflightSpecs && preflightSpecs.length > 0) {
    const shouldBlock = await preflightAll(preflightSpecs, { cooldown, failOn });
    if (shouldBlock && !force) {
      console.log(`\n  ${R.C.red}${preflightBlockedMessage}${R.C.reset}\n`);
      process.exit(1);
    }
    if (preflightSpecs.length > 0) console.log();
  }

  const beforeLockfile = readLockfile(root);
  const beforePkgs     = beforeLockfile ? extractPackages(beforeLockfile) : {};

  console.log(`  Running: npm ${npmArgs.join(' ')} --ignore-scripts`);
  const result = runSafe(npmArgs, { cwd: root, dryRun });
  if (!dryRun && result.status !== 0) {
    console.error(`\n  ${R.C.red}npm exited ${result.status}${R.C.reset}\n`);
    process.exit(result.status);
  }
  await runPostInstallPipeline(root, beforePkgs, dryRun, { deep });
}

async function cmdAdd(args) {
  const root     = findProjectRoot();
  const pkgSpecs = args.positional;
  const npmTail  = stripScgWrapperFlags(args.raw);
  const dryRun   = !!args.flags['dry-run'];
  const cooldown = cooldownFromPolicyOrFlags(root, args.flags);
  const failOn   = failOnFromPolicyOrFlags(root, args.flags);
  const force    = !!args.flags.force;

  if (pkgSpecs.length === 0) {
    console.error('Usage: scg add <package>[@version] [...]');
    process.exit(1);
  }

  const npmArgs = ['install', ...npmTail];
  if (!npmArgs.includes('--save') && !npmArgs.includes('--no-save')) npmArgs.push('--save');

  console.log(`  Adding: ${pkgSpecs.join(', ')}`);
  await runNpmWrapper({
    root, label: 'SCG Add', npmArgs,
    preflightSpecs: pkgSpecs,
    cooldown, failOn, force, dryRun,
    deep: !!args.flags.deep,
    preflightBlockedMessage: `Pre-flight failed at policy failOn=${failOn}. Use --force to install anyway (not recommended).`,
  });
}
async function cmdInstall(args) {
  const root   = findProjectRoot();
  const dryRun = !!args.flags['dry-run'];
  await runNpmWrapper({
    root, label: 'SCG Install',
    npmArgs: ['install', ...stripScgWrapperFlags(args.raw)],
    dryRun,
    deep: !!args.flags.deep,
  });
}
async function cmdCI(args) {
  const root   = findProjectRoot();
  const dryRun = !!args.flags['dry-run'];
  await runNpmWrapper({
    root, label: 'SCG CI',
    npmArgs: ['ci', ...stripScgWrapperFlags(args.raw)],
    dryRun,
    deep: !!args.flags.deep,
  });
}
async function cmdUpdate(args) {
  const root     = findProjectRoot();
  const dryRun   = !!args.flags['dry-run'];
  const cooldown = cooldownFromPolicyOrFlags(root, args.flags);
  const failOn   = failOnFromPolicyOrFlags(root, args.flags);
  const force    = !!args.flags.force;
  const targets  = args.positional;
  const npmTail  = stripScgWrapperFlags(args.raw);

  if (targets.length === 0 && !(args.flags.all || args.flags['force-all'])) {
    R.header('SCG Update');
    console.log(`\n  ${R.C.red}${R.C.bold}Tell scg which packages to update.${R.C.reset}`);
    console.log(`\n  ${R.C.bold}Examples:${R.C.reset}`);
    console.log(`    ${R.C.cyan}scg update lodash${R.C.reset}                   update one package`);
    console.log(`    ${R.C.cyan}scg update react react-dom${R.C.reset}          update several packages`);
    console.log(`    ${R.C.cyan}scg update --all${R.C.reset}                    update everything ${R.C.dim}(weaker — see below)${R.C.reset}`);
    console.log(`\n  ${R.C.dim}Targeted updates run a per-package preflight check against the${R.C.reset}`);
    console.log(`  ${R.C.dim}npm registry before downloading. --all skips that check.${R.C.reset}\n`);
    process.exit(1);
  }

  if (targets.length === 0) {
    R.header('SCG Update');
    console.log(`  Enforcing: ${ignoreFlagNotice()}\n`);
    console.log(`  ${R.C.yellow}${R.C.bold}⚠ EXPLICIT RISK BUDGET: --all skips per-package preflight.${R.C.reset}`);
    console.log(`  ${R.C.yellow}This is faster and more convenient than targeted updates,${R.C.reset}`);
    console.log(`  ${R.C.yellow}but materially weaker. Post-install inspection and phantom${R.C.reset}`);
    console.log(`  ${R.C.yellow}analysis still run, but will not catch a malicious version${R.C.reset}`);
    console.log(`  ${R.C.yellow}before npm fetches it. Prefer 'scg update <pkg>' for security.${R.C.reset}`);
    console.log();

    const beforeLockfile = readLockfile(root);
    const beforePkgs     = beforeLockfile ? extractPackages(beforeLockfile) : {};
    const npmArgs = ['update', ...npmTail];
    console.log(`  Running: npm ${npmArgs.join(' ')} --ignore-scripts`);
    const result = runSafe(npmArgs, { cwd: root, dryRun });
    if (!dryRun && result.status !== 0) process.exit(result.status);
    await runPostInstallPipeline(root, beforePkgs, dryRun, { deep: !!args.flags.deep });
    return;
  }

  console.log(`  Running pre-flight checks for update targets...`);
  await runNpmWrapper({
    root, label: 'SCG Update',
    npmArgs: ['update', ...npmTail],
    preflightSpecs: targets,
    cooldown, failOn, force, dryRun,
    deep: !!args.flags.deep,
    preflightBlockedMessage: `Pre-flight failed at policy failOn=${failOn}. Use --force to update anyway.`,
  });
}
async function cmdRemove(args) {
  const root   = findProjectRoot();
  const pkgs   = args.positional;
  const dryRun = !!args.flags['dry-run'];
  if (pkgs.length === 0) { console.error('Usage: scg remove <pkg> [...]'); process.exit(1); }
  R.header('SCG Remove');
  const npmArgs = ['uninstall', ...stripScgWrapperFlags(args.raw)];
  console.log(`  Running: npm ${npmArgs.join(' ')} --ignore-scripts`);
  const result = runSafe(npmArgs, { cwd: root, dryRun });
  if (!dryRun && result.status !== 0) { process.exit(result.status); }
  if (!dryRun) console.log(`\n  ${R.C.green}Removed: ${pkgs.join(', ')}${R.C.reset}\n`);
}
async function cmdRebuildApproved(args) {
  const root   = findProjectRoot();
  const pkgs   = args.positional;
  const dryRun = !!args.flags['dry-run'];
  R.header('SCG Rebuild Approved');
  const policy   = loadPolicy(root);
  const approved = listApprovedBuilds(policy);
  if (approved.length === 0) {
    console.log(`\n  ${R.C.yellow}No approved builds in ${POLICY_FILE}.${R.C.reset}`);
    console.log(`  Use: scg policy approve-build <pkg>@<ver>\n`);
    return;
  }
  if (pkgs.length > 0) {
    console.log(`  Rebuilding specified (approved): ${pkgs.join(', ')}\n`);
  } else {
    console.log(`  Rebuilding all approved (${approved.length}): ${approved.map(a => a.key).join(', ')}\n`);
  }
  const { rebuilt, skipped, denied, hashMismatch } = rebuildApproved(root, pkgs, { dryRun });
  if (hashMismatch.length > 0) {
    console.log(`  ${R.C.red}${R.C.bold}Script hash mismatch:${R.C.reset}`);
    for (const h of hashMismatch) console.log(`    ${R.C.red}x${R.C.reset}  ${h.spec}  ${R.C.dim}${h.message}${R.C.reset}`);
  }
  if (denied.length > 0)   console.log(`  ${R.C.red}Denied:${R.C.reset} ${denied.join(', ')}`);
  if (skipped.length > 0)  console.log(`  ${R.C.yellow}Skipped:${R.C.reset} ${skipped.join(', ')}`);
  if (rebuilt.length > 0)  console.log(`  ${R.C.green}${dryRun ? 'Would rebuild' : 'Rebuilt'}:${R.C.reset} ${rebuilt.join(', ')}`);
  console.log();
  if (hashMismatch.length > 0) process.exit(1);
}

// ── policy ────────────────────────────────────────────────────────────────────

async function cmdPolicy(args) {
  const sub  = args.positional[0];
  const rest = { ...args, positional: args.positional.slice(1) };
  if      (sub === 'approve-build') return cmdPolicyApprove(rest);
  else if (sub === 'deny-build')    return cmdPolicyDeny(rest);
  else if (sub === 'list')          return cmdPolicyList(rest);
  else {
    console.error(`Unknown policy subcommand: ${sub || '(none)'}\n  Available: approve-build, deny-build, list`);
    process.exit(1);
  }
}

async function cmdPolicyApprove(args) {
  const root = findProjectRoot();
  const spec = args.positional[0];
  if (!spec) { console.error('Usage: scg policy approve-build <pkg>[@ver]'); process.exit(1); }
  const { name, version } = parseSpec(spec);
  const meta    = readInstalledMeta(root, name);
  const scripts = meta ? extractScriptsFromMeta(meta) : {};
  const key     = approveBuild(root, name, version, scripts);
  console.log(`\n  ${R.C.green}Approved: ${key}${R.C.reset}`);
  for (const [k, v] of Object.entries(scripts)) console.log(`    ${R.C.dim}${k}: ${v}${R.C.reset}`);
  console.log(`  Saved to: ${POLICY_FILE}`);
  console.log(`  Now run: ${R.C.cyan}scg rebuild-approved${R.C.reset}\n`);
}

async function cmdPolicyDeny(args) {
  const root   = findProjectRoot();
  const spec   = args.positional[0];
  const reason = args.flags.reason || '';
  if (!spec) { console.error('Usage: scg policy deny-build <pkg>[@ver]'); process.exit(1); }
  const { name, version } = parseSpec(spec);
  const key     = denyBuild(root, name, version, reason);
  console.log(`\n  ${R.C.red}Denied: ${key}${reason ? ` (${reason})` : ''}${R.C.reset}`);
  console.log(`  Saved to: ${POLICY_FILE}\n`);
}

async function cmdPolicyList(args) {
  const root   = findProjectRoot();
  const policy = loadPolicy(root);
  R.header('SCG Policy');
  console.log(`  File: ${path.join(root, POLICY_FILE)}\n`);
  const approved = Object.entries(policy.approvedBuilds);
  const denied   = Object.entries(policy.deniedBuilds);
  if (approved.length === 0) {
    console.log(`  ${R.C.dim}No approved builds${R.C.reset}`);
  } else {
    console.log(`  ${R.C.green}${R.C.bold}Approved (${approved.length}):${R.C.reset}`);
    for (const [key, e] of approved) {
      const scripts = Object.keys(e.scripts || {}).join(', ') || 'no scripts recorded';
      console.log(`    ${R.C.green}+${R.C.reset}  ${R.C.bold}${key}${R.C.reset}  ${R.C.dim}[${scripts}] by ${e.approvedBy || '?'} on ${(e.approvedAt || '?').slice(0, 10)}${R.C.reset}`);
    }
  }
  if (denied.length > 0) {
    console.log(`\n  ${R.C.red}${R.C.bold}Denied (${denied.length}):${R.C.reset}`);
    for (const [key, e] of denied) {
      console.log(`    ${R.C.red}-${R.C.reset}  ${R.C.bold}${key}${R.C.reset}  ${R.C.dim}${e.reason || ''}${R.C.reset}`);
    }
  }
  const s = policy.settings || {};
  console.log(`\n  ${R.C.dim}Settings: cooldownDays=${s.cooldownDays ?? 3}, failOn=${s.failOn ?? 'HIGH'}${R.C.reset}\n`);
}

// ── analysis ──────────────────────────────────────────────────────────────────

async function cmdCheck(args) {
  const spec = args.positional[0];
  const root = findProjectRoot();
  const cooldown = cooldownFromPolicyOrFlags(root, args.flags);
  const json = !!args.flags.json;
  if (!spec) { console.error('Usage: scg check <pkg>[@ver]'); process.exit(1); }
  const { name } = parseSpec(spec);
  let { version } = parseSpec(spec);

  try {
    version = await resolveVersion(name, version || 'latest');
    if (!version) {
      if (json) console.log(JSON.stringify({ error: `Unable to resolve ${spec}` }, null, 2));
      else console.log(`  ${R.C.red}Unable to resolve: ${spec}${R.C.reset}\n`);
      process.exit(1);
    }
  } catch (e) {
    if (json) console.log(JSON.stringify({ error: e.message }, null, 2));
    else console.error(`\n  ${R.C.red}Registry error: ${e.message}${R.C.reset}\n`);
    process.exit(2);
  }

  let result;
  try { result = await checkPackage(name, version, { cooldownDays: cooldown, deepPhantom: !!args.flags.deep }); }
  catch (e) {
    if (json) console.log(JSON.stringify({ error: e.message }, null, 2));
    else console.error(`\n  ${R.C.red}Registry error: ${e.message}${R.C.reset}\n`);
    process.exit(2);
  }

  result.resolved = { input: spec, name, version };
  if (json) { console.log(JSON.stringify(result, null, 2)); return; }

  R.header(`SCG Check: ${spec}`);
  const { profile, signals, riskLevel } = result;
  const ageLabel  = profile.ageDays !== null ? `${profile.ageDays}d old` : 'age unknown';
  const provLabel = profile.provenance?.currentHasProvenance
    ? `${R.C.green}OIDC provenance${R.C.reset}` : `${R.C.yellow}no provenance${R.C.reset}`;
  console.log(`\n  ${R.C.bold}${name}@${version}${R.C.reset}  ${R.C.dim}${ageLabel} * ${profile.totalVersions} versions${R.C.reset}`);
  if (spec !== `${name}@${version}`) console.log(`  Resolved from: ${spec}`);
  console.log(`  Provenance: ${provLabel}`);
  if (profile.previousVersion) console.log(`  Previous: ${profile.previousVersion}`);
  if (profile.depDiff) {
    if (profile.depDiff.added.length > 0) {
      console.log(`\n  ${R.C.yellow}NEW DEPS vs ${profile.previousVersion}:${R.C.reset}`);
      for (const dep of profile.depDiff.added) {
        const dp = profile.newDepProfiles?.[dep];
        if (dp && !dp.error) {
          const exactNote  = dp.exactVersionResolved === false ? ` ${R.C.dim}(version approximate)${R.C.reset}` : '';
          const scriptFlag = dp.hasLifecycleScripts ? ` ${R.C.red}[HAS POSTINSTALL]${R.C.reset}` : '';
          console.log(`    + ${R.C.bold}${dep}@${dp.version}${R.C.reset}  ${R.C.dim}pkg ${dp.packageAgeDays ?? '?'}d old, ${dp.totalVersions ?? '?'} versions${R.C.reset}${scriptFlag}${exactNote}`);
        } else {
          console.log(`    + ${dep}  ${R.C.dim}(metadata unavailable)${R.C.reset}`);
        }
      }
    }
    if (profile.depDiff.removed.length > 0) {
      console.log(`  ${R.C.dim}Removed: ${profile.depDiff.removed.join(', ')}${R.C.reset}`);
    }
  }
  if (signals.length > 0) { console.log(); R.printFindings(signals); }
  const safe = riskLevel === 'INFO';
  R.printSummary(riskLevel, safe ? 0 : 1);
  if (!safe) process.exit(1);
}
async function cmdAudit(args) {
  const root     = findProjectRoot();
  const cooldown = cooldownFromPolicyOrFlags(root, args.flags);
  const failOn   = failOnFromPolicyOrFlags(root, args.flags);
  const fetch    = !!args.flags['fetch-dates'];
  R.header('SCG Audit');
  console.log(`  Project: ${root}\n`);

  R.subHeader('1. Policy');
  const policy   = loadPolicy(root);
  const approved = listApprovedBuilds(policy);
  const pFile    = path.join(root, POLICY_FILE);
  if (fs.existsSync(pFile)) {
    console.log(`  ${R.C.green}${POLICY_FILE} found (${approved.length} approved builds)${R.C.reset}`);
  } else {
    console.log(`  ${R.C.yellow}No ${POLICY_FILE} -- run scg init to create${R.C.reset}`);
  }

  R.subHeader('2. Install-script packages');
  const lockfile = readLockfile(root);
  if (lockfile) {
    const report = inspectInstall(root, { beforeLockfile: null });
    if (report.needsApproval.length === 0 && report.blocked.length === 0 && (!report.approvedChanged || report.approvedChanged.length === 0)) {
      console.log(`  ${R.C.green}All install-script packages accounted for in policy${R.C.reset}`);
    } else {
      printInspectionReport(report);
    }
  } else {
    console.log(`  ${R.C.dim}No package-lock.json -- install first${R.C.reset}`);
  }

  R.subHeader('3. Phantom deps (root project)');
  const phantomResult = detectPhantoms(root, { srcDirs: [root] });
  R.printPhantomReport(phantomResult);

  R.subHeader('4. Snapshot drift');
  const prePath = snapshotPath(root, 'pre');
  let before    = loadSnapshot(prePath) || { packages: {} };
  if (!loadSnapshot(prePath)) {
    console.log(`  ${R.C.dim}No pre-snapshot (run scg snapshot --pre to baseline)${R.C.reset}`);
  }
  const after    = await takeSnapshot(root, { fetchDates: fetch });
  const findings = diffSnapshots(before, after, { cooldownDays: cooldown });
  printFindings(findings);

  const risk     = aggregateRisk(findings);
  const exitCode = riskAtOrAbove(risk, failOn) ? 1 : 0;
  R.printSummary(exitCode === 0 ? 'INFO' : risk, exitCode);
  process.exit(exitCode);
}

async function cmdPhantom(args) {
  const root    = findProjectRoot();
  const srcDirs = args.flags.src ? [args.flags.src] : [root];
  R.header('SCG Phantom');
  const result = detectPhantoms(root, { srcDirs });
  R.printPhantomReport(result);
  console.log();
  if (result.phantoms.length > 0) process.exit(1);
}

async function cmdScripts(args) {
  const root = findProjectRoot();
  R.header('SCG Lifecycle Scripts');
  const audit = auditLifecycleScripts(root);
  R.printScriptAudit(audit);
  console.log();
  if (audit.pending.length > 0) process.exit(1);
}

// ── init ──────────────────────────────────────────────────────────────────────

async function cmdInit(args) {
  const root      = findProjectRoot();
  const pkgPath   = path.join(root, 'package.json');
  const withNpmrc = !!args.flags.npmrc;
  const withGHA   = !!args.flags.gha;
  const dryRun    = !!args.flags['dry-run'];
  const doRotate  = !!args.flags['rotate-token'];
  R.header('SCG Init');
  if (!fs.existsSync(pkgPath)) { console.error('  No package.json'); process.exit(1); }
  const changes = [];

  // ── 1. Policy file ────────────────────────────────────────────────────────
  const policyCreated = !dryRun ? initPolicy(root) : true;
  if (policyCreated || dryRun) changes.push(`+ ${POLICY_FILE}`);
  else                         changes.push(`~ ${POLICY_FILE} already exists`);

  // ── 2. .scg-lock (NOT committed — generated fresh each session) ──────────
  // .scg-lock is added to .gitignore. SCG generates a fresh session token
  // at the start of every install/ci/add/update command. This means:
  //   - local dev: token is always current session, cannot be pre-set in ~/.zshrc
  //   - CI:        scg ci generates the token; raw npm ci blocks (no .scg-lock)
  //   - rotate:    no longer needed — token rotates automatically every session
  if (doRotate) {
    // --rotate-token is a no-op in the new model but accepted for compatibility
    changes.push(`~ ${SCG_LOCK}  (auto-generated per-session — no explicit rotation needed)`);
  }
  // .scg-lock itself will be created by the first scg install/ci run
  changes.push(`  ${SCG_LOCK}  will be auto-generated per-session (added to .gitignore)`);

  // ── 3. Muscle-memory guard (preinstall in package.json) ───────────────────
  const pkg        = JSON.parse(fs.readFileSync(pkgPath, 'utf8'));
  const pkgScripts = pkg.scripts || {};
  const guardScript = buildGuardScript();

  let guardChange = null;
  if (!pkgScripts.preinstall) {
    pkgScripts.preinstall = guardScript;
    guardChange = '+ scripts.preinstall  (SCG muscle-memory guard)';
  } else if (!pkgScripts.preinstall.includes('.scg-lock')) {
    pkgScripts.preinstall = guardScript + ' && ' + pkgScripts.preinstall;
    guardChange = '~ scripts.preinstall  (SCG guard prepended)';
  } else {
    guardChange = '~ scripts.preinstall  (SCG guard already present)';
  }

  if (guardChange) {
    if (!dryRun) {
      pkg.scripts = pkgScripts;
      fs.writeFileSync(pkgPath, JSON.stringify(pkg, null, 2) + '\n');
    }
    changes.push(guardChange);
  }

  // ── 4. Optional .npmrc ───────────────────────────────────────────────────
  if (withNpmrc) {
    const np   = path.join(root, '.npmrc');
    const line = 'ignore-scripts=true';
    if (!fs.existsSync(np)) {
      if (!dryRun) fs.writeFileSync(np, line + '\n');
      changes.push('+ .npmrc  (ignore-scripts=true)');
    } else {
      const npmrcContent = fs.readFileSync(np, 'utf8');
      if (!npmrcContent.includes('ignore-scripts')) {
        if (!dryRun) fs.appendFileSync(np, '\n' + line + '\n');
        changes.push('~ .npmrc  (appended ignore-scripts=true)');
      } else { changes.push('~ .npmrc already has ignore-scripts'); }
    }
  }

  // ── 5. Optional GitHub Actions workflow ──────────────────────────────────
  if (withGHA) {
    const ghaDir  = path.join(root, '.github', 'workflows');
    const ghaPath = path.join(ghaDir, 'supply-chain-guard.yml');
    if (!fs.existsSync(ghaPath)) {
      if (!dryRun) { fs.mkdirSync(ghaDir, { recursive: true }); fs.writeFileSync(ghaPath, generateGHAWorkflow()); }
      changes.push('+ .github/workflows/supply-chain-guard.yml');
    } else { changes.push('~ GHA workflow already exists'); }
  }

  // ── 6. .gitignore (snapshot files only — NOT .scg-lock) ──────────────────
  const giPath  = path.join(root, '.gitignore');
  // .scg-lock is intentionally NOT committed — it's a per-session file.
  // This is the critical difference from "commit the token" approach:
  // SCG generates a fresh token at the start of each install.
  const giLines = '\n# supply-chain-guard\n.scg-snapshot-*.json\n.scg-lock\n';
  if (!fs.existsSync(giPath)) {
    if (!dryRun) fs.writeFileSync(giPath, giLines);
    changes.push('+ .gitignore');
  } else if (!fs.readFileSync(giPath, 'utf8').includes('.scg-snapshot')) {
    if (!dryRun) fs.appendFileSync(giPath, giLines);
    changes.push('~ .gitignore  (added snapshot exclusions)');
  }

  // ── Output ────────────────────────────────────────────────────────────────
  if (dryRun) console.log('  (dry-run)\n');
  for (const ch of changes) console.log(`  ${ch.startsWith('+') ? R.C.green : R.C.dim}${ch}${R.C.reset}`);

  console.log(`\n  ${R.C.bold}${R.C.green}Project is now protected.${R.C.reset}`);
  console.log(`\n  ${R.C.bold}Use these commands instead of raw npm:${R.C.reset}`);
  console.log(`    ${R.C.cyan}scg install${R.C.reset}              for ${R.C.dim}npm install${R.C.reset}`);
  console.log(`    ${R.C.cyan}scg add <pkg>${R.C.reset}            for ${R.C.dim}npm install <pkg> --save${R.C.reset}`);
  console.log(`    ${R.C.cyan}scg ci${R.C.reset}                   for ${R.C.dim}npm ci${R.C.reset} (CI / fresh installs)`);
  console.log(`    ${R.C.cyan}scg update <pkg>${R.C.reset}         for ${R.C.dim}npm update <pkg>${R.C.reset}`);

  console.log(`\n  ${R.C.bold}When a package needs to run a build script:${R.C.reset}`);
  console.log(`    ${R.C.cyan}scg policy approve-build <pkg>@<ver>${R.C.reset}`);
  console.log(`    ${R.C.cyan}scg rebuild-approved${R.C.reset}`);

  console.log(`\n  ${R.C.bold}Commit the policy file so your team and CI share it:${R.C.reset}`);
  console.log(`    ${R.C.dim}git add package.json ${POLICY_FILE}${R.C.reset}`);
  console.log(`    ${R.C.dim}git commit -m "chore: init scg"${R.C.reset}`);

  console.log(`\n  ${R.C.dim}${SCG_LOCK} is regenerated each session and stays out of git.${R.C.reset}`);
  console.log(`  ${R.C.dim}Run ${R.C.reset}${R.C.cyan}scg doctor${R.C.reset}${R.C.dim} anytime to verify the setup is intact.${R.C.reset}`);
  console.log(`  ${R.C.dim}For muscle-memory shim, see ${R.C.reset}${R.C.cyan}recipes/README.md${R.C.reset}${R.C.dim} (optional).${R.C.reset}\n`);
}

function generateGHAWorkflow() {
  return `# supply-chain-guard CI workflow\nname: Supply Chain Guard\non:\n  pull_request:\n    paths: ['package.json', 'package-lock.json']\njobs:\n  scg-check:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4\n      - uses: actions/setup-node@v4\n        with: { node-version: '24', cache: 'npm' }\n      - run: npm install -g supply-chain-guard\n      - run: scg ci\n      - run: scg rebuild-approved\n      - run: scg audit\n`;
}

// ── legacy ────────────────────────────────────────────────────────────────────

async function cmdSnapshot(args) {
  const label = args.flags.pre ? 'pre' : (args.flags.post ? 'post' : 'pre');
  const root  = findProjectRoot();
  const snap  = await takeSnapshot(root, { fetchDates: !!args.flags['fetch-dates'] });
  const file  = snapshotPath(root, label);
  saveSnapshot(snap, file);
  console.log(`  ${R.C.green}Saved ${path.basename(file)} (${Object.keys(snap.packages).length} packages)${R.C.reset}\n`);
}

async function cmdDiff(args) {
  const root     = findProjectRoot();
  const failOn   = failOnFromPolicyOrFlags(root, args.flags);
  const cooldown = cooldownFromPolicyOrFlags(root, args.flags);
  R.header('SCG Diff (legacy)');
  const prePath = snapshotPath(root, 'pre');
  let before    = loadSnapshot(prePath);
  let after;
  if (before && !fs.existsSync(snapshotPath(root, 'post'))) {
    after = await takeSnapshot(root, { fetchDates: !!args.flags['fetch-dates'] });
    saveSnapshot(after, snapshotPath(root, 'post'));
  } else if (before) {
    after = loadSnapshot(snapshotPath(root, 'post'));
  } else {
    console.log(`  ${R.C.yellow}No pre-snapshot${R.C.reset}\n`);
    after  = await takeSnapshot(root, {});
    before = { packages: {} };
  }
  const findings = diffSnapshots(before, after, { cooldownDays: cooldown });
  const risk     = aggregateRisk(findings);
  printFindings(findings);
  const riskOrder  = ['INFO', 'WARN', 'HIGH', 'CRITICAL'];
  const shouldFail = riskOrder.indexOf(risk) >= riskOrder.indexOf(failOn);
  R.printSummary(risk, shouldFail ? 1 : 0);
  if (shouldFail) process.exit(1);
}

async function cmdNpmPassthrough(args) {
  const npmArgs = args.positional;
  console.log(`\n  ${R.C.yellow}SCG ESCAPE HATCH -- raw npm, scripts NOT suppressed${R.C.reset}\n`);
  const result = runRaw(npmArgs, { cwd: findProjectRoot() });
  if (result.status !== 0) process.exit(result.status);
}

// ── scg doctor ───────────────────────────────────────────────────────────────

async function cmdDoctor(args) {
  const root = findProjectRoot();
  R.header('SCG Doctor');
  console.log(`  Project: ${root}\n`);

  const issues  = [];  // blocking
  const warns   = [];  // non-blocking advisory

  // ── 1. Policy file ────────────────────────────────────────────────────────
  const policyPath = path.join(root, '.scg-policy.json');
  if (!fs.existsSync(policyPath)) {
    issues.push('No .scg-policy.json — run: scg init');
  } else {
    console.log(`  ${R.C.green}✓${R.C.reset}  .scg-policy.json present`);
  }

  // ── 2. .scg-lock ──────────────────────────────────────────────────────────
  // .scg-lock is NOT committed to git — it's generated fresh by each scg command.
  // In CI, 'scg ci' generates it. Locally, 'scg install/add' generates it.
  // Missing .scg-lock is normal in a fresh clone; it gets created on first scg run.
  const lockPath = path.join(root, SCG_LOCK);
  if (!fs.existsSync(lockPath)) {
    // Check .gitignore — it should be there
    const giPath2 = path.join(root, '.gitignore');
    const giContent = fs.existsSync(giPath2) ? fs.readFileSync(giPath2, 'utf8') : '';
    if (!giContent.includes(SCG_LOCK)) {
      warns.push(`.scg-lock not in .gitignore — run: scg init to fix`);
    } else {
      console.log(`  ${R.C.green}✓${R.C.reset}  .scg-lock not present (expected — will be auto-generated by scg ci/install)`);
    }
  } else {
    const token = readToken(root);
    if (token) {
      console.log(`  ${R.C.green}✓${R.C.reset}  .scg-lock present with valid session token`);
    } else {
      warns.push('.scg-lock exists but token is invalid — it will be regenerated on next scg run');
    }
  }

  // ── 3. Preinstall guard in package.json ───────────────────────────────────
  let pkgJson = null;
  try { pkgJson = JSON.parse(fs.readFileSync(path.join(root, 'package.json'), 'utf8')); } catch {}
  if (pkgJson) {
    const pre = pkgJson.scripts?.preinstall || '';
    if (pre.includes('.scg-lock')) {
      console.log(`  ${R.C.green}✓${R.C.reset}  preinstall guard present (reads .scg-lock)`);
    } else if (pre.includes('SCG_ACTIVE')) {
      warns.push('preinstall guard uses static SCG_ACTIVE check — run: scg init to upgrade to dynamic token');
    } else {
      issues.push('No SCG preinstall guard in package.json — run: scg init');
    }

    // Check for raw npm install in scripts
    for (const [key, val] of Object.entries(pkgJson.scripts || {})) {
      if (typeof val === 'string' && /\bnpm install\b(?!\s*-g)/.test(val) && !val.includes('scg')) {
        warns.push(`scripts.${key} uses raw 'npm install' — consider replacing with scg install`);
      }
      // Check for raw npx invocations.
      // npx downloads and executes packages directly, bypassing scg entirely.
      // It is a documented social-engineering vector ("just run: npx tool init")
      // that no install-time guard can intercept. We can't fix it for users,
      // but we can flag it when it appears in their own scripts so they know
      // the exposure exists.
      if (typeof val === 'string' && /(^|[\s;&|`])npx\s+/.test(val)) {
        warns.push(
          `scripts.${key} uses 'npx' — npx bypasses scg entirely. ` +
          `Consider installing the tool as a dev dependency and invoking it ` +
          `via package.json scripts (which run with the local node_modules/.bin path) ` +
          `instead of fetching it on-the-fly.`
        );
      }
    }
  }

  // ── 4. .npmrc ─────────────────────────────────────────────────────────────
  const npmrcPath = path.join(root, '.npmrc');
  if (fs.existsSync(npmrcPath)) {
    const npmrc = fs.readFileSync(npmrcPath, 'utf8');
    if (npmrc.includes('ignore-scripts=true')) {
      console.log(`  ${R.C.green}✓${R.C.reset}  .npmrc has ignore-scripts=true`);
    } else {
      warns.push('.npmrc exists but does not set ignore-scripts=true (run: scg init --npmrc)');
    }
  } else {
    warns.push('No .npmrc — consider running: scg init --npmrc to add ignore-scripts=true');
  }

  // ── 5. Packages with scripts not in policy ────────────────────────────────
  const lockfile = readLockfile(root);
  if (lockfile) {
    const { loadPolicy } = require('../src/policy');
    const policy = loadPolicy(root);
    const afterPkgs = extractPackages(lockfile);
    let unapprovedCount = 0;
    for (const [name, entry] of Object.entries(afterPkgs)) {
      if (!entry.hasInstallScript) continue;
      const { isBuildApproved, isBuildDenied } = require('../src/policy');
      if (!isBuildApproved(policy, name, entry.version) && !isBuildDenied(policy, name, entry.version)) {
        unapprovedCount++;
      }
    }
    if (unapprovedCount > 0) {
      warns.push(`${unapprovedCount} installed package(s) with lifecycle scripts not in policy (run: scg audit)`);
    } else if (lockfile) {
      console.log(`  ${R.C.green}✓${R.C.reset}  All install-script packages accounted for in policy`);
    }
  }

  // ── 6. Co-change detection (policy + deps in same git diff) ─────────────
  // Changing .scg-policy.json in the same PR as package.json/package-lock.json
  // is a governance risk: the reviewer must scrutinise both simultaneously.
  //
  // We try `git diff --name-only HEAD` first (clean one-file-per-line output),
  // and fall back to `git status --porcelain` only if that fails. The two
  // formats are NOT the same — porcelain v1 emits "XY<space>path" where XY is
  // a two-character status code — so we parse them separately rather than
  // running the output of one through the other's parser.
  try {
    const { execSync } = require('child_process');
    const gitOpts = { cwd: root, encoding: 'utf8', stdio: ['pipe','pipe','pipe'] };

    let changedFiles = [];
    try {
      const diffOut = execSync('git diff --name-only HEAD', gitOpts).trim();
      changedFiles = diffOut.split('\n').filter(Boolean);
    } catch {
      // Not a git repo, no HEAD yet, or git unavailable — try status as a
      // fallback. porcelain format: "XY path" where XY is exactly two chars
      // followed by a single space. A rename is "R  old -> new"; we want the
      // new path in that case.
      const statusOut = execSync('git status --porcelain', gitOpts).trim();
      changedFiles = statusOut.split('\n')
        .map(line => {
          if (line.length < 4) return null;
          let filePart = line.slice(3);
          const arrow = filePart.indexOf(' -> ');
          if (arrow !== -1) filePart = filePart.slice(arrow + 4);
          // Porcelain quotes paths with unusual characters; strip quotes.
          if (filePart.startsWith('"') && filePart.endsWith('"')) {
            filePart = filePart.slice(1, -1);
          }
          return filePart;
        })
        .filter(Boolean);
    }

    const policyChanged = changedFiles.some(f => f === POLICY_FILE || f.endsWith('/' + POLICY_FILE));
    const depsChanged   = changedFiles.some(f => f === 'package.json' || f === 'package-lock.json');
    if (policyChanged && depsChanged) {
      warns.push(
        `${POLICY_FILE} and package.json/package-lock.json changed together.\n` +
        `  Risk: a dependency bump + policy approval in the same PR can bypass review.\n` +
        `  Recommendation: split into separate PRs (deps first, then policy approval).`
      );
    }
  } catch {
    // git not available or not a git repo — skip silently
  }

  // ── Output ────────────────────────────────────────────────────────────────
  if (warns.length > 0) {
    console.log(`\n  ${R.C.yellow}${R.C.bold}Things to look at (${warns.length}):${R.C.reset}`);
    for (const w of warns) console.log(`    ${R.C.yellow}!${R.C.reset}  ${w}`);
  }

  if (issues.length > 0) {
    console.log(`\n  ${R.C.red}${R.C.bold}Issues that need fixing (${issues.length}):${R.C.reset}`);
    for (const i of issues) console.log(`    ${R.C.red}-${R.C.reset}  ${i}`);
    console.log(`\n  ${R.C.red}${R.C.bold}Project is not fully protected.${R.C.reset}`);
    console.log(`  ${R.C.bold}Fix:${R.C.reset} run ${R.C.cyan}scg init${R.C.reset} to repair the setup.\n`);
    process.exit(1);
  } else if (warns.length > 0) {
    console.log(`\n  ${R.C.yellow}${R.C.bold}Setup is functional but has warnings above.${R.C.reset}\n`);
  } else {
    console.log(`\n  ${R.C.green}${R.C.bold}Everything looks good.${R.C.reset} Your project is properly protected.`);
    console.log(`\n  ${R.C.bold}Reminder:${R.C.reset} use ${R.C.cyan}scg install${R.C.reset} / ${R.C.cyan}scg add${R.C.reset} / ${R.C.cyan}scg ci${R.C.reset} instead of raw npm.`);
    console.log(`  ${R.C.dim}Tip: add ${R.C.reset}${R.C.cyan}scg doctor${R.C.reset}${R.C.dim} to your CI pipeline to catch drift early.${R.C.reset}\n`);
  }
}

// ── help ──────────────────────────────────────────────────────────────────────

function cmdHelp() {
  console.log(`
${R.C.bold}supply-chain-guard (scg) v0.8.0${R.C.reset}  ${R.C.dim}— protect your npm dependencies${R.C.reset}

${R.C.bold}EVERYDAY USE${R.C.reset}  ${R.C.dim}use these instead of raw npm${R.C.reset}
  ${R.C.cyan}scg install${R.C.reset}                      install everything from package.json
  ${R.C.cyan}scg add <pkg>[@ver]${R.C.reset}              add a new dependency (with preflight check)
  ${R.C.cyan}scg ci${R.C.reset}                           clean install for CI / fresh checkouts
  ${R.C.cyan}scg update <pkg> [<pkg2>...]${R.C.reset}     update specific packages (with preflight)
  ${R.C.cyan}scg update <pkg> --all${R.C.reset}           update everything ${R.C.dim}(no per-package preflight)${R.C.reset}
  ${R.C.cyan}scg remove <pkg>${R.C.reset}                 uninstall a package

${R.C.bold}NATIVE BUILDS${R.C.reset}  ${R.C.dim}for packages that need to compile (esbuild, sharp, ...)${R.C.reset}
  ${R.C.cyan}scg policy approve-build <pkg>@<ver>${R.C.reset}  approve a package's build script
  ${R.C.cyan}scg policy deny-build <pkg>${R.C.reset}           explicitly block a package
  ${R.C.cyan}scg policy list${R.C.reset}                       show what's currently approved
  ${R.C.cyan}scg rebuild-approved [pkg...]${R.C.reset}         run npm rebuild for approved packages

${R.C.bold}HEALTH AND ANALYSIS${R.C.reset}
  ${R.C.cyan}scg doctor${R.C.reset}                       verify the project setup is intact
  ${R.C.cyan}scg check <pkg>[@ver]${R.C.reset}            inspect a package before installing it
  ${R.C.cyan}scg audit${R.C.reset}                        full project audit (policy + phantoms + drift)
  ${R.C.cyan}scg phantom [--src <dir>]${R.C.reset}        find dependencies declared but never imported
  ${R.C.cyan}scg scripts${R.C.reset}                      list lifecycle scripts not yet in policy

${R.C.bold}SETUP${R.C.reset}
  ${R.C.cyan}scg init [--npmrc] [--gha] [--dry-run]${R.C.reset}    one-time project initialization

${R.C.bold}ESCAPE HATCH${R.C.reset}  ${R.C.dim}use only when you really need raw npm${R.C.reset}
  ${R.C.cyan}scg npm -- <raw npm args>${R.C.reset}        bypass scg, run npm directly (prints warning)

${R.C.bold}OPTIONS${R.C.reset}
  --dry-run        print what would happen without executing
  --deep           run tarball-based phantom scan (slower, higher confidence)
  --all            for scg update: update everything without per-package preflight
  --force          skip preflight block (scg add)
  --cooldown <n>   minimum days since publish before a version is "trusted" (default: 3)
  --json           machine-readable output (scg check)

${R.C.dim}Full docs: https://github.com/.../supply-chain-guard${R.C.reset}
`);
}

// ── main ──────────────────────────────────────────────────────────────────────

async function main() {
  const argv = process.argv.slice(2);
  const cmd  = argv[0];
  const args = parseArgs(argv.slice(1));
  try {
    switch (cmd) {
      case 'add':              await cmdAdd(args);             break;
      case 'install':          await cmdInstall(args);         break;
      case 'ci':               await cmdCI(args);              break;
      case 'update':           await cmdUpdate(args);          break;
      case 'remove':
      case 'rm':
      case 'uninstall':        await cmdRemove(args);          break;
      case 'rebuild-approved': await cmdRebuildApproved(args); break;
      case 'policy':           await cmdPolicy(args);          break;
      case 'check':            await cmdCheck(args);           break;
      case 'audit':            await cmdAudit(args);           break;
      case 'phantom':          await cmdPhantom(args);         break;
      case 'scripts':          await cmdScripts(args);         break;
      case 'init':             await cmdInit(args);            break;
      case 'doctor':           await cmdDoctor(args);          break;
      case 'npm':              await cmdNpmPassthrough(args);  break;
      case 'snapshot':         await cmdSnapshot(args);        break;
      case 'diff':             await cmdDiff(args);            break;
      case 'help': case '--help': case '-h': case undefined: cmdHelp(); break;
      default:
        console.error(`Unknown command: ${cmd}. Run "scg help".`);
        process.exit(1);
    }
  } catch (err) {
    console.error(`\n${R.C.red}Error: ${err.message}${R.C.reset}`);
    if (process.env.DEBUG) console.error(err.stack);
    process.exit(2);
  }
}

main();
