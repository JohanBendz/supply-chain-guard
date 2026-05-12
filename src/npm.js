'use strict';
/**
 * npm.js
 *
 * Safe subprocess wrapper for npm.
 * All dependency-changing operations run with --ignore-scripts forced on.
 * Raw passthrough available via runRaw() for the escape-hatch command.
 */

const { spawnSync } = require('child_process');
const { generateSessionToken } = require('./lock-token');

// npm binary name: 'npm.cmd' on Windows, 'npm' elsewhere
const NPM_BIN = process.platform === 'win32' ? 'npm' : 'npm';

// Environment variables that an attacker-controlled package, having run as
// part of normal application code BEFORE scg rebuild-approved kicks off,
// could use to inject code into the next subprocess Node spawns.
//
// The "confused deputy" pattern: a malicious package's functional code (no
// install scripts at all, so it passes scg) sets process.env.NODE_OPTIONS
// to include "--require ./payload.js". Later, when scg rebuild-approved
// runs an APPROVED package's build script (esbuild, sharp), Node honours
// NODE_OPTIONS and loads the payload with full file-system access — even
// though the build script itself was scg-approved.
//
// Defense: when running approved-build subprocesses, strip these variables
// from the inherited environment. The build script gets a known-clean env.
// Legitimate uses of NODE_OPTIONS (heap size, deprecation flags) are
// sacrificed for build scripts specifically; the user can pass them via
// the package.json build script itself if needed.
const SANITIZED_ENV_VARS = [
  'NODE_OPTIONS',           // --require, --import, --inspect, etc.
  'NODE_PATH',              // adds paths to module resolution
  'NODE_PRESERVE_SYMLINKS',
  'NODE_PRESERVE_SYMLINKS_MAIN',
  'NODE_REPL_HISTORY',
  'NODE_EXTRA_CA_CERTS',    // could MITM HTTPS in spawned process
  'NODE_TLS_REJECT_UNAUTHORIZED', // could disable cert validation
  'NODE_NO_WARNINGS',
  'NODE_PENDING_DEPRECATION',
];

/**
 * Build a sanitized environment object for spawning approved build scripts.
 * Removes NODE_* injection vectors and the npm_config_node_options shim
 * (which npm propagates as NODE_OPTIONS to child processes).
 *
 * Returns a NEW object — never mutates process.env.
 */
function sanitizeEnv(baseEnv) {
  const out = Object.assign({}, baseEnv);
  for (const key of SANITIZED_ENV_VARS) {
    delete out[key];
  }
  // npm-prefixed config shims that map to Node flags. npm sets these from
  // .npmrc and CLI flags; an attacker who can write .npmrc can inject via
  // them just like via NODE_OPTIONS.
  for (const k of Object.keys(out)) {
    if (k.startsWith('npm_config_node_options') ||
        k === 'npm_config_node_options' ||
        k === 'npm_config_user_agent_node_options') {
      delete out[k];
    }
  }
  return out;
}

// Dependency-changing npm commands that must always run with --ignore-scripts.
// 'i' is the short form of 'install'. We deliberately do NOT include 'add'
// (that is yarn's command, not npm's) — keeping it would be misleading.
const SAFE_COMMANDS = new Set(['install', 'i', 'ci', 'update', 'uninstall', 'remove', 'rm']);

/**
 * Run npm with --ignore-scripts injected for dependency-changing commands.
 *
 * @param {string[]} args    - npm subcommand + flags, e.g. ['install', 'axios']
 * @param {object}   opts
 * @param {string}   opts.cwd        - working directory (default: process.cwd())
 * @param {boolean}  opts.dryRun     - print the command but don't execute
 * @param {object}   opts.env        - extra env vars to merge
 * @param {boolean}  opts.inheritIO  - pipe stdio to terminal (default true)
 * @returns {{ status: number, stdout?: string, stderr?: string }}
 */
function runSafe(args, opts = {}) {
  const { cwd = process.cwd(), dryRun = false, env, inheritIO = true } = opts;

  const subcommand = args[0];
  const isSafeCmd  = subcommand && SAFE_COMMANDS.has(subcommand);

  // Build final arg list, injecting --ignore-scripts if not already present
  let finalArgs = [...args];
  if (isSafeCmd && !finalArgs.includes('--ignore-scripts')) {
    finalArgs.push('--ignore-scripts');
  }

  if (dryRun) {
    return { status: 0, dryRun: true, command: `${NPM_BIN} ${finalArgs.join(' ')}` };
  }

  // Generate a fresh session token. .scg-lock is NOT committed — SCG writes
  // it fresh at the start of every install. The preinstall guard reads the
  // file and validates SCG_ACTIVE matches. Since the token changes every run,
  // hardcoding SCG_ACTIVE=<anything> in ~/.zshrc is always stale → blocked.
  const _sessionToken = isSafeCmd ? generateSessionToken(cwd) : null;

  const spawnOpts = {
    cwd,
    env: Object.assign({}, process.env, env,
      _sessionToken ? { SCG_ACTIVE: _sessionToken } : {}),
    stdio: inheritIO ? 'inherit' : 'pipe',
    shell: process.platform === 'win32',
  };

  const result = spawnSync(NPM_BIN, finalArgs, spawnOpts);

  if (result.error) {
    throw new Error(`npm spawn error: ${result.error.message}`);
  }

  return {
    status:  result.status ?? 1,
    stdout:  result.stdout ? result.stdout.toString() : undefined,
    stderr:  result.stderr ? result.stderr.toString() : undefined,
    command: `${NPM_BIN} ${finalArgs.join(' ')}`,
  };
}

/**
 * Raw npm passthrough — no --ignore-scripts injection.
 * Used for the `scg npm -- <args>` escape hatch and for `scg rebuild-approved`.
 *
 * @param {string[]} args
 * @param {object}   opts
 * @param {string}   opts.cwd
 * @param {boolean}  opts.dryRun
 * @param {object}   opts.env       - extra env vars to merge
 * @param {boolean}  opts.sanitizeEnv  - if true, strip NODE_OPTIONS and friends.
 *                                       Use for `scg rebuild-approved` to prevent
 *                                       confused-deputy attacks via env injection.
 */
function runRaw(args, opts = {}) {
  const { cwd = process.cwd(), dryRun = false, env, sanitizeEnv: doSanitize = false } = opts;

  if (dryRun) {
    return { status: 0, dryRun: true, command: `${NPM_BIN} ${args.join(' ')}` };
  }

  // For rebuild-approved we sanitize the inherited env to defeat the
  // confused-deputy pattern where a non-script package mutates NODE_OPTIONS
  // before scg rebuild runs an approved package's build script.
  const baseEnv = doSanitize ? sanitizeEnv(process.env) : process.env;

  const result = spawnSync(NPM_BIN, args, {
    cwd,
    env: Object.assign({}, baseEnv, env),
    stdio: 'inherit',
    shell: process.platform === 'win32',
  });

  if (result.error) throw new Error(`npm spawn error: ${result.error.message}`);

  return {
    status:  result.status ?? 1,
    command: `${NPM_BIN} ${args.join(' ')}`,
  };
}

/**
 * Returns the npm --ignore-scripts flag string (useful for logging).
 */
function ignoreFlagNotice() {
  return '--ignore-scripts (forced by SCG)';
}

module.exports = { runSafe, runRaw, NPM_BIN, SAFE_COMMANDS, ignoreFlagNotice, sanitizeEnv };
