'use strict';
/**
 * lock-token.js
 *
 * Manages the dynamic SCG_ACTIVE session token.
 *
 * DESIGN DECISION: .scg-lock is NOT committed to git.
 *
 * Rationale:
 *   If committed, a developer can read the token and hardcode it in ~/.zshrc
 *   to bypass the guard. Instead, .scg-lock is generated fresh each session:
 *
 *   Local dev:  `scg install` / `scg add` generates the token on-the-fly,
 *               writes .scg-lock, then passes SCG_ACTIVE=<token> to npm.
 *               The preinstall guard reads .scg-lock and validates the match.
 *               Token is different every session — cannot be pre-set globally.
 *
 *   CI:         `scg ci` generates the token, runs npm ci --ignore-scripts.
 *               CI never calls raw `npm ci` — only `scg ci`.
 *               If raw `npm ci` is called before `scg ci`, .scg-lock won't exist
 *               and the guard will block (initialized repo) or warn (not initialized).
 *
 * .gitignore:   scg init adds .scg-lock to .gitignore automatically.
 *
 * Anti-bypass:  Even if a developer sees a previous token value, the next scg run
 *               generates a new token. ~/.zshrc hardcoding is always stale.
 */

const fs     = require('fs');
const path   = require('path');
const crypto = require('crypto');

const LOCK_FILE   = '.scg-lock';
const TOKEN_CHARS = 32; // 128 bits entropy

function lockFilePath(projectRoot) {
  return path.join(projectRoot, LOCK_FILE);
}

/** Generate a cryptographically random session token. */
function generateToken() {
  return crypto.randomBytes(TOKEN_CHARS / 2).toString('hex');
}

/** Read token from .scg-lock. Returns null if missing or malformed. */
function readToken(projectRoot) {
  const file = lockFilePath(projectRoot);
  if (!fs.existsSync(file)) return null;
  try {
    const raw = JSON.parse(fs.readFileSync(file, 'utf8'));
    return (typeof raw.token === 'string' && /^[0-9a-f]{32}$/.test(raw.token))
      ? raw.token : null;
  } catch { return null; }
}

/** Write a new token to .scg-lock. Always generates a fresh token. */
function writeToken(projectRoot, token) {
  fs.writeFileSync(
    lockFilePath(projectRoot),
    JSON.stringify({ token, createdAt: new Date().toISOString() }, null, 2) + '\n',
  );
}

/**
 * Generate a fresh session token and write it to .scg-lock.
 * Called at the start of every SCG wrapper command (install, add, ci, update).
 * Returns the new token.
 */
function generateSessionToken(projectRoot) {
  const token = generateToken();
  writeToken(projectRoot, token);
  return token;
}

/**
 * @deprecated Use generateSessionToken() directly. Kept as a thin alias for
 * tests and for downstream callers in src/index.js that still import the
 * legacy name. The only behavioural difference from generateSessionToken is
 * the return shape: { token, created: true } instead of the bare token
 * string, retained so the existing test assertions continue to pass.
 */
function ensureToken(projectRoot) {
  return { token: generateSessionToken(projectRoot), created: true };
}

/** Explicit rotation (for scg init --rotate-token). Same as generateSessionToken. */
function rotateToken(projectRoot) {
  return generateSessionToken(projectRoot);
}

/**
 * Build the preinstall guard script for package.json.
 *
 * Guard behavior:
 *   .scg-lock present, token matches SCG_ACTIVE  → pass  (SCG is wrapping npm)
 *   .scg-lock present, token mismatch            → block (wrong session / stale)
 *   .scg-lock missing, .scg-policy.json exists   → block (initialized repo, use scg ci)
 *   .scg-lock missing, no policy                 → warn + pass (not yet initialized)
 *
 * In CI: `scg ci` generates .scg-lock before npm runs, so the guard always sees
 * a fresh token. Raw `npm ci` will block because .scg-lock won't exist.
 */
function buildGuardScript() {
  // The guard runs as `node -e "<inner>"` from npm's preinstall lifecycle.
  // npm sets cwd to the project root for every lifecycle script (including
  // when invoked via `npm install --prefix ./other`), and inside `node -e`
  // both `__dirname` and `process.cwd()` evaluate to that directory. We use
  // cwd explicitly because it's the documented contract — `__dirname` inside
  // `-e` happens to coincide but isn't a guarantee long-term.
  const inner = [
    "var d=process.cwd();",
    "var lf=require('path').join(d,'.scg-lock');",
    "var pf=require('path').join(d,'.scg-policy.json');",
    "var fs=require('fs');",
    "var t;",
    "if(fs.existsSync(lf)){",
    "  try{t=JSON.parse(fs.readFileSync(lf,'utf8')).token;}catch(e){t=null;}",
    "}else{",
    "  var init=fs.existsSync(pf);",
    "  if(init){",
    "    var r='\\x1b[0m',b='\\x1b[31m\\x1b[1m',c='\\x1b[36m',d2='\\x1b[2m';",
    "    console.error('');",
    "    console.error(b+'Raw npm install was blocked by Supply Chain Guard.'+r);",
    "    console.error('');",
    "    console.error('  This project is protected against malicious install scripts.');",
    "    console.error('  Use the safe wrapper instead:');",
    "    console.error('');",
    "    console.error('      '+c+'scg install'+r+'        for npm install');",
    "    console.error('      '+c+'scg add <pkg>'+r+'      for npm install <pkg>');",
    "    console.error('      '+c+'scg ci'+r+'             for npm ci');",
    "    console.error('');",
    "    console.error('  '+d2+'Why: scg forces --ignore-scripts and runs preflight checks'+r);",
    "    console.error('  '+d2+'against the npm registry before any code is downloaded.'+r);",
    "    console.error('');",
    "    process.exit(1);",
    "  }",
    // Not initialized: warn only (graceful onboarding for new contributors)
    "  console.warn('\\x1b[33mSupply Chain Guard is not initialized in this project. Run: scg init\\x1b[0m');",
    "  process.exit(0);",
    "}",
    "if(process.env.SCG_ACTIVE!==t){",
    "var r='\\x1b[0m',b='\\x1b[31m\\x1b[1m',c='\\x1b[36m',d2='\\x1b[2m';",
    "console.error('');",
    "console.error(b+'Raw npm install was blocked by Supply Chain Guard.'+r);",
    "console.error('');",
    "console.error('  Use the safe wrapper instead:');",
    "console.error('');",
    "console.error('      '+c+'scg install'+r+'        for npm install');",
    "console.error('      '+c+'scg add <pkg>'+r+'      for npm install <pkg>');",
    "console.error('      '+c+'scg ci'+r+'             for npm ci');",
    "console.error('');",
    "console.error('  '+d2+'Why: scg forces --ignore-scripts and runs preflight checks'+r);",
    "console.error('  '+d2+'against the npm registry before any code is downloaded.'+r);",
    "console.error('');",
    "process.exit(1);}",
  ].join('');
  return `node -e "${inner}"`;
}

module.exports = {
  LOCK_FILE,
  lockFilePath,
  generateToken,
  generateSessionToken,
  readToken,
  writeToken,
  ensureToken,
  rotateToken,
  buildGuardScript,
};
