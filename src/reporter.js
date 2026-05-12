'use strict';
/**
 * reporter.js
 * Terminal output with ANSI colors. Degrades gracefully when NO_COLOR is set.
 */

const USE_COLOR = !process.env.NO_COLOR && process.stdout.isTTY;

const C = {
  reset:   USE_COLOR ? '\x1b[0m'  : '',
  bold:    USE_COLOR ? '\x1b[1m'  : '',
  dim:     USE_COLOR ? '\x1b[2m'  : '',
  red:     USE_COLOR ? '\x1b[31m' : '',
  yellow:  USE_COLOR ? '\x1b[33m' : '',
  green:   USE_COLOR ? '\x1b[32m' : '',
  cyan:    USE_COLOR ? '\x1b[36m' : '',
  magenta: USE_COLOR ? '\x1b[35m' : '',
  white:   USE_COLOR ? '\x1b[37m' : '',
  bgRed:   USE_COLOR ? '\x1b[41m' : '',
};

const SEV_STYLE = {
  CRITICAL: { color: C.red,     icon: '✖ CRITICAL', badge: `${C.bgRed}${C.white}` },
  HIGH:     { color: C.red,     icon: '⚠ HIGH',     badge: C.red },
  WARN:     { color: C.yellow,  icon: '! WARN',      badge: C.yellow },
  INFO:     { color: C.cyan,    icon: '· INFO',      badge: C.cyan },
};

function sevLine(severity) {
  const s = SEV_STYLE[severity] || SEV_STYLE.INFO;
  return `${s.color}${C.bold}${s.icon}${C.reset}`;
}

function header(text) {
  const line = '─'.repeat(Math.min(text.length + 4, 72));
  console.log(`\n${C.bold}${C.cyan}${line}${C.reset}`);
  console.log(`${C.bold}${C.cyan}  ${text}${C.reset}`);
  console.log(`${C.bold}${C.cyan}${line}${C.reset}`);
}

function subHeader(text) {
  console.log(`\n${C.bold}${text}${C.reset}`);
}

// ─── finding display ──────────────────────────────────────────────────────────

function printFindings(findings) {
  if (findings.length === 0) {
    console.log(`  ${C.green}✓ No findings${C.reset}`);
    return;
  }

  const bySev = { CRITICAL: [], HIGH: [], WARN: [], INFO: [] };
  for (const f of findings) {
    (bySev[f.severity] || bySev.INFO).push(f);
  }

  for (const sev of ['CRITICAL', 'HIGH', 'WARN', 'INFO']) {
    if (bySev[sev].length === 0) continue;
    for (const f of bySev[sev]) {
      console.log(`\n  ${sevLine(sev)}  ${C.bold}${f.package}${C.reset}  ${C.dim}${f.version}${C.reset}`);
      console.log(`     ${f.message}`);
      if (f.detail) {
        console.log(`     ${C.dim}${f.detail}${C.reset}`);
      }
    }
  }
}

// ─── phantom display ─────────────────────────────────────────────────────────

function printPhantomReport(result) {
  if (result.phantoms.length === 0) {
    console.log(`  ${C.green}✓ All declared dependencies are imported in source${C.reset}`);
    console.log(`  ${C.dim}Checked ${result.totalSourceFiles} source files, ${result.declared.length} declared deps${C.reset}`);
    return;
  }

  console.log(`  ${C.dim}Checked ${result.totalSourceFiles} source files, ${result.declared.length} declared deps${C.reset}\n`);

  console.log(`  ${C.red}${C.bold}⚠ PHANTOM DEPENDENCIES DETECTED${C.reset}`);
  console.log(`  ${C.dim}These packages are in package.json but never imported/required in source.${C.reset}`);
  console.log(`  ${C.dim}This is the exact signature of the axios/mock-unapproved-dep attack.${C.reset}\n`);

  for (const p of result.phantoms) {
    console.log(`  ${C.red}✖${C.reset}  ${C.bold}${p}${C.reset}`);
  }

  console.log(`\n  ${C.dim}Used deps (${result.used.length}): ${result.used.join(', ')}${C.reset}`);
}

// ─── postinstall display ──────────────────────────────────────────────────────

function printScriptAudit({ approved, pending, source }) {
  console.log(`  ${C.dim}Reading from: ${source}${C.reset}\n`);

  if (pending.length === 0) {
    console.log(`  ${C.green}✓ All lifecycle scripts previously approved (${approved.length} total)${C.reset}`);
    return;
  }

  console.log(`  ${C.yellow}${C.bold}⚠ ${pending.length} UNAPPROVED LIFECYCLE SCRIPT(S)${C.reset}`);
  console.log(`  ${C.dim}These scripts will run automatically during npm install.${C.reset}`);
  console.log(`  ${C.dim}Review each one before approving with: scg approve <package>${C.reset}\n`);

  for (const e of pending) {
    console.log(`  ${C.yellow}!${C.reset}  ${C.bold}${e.package}@${e.version}${C.reset}  ${C.dim}[${e.scriptKey}]${C.reset}`);
    console.log(`       ${C.dim}${e.scriptValue.slice(0, 120)}${e.scriptValue.length > 120 ? '…' : ''}${C.reset}`);
  }

  if (approved.length > 0) {
    console.log(`\n  ${C.dim}Previously approved: ${approved.map(e => `${e.package}@${e.version}`).join(', ')}${C.reset}`);
  }
}

// ─── summary banner ───────────────────────────────────────────────────────────

function printSummary(riskLevel, exitCode) {
  const isClean = exitCode === 0;
  if (isClean) {
    console.log(`\n${C.green}${C.bold}  No major risks found.${C.reset} ${C.dim}Safe to install if you trust the source.${C.reset}\n`);
  } else {
    const style = SEV_STYLE[riskLevel] || SEV_STYLE.WARN;
    console.log(`\n${style.color}${C.bold}  Risk level: ${riskLevel}.${C.reset} ${C.bold}Review the findings above before proceeding.${C.reset}\n`);
  }
}

module.exports = {
  header,
  subHeader,
  printFindings,
  printPhantomReport,
  printScriptAudit,
  printSummary,
  C,
};
