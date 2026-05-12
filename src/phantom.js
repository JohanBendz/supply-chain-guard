'use strict';
/**
 * phantom.js
 * 
 * Detects "phantom dependencies" — packages listed in package.json (or
 * installed transitively via a direct dep) that are NEVER actually
 * import()'d or require()'d anywhere in the project source.
 *
 * This is the exact signature of the axios attack:
 *   mock-unapproved-dep was in axios's package.json but zero grep hits in source.
 *
 * Works for the PACKAGE MAINTAINER perspective (you own the code being audited).
 * Run: scg phantom [--src ./src] [--pkg ./package.json]
 */

const fs   = require('fs');
const path = require('path');
const { extractCode } = require('./js-lexer');

// ─── source scanner ──────────────────────────────────────────────────────────

const SOURCE_EXTENSIONS = new Set(['.js', '.mjs', '.cjs', '.ts', '.tsx', '.jsx', '.vue', '.svelte']);
const IGNORE_DIRS       = new Set(['node_modules', '.git', 'dist', 'build', 'coverage', '.next', '.nuxt', 'out']);

/** Walk source tree and collect all JS/TS files */
function collectSourceFiles(dir, files = []) {
  let entries;
  try { entries = fs.readdirSync(dir, { withFileTypes: true }); }
  catch { return files; }

  for (const entry of entries) {
    if (IGNORE_DIRS.has(entry.name)) continue;
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      collectSourceFiles(full, files);
    } else if (entry.isFile() && SOURCE_EXTENSIONS.has(path.extname(entry.name))) {
      files.push(full);
    }
  }
  return files;
}

/**
 * Extract all imported/required module names from a file.
 * Handles:
 *   require('name')
 *   require("name/subpath")  → extracts 'name'
 *   import ... from 'name'
 *   import('name')
 *   export ... from 'name'
 */
function extractImports(filePath) {
  let src;
  try { src = fs.readFileSync(filePath, 'utf8'); }
  catch { return new Set(); }

  const found = new Set();

  // Use the lexer to produce a code-only view. This replaces the previous
  // regex-based comment-strip pass which could be defeated by:
  //   - block-comment syntax inside template literals
  //   - line-comment syntax inside string literals
  //   - regex literals containing comment-like patterns
  //   - paired string literals bracketing fake markers
  // The lexer is a state machine that knows the lexical context at every
  // position, so all four evasion classes are handled deterministically.
  // String literals stay in the output (so `require('pkg')` arguments
  // remain matchable); only comments, regex literals, and template literal
  // text are stripped.
  const stripped = extractCode(src);

  // require('x') / require("x")
  const requireRe = /require\s*\(\s*['"`]([^'"`\s]+)['"`]/g;
  let m;
  while ((m = requireRe.exec(stripped)) !== null) {
    const spec = normaliseSpecifier(m[1]);
    if (spec) found.add(spec);
  }

  // import / export ... from 'x' — loose form that handles `import type`,
  // inline `{ type Foo }`, namespace imports, and re-exports.
  const fromRe = /(?:^|[\s;])(?:import|export)\b[^'"`\n]*?\bfrom\s+['"`]([^'"`\s]+)['"`]/g;
  while ((m = fromRe.exec(stripped)) !== null) {
    const spec = normaliseSpecifier(m[1]);
    if (spec) found.add(spec);
  }

  // Dynamic import('x')
  const dynRe = /\bimport\s*\(\s*['"`]([^'"`\s]+)['"`]/g;
  while ((m = dynRe.exec(stripped)) !== null) {
    const spec = normaliseSpecifier(m[1]);
    if (spec) found.add(spec);
  }

  return found;
}

/** 'lodash/get' → 'lodash', '@scope/pkg/deep' → '@scope/pkg' */
function normaliseSpecifier(spec) {
  if (spec.startsWith('.') || spec.startsWith('/')) return null; // relative/absolute
  if (spec.startsWith('@')) {
    const parts = spec.split('/');
    return parts.length >= 2 ? `${parts[0]}/${parts[1]}` : spec;
  }
  return spec.split('/')[0];
}

// ─── dependency reader ───────────────────────────────────────────────────────

function readDirectDeps(pkgJsonPath) {
  let pkg;
  try { pkg = JSON.parse(fs.readFileSync(pkgJsonPath, 'utf8')); }
  catch { return new Set(); }

  return new Set([
    ...Object.keys(pkg.dependencies    || {}),
    // intentionally exclude devDependencies from phantom check — they don't ship
  ]);
}

// ─── public API ──────────────────────────────────────────────────────────────

/**
 * Scan a project for phantom dependencies.
 *
 * @param {string} projectRoot
 * @param {object} opts
 * @param {string[]} opts.srcDirs  - subdirs to scan (default: whole root minus ignored)
 * @returns {{ phantoms: string[], used: string[], declared: string[] }}
 */
function detectPhantoms(projectRoot, opts = {}) {
  const pkgJsonPath = path.join(projectRoot, 'package.json');
  const declared = readDirectDeps(pkgJsonPath);

  const srcDirs = (opts.srcDirs || [projectRoot]).map(d =>
    path.isAbsolute(d) ? d : path.join(projectRoot, d)
  );

  // Collect all imports across all source files
  const allImports = new Set();
  for (const dir of srcDirs) {
    const files = collectSourceFiles(dir);
    for (const file of files) {
      for (const spec of extractImports(file)) {
        if (spec) allImports.add(spec);
      }
    }
  }

  // Phantoms = declared in package.json but never imported in source
  const phantoms = [...declared].filter(dep => !allImports.has(dep));
  const used     = [...declared].filter(dep =>  allImports.has(dep));

  return {
    phantoms,
    used,
    declared: [...declared],
    totalSourceFiles: srcDirs.reduce((n, d) => n + collectSourceFiles(d).length, 0),
  };
}

module.exports = { detectPhantoms };
