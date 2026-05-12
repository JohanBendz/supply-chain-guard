'use strict';
/**
 * delta-phantom.js
 *
 * "Delta phantom" analysis: when package A changes from version X to Y,
 * and Y introduces a new transitive dependency B, determine whether B
 * is genuinely referenced by A's source, or is a phantom injected purely
 * for its postinstall side-effects (the axios attack pattern).
 *
 * Two detection layers:
 *
 *   Layer 1 — Manifest heuristic (offline, fast, LOW confidence)
 *     Checks whether the dep name appears in the parent's published manifest
 *     fields: main, exports, files, scripts, readme.
 *     Cheap but misses dynamic requires and produces LOW confidence.
 *
 *   Layer 2 — Tarball source scan (network, thorough, HIGH confidence)
 *     Downloads the parent package tarball, extracts JS/TS files, runs
 *     require/import extraction from phantom.js, and checks for real usage.
 *     This is what would have given HIGH confidence on the axios attack.
 */

const fs     = require('fs');
const path   = require('path');
const os     = require('os');
const https  = require('https');
const zlib   = require('zlib');
const { extractCode } = require('./js-lexer');

// ─── types ────────────────────────────────────────────────────────────────────
// DeltaPhantomResult:
// {
//   dep:           string,
//   parent:        string,
//   parentVersion: string,
//   verdict:       'LIKELY_PHANTOM' | 'LIKELY_USED' | 'UNKNOWN',
//   confidence:    'HIGH' | 'LOW',
//   reason:        string,
//   signals:       string[],
//   layer:         'manifest' | 'tarball',
// }

// ─── Layer 1: manifest heuristic (offline) ───────────────────────────────────

/**
 * Check whether a dep name appears in a parent package manifest's
 * fields that reference actual source files or entry points.
 */
function checkManifestReferences(parentMeta, depName) {
  if (!parentMeta) return { referenced: false, fields: [] };

  const signals = [];
  const searchIn = [
    ['main',    parentMeta.main],
    ['module',  parentMeta.module],
    ['browser', typeof parentMeta.browser === 'string' ? parentMeta.browser : null],
    ['exports', JSON.stringify(parentMeta.exports || {})],
    ['files',   (parentMeta.files || []).join(',')],
    ['scripts', JSON.stringify(parentMeta.scripts || {})],
    ['readme',  parentMeta.readme || ''],
  ];

  for (const [field, value] of searchIn) {
    if (value && value.includes(depName)) signals.push(field);
  }

  return { referenced: signals.length > 0, fields: signals };
}

/**
 * Layer 1 analysis using manifest fields only.
 * Returns LOW confidence result.
 */
function analyseManifestPhantom(parentVersionMeta, depName) {
  if (!parentVersionMeta) {
    return _result(depName, 'unknown', 'unknown', 'UNKNOWN', 'LOW', 'manifest',
      'Parent manifest unavailable', []);
  }

  const parentName    = parentVersionMeta.name    || 'unknown';
  const parentVersion = parentVersionMeta.version || 'unknown';
  const isDeclaredDep = !!(parentVersionMeta.dependencies || {})[depName];

  if (!isDeclaredDep) {
    return _result(depName, parentName, parentVersion, 'UNKNOWN', 'LOW', 'manifest',
      `${depName} not found in ${parentName}@${parentVersion} dependencies`, []);
  }

  const { referenced, fields } = checkManifestReferences(parentVersionMeta, depName);

  if (!referenced) {
    return _result(depName, parentName, parentVersion, 'LIKELY_PHANTOM', 'LOW', 'manifest',
      `${depName} declared in dependencies but not referenced in manifest fields (main, exports, files, scripts, readme)`,
      []);
  }

  return _result(depName, parentName, parentVersion, 'LIKELY_USED', 'LOW', 'manifest',
    `${depName} referenced in manifest fields: ${fields.join(', ')}`, fields);
}

// ─── Layer 2: tarball source scan (network) ──────────────────────────────────

const SOURCE_EXTENSIONS = new Set(['.js', '.mjs', '.cjs', '.ts', '.tsx', '.jsx']);

// Safety limits for tarball scanning.
// A legitimate npm package tarball is almost always < 50 MB compressed.
// Values beyond these thresholds indicate a tar-bomb or malformed archive.
const MAX_COMPRESSED_BYTES   = 50  * 1024 * 1024; // 50 MB compressed
const MAX_UNCOMPRESSED_BYTES = 200 * 1024 * 1024; // 200 MB uncompressed
const MAX_FILE_COUNT         = 5_000;              // max entries in archive

/**
 * Download a tarball from the given URL into a temp file.
 * Enforces MAX_COMPRESSED_BYTES during streaming — aborts and rejects
 * if the response body exceeds the limit before the download completes.
 * Returns the temp file path.
 */
function downloadTarball(url) {
  return new Promise((resolve, reject) => {
    const tmpFile = path.join(
      os.tmpdir(),
      `scg-tarball-${Date.now()}-${Math.random().toString(36).slice(2)}.tgz`,
    );
    const dest = fs.createWriteStream(tmpFile);

    function doGet(targetUrl, redirects = 0) {
      if (redirects > 5) { reject(new Error('Too many redirects')); return; }

      const req = https.get(targetUrl, { timeout: 20000 }, (res) => {
        if (res.statusCode === 302 || res.statusCode === 301) {
          res.resume(); // drain redirected body
          doGet(res.headers.location, redirects + 1);
          return;
        }
        if (res.statusCode !== 200) {
          reject(new Error(`HTTP ${res.statusCode} downloading tarball`));
          return;
        }

        // Reject immediately if Content-Length already exceeds limit
        const declaredSize = parseInt(res.headers['content-length'] || '0', 10);
        if (declaredSize > MAX_COMPRESSED_BYTES) {
          req.destroy();
          reject(new Error(
            `Tarball too large: ${declaredSize} bytes exceeds ${MAX_COMPRESSED_BYTES} byte limit (possible tar bomb)`,
          ));
          return;
        }

        // Count bytes as they stream in — abort if limit hit mid-download
        let received = 0;
        res.on('data', (chunk) => {
          received += chunk.length;
          if (received > MAX_COMPRESSED_BYTES) {
            req.destroy();
            dest.destroy();
            try { fs.unlinkSync(tmpFile); } catch {}
            reject(new Error(
              `Tarball download aborted: exceeded ${MAX_COMPRESSED_BYTES} byte limit mid-stream (possible tar bomb)`,
            ));
          }
        });

        res.pipe(dest);
        dest.on('finish', () => resolve(tmpFile));
        dest.on('error', reject);
      });

      req.on('error', reject);
      req.on('timeout', () => { req.destroy(); reject(new Error('Tarball download timed out')); });
    }

    doGet(url);
  });
}

/**
 * Extract import/require specifiers from JS source text.
 * Mirrors the logic in phantom.js but operates on a string.
 */
function extractImportsFromSource(src) {
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

  const requireRe = /require\s*\(\s*['"`]([^'"`\s]+)['"`]/g;
  let m;
  while ((m = requireRe.exec(stripped)) !== null) {
    const spec = normaliseSpecifier(m[1]);
    if (spec) found.add(spec);
  }

  // Match anything ending in `from '<spec>'` regardless of what came before.
  // This is intentionally loose so it catches all of:
  //   import x from 'pkg'
  //   import { a, b } from 'pkg'
  //   import * as ns from 'pkg'
  //   import type { T } from 'pkg'         (TS)
  //   import { type T, val } from 'pkg'    (TS inline type)
  //   export { foo } from 'pkg'
  //   export * from 'pkg'
  //   export type { T } from 'pkg'         (TS)
  const fromRe = /(?:^|[\s;])(?:import|export)\b[^'"`\n]*?\bfrom\s+['"`]([^'"`\s]+)['"`]/g;
  while ((m = fromRe.exec(stripped)) !== null) {
    const spec = normaliseSpecifier(m[1]);
    if (spec) found.add(spec);
  }

  // Dynamic import expression: import('pkg')
  const dynRe = /\bimport\s*\(\s*['"`]([^'"`\s]+)['"`]/g;
  while ((m = dynRe.exec(stripped)) !== null) {
    const spec = normaliseSpecifier(m[1]);
    if (spec) found.add(spec);
  }

  return found;
}

function normaliseSpecifier(spec) {
  if (!spec || spec.startsWith('.') || spec.startsWith('/')) return null;
  if (spec.startsWith('@')) {
    const parts = spec.split('/');
    return parts.length >= 2 ? `${parts[0]}/${parts[1]}` : spec;
  }
  return spec.split('/')[0];
}

/**
 * Parse a POSIX tar stream (uncompressed) and call onFile for each entry.
 *
 * Safety limits enforced:
 *   - MAX_UNCOMPRESSED_BYTES: total uncompressed size limit (200 MB)
 *   - MAX_FILE_COUNT:         maximum number of entries (5000)
 *
 * Throws a descriptive error if either limit is breached — this prevents
 * tar-bomb DoS attacks from exhausting Node.js heap memory.
 *
 * tar format: 512-byte header blocks followed by file content blocks.
 * Header offsets:
 *   0   name     100 bytes
 *   124 size      12 bytes (octal)
 *   156 typeflag   1 byte  ('0'=regular file, '\0'=regular, '5'=dir)
 */
function parseTar(buffer, onFile) {
  let offset    = 0;
  let totalSize = 0;
  let fileCount = 0;

  // Pending overrides from preceding extended-header entries.
  // - PaxHeader (typeflag 'x'): payload contains "<len> path=<value>\n" records
  //   that override fields on the *next* regular file entry.
  // - GNU longlink (typeflag 'L'): payload is the raw long filename for the
  //   next regular file entry.
  // Both are how npm-packed tarballs represent file paths longer than the
  // 100-byte ustar `name` field, which is common for scoped packages with
  // deep directory structures (e.g. @babel/parser, @typescript-eslint/...).
  // Without this handling, those entries are silently skipped and source-file
  // scanning misses real require()/import statements, producing false phantom
  // verdicts on legitimate dependencies.
  let pendingLongName = null;

  // Duplicate-path detection. This is a security control against
  // "differential parsing" / "tar desync" attacks: a malicious tarball
  // contains two entries with the same path. The npm `tar` package, when
  // unpacking to disk, applies entries in stream order — last write wins.
  // A naive in-memory scanner that stops at the first occurrence (or just
  // emits each entry as encountered) sees the FIRST file's content and
  // says "approved", but disk gets the SECOND file's content. The two
  // parsers disagree about what the tarball contains. This pattern has
  // been exploited in real archive-format vulnerabilities (notably
  // GHSA-r628-mhmh-qjhw in npm's own tar handling).
  //
  // Defense: refuse any tarball that contains the same path twice. No
  // legitimate npm package has duplicate entry paths — `npm pack` never
  // produces them, and there is no benign use case for them. Treat it as
  // a hard fail at the same severity as the tar-bomb size limits.
  const seenPaths = new Set();

  function parsePaxPath(content) {
    // Pax records are "LEN KEY=VALUE\n" where LEN is the byte length of the
    // entire record including LEN itself and the trailing newline. Multiple
    // records may be concatenated. We only care about the `path` key.
    const text = content.toString('utf8');
    let i = 0;
    while (i < text.length) {
      // Read the length prefix up to the first space
      const sp = text.indexOf(' ', i);
      if (sp === -1) break;
      const len = parseInt(text.slice(i, sp), 10);
      if (!len || len <= 0 || i + len > text.length) break;
      const record = text.slice(sp + 1, i + len - 1); // strip trailing \n
      const eq = record.indexOf('=');
      if (eq !== -1) {
        const key = record.slice(0, eq);
        const val = record.slice(eq + 1);
        if (key === 'path') return val;
      }
      i += len;
    }
    return null;
  }

  while (offset + 512 <= buffer.length) {
    const header = buffer.slice(offset, offset + 512);

    // End-of-archive: two consecutive 512-byte zero blocks
    if (header.every(b => b === 0)) break;

    let name       = header.slice(0, 100).toString('utf8').replace(/\0+$/, '');
    const sizeOct  = header.slice(124, 136).toString('utf8').replace(/\0+$/, '').trim();
    const typeflag = String.fromCharCode(header[156]);
    // ustar prefix field (offset 345, 155 bytes) is concatenated with name
    // for paths up to ~255 bytes; this is the *non-extended* long-path mechanism.
    const prefix   = header.slice(345, 500).toString('utf8').replace(/\0+$/, '');
    if (prefix && (typeflag === '0' || typeflag === '\0')) {
      name = prefix + '/' + name;
    }
    const size     = parseInt(sizeOct, 8) || 0;

    // Guard: entry size sanity check before accumulation
    if (size < 0) {
      throw new Error(`Invalid tar entry: negative size for "${name}"`);
    }

    totalSize += size;
    if (totalSize > MAX_UNCOMPRESSED_BYTES) {
      throw new Error(
        `Tarball too large uncompressed: exceeded ${MAX_UNCOMPRESSED_BYTES} byte limit ` +
        `after ${fileCount} entries — possible tar bomb. Scan aborted.`,
      );
    }

    fileCount++;
    if (fileCount > MAX_FILE_COUNT) {
      throw new Error(
        `Tarball contains too many entries: exceeded ${MAX_FILE_COUNT} file limit ` +
        `— possible tar bomb. Scan aborted.`,
      );
    }

    offset += 512; // move past header
    const content = size > 0 ? buffer.slice(offset, offset + size) : Buffer.alloc(0);

    if (typeflag === 'x' || typeflag === 'X') {
      // PaxHeader extended attributes — apply path override to next entry.
      // PaxHeader paths are NOT checked for duplicates here because they
      // describe metadata for the NEXT entry, not a file in their own right.
      const overridePath = parsePaxPath(content);
      if (overridePath) pendingLongName = overridePath;
    } else if (typeflag === 'L') {
      // GNU longlink — content IS the next entry's filename
      pendingLongName = content.toString('utf8').replace(/\0+$/, '');
    } else if ((typeflag === '0' || typeflag === '\0') && size > 0) {
      const effectiveName = pendingLongName || name;
      pendingLongName = null;

      // Guard: sanitise file names to prevent path traversal in downstream
      // code that might use the name for display, logging, or temp extraction.
      // We do NOT write to disk here, but names are logged in reports.
      const safeName = effectiveName.replace(/\.\.\//g, '__/').replace(/^\//, '');

      // Tar desync defense: refuse duplicate paths. See the seenPaths
      // declaration above for the full rationale.
      if (seenPaths.has(safeName)) {
        throw new Error(
          `Duplicate entry path in tarball: "${safeName}". ` +
          `This is the signature of a tar-desync / differential-parsing attack ` +
          `where the in-memory scanner sees one file's content and the on-disk ` +
          `extractor sees another. No legitimate npm package contains duplicate ` +
          `entry paths. Scan aborted.`
        );
      }
      seenPaths.add(safeName);

      onFile(safeName, content);
    } else {
      // Other typeflags (directory, symlink, hardlink, etc.) — clear any
      // pending long name so it doesn't bleed into a later entry.
      pendingLongName = null;
    }

    // Advance past content, rounded up to 512-byte boundary
    offset += Math.ceil(size / 512) * 512;
  }
}

/**
 * Download, extract, and scan a package tarball for uses of depName.
 *
 * @param {string} tarballUrl   - from packument dist.tarball
 * @param {string} depName      - dependency name to search for
 * @param {string} parentName   - for logging
 * @param {string} parentVersion
 * @returns {Promise<DeltaPhantomResult>}
 */
async function scanTarball(tarballUrl, depName, parentName, parentVersion) {
  let tmpFile = null;
  try {
    tmpFile = await downloadTarball(tarballUrl);

    // Read compressed bytes and gunzip to tar buffer.
    // Note: downloadTarball already enforced MAX_COMPRESSED_BYTES on the
    // download stream. parseTar will enforce MAX_UNCOMPRESSED_BYTES on the
    // expanded content. Both guards together prevent tar-bomb DoS.
    const compressed = fs.readFileSync(tmpFile);
    let tarBuffer;
    try {
      tarBuffer = zlib.gunzipSync(compressed);
    } catch (e) {
      throw new Error(`Failed to decompress tarball: ${e.message}`);
    }

    const allImports   = new Set();
    const scannedFiles = [];

    parseTar(tarBuffer, (name, content) => {
      const ext = path.extname(name).toLowerCase();
      if (!SOURCE_EXTENSIONS.has(ext)) return;

      // Skip node_modules inside the tarball (shouldn't exist but guard anyway)
      if (name.includes('/node_modules/')) return;

      try {
        const src = content.toString('utf8');
        const imports = extractImportsFromSource(src);
        for (const imp of imports) allImports.add(imp);
        scannedFiles.push(name);
      } catch {
        // Binary or unparseable file — skip
      }
    });

    const found = allImports.has(depName);

    if (found) {
      return _result(depName, parentName, parentVersion, 'LIKELY_USED', 'HIGH', 'tarball',
        `${depName} found in imports/requires across ${scannedFiles.length} source files`,
        [...allImports].filter(i => i === depName));
    } else {
      return _result(depName, parentName, parentVersion, 'LIKELY_PHANTOM', 'HIGH', 'tarball',
        `${depName} NOT found in any require/import across ${scannedFiles.length} source files in ${parentName}@${parentVersion} tarball`,
        []);
    }
  } finally {
    if (tmpFile) {
      try { fs.unlinkSync(tmpFile); } catch {}
    }
  }
}

// ─── combined analysis ────────────────────────────────────────────────────────

/**
 * Full delta phantom analysis for a newly-introduced dep.
 * Runs manifest heuristic first (fast); optionally follows with tarball scan.
 *
 * @param {object} parentVersionMeta  - from registry getVersionMeta
 * @param {string} depName
 * @param {object} opts
 * @param {boolean} opts.tarball      - if true, download + scan the tarball
 * @param {string}  opts.tarballUrl   - required when opts.tarball is true
 * @returns {Promise<DeltaPhantomResult>}
 */
async function analysePhantom(parentVersionMeta, depName, opts = {}) {
  const manifestResult = analyseManifestPhantom(parentVersionMeta, depName);

  if (!opts.tarball) {
    return manifestResult;
  }

  if (!opts.tarballUrl) {
    return { ...manifestResult,
      reason: manifestResult.reason + ' (tarball URL not provided for HIGH confidence scan)',
    };
  }

  try {
    const tarballResult = await scanTarball(
      opts.tarballUrl, depName,
      parentVersionMeta?.name    || 'unknown',
      parentVersionMeta?.version || 'unknown',
    );
    return tarballResult;
  } catch (e) {
    // Tarball scan failed — fall back to manifest result, noting the failure
    return {
      ...manifestResult,
      reason: manifestResult.reason + ` (tarball scan failed: ${e.message})`,
      _tarballError: e.message,
    };
  }
}

/**
 * Batch analysis for multiple newly-added deps.
 * Manifest-only (fast path). Use analysePhantom individually for tarball scans.
 */
function analyseNewDeps(parentVersionMeta, newDeps) {
  return newDeps.map(dep => analyseManifestPhantom(parentVersionMeta, dep));
}

// ─── helpers ──────────────────────────────────────────────────────────────────

function _result(dep, parent, parentVersion, verdict, confidence, layer, reason, signals) {
  return { dep, parent, parentVersion, verdict, confidence, layer, reason, signals };
}

module.exports = {
  analyseManifestPhantom,
  analysePhantom,
  analyseNewDeps,
  checkManifestReferences,
  // Exported for testing
  extractImportsFromSource,
  parseTar,
  normaliseSpecifier,
};
