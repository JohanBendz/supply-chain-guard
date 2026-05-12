'use strict';
/**
 * registry-cache.js
 *
 * Two-level cache for npm registry packument data:
 *   Level 1 — in-memory Map (instant, per-process lifetime)
 *   Level 2 — disk cache in os.tmpdir() (TTL-based, survives short tool re-runs)
 *
 * Motivation: `scg add pkg1 pkg2 pkg3` and `scg update --all` can issue dozens
 * of registry requests. Each packument fetch is ~50–200 KB. Caching avoids
 * redundant round-trips without adding external dependencies.
 *
 * Cache is keyed by package name. Packument data changes rarely between
 * subsequent `scg` runs in the same dev session.
 */

const fs   = require('fs');
const path = require('path');
const os   = require('os');

const CACHE_DIR = path.join(os.tmpdir(), 'scg-registry-cache');
const CACHE_TTL_MS = 5 * 60 * 1000; // 5 minutes on disk

// ── in-memory cache ───────────────────────────────────────────────────────────

const memCache = new Map(); // name → { data, ts }

function memGet(name) {
  const entry = memCache.get(name);
  if (!entry) return null;
  if (Date.now() - entry.ts > CACHE_TTL_MS) {
    memCache.delete(name);
    return null;
  }
  return entry.data;
}

function memSet(name, data) {
  memCache.set(name, { data, ts: Date.now() });
}

// ── disk cache ────────────────────────────────────────────────────────────────

function diskPath(name) {
  // Safe filename: replace '/' and '@' with '_'
  const safe = name.replace(/[@/]/g, '_');
  return path.join(CACHE_DIR, `${safe}.json`);
}

function diskGet(name) {
  try {
    const file = diskPath(name);
    if (!fs.existsSync(file)) return null;
    const raw  = JSON.parse(fs.readFileSync(file, 'utf8'));
    if (!raw.ts || Date.now() - raw.ts > CACHE_TTL_MS) {
      fs.unlinkSync(file);
      return null;
    }
    return raw.data;
  } catch { return null; }
}

function diskSet(name, data) {
  try {
    fs.mkdirSync(CACHE_DIR, { recursive: true });
    fs.writeFileSync(diskPath(name), JSON.stringify({ data, ts: Date.now() }));
  } catch { /* non-fatal */ }
}

// ── public API ────────────────────────────────────────────────────────────────

/**
 * Get a packument from cache (memory → disk → null).
 */
function getCached(name) {
  return memGet(name) || diskGet(name);
}

/**
 * Store a packument in both caches.
 */
function setCached(name, data) {
  memSet(name, data);
  diskSet(name, data);
}

/**
 * Invalidate a single package from all cache levels.
 */
function invalidate(name) {
  memCache.delete(name);
  try { fs.unlinkSync(diskPath(name)); } catch {}
}

/**
 * Clear all disk cache entries (e.g. on `scg init --rotate-token`).
 */
function clearDiskCache() {
  try {
    for (const f of fs.readdirSync(CACHE_DIR)) {
      fs.unlinkSync(path.join(CACHE_DIR, f));
    }
  } catch {}
}

/**
 * Return cache stats for diagnostics.
 */
function stats() {
  let diskEntries = 0;
  try { diskEntries = fs.readdirSync(CACHE_DIR).length; } catch {}
  return { memEntries: memCache.size, diskEntries, ttlMs: CACHE_TTL_MS };
}

module.exports = { getCached, setCached, invalidate, clearDiskCache, stats };
