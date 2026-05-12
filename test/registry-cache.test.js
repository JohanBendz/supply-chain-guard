'use strict';
/**
 * test/registry-cache.test.js
 * Tests for src/registry-cache.js — in-memory + disk TTL cache.
 */

const { getCached, setCached, invalidate, clearDiskCache, stats } =
  require('../src/registry-cache');

let passed = 0;
let failed = 0;

function assert(condition, label) {
  if (condition) { console.log(`  ✓  ${label}`); passed++; }
  else           { console.error(`  ✖  ${label}`); failed++; }
}
function section(title) {
  const pad = Math.max(2, 54 - title.length);
  console.log(`\n── ${title} ${'─'.repeat(pad)}`);
}

section('basic get/set — memory layer');

// Start clean
clearDiskCache();
invalidate('test-pkg');

assert(getCached('test-pkg') === null, 'cache miss returns null');
setCached('test-pkg', { name: 'test-pkg', version: '1.0.0' });
const hit = getCached('test-pkg');
assert(hit !== null, 'cache hit after set');
assert(hit.name === 'test-pkg', 'cached data preserved correctly');

section('invalidate removes from cache');

invalidate('test-pkg');
assert(getCached('test-pkg') === null, 'invalidate removes entry');

section('disk cache persists across memory cache misses');

setCached('disk-pkg', { name: 'disk-pkg', version: '2.0.0' });
// Simulate memory cache miss by directly checking disk
const { stats: cacheStats } = require('../src/registry-cache');
const s1 = cacheStats();
assert(s1.diskEntries >= 1, 'disk cache has at least one entry after set');
assert(s1.memEntries >= 1, 'memory cache has at least one entry');
assert(typeof s1.ttlMs === 'number', 'TTL is a number');
assert(s1.ttlMs === 5 * 60 * 1000, 'TTL is 5 minutes');

section('clearDiskCache empties disk tier');

clearDiskCache();
const s2 = cacheStats();
assert(s2.diskEntries === 0, 'disk entries cleared');
// Memory entries may still be present (clearDiskCache only clears disk)

section('scoped package names are handled safely');

setCached('@scope/utils', { name: '@scope/utils' });
const scopedHit = getCached('@scope/utils');
assert(scopedHit !== null, 'scoped package cached');
assert(scopedHit.name === '@scope/utils', 'scoped package data correct');
invalidate('@scope/utils');

section('multiple packages cached independently');

setCached('lodash', { name: 'lodash', versions: ['4.17.21'] });
setCached('express', { name: 'express', versions: ['4.18.0'] });
assert(getCached('lodash')?.name === 'lodash',   'lodash cached separately');
assert(getCached('express')?.name === 'express', 'express cached separately');
invalidate('lodash');
assert(getCached('lodash') === null,             'lodash invalidated');
assert(getCached('express')?.name === 'express', 'express unaffected by lodash invalidate');

section('null data not cached');

setCached('not-found-pkg', null);
assert(getCached('not-found-pkg') === null, 'null response not cached (would be stale 404)');

// ── summary ───────────────────────────────────────────────────────────────────

clearDiskCache(); // clean up after tests

console.log(`\n${'─'.repeat(52)}`);
console.log(`  Results: ${passed} passed, ${failed} failed\n`);
process.exit(failed > 0 ? 1 : 0);
