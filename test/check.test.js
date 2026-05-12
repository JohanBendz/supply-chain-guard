'use strict';
/**
 * test/check.test.js
 * Tests the scoring logic in check.js using mocked registry profiles.
 * No network required.
 */

const { scoreProfile, SIGNALS } = require('../src/check');
const { SEV } = require('../src/diff');

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

function hasCode(signals, code) {
  return signals.some(s => s.code === code);
}

function hasSev(signals, sev) {
  return signals.some(s => s.severity === sev);
}

// ─── Mock: axios 1.14.1 (the compromised version) ────────────────────────────

section('axios@1.14.1 — full attack simulation');

const axiosCompromisedProfile = {
  name: 'axios',
  version: '1.14.1',
  ageDays: 0,
  publishedAt: new Date(Date.now() - 2 * 3600 * 1000).toISOString(), // 2 hrs ago
  hasLifecycleScripts: false, // axios itself has no postinstall
  scripts: {},
  provenance: {
    currentHasProvenance: false,   // manually published with stolen token
    previousUsedProvenance: true,  // 1.14.0 used OIDC — regression!
    regression: true,
    currentDetail: 'Published manually by npm user: jasonsaayman',
  },
  previousVersion: '1.14.0',
  depDiff: {
    added: ['mock-unapproved-dep'],
    removed: [],
  },
  newDepProfiles: {
    'mock-unapproved-dep': {
      version: '4.2.1',
      ageDays: 0,
      packageAgeDays: 0,       // brand new package
      totalVersions: 2,        // only 2 versions ever
      hasLifecycleScripts: true,
      scripts: { postinstall: 'node postinstall-hook.js' },
    }
  },
  totalVersions: 142,
};

const axiosSignals = scoreProfile(axiosCompromisedProfile, { cooldownDays: 3 });

assert(hasCode(axiosSignals, 'NEW_DEP_ADDED'),             'flags new dependency (mock-unapproved-dep)');
assert(hasCode(axiosSignals, 'NEW_DEP_WITH_SCRIPTS'),      'flags new dep has postinstall script');
assert(hasCode(axiosSignals, 'NEW_DEP_BRAND_NEW_PACKAGE'), 'flags dep is a brand-new package');
assert(hasCode(axiosSignals, 'PROVENANCE_REGRESSION'),     'flags provenance regression (OIDC → manual)');
assert(hasCode(axiosSignals, 'SINGLE_VERSION_PACKAGE') === false, 'does not fire SINGLE_VERSION on 2-version package');
assert(hasSev(axiosSignals, SEV.CRITICAL),                 'overall severity is CRITICAL');
assert(axiosSignals.filter(s => s.severity === SEV.CRITICAL).length >= 2, 'at least 2 CRITICAL signals');

// ─── Mock: axios 1.14.0 (the safe previous version) ──────────────────────────

section('axios@1.14.0 — clean version');

const axiosSafeProfile = {
  name: 'axios',
  version: '1.14.0',
  ageDays: 45,
  publishedAt: new Date(Date.now() - 45 * 86400000).toISOString(),
  hasLifecycleScripts: false,
  scripts: {},
  provenance: {
    currentHasProvenance: true,
    previousUsedProvenance: true,
    regression: false,
    currentDetail: 'OIDC attestation present',
  },
  previousVersion: '1.13.1',
  depDiff: { added: [], removed: [] },
  newDepProfiles: {},
  totalVersions: 141,
};

const axiosSafeSignals = scoreProfile(axiosSafeProfile, { cooldownDays: 3 });
assert(axiosSafeSignals.length === 0, 'no signals for clean version');
assert(!hasSev(axiosSafeSignals, SEV.CRITICAL), 'no CRITICAL on safe version');

// ─── Mock: brand-new package with postinstall ─────────────────────────────────

section('totally-legit-pkg@1.0.0 — new package with scripts');

const newPkgProfile = {
  name: 'totally-legit-pkg',
  version: '1.0.0',
  ageDays: 1,
  publishedAt: new Date(Date.now() - 1 * 86400000).toISOString(),
  hasLifecycleScripts: true,
  scripts: { postinstall: 'node install.js' },
  provenance: { currentHasProvenance: false, previousUsedProvenance: false, regression: false, currentDetail: 'new package' },
  previousVersion: null,
  depDiff: null,
  newDepProfiles: {},
  totalVersions: 1,
};

const newPkgSignals = scoreProfile(newPkgProfile, { cooldownDays: 3 });
assert(hasCode(newPkgSignals, 'VERSION_VERY_NEW_WITH_SCRIPTS'), 'flags very new version with scripts');
assert(hasSev(newPkgSignals, SEV.CRITICAL), 'CRITICAL for brand new + postinstall');

// ─── Mock: version update without script changes (routine bump) ───────────────

section('lodash@4.17.22 — routine patch, no dep changes, old enough');

const lodashProfile = {
  name: 'lodash',
  version: '4.17.22',
  ageDays: 120,
  publishedAt: new Date(Date.now() - 120 * 86400000).toISOString(),
  hasLifecycleScripts: false,
  scripts: {},
  provenance: { currentHasProvenance: false, previousUsedProvenance: false, regression: false, currentDetail: 'no provenance' },
  previousVersion: '4.17.21',
  depDiff: { added: [], removed: [] },
  newDepProfiles: {},
  totalVersions: 80,
};

const lodashSignals = scoreProfile(lodashProfile, { cooldownDays: 3 });
// Lodash doesn't use provenance — no regression. No new deps. Not new. Should be clean.
assert(!hasCode(lodashSignals, 'NEW_DEP_ADDED'), 'no false positive on routine bump');
assert(!hasSev(lodashSignals, SEV.CRITICAL), 'no CRITICAL on routine bump');

// ─── Mock: provenance regression without new deps ─────────────────────────────

section('some-pkg@2.0.0 — provenance regression alone');

const provRegressProfile = {
  name: 'some-pkg',
  version: '2.0.0',
  ageDays: 5,
  publishedAt: new Date(Date.now() - 5 * 86400000).toISOString(),
  hasLifecycleScripts: false,
  scripts: {},
  provenance: {
    currentHasProvenance: false,
    previousUsedProvenance: true,
    regression: true,
    currentDetail: 'Published manually',
  },
  previousVersion: '1.9.0',
  depDiff: { added: [], removed: [] },
  newDepProfiles: {},
  totalVersions: 30,
};

const provRegressSignals = scoreProfile(provRegressProfile, { cooldownDays: 3 });
assert(hasCode(provRegressSignals, 'PROVENANCE_REGRESSION'), 'flags provenance regression alone');
assert(hasSev(provRegressSignals, SEV.CRITICAL), 'CRITICAL for provenance regression');

// ─── Mock: cooldown threshold boundary ───────────────────────────────────────

section('cooldown boundary tests');

function makeAgedProfile(ageDays) {
  return {
    name: 'test-pkg', version: '1.0.0',
    ageDays, publishedAt: new Date(Date.now() - ageDays * 86400000).toISOString(),
    hasLifecycleScripts: true, scripts: { postinstall: 'echo hi' },
    provenance: { regression: false, currentHasProvenance: false, previousUsedProvenance: false, currentDetail: '' },
    previousVersion: null, depDiff: null, newDepProfiles: {}, totalVersions: 5,
  };
}

const day1 = scoreProfile(makeAgedProfile(1), { cooldownDays: 3 });
const day4 = scoreProfile(makeAgedProfile(4), { cooldownDays: 3 });

assert(hasCode(day1, 'VERSION_VERY_NEW_WITH_SCRIPTS'), 'day-1 package triggers cooldown');
assert(!hasCode(day4, 'VERSION_VERY_NEW_WITH_SCRIPTS'), 'day-4 package clears cooldown');
assert(!hasCode(day4, 'VERSION_VERY_NEW'), 'day-4 package clears cooldown entirely');

// ─── Summary ─────────────────────────────────────────────────────────────────

console.log(`\n${'─'.repeat(52)}`);
console.log(`  Results: ${passed} passed, ${failed} failed\n`);

process.exit(failed > 0 ? 1 : 0);
