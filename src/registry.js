'use strict';
/**
 * registry.js
 *
 * Rich npm registry client.  All network I/O is here; the rest of the
 * codebase stays offline-capable.
 *
 * Key signals extracted per package-version:
 *   - publish timestamp & age
 *   - OIDC / trusted-publishing provenance (missing = manual token publish)
 *   - new dependencies vs previous version (phantom dep injection)
 *   - maintainer account details (account age, email change)
 *   - lifecycle scripts in the published package.json
 */

const https  = require('https');
const semver = require('semver');
const { getCached, setCached } = require('./registry-cache');

const REGISTRY = 'https://registry.npmjs.org';
const DEFAULT_TIMEOUT_MS = 8000;

// Hard limits / retry policy for registry HTTP calls.
// MAX_PACKUMENT_BYTES is generous — the largest real packuments (e.g. lodash,
// react) are a few hundred KB, but transitive metadata can grow. We cap well
// below "could OOM Node" while still leaving headroom for legitimate growth.
const MAX_PACKUMENT_BYTES = 10 * 1024 * 1024; // 10 MB
const MAX_REDIRECTS       = 5;
const MAX_RETRIES         = 2;                // total attempts = 1 + retries
const RETRY_BACKOFF_MS    = 250;

// ─── low-level fetch ──────────────────────────────────────────────────────────

function httpsGetOnce(url, redirectsLeft = MAX_REDIRECTS) {
  return new Promise((resolve, reject) => {
    const req = https.get(url, { timeout: DEFAULT_TIMEOUT_MS }, (res) => {
      // Follow up to MAX_REDIRECTS hops. The npm registry itself rarely
      // redirects, but CDN failovers and mirrors do. Without this the
      // packument fetch would silently fail on common operational events.
      if ([301, 302, 307, 308].includes(res.statusCode)) {
        res.resume();
        if (redirectsLeft <= 0) {
          reject(new Error(`Too many redirects fetching ${url}`));
          return;
        }
        const next = res.headers.location;
        if (!next) { reject(new Error(`Redirect with no Location header from ${url}`)); return; }
        // Resolve relative redirect targets against the original URL
        const resolvedNext = next.startsWith('http') ? next : new URL(next, url).toString();
        httpsGetOnce(resolvedNext, redirectsLeft - 1).then(resolve, reject);
        return;
      }
      if (res.statusCode === 404) { resolve(null); return; }
      if (res.statusCode !== 200) {
        // Drain and surface a typed error so the retry layer can act on it.
        res.resume();
        const err = new Error(`HTTP ${res.statusCode} fetching ${url}`);
        err.statusCode = res.statusCode;
        reject(err);
        return;
      }

      // Reject early if Content-Length already declares an oversized body.
      const declaredSize = parseInt(res.headers['content-length'] || '0', 10);
      if (declaredSize > MAX_PACKUMENT_BYTES) {
        req.destroy();
        reject(new Error(
          `Registry response too large: ${declaredSize} bytes exceeds ${MAX_PACKUMENT_BYTES} byte limit`,
        ));
        return;
      }

      // Stream and enforce size cap mid-flight in case Content-Length is absent
      // or lying. Without this, a malicious or compromised mirror could exhaust
      // Node heap by streaming an unbounded JSON blob.
      let received = 0;
      let body = '';
      res.on('data', d => {
        received += d.length;
        if (received > MAX_PACKUMENT_BYTES) {
          req.destroy();
          reject(new Error(
            `Registry response exceeded ${MAX_PACKUMENT_BYTES} byte limit mid-stream`,
          ));
          return;
        }
        body += d;
      });
      res.on('end', () => {
        try { resolve(JSON.parse(body)); }
        catch (e) { reject(new Error(`JSON parse error for ${url}: ${e.message}`)); }
      });
    });
    req.on('error', reject);
    req.on('timeout', () => { req.destroy(); reject(new Error(`Timeout fetching ${url}`)); });
  });
}

/**
 * httpsGet wrapper with simple retry on transient failures.
 *
 * Retries on: timeouts, connection resets, 5xx responses.
 * Does NOT retry on: 4xx responses (other than 404, which httpsGetOnce
 * resolves to null), parse errors, or oversized-body rejections.
 *
 * Backoff is linear (not exponential) — registry calls are user-facing and
 * we'd rather fail fast than make a flaky `scg add` feel slow.
 */
async function httpsGet(url) {
  let lastErr;
  for (let attempt = 0; attempt <= MAX_RETRIES; attempt++) {
    try {
      return await httpsGetOnce(url);
    } catch (e) {
      lastErr = e;
      const transient =
        /timeout/i.test(e.message) ||
        /ECONNRESET/i.test(e.message) ||
        /ENOTFOUND/i.test(e.message) ||
        /EAI_AGAIN/i.test(e.message) ||
        (e.statusCode && e.statusCode >= 500);
      if (!transient || attempt === MAX_RETRIES) throw e;
      await new Promise(r => setTimeout(r, RETRY_BACKOFF_MS * (attempt + 1)));
    }
  }
  throw lastErr;
}

function encodePackageName(name) {
  // Validate and encode. npm package names are restricted to lowercase
  // alphanumerics, dots, hyphens, and underscores, with an optional
  // @scope/ prefix. We enforce this up-front rather than trusting the
  // caller, because `name` can flow in from lockfile keys, CLI args, or
  // registry packuments — any of which a well-resourced attacker might
  // poison to include path-traversal or query-string injection sequences.
  const NAME_RE = /^(?:@[a-z0-9][a-z0-9._-]*\/)?[a-z0-9][a-z0-9._-]*$/i;
  if (!NAME_RE.test(name) || name.includes('..')) {
    throw new Error(`Invalid package name: ${JSON.stringify(name)}`);
  }
  // Scoped names: encode the '/' between scope and name, keep everything
  // else verbatim (the regex above already guarantees no unsafe chars).
  return name.startsWith('@') ? name.replace('/', '%2F') : name;
}

function encodeVersion(version) {
  // Versions are also attacker-influenced (come from lockfiles, CLI specs).
  // Restrict to semver-ish characters plus the npm-style prefixes and
  // range operators. No '/', '?', '#', or whitespace.
  if (!/^[a-zA-Z0-9.+\-_~^><=|&* ]+$/.test(String(version))) {
    throw new Error(`Invalid version spec: ${JSON.stringify(version)}`);
  }
  return encodeURIComponent(version);
}

// ─── public API ───────────────────────────────────────────────────────────────

/**
 * Fetch the full packument (all-versions metadata) for a package.
 * Two-level cache: in-memory (per-process) → disk (5 min TTL) → network.
 * Avoids redundant round-trips in scg add/update --all flows.
 */
async function getPackument(name) {
  const cached = getCached(name);
  if (cached) return cached;
  const url  = `${REGISTRY}/${encodePackageName(name)}`;
  const data = await httpsGet(url);
  if (data) setCached(name, data);
  return data;
}

/**
 * Resolve an npm version spec (latest, dist-tag, exact version, or semver range)
 * to the concrete version npm would most likely install from the public registry.
 * Returns null when the package/spec cannot be resolved.
 */
async function resolveVersion(name, versionSpec = 'latest') {
  const packument = await getPackument(name);
  if (!packument) return null;

  const spec = versionSpec || 'latest';
  const versions = Object.keys(packument.versions || {}).filter(v => semver.valid(v));

  if (semver.valid(spec) && packument.versions?.[spec]) return spec;

  const distTag = packument['dist-tags']?.[spec];
  if (distTag && packument.versions?.[distTag]) return distTag;

  const range = semver.validRange(spec);
  if (range) return semver.maxSatisfying(versions, range);

  return null;
}
/**
 * Fetch metadata for a single version.
 */
async function getVersionMeta(name, version) {
  const url = `${REGISTRY}/${encodePackageName(name)}/${encodeVersion(version)}`;
  return await httpsGet(url);
}

/**
 * Get the sorted list of published versions with timestamps.
 * Returns: [ { version, publishedAt, ageMs }, ... ] newest first
 */
async function getVersionHistory(name) {
  const packument = await getPackument(name);
  if (!packument) return null;

  const times = packument.time || {};
  const versions = Object.keys(packument.versions || {})
    .filter(v => times[v])
    .map(v => ({
      version: v,
      publishedAt: times[v],
      ageMs: Date.now() - new Date(times[v]).getTime(),
      ageDays: Math.floor((Date.now() - new Date(times[v]).getTime()) / 86_400_000),
    }))
    .sort((a, b) => new Date(b.publishedAt) - new Date(a.publishedAt));

  return versions;
}

/**
 * Return the version immediately before `version` in publish order.
 */
async function getPreviousVersion(name, version) {
  const history = await getVersionHistory(name);
  if (!history) return null;
  const idx = history.findIndex(h => h.version === version);
  if (idx === -1 || idx === history.length - 1) return null;
  return history[idx + 1].version;
}

/**
 * Compare dependencies between two versions of the same package.
 * Returns { added, removed } — both are arrays of package names.
 */
async function diffDependencies(name, versionA, versionB) {
  const [metaA, metaB] = await Promise.all([
    getVersionMeta(name, versionA),
    getVersionMeta(name, versionB),
  ]);

  if (!metaA || !metaB) return null;

  const depsA = new Set(Object.keys(metaA.dependencies || {}));
  const depsB = new Set(Object.keys(metaB.dependencies || {}));

  return {
    added:   [...depsB].filter(d => !depsA.has(d)),
    removed: [...depsA].filter(d => !depsB.has(d)),
  };
}

/**
 * Check whether a specific version has npm provenance (OIDC trusted-publishing).
 *
 * A legitimate release from GitHub Actions will have:
 *   dist.attestations  (npm >=9.5)
 *   or _npmUser matching a CI system
 *
 * Absence of provenance on a package that previously used it is a red flag.
 */
async function getProvenanceInfo(name, version) {
  const meta = await getVersionMeta(name, version);
  if (!meta) return { hasProvenance: false, detail: 'version not found' };

  // npm provenance via attestations field (npm >=9.5 / registry >=2024)
  if (meta.dist && meta.dist.attestations) {
    const attest = meta.dist.attestations;
    return {
      hasProvenance: true,
      type: 'attestation',
      url: attest.url || null,
      detail: `OIDC attestation present`,
    };
  }

  // Older provenance via _resolved + integrity check
  if (meta._npmUser) {
    return {
      hasProvenance: false,
      publishedBy: meta._npmUser.name || null,
      publishedByEmail: meta._npmUser.email || null,
      detail: `Published manually by npm user: ${meta._npmUser.name || 'unknown'}`,
    };
  }

  return { hasProvenance: false, detail: 'No provenance metadata found' };
}

/**
 * Check whether previous versions of a package used OIDC provenance.
 * If yes-then-no, it's a strong signal of credential compromise.
 */
async function checkProvenanceRegression(name, currentVersion) {
  const packument = await getPackument(name);
  if (!packument) return null;

  const history = await getVersionHistory(name);
  if (!history || history.length < 2) return null;

  // Check the last 5 published versions before current. The previous
  // implementation awaited each getProvenanceInfo sequentially in a loop,
  // making this 5 round-trips serially. Fetch in parallel and pick the
  // first that had provenance — `Promise.all` is fine here because we want
  // all results anyway (the array is small and bounded).
  const currentIdx = history.findIndex(h => h.version === currentVersion);
  const previousVersions = history.slice(currentIdx + 1, currentIdx + 6);

  const [prevProvs, currentProv] = await Promise.all([
    Promise.all(previousVersions.map(({ version }) =>
      getProvenanceInfo(name, version).catch(() => ({ hasProvenance: false }))
    )),
    getProvenanceInfo(name, currentVersion),
  ]);

  const previousUsedProvenance = prevProvs.some(p => p.hasProvenance);

  return {
    currentHasProvenance: currentProv.hasProvenance,
    previousUsedProvenance,
    regression: previousUsedProvenance && !currentProv.hasProvenance,
    currentDetail: currentProv.detail,
  };
}

/**
 * Get lifecycle scripts declared in a specific published version.
 */
async function getPublishedScripts(name, version) {
  const meta = await getVersionMeta(name, version);
  if (!meta || !meta.scripts) return {};

  const LIFECYCLE = ['preinstall', 'install', 'postinstall', 'prepare', 'prepack', 'postpack'];
  const result = {};
  for (const k of LIFECYCLE) {
    if (meta.scripts[k]) result[k] = meta.scripts[k];
  }
  return result;
}

/**
 * Full risk profile for a specific package@version.
 * This is the main entry point for `scg check`.
 */
async function getVersionRiskProfile(name, version) {
  const [history, provenanceRegression, scripts, versionMeta] = await Promise.all([
    getVersionHistory(name),
    checkProvenanceRegression(name, version).catch(() => null),
    getPublishedScripts(name, version).catch(() => ({})),
    getVersionMeta(name, version).catch(() => null),
  ]);

  const versionHistory = history || [];
  const entry = versionHistory.find(h => h.version === version);
  const ageDays   = entry?.ageDays ?? null;
  const publishedAt = entry?.publishedAt ?? null;

  // Dep diff vs previous version
  let depDiff = null;
  const prevVersion = await getPreviousVersion(name, version).catch(() => null);
  if (prevVersion) {
    depDiff = await diffDependencies(name, prevVersion, version).catch(() => null);
  }

  // For each newly added dep, fetch its own risk profile (one level deep).
  // FIX: use the exact version declared in the parent manifest, not depHistory[0].
  const newDepProfiles = {};
  if (depDiff && depDiff.added.length > 0) {
    await Promise.all(depDiff.added.map(async (dep) => {
      try {
        const depPackument = await getPackument(dep);
        if (!depPackument) { newDepProfiles[dep] = { error: 'not found' }; return; }

        // Use semver.maxSatisfying to resolve the exact version that npm
        // would install for the declared range. Handles all valid range
        // syntaxes: ^1.2.3, ~1.2.3, >=1.2.3 <2.0.0, 1.2.x, etc.
        const rawRange   = versionMeta?.dependencies?.[dep] || '';
        const depHistory = await getVersionHistory(dep);
        const allVersions = (depHistory || []).map(h => h.version);

        // maxSatisfying returns null when the range is not a valid semver range
        // (e.g. "latest", "next", git URLs) — we fall back gracefully.
        let resolvedExact = semver.validRange(rawRange)
          ? semver.maxSatisfying(allVersions, rawRange)
          : null;

        let depEntry = resolvedExact
          ? (depHistory?.find(h => h.version === resolvedExact) || null)
          : null;

        // exactVersionResolved=true means semver gave us a definitive match.
        // false means we fell back to the most-recently published version,
        // which may differ from what npm would actually install.
        const exactVersionResolved = !!depEntry;
        if (!depEntry) depEntry = depHistory?.[0] || null;

        // resolvedVersion: semver match if available, otherwise 'unknown'.
        // Never use inline regex stripping — that was the original bug.
        // If depEntry is null (no matching version in registry history),
        // we surface 'unknown' so callers know the scan was incomplete.
        const resolvedVersion = depEntry?.version || 'unknown';
        const depScripts = await getPublishedScripts(dep, resolvedVersion).catch(() => ({}));
        const firstPublished = depPackument.time?.created;

        newDepProfiles[dep] = {
          version: resolvedVersion,
          exactVersionResolved,
          ageDays:  depEntry?.ageDays  ?? null,
          publishedAt: depEntry?.publishedAt ?? null,
          firstPublishedAt: firstPublished ?? null,
          packageAgeDays: firstPublished
            ? Math.floor((Date.now() - new Date(firstPublished).getTime()) / 86_400_000)
            : null,
          hasLifecycleScripts: Object.keys(depScripts).length > 0,
          scripts: depScripts,
          totalVersions: depHistory?.length ?? null,
        };
      } catch (e) {
        newDepProfiles[dep] = { error: e.message };
      }
    }));
  }

  return {
    name,
    version,
    ageDays,
    publishedAt,
    hasLifecycleScripts: Object.keys(scripts).length > 0,
    scripts,
    provenance: provenanceRegression,
    previousVersion: prevVersion,
    depDiff,
    newDepProfiles,
    totalVersions: versionHistory.length,
  };
}

module.exports = {
  getPackument,
  resolveVersion,
  getVersionMeta,
  getVersionHistory,
  getPreviousVersion,
  diffDependencies,
  getProvenanceInfo,
  checkProvenanceRegression,
  getPublishedScripts,
  getVersionRiskProfile,
};
