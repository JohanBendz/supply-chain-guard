'use strict';
/**
 * spec.js
 *
 * Shared package spec parser. A "spec" is a string identifying an npm
 * package, optionally with a version: "foo", "foo@1.2.3",
 * "@scope/foo", "@scope/foo@^2.0.0", "foo@latest".
 *
 * The parser must handle scoped packages correctly: a leading "@" is
 * part of the package name, NOT a version separator. Splitting on the
 * *first* "@" after position 0 (or *last* "@" — they happen to give the
 * same answer for these inputs) is the correct rule. Several callsites
 * in the codebase used to inline this with `lastIndexOf('@')`, which is
 * subtle and easy to get wrong, so the canonical implementation lives
 * here and both bin/scg.js and src/rebuild.js import it.
 */

/**
 * Parse a package spec into { name, version }.
 * version is null when no version was provided.
 *
 * Examples:
 *   parseSpec('foo')              → { name: 'foo',         version: null }
 *   parseSpec('foo@1.2.3')        → { name: 'foo',         version: '1.2.3' }
 *   parseSpec('@scope/foo')       → { name: '@scope/foo',  version: null }
 *   parseSpec('@scope/foo@1.0.0') → { name: '@scope/foo',  version: '1.0.0' }
 *   parseSpec('foo@latest')       → { name: 'foo',         version: 'latest' }
 *   parseSpec('foo@^2.0.0')       → { name: 'foo',         version: '^2.0.0' }
 */
function parseSpec(spec) {
  if (typeof spec !== 'string' || spec.length === 0) {
    return { name: spec || '', version: null };
  }
  // For "@scope/foo@1.2.3" we want the @ AFTER the scope, not the leading one.
  const searchFrom = spec.startsWith('@') ? 1 : 0;
  const atIdx      = spec.indexOf('@', searchFrom);
  if (atIdx <= 0) return { name: spec, version: null };
  return { name: spec.slice(0, atIdx), version: spec.slice(atIdx + 1) };
}

/**
 * Build a "name@version" key, or just "name" when no version is given.
 * Inverse of parseSpec for the most common use case.
 */
function buildSpec(name, version) {
  return version ? `${name}@${version}` : name;
}

module.exports = { parseSpec, buildSpec };
