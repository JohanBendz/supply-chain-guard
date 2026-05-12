'use strict';
/**
 * js-lexer.js
 *
 * Minimal hand-rolled tokenizer for JavaScript / TypeScript source.
 * Single purpose: produce a "code-only" view of source where comments,
 * regex literals, and template-literal text content have been removed,
 * while leaving STRING LITERALS INTACT (because they carry the
 * `require('pkg')` argument that downstream phantom detection needs).
 *
 * Why a lexer at all?
 *   The previous implementation used regex passes to strip comments
 *   before scanning. That heuristic is defeated by:
 *
 *     (a) block-comment syntax inside template literals
 *     (b) line-comment syntax inside string literals
 *     (c) regex literals containing comment-like sequences
 *     (d) string literal pairs that bracket "real" code between fake markers
 *
 *   A regex strip touches all four wrong. The only correct fix is to know
 *   the lexical state at every position. That's a state machine, not a regex.
 *
 * Design decision: STRINGS STAY IN CODE
 *   The downstream consumer is the require/import scanner. It NEEDS to see
 *   `require('pkg-name')` including the string literal. So we do NOT strip
 *   strings as a class. What we strip is exactly the contexts where a
 *   `require('x')`-looking sequence is NOT actually code:
 *     - Comments         (// ... and slash-star ... star-slash)
 *     - Template TEXT    (the literal portion of a template — but ${...} stays)
 *     - Regex literals   (/foo/g)
 *
 *   Strings stay because the lexer's knowledge of where strings end is
 *   exactly what defeats evasion (b) and (d): a // inside a string doesn't
 *   become a comment, and "/*" doesn't open a comment.
 *
 * Why not use acorn / espree?
 *   Adding a parser dependency to a supply-chain-security tool is exactly
 *   the kind of thing the tool is built to discourage. We keep scg's runtime
 *   dependency footprint at one (semver) on principle.
 *
 * Output:
 *   tokenize(src)   → { regions: [{kind, start, end}, ...] }
 *   extractCode(src) → same-length string with non-CODE replaced by spaces
 *                      (newlines preserved so line numbers stay aligned)
 */

const KIND = Object.freeze({
  CODE:          'CODE',
  STRING:        'STRING',  // string literal — included in extractCode output, but Unicode escapes inside are NOT normalized
  COMMENT:       'COMMENT',
  TEMPLATE_TEXT: 'TEMPLATE_TEXT',
  REGEX:         'REGEX',
});

// Single-character tokens that, as the last significant code character,
// mean a following `/` opens a regex literal rather than division.
// Standard "regex follows expression boundary" set.
const REGEX_PRECEDERS = new Set([
  '(', ',', '=', ':', '[', '!', '&', '|', '?', '{', '}', ';',
  '+', '-', '*', '%', '^', '~', '<', '>',
]);

// Multi-character keywords after which `/` starts a regex.
const REGEX_PRECEDING_KEYWORDS = new Set([
  'return', 'typeof', 'instanceof', 'in', 'of', 'new', 'delete',
  'void', 'throw', 'yield', 'await', 'case', 'do', 'else',
]);

function isIdentStart(code) {
  return (code >= 0x41 && code <= 0x5A) ||
         (code >= 0x61 && code <= 0x7A) ||
         code === 0x5F || code === 0x24;
}
function isIdentCont(code) {
  return isIdentStart(code) || (code >= 0x30 && code <= 0x39);
}

function tokenize(src) {
  if (typeof src !== 'string') return { regions: [] };
  const len = src.length;
  const regions = [];

  // Template interpolation stack: each entry stores the brace depth at
  // the moment we entered ${...}. When braceDepth returns to that value
  // via a closing `}`, we resume template-text consumption.
  const tplStack = [];
  let braceDepth = 0;

  // Significance tracking for regex-vs-division.
  let lastSigChar  = '';
  let lastSigIdent = '';

  let i = 0;
  let codeStart = 0;

  function emitCodeUpTo(end) {
    if (end > codeStart) regions.push({ kind: KIND.CODE, start: codeStart, end });
  }
  function emitNonCode(kind, start, end) {
    if (end > start) regions.push({ kind, start, end });
  }

  function slashIsRegex() {
    if (!lastSigChar) return true;
    if (REGEX_PRECEDERS.has(lastSigChar)) return true;
    if (lastSigIdent && REGEX_PRECEDING_KEYWORDS.has(lastSigIdent)) return true;
    return false;
  }

  // Consume a template body. The caller has already advanced i past either
  // the opening backtick or the closing `}` of an interpolation, and passed
  // tplRegionStart pointing at the first byte we should include in the
  // emitted TEMPLATE_TEXT region (typically i-1, to include the backtick or
  // closing brace).
  function consumeTemplateBody(tplRegionStart) {
    while (i < len) {
      const ch = src[i];
      if (ch === '\\') { i += 2; continue; }
      if (ch === '`') {
        i++;
        emitNonCode(KIND.TEMPLATE_TEXT, tplRegionStart, i);
        codeStart = i;
        return;
      }
      if (ch === '$' && src[i + 1] === '{') {
        i += 2;
        emitNonCode(KIND.TEMPLATE_TEXT, tplRegionStart, i);
        codeStart = i;
        tplStack.push({ braceDepth });
        braceDepth++;
        return;
      }
      i++;
    }
    // Unterminated template — emit what we have.
    emitNonCode(KIND.TEMPLATE_TEXT, tplRegionStart, i);
    codeStart = i;
  }

  while (i < len) {
    const c  = src[i];
    const c2 = src[i + 1];

    // Line comment
    if (c === '/' && c2 === '/') {
      emitCodeUpTo(i);
      const start = i;
      i += 2;
      while (i < len && src[i] !== '\n') i++;
      emitNonCode(KIND.COMMENT, start, i);
      codeStart = i;
      continue;
    }

    // Block comment
    if (c === '/' && c2 === '*') {
      emitCodeUpTo(i);
      const start = i;
      i += 2;
      while (i + 1 < len && !(src[i] === '*' && src[i + 1] === '/')) i++;
      if (i + 1 < len) i += 2;
      else i = len;
      emitNonCode(KIND.COMMENT, start, i);
      codeStart = i;
      continue;
    }

    // String literal — emitted as a separate STRING region. The string
    // (including its delimiters) is preserved verbatim in extractCode output
    // because the require/import scanner needs to see the literal argument.
    // String contents are NOT subject to Unicode-escape normalization, since
    // string escapes have different semantics from identifier escapes (they
    // expand at runtime, not parse time).
    if (c === '"' || c === "'") {
      emitCodeUpTo(i);
      const quote = c;
      const start = i;
      i++;
      while (i < len) {
        const ch = src[i];
        if (ch === '\\') { i += 2; continue; }
        if (ch === quote) { i++; break; }
        if (ch === '\n') break; // unterminated, recover
        i++;
      }
      emitNonCode(KIND.STRING, start, i);
      codeStart = i;
      lastSigChar  = quote;
      lastSigIdent = '';
      continue;
    }

    // Template literal
    if (c === '`') {
      emitCodeUpTo(i);
      const tStart = i;
      i++;
      consumeTemplateBody(tStart);
      lastSigChar  = '`';
      lastSigIdent = '';
      continue;
    }

    // Regex vs division
    if (c === '/' && slashIsRegex()) {
      emitCodeUpTo(i);
      const start = i;
      i++;
      let inCharClass = false;
      while (i < len) {
        const ch = src[i];
        if (ch === '\\') { i += 2; continue; }
        if (ch === '[' && !inCharClass) { inCharClass = true; i++; continue; }
        if (ch === ']' &&  inCharClass) { inCharClass = false; i++; continue; }
        if (ch === '/' && !inCharClass) { i++; break; }
        if (ch === '\n') break;
        i++;
      }
      while (i < len && /[gimsuyd]/.test(src[i])) i++;
      emitNonCode(KIND.REGEX, start, i);
      codeStart = i;
      lastSigChar  = '/';
      lastSigIdent = '';
      continue;
    }

    // Identifier
    if (isIdentStart(src.charCodeAt(i))) {
      let q = i + 1;
      while (q < len && isIdentCont(src.charCodeAt(q))) q++;
      lastSigIdent = src.slice(i, q);
      lastSigChar  = src[q - 1];
      i = q;
      continue;
    }

    // Brace tracking for template interpolation
    if (c === '{') {
      braceDepth++;
      lastSigChar  = c;
      lastSigIdent = '';
      i++;
      continue;
    }
    if (c === '}') {
      braceDepth--;
      const top = tplStack[tplStack.length - 1];
      if (top && braceDepth === top.braceDepth) {
        // Closing brace of an interpolation. Flush code up to (and not
        // including) this `}`, then resume template-text from this `}`.
        emitCodeUpTo(i);
        const reEnter = i;
        i++;
        tplStack.pop();
        consumeTemplateBody(reEnter);
        continue;
      }
      lastSigChar  = c;
      lastSigIdent = '';
      i++;
      continue;
    }

    if (c === ' ' || c === '\t' || c === '\n' || c === '\r') {
      i++;
      continue;
    }

    lastSigChar  = c;
    lastSigIdent = '';
    i++;
  }
  emitCodeUpTo(i);

  return { regions };
}

/**
 * Normalize Unicode escape sequences in identifier positions.
 *
 * JavaScript treats identifiers containing \uXXXX or \u{XXXX} as literally
 * equivalent to their unescaped form: `\u0072equire('x')` is the same as
 * `require('x')`. An attacker can use this to defeat the regex-based
 * import scanner — the lexer sees a CODE region containing `\u0072equire`,
 * the scanner's regex looks for the literal text `require`, no match, the
 * package is flagged as not-imported, and the malicious phantom dependency
 * slips through (or, conversely, a real require gets misclassified).
 *
 * Defense: replace \uXXXX and \u{XXXX} sequences in CODE regions with
 * their actual character values BEFORE running the require/import regex.
 * We deliberately do NOT normalize escapes inside string literals (those
 * are runtime escapes with different semantics) or comments (those are
 * not code). The lexer's region split makes this safe — STRING regions
 * are preserved verbatim, only CODE regions get the normalization pass.
 *
 * Note: this changes the length of the output relative to source. Same-
 * length preservation is sacrificed in exchange for closing the evasion
 * vector. Downstream consumers (the require/import regex pass) only care
 * about content, not byte offsets.
 */
function normalizeIdentifierEscapes(text) {
  // \u{XXXX...}  — extended escape, 1-6 hex digits
  // \uXXXX       — basic escape, exactly 4 hex digits
  return text
    .replace(/\\u\{([0-9a-fA-F]{1,6})\}/g, (_, hex) => {
      try {
        const cp = parseInt(hex, 16);
        if (cp > 0x10FFFF) return _;
        return String.fromCodePoint(cp);
      } catch { return _; }
    })
    .replace(/\\u([0-9a-fA-F]{4})/g, (_, hex) => {
      try {
        return String.fromCharCode(parseInt(hex, 16));
      } catch { return _; }
    });
}

/**
 * Produce a code-only view of the source where comments, regex literals,
 * and template literal text have been removed but string literals are
 * preserved (so `require('pkg')` arguments remain matchable). Unicode
 * identifier escapes in CODE regions are normalized to their literal form
 * to defeat lexer-bypass attacks like `\u0072equire('malware')`.
 */
function extractCode(src) {
  if (typeof src !== 'string') return '';
  const { regions } = tokenize(src);

  // Walk regions in order, building the output as a list of segments.
  // CODE regions are normalized; STRING regions are appended verbatim;
  // everything else is replaced by an equal-length run of spaces (with
  // newlines preserved so line numbers stay roughly aligned).
  //
  // We do NOT guarantee same-length output anymore — the Unicode
  // normalization pass changes length. The downstream consumer (the
  // require/import regex) doesn't care about positions.
  const out = [];
  let cursor = 0;
  for (const r of regions) {
    // Fill gaps between regions with spaces (shouldn't happen if regions
    // cover the source, but defensive)
    while (cursor < r.start) {
      out.push(src[cursor] === '\n' ? '\n' : ' ');
      cursor++;
    }
    if (r.kind === KIND.CODE) {
      out.push(normalizeIdentifierEscapes(src.slice(r.start, r.end)));
    } else if (r.kind === KIND.STRING) {
      // String literals are preserved verbatim — we need them so the
      // require('x') argument matches in the downstream regex.
      out.push(src.slice(r.start, r.end));
    } else {
      // COMMENT, TEMPLATE_TEXT, REGEX — replace with whitespace
      for (let p = r.start; p < r.end; p++) {
        out.push(src[p] === '\n' ? '\n' : ' ');
      }
    }
    cursor = r.end;
  }
  // Trailing gap
  while (cursor < src.length) {
    out.push(src[cursor] === '\n' ? '\n' : ' ');
    cursor++;
  }
  return out.join('');
}

module.exports = { tokenize, extractCode, KIND };
