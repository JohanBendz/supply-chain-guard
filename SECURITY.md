# Security Architecture

## Defense layers (v0.8.0)

### Layer 1 — Wrapper enforcement (`scg install`, `scg add`, `scg ci`)
SCG wraps npm for all dependency-changing operations and forces `--ignore-scripts` unconditionally. Postinstall scripts never run during install. This is the primary defense.

### Layer 2 — Dynamic install guard (`.scg-lock`)
Every `scg install` / `scg add` / `scg ci` / `scg update` run generates a fresh 128-bit random token, writes it to `.scg-lock` (which is in `.gitignore` and **not** committed), and passes it as `SCG_ACTIVE` to the npm subprocess. The `preinstall` hook injected by `scg init` reads `.scg-lock` at runtime and validates `SCG_ACTIVE` against it. See "Layer 2 model change" below for the rationale.

**Why dynamic?** A static check like `if (!process.env.SCG_ACTIVE)` can be bypassed by adding `export SCG_ACTIVE=1` to `~/.zshrc`. A per-session token prevents that accidental/stale global bypass pattern. This is a muscle-memory guard, not a strong boundary against an active local attacker who deliberately reads the current token.

SCG sets `SCG_ACTIVE=<token>` in its own npm subprocess via `runSafe()`, so the guard is transparent when SCG is in control. Raw `npm install` lacks the token → exit 1.

### Layer 3 — Post-install inspection (`.scg-policy.json`)
After every install, SCG reads `package-lock.json` and installed `package.json` files. Each package with lifecycle scripts is checked against `.scg-policy.json`:
- **blocked** (in `deniedBuilds`) → install fails, exit 1
- **needsApproval** (scripts present, not in policy) → warning, no scripts ran
- **approved** (in `approvedBuilds`) → script hash verified immediately; changed scripts require re-approval

### Layer 4 — Script hash binding (SRI)
`scg policy approve-build` records a `sha256:` hash of the approved script text at approval time. Post-install inspection and `scg rebuild-approved` both re-read the installed scripts and recompute the hash. A mismatch (package compromised after approval) is reported as `approvedChanged`, blocks rebuild, and requires re-approval.

### Layer 5 — Pre-flight registry checks (`scg add`, `scg check`)
Before installing a candidate package, SCG first resolves unversioned specs, dist-tags, exact versions, and semver ranges to a concrete version, then queries the npm registry for:
- Provenance regression (previous version used OIDC, this one doesn't)
- New dependencies with lifecycle scripts
- Brand-new packages (<7 days old, ≤3 versions)
- Version age within cooldown window

### Layer 6 — Phantom dependency detection (`scg phantom`, `scg check`)
Manifest heuristic (offline, fast): checks whether a new dep is referenced in the parent package's `main`, `exports`, `files`, `scripts`, `readme` fields.

Tarball scan (network, HIGH confidence): downloads the parent `.tgz`, extracts JS/TS files, scans for `require()`/`import` of the dep. Results in `LIKELY_PHANTOM` (HIGH confidence) if never imported.

**Tar-bomb protection:** compressed size limit (50 MB), streaming byte counter aborts mid-download, uncompressed size limit (200 MB), file count limit (5 000 entries).

## Remaining limitations

| Attack vector | Mitigated? | Notes |
|---|---|---|
| Compromised maintainer publishes unapproved version | ✅ Layers 1–5 | Pre-flight detects provenance regression + new deps with scripts |
| Developer types `npm install` by habit | ✅ Layer 2 | Dynamic token guard blocks accidental raw npm use |
| Stale `export SCG_ACTIVE=<token>` in `~/.zshrc` | ✅ Layer 2 | Token rotates; stale global values fail |
| Active local attacker deliberately reads `.scg-lock` and sets `SCG_ACTIVE` | ❌ Out of scope | The guard is not a local privilege boundary |
| `npm install -g unapproved-tool` (global) | ❌ Out of scope | Project-level guard doesn't apply; requires OS-level hooking or education |
| Approved native module compromised post-approval | ✅ Layers 3–4 | Script hash mismatch is reported during inspection and blocks rebuild |
| Tar-bomb DoS via tarball scan | ✅ Layer 6 | Three-stage size/count limits |
| Path traversal in tar entries | ✅ Layer 6 | In-memory only; entry names used for display only, not for fs writes |
| Yarn/pnpm users | ⚠️ Partial | Lockfile reader supports npm only; install inspector falls back to node_modules scan |
| Monorepos | ⚠️ Partial | Policy and phantom scan start from package.json root; use `--src` for explicit paths |

---

## v0.8.0 updates

### Wrapper argument preservation

Wrapper commands preserve npm flags and remove only SCG-owned flags before spawning npm. This avoids silent intent drift such as dropping `--omit=dev`, `--workspace app`, or `--legacy-peer-deps`.

### Range/tag resolution

Pre-flight resolves exact versions, semver ranges, dist-tags, and unversioned specs to concrete versions before scoring. Registry checks are no longer attempted against literal range strings such as `^1.14.0`.

### Policy settings enforcement

`.scg-policy.json.settings.cooldownDays` and `.scg-policy.json.settings.failOn` are active command defaults. CLI flags override policy only for the current invocation.

### Pure JSON check output

`scg check --json` writes only JSON to stdout. Human-readable progress output is suppressed so CI can parse it safely.

### Layer 2 model change — per-session tokens, not committed

`.scg-lock` is **not committed to git**. It is generated fresh at the start of every `scg install`, `scg add`, `scg ci`, and `scg update` run. `scg init` adds it to `.gitignore`.

**Why not committed?**
If the token is committed, anyone who clones the repo can read it and add `export SCG_ACTIVE=<token>` to `~/.zshrc`. Since the token changes every session, this is always stale for normal muscle-memory bypasses — there is nothing useful to hardcode in a shell profile.

**CI model:**
```yaml
- run: npm install -g supply-chain-guard
- run: scg ci          # generates .scg-lock, then runs npm ci --ignore-scripts
- run: scg rebuild-approved
```

Raw `npm ci` before `scg ci` will trigger the preinstall guard if `.scg-policy.json` exists. Guard behavior when `.scg-lock` is missing:

| `.scg-policy.json` | `.scg-lock` | Result |
|---|---|---|
| Missing | Missing | warn + pass (not yet initialized) |
| Present | Missing | **block** — use `scg ci` first |
| Present | Present, wrong token | **block** — stale token |
| Present | Present, correct token | pass |

### `scg update` — explicit targets required (Issue 1)

`scg update` without a package list now exits 1 with a clear explanation. Use `scg update <pkg>` for preflight-checked individual updates, or `scg update <pkg> --all` to update all packages with post-install inspection but no per-package preflight.

### Registry cache (Issue B)

Packument data is cached in memory and on disk (5-minute TTL) to avoid redundant registry round-trips during `scg add pkg1 pkg2` and `scg update --all` flows.

### Co-change detection (Issue 3)

`scg doctor` now checks whether `.scg-policy.json` and `package.json`/`package-lock.json` are changed in the same git diff, and warns if so.


---

## Threat model

This section articulates what scg defends against and what it does not,
so users can make informed decisions about their defense-in-depth posture.
Updated for v0.8.0 based on adversarial review rounds 1-6.

### In scope — these attacks scg deterministically defends against

**Install-time script execution.** `postinstall`, `preinstall`, `install`,
and `prepare` scripts in direct or transitive dependencies cannot run
during `scg install` / `scg add` / `scg ci` / `scg update`. This is
enforced by `--ignore-scripts` and the per-session `.scg-lock` guard
against raw `npm install`. (Layers 1, 2.)

**Phantom dependency injection.** A malicious package declared in a
parent's `package.json` but never imported anywhere in its source —
the axios/`mock-unapproved-dep` attack pattern — is detected by
`scg phantom` (for the current project) and by `scg add` / `scg check`
(for candidate packages via registry-side manifest scan, with optional
tarball-level source scan at HIGH confidence). (Layer 6.)

**Provenance regression.** A version published without OIDC
trusted-publishing attestation when previous versions had one — the
"stolen maintainer token" pattern — is detected by `scg check` / `scg add`
pre-flight. (Layer 5.)

**Script tampering after approval.** After
`scg policy approve-build <pkg>@<ver>`, the approved script text is
hashed and recorded. If the installed script changes later, post-install
inspection reports `approvedChanged` and `scg rebuild-approved` blocks
the rebuild. (Layers 3, 4.)

**Lexer-evasion phantom attacks.** Attempts to hide a `require()` or
`import` call from the phantom scanner using `\u0072equire` Unicode
identifier escapes, fake requires in comments, block-comment syntax
inside template literals, and other lexical tricks are defeated by
the state-machine lexer. (`src/js-lexer.js`.)

**Tar desync / differential parsing attacks.** A `.tgz` containing
two entries with the same path — where an in-memory scanner sees one
file and the on-disk extractor sees another — is rejected by the
tarball parser. (`parseTar` in `src/delta-phantom.js`.)

**Confused-deputy via environment injection.** A non-script package's
functional code setting `NODE_OPTIONS="--require ./payload.js"` to
inject into a later `scg rebuild-approved` run is defeated by the
env sanitization pass that strips `NODE_*` and `npm_config_node_options*`
variables before spawning the rebuild subprocess. (`sanitizeEnv` in
`src/npm.js`.)

**Muscle-memory bypass.** `npm install` / `npm ci` by habit in a scg-
initialized project is blocked by the preinstall guard, which runs
regardless of whether the optional `recipes/npm` shim is installed. This
protects against accidental raw npm use, not against a developer or local
attacker deliberately extracting the live token.

### Out of scope — scg explicitly does NOT defend against these

**Dynamic require obfuscation.** Constructing the string "require" at
runtime (`globalThis['req'+'uire']('x')`, `eval('req'+'uire')`,
`Function('return req'+'uire')()`, dynamic `import(base+suffix)`) is
not detectable by static analysis. scg's phantom detection catches
the *structural* anti-pattern (dep declared but not referenced in
source), but cannot prove that no execution path reaches an obfuscated
call. For this threat class, use a runtime monitor (policy-based node
sandbox, container allowlist) as a separate layer.

**npx / npm exec social engineering.** `npx some-tool init` fetches
and executes code without going through `npm install`, so no install-
time control can intercept it. scg flags `npx` uses in your own
`package.json` scripts (`scg doctor`) but cannot protect you from
README instructions telling you to run `npx` in your terminal.

**File-system tampering outside scg's control.** If an attacker has
write access to `node_modules/`, `.bin/` symlinks, or other files in
the project tree *outside* the normal install flow, scg's install-time
controls don't apply. Defense is OS-level file permissions, not scg.

**Compromised developer workstation.** If the developer's machine is
already compromised (keylogger, malicious global npm module,
compromised shell rc), scg running in that environment cannot be a
trust anchor. scg assumes the local Node.js, npm binary, and the scg
install itself are trustworthy.

**Runtime payloads in functional code.** If an attacker publishes a
package whose *normal* runtime behavior exfiltrates data when your
application uses it, scg's install-time checks don't help. This is a
different threat class (application security / dependency behavior
auditing), addressed by tools like Socket, Snyk, or manual code review.

**Typosquatting / lookalike packages.** scg will happily install
`lodahs` if you type it. Pre-flight signals (brand-new package, no
download history) provide partial protection, but scg is not a
typo-resolution tool.

**Compromised npm registry.** scg trusts what `registry.npmjs.org`
returns. A registry-level compromise (the attacker controls the
registry response itself) bypasses all registry-based pre-flight
checks. Mitigation: use a trusted private registry with integrity
verification.

### Threat-model maturity

scg v0.8.0 has been through six adversarial review rounds, each of
which found real bugs. That track record should be read two ways:

1. **Positive**: each round produced deterministic fixes with
   regression tests. The attacks found are now blocked and will
   stay blocked.
2. **Realistic**: each round found bugs the previous rounds missed.
   Further review will find more. This threat model represents
   scg's *current* defensive posture, not a provably exhaustive
   enumeration of possible attacks.

---

## Reporting security issues

If you believe you have found a security vulnerability in
supply-chain-guard, please report it privately. Do **not** open a
public GitHub issue for security reports.

**Preferred channels:**
- GitHub Security Advisories (private vulnerability reporting)
- Email: scg@bortbytt.se

**What to include:**
- A description of the vulnerability and its impact
- Steps to reproduce, ideally with a minimal proof-of-concept
- Your suggested fix or mitigation, if you have one
- Whether you would like public credit in the advisory

**What to expect:**
- Acknowledgement within 72 hours
- An initial assessment within 7 days
- A coordinated disclosure timeline agreed with you, typically
  30-90 days depending on severity and complexity
- Public credit in the advisory unless you prefer anonymity

scg does not currently offer a bug bounty. We will credit every
legitimate report in the advisory and the changelog.

**Do NOT report through these channels:**
- Public GitHub issues
- Social media
- Pull requests that describe the vulnerability in the commit message

Thanks for helping keep the JavaScript ecosystem safer.
