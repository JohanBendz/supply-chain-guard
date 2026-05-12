# supply-chain-guard

**The secure front door for npm dependency management.**

> **Status: pre-1.0 (v0.8.0).** Core functionality is stable and covered by
> 471 tests across six adversarial review rounds. The CLI surface and
> `.scg-policy.json` schema may still evolve before 1.0. Security-critical
> behavior (the defense layers documented in [SECURITY.md](SECURITY.md))
> is considered stable.

SCG wraps npm for all dependency-changing operations, forces `--ignore-scripts` by default, enforces a repo-local build approval policy, and detects phantom dependencies.

---

## Verified to prevent

On March 31, 2026, axios was compromised:

1. Attacker hijacked the maintainer's npm credentials
2. Published `axios@1.14.1` containing a new dependency: `mock-unapproved-dep@4.2.1`
3. `mock-unapproved-dep` had a `postinstall` script that ran automatically during `npm install`
4. The script downloaded and executed a cross-platform RAT (remote access trojan)
5. `mock-unapproved-dep` was **never imported anywhere in axios's source** — it existed only to run its `postinstall` hook

On May 11, 2026, the TanStack ecosystem was compromised via the Mini Shai-Hulud campaign:

1. Attacker chained GitHub Actions vulnerabilities (pull_request_target + cache poisoning + OIDC extraction)
2. Published 84 malicious versions across 42 @tanstack/* packages 
3. Injected ~2.3MB obfuscated `router_init.js` with credential harvesting payload
4. Payload targeted CI credentials (GitHub OIDC, AWS, GCP, Vault, Kubernetes)
5. Self-propagated via npm maintainer enumeration
6. **Zero imports of the malicious code in legitimate source** — pure phantom dependency pattern

---

## Install

```bash
npm install -g supply-chain-guard
```

## Quick start

```bash
# One-time project setup
scg init

# Use these instead of raw npm
scg add express          # instead of: npm install express --save
scg install              # instead of: npm install
scg ci                   # instead of: npm ci  (in CI pipelines)
scg update lodash        # instead of: npm update lodash

# If a package needs native compilation (esbuild, sharp, bcrypt...)
scg policy approve-build esbuild@0.21.5
scg rebuild-approved

# Commit the policy to source control
git add .scg-policy.json && git commit -m "chore: approve esbuild build"
```

### Tip: a local `./npm` shim for muscle memory

If your team keeps reflexively typing `npm install` instead of `scg install`,
you can drop a tiny shim into your repo root that routes the dependency-
changing subcommands through scg, while passing everything else (`./npm test`,
`./npm run build`) through to real npm. Two ready-to-copy files live in
[`recipes/npm`](recipes/npm) (POSIX) and [`recipes/npm.cmd`](recipes/npm.cmd)
(Windows). See [`recipes/README.md`](recipes/README.md) for the full
explanation.

This is **not a security boundary** — the actual protection against raw
`npm install` is the `.scg-lock` preinstall guard injected by `scg init`,
which runs regardless of whether you used the shim. The recipe is purely
about convenience: making the right thing also be the easy thing.

We ship this as an opt-in recipe rather than baking it into `scg init`
because it's a UX question, not a security one, and we'd rather you
choose it than be forced into it.

---

## How it works

### 1. All installs run with `--ignore-scripts`

Every `scg install`, `scg ci`, `scg add`, `scg update`, and `scg remove` calls npm with `--ignore-scripts` forced on. SCG strips its own wrapper flags (`--dry-run`, `--deep`, `--cooldown`, `--fail-on`, `--force`, `--all`) before spawning npm, but preserves npm flags such as `--omit=dev`, `--workspace app`, `--legacy-peer-deps`, and `--save-exact`. Postinstall scripts **never run automatically**.

```
scg add axios@1.14.1
→ npm install axios@1.14.1 --save --ignore-scripts
```

This is the primary defense. Scripts don't run. RATs don't download.

### 2. Post-install inspection against `.scg-policy.json`

After every install, SCG reads `package-lock.json` and the installed `package.json` files to find packages that declare lifecycle scripts. It checks each against the repo-local policy:

- **Blocked** (in `deniedBuilds`) → install fails with exit 1
- **Unapproved** (has scripts, not in policy) → warning with approval instructions
- **Approved** (in `approvedBuilds`) → noted; rebuild via `scg rebuild-approved`
- **Clean** (no scripts) → silently passes

### 3. Explicit rebuild approval

Native modules that genuinely need `postinstall` (esbuild, sharp, bcrypt, sqlite3) are handled through an explicit approval flow:

```bash
scg policy approve-build esbuild@0.21.5    # review and approve
scg rebuild-approved                        # run npm rebuild for approved packages only
```

The approval is recorded in `.scg-policy.json` with the approver identity, the actual script text, and a SHA-256 hash of that script object. Commit it to source control so CI and the whole team share the same policy. If the installed script text changes after approval, SCG reports an approved-script change during install inspection and blocks `scg rebuild-approved` until the package is reviewed and re-approved.

### 4. Pre-flight registry checks

`scg add` and targeted `scg update` run a pre-flight registry check before installing. Version specs are resolved first, so exact versions, dist-tags, unversioned specs, and semver ranges such as `^1.2.3` are checked against the concrete version npm would install:

```bash
scg add axios@1.14.1
→ Pre-flight: axios@1.14.1... CRITICAL
  ✖ CRITICAL  NEW_DEP_WITH_SCRIPTS  — mock-unapproved-dep@4.2.1 has postinstall
  ✖ CRITICAL  NEW_DEP_BRAND_NEW_PACKAGE — pkg 0d old, 2 total versions
  ✖ CRITICAL  PROVENANCE_REGRESSION — 1.14.0 used OIDC; 1.14.1 did not
  Pre-flight failed. Use --force to install anyway.
```

Three independent signals from three different data sources, all pointing the same way.

---

## Policy file

`scg init` creates `.scg-policy.json` in your project root. **Commit this file.**

```json
{
  "version": 1,
  "approvedBuilds": {
    "esbuild@0.21.5": {
      "approvedAt": "2026-04-05T12:00:00.000Z",
      "approvedBy": "git:John Doe",
      "scripts": { "postinstall": "node install.js" }
    }
  },
  "deniedBuilds": {
    "mock-unapproved-dep@4.2.1": {
      "deniedAt": "2026-04-05T12:00:00.000Z",
      "reason": "unapproved-script — axios supply chain attack"
    }
  },
  "settings": {
    "cooldownDays": 3,
    "failOn": "HIGH"
  }
}
```

Policy is enforced identically in local dev, CI, and any other environment that runs `scg`. `settings.cooldownDays` and `settings.failOn` are active defaults for pre-flight and audit commands; CLI flags can override them for a single run.

---

## Commands

### Wrapper commands

```bash
scg add <pkg>[@ver]           # preflight + npm install --ignore-scripts
scg install                   # npm install --ignore-scripts
scg ci                        # npm ci --ignore-scripts
scg update [pkg...]           # npm update --ignore-scripts
scg remove <pkg>              # npm uninstall --ignore-scripts
scg rebuild-approved [pkg...] # npm rebuild for policy-approved packages only
```

### Policy management

```bash
scg policy approve-build <pkg>[@ver]              # approve a package's build scripts
scg policy deny-build   <pkg>[@ver] --reason "…"  # explicitly block a package
scg policy list                                   # show current policy
```

### Setup

```bash
scg init              # creates .scg-policy.json + .gitignore update
scg init --npmrc      # also writes .npmrc with ignore-scripts=true
scg init --gha        # also generates GitHub Actions workflow
scg init --dry-run    # preview without writing
```

### Analysis

```bash
scg check <pkg>[@ver]         # pre-flight registry check (provenance, dep diff, age)
scg audit                     # full project audit: policy + lockfile + phantom + snapshot
scg phantom [--src <dir>]     # detect dependencies declared but never imported in source
scg scripts                   # list all unapproved lifecycle scripts
```

### Escape hatch

```bash
scg npm -- <raw npm args>     # raw npm passthrough (prints warning, scripts NOT suppressed)
```

### Legacy / diagnostic

```bash
scg snapshot --pre/--post     # snapshot node_modules state (for diff-based workflows)
scg diff [--fail-on HIGH]     # compare pre/post snapshots
```

---

## CI integration

### GitHub Actions

```yaml
# Generated by: scg init --gha
- name: Install supply-chain-guard
  run: npm install -g supply-chain-guard

- name: Install dependencies (scripts suppressed)
  run: scg ci

- name: Rebuild approved native modules
  run: scg rebuild-approved

- name: Audit
  run: scg audit
```

### Azure DevOps / generic CI

```bash
npm install -g supply-chain-guard
scg ci
scg rebuild-approved
scg audit
```

The `.scg-policy.json` in the repo is the single source of truth — CI enforces the same approved/denied policy as local dev.

---

## Native modules

Packages like `esbuild`, `sharp`, `bcrypt`, `sqlite3`, `canvas` need their `postinstall`/`install` scripts to compile native binaries. With SCG the workflow is:

```bash
# 1. Install without running scripts
scg add esbuild

# 2. SCG reports it as needing approval:
#    ! esbuild@0.21.5  [postinstall: node install.js]

# 3. Review the script, then approve
scg policy approve-build esbuild@0.21.5

# 4. Run the build
scg rebuild-approved

# 5. Commit the policy
git add .scg-policy.json && git commit -m "chore: approve esbuild@0.21.5 build"
```

On CI, `scg rebuild-approved` reads the committed policy and rebuilds only those packages.

---

## Phantom dependency detection

The `scg phantom` command scans your project's source files for `require()` and `import` statements and compares them against `package.json`. Any declared dependency **never actually imported** is flagged.

This is the direct structural signature of the axios attack — `mock-unapproved-dep` was in axios's `package.json` but had zero references in 86 source files.

```bash
cd node_modules/axios
scg phantom --src lib

# ⚠ PHANTOM DEPENDENCIES DETECTED
# ✖  mock-unapproved-dep   (0 imports in source, declared in package.json)
```

---

## Options

| Flag | Default | Commands |
|---|---|---|
| `--dry-run` | off | add, install, ci, update, remove, rebuild-approved, init |
| `--force` | off | add, update (bypass pre-flight block) |
| `--cooldown <n>` | policy `settings.cooldownDays` or 3 | add, update, check, audit, diff |
| `--fail-on <sev>` | policy `settings.failOn` or HIGH | add, update, audit, diff |
| `--json` | off | check (pure JSON on stdout) |
| `--npmrc` | off | init |
| `--gha` | off | init |

---

## Architecture

```
src/
  policy.js          # .scg-policy.json: approve/deny builds, load/save
  npm.js             # safe npm wrapper — forces --ignore-scripts
  spec.js            # npm package spec parsing
  lockfile.js        # package-lock.json reader (v1/v2/v3), diff
  install-inspector.js  # post-install policy enforcement
  rebuild.js         # npm rebuild for approved packages only
  check.js           # pre-flight risk scorer (signals → CRITICAL/HIGH/WARN)
  registry.js        # npm registry client (provenance, dep diff, exact version)
  diff.js            # snapshot-based dependency diff
  snapshot.js        # node_modules state snapshots
  phantom.js         # require/import scanner for phantom detection
  delta-phantom.js   # manifest and tarball phantom checks for dep changes
  postinstall-guard.js  # legacy lifecycle script whitelist
  reporter.js        # terminal output with ANSI color

bin/
  scg.js             # CLI entry point

test/
  run.js                      # snapshot, diff, phantom, edge cases
  check.test.js               # pre-flight scoring
  policy.test.js              # policy CRUD
  npm.test.js                 # --ignore-scripts enforcement
  lockfile.test.js            # lockfile parsing and diff
  install-inspector.test.js   # post-install policy enforcement
  rebuild.test.js             # rebuild-approved flow
  registry-exactversion.test.js  # exact-version bug regression
  delta-phantom.test.js       # manifest phantom analysis
  init.test.js                # scg init behavior
```

---

## v0.8.0 updates

### Wrapper compatibility

SCG now keeps npm's intent intact for wrapper commands. npm flags are preserved and passed through to npm, while SCG-only flags are consumed by SCG and removed from the spawned npm command. This fixes cases such as:

```bash
scg install --omit=dev --legacy-peer-deps
scg ci --workspace app
scg add lodash --save-exact
```

### Version resolution before pre-flight

Pre-flight checks now resolve unversioned specs, dist-tags, exact versions, and semver ranges to a concrete version before risk scoring. That means `scg add axios@^1.14.0` checks the resolved version instead of trying to query the registry for the literal range string.

### Policy settings are active defaults

`.scg-policy.json.settings.cooldownDays` and `.scg-policy.json.settings.failOn` now drive command behavior by default. CLI flags still override policy for a single invocation.

### JSON output contract

`scg check --json` now writes only JSON to stdout. Human headers and progress lines are suppressed so CI tools can safely parse the output.

### Earlier script-hash enforcement

Approved build scripts are checked during post-install inspection, not only during `scg rebuild-approved`. A package approved in policy but changed on disk is reported as `approvedChanged` and treated as unclean until re-approved.

---

## Known limitations / follow-ups

- **Monorepo support**: `scg phantom` and policy lookup start from the package.json root. Workspaces need explicit `--src` paths.
- **Yarn / pnpm lockfiles**: `src/lockfile.js` reads `package-lock.json` only. `yarn.lock` and `pnpm-lock.yaml` are not yet parsed (install-inspector falls back to node_modules scan).
- **Socket Security feed integration**: `check` uses the npm registry directly. A Socket API integration would give pre-publication malware signals.

---

## Security architecture (v0.8.0)

See [SECURITY.md](./SECURITY.md) for full defense-in-depth documentation.

### Dynamic install guard (`.scg-lock`)

Every `scg install` / `scg add` / `scg ci` / `scg update` run generates a fresh 128-bit random token, writes it to `.scg-lock` (which is in `.gitignore` and never committed), and passes it as `SCG_ACTIVE` to the npm subprocess. The `preinstall` hook reads `.scg-lock` and validates the match. This is a muscle-memory guard against accidental raw `npm install`, not a strong boundary against an active local attacker who can deliberately read the current token.

**Why not `SCG_ACTIVE=1`?** Any developer can add `export SCG_ACTIVE=1` to `~/.zshrc` and silently re-enable raw `npm install`. A per-session token prevents that accidental/stale global bypass pattern.

```bash
scg init                 # installs the preinstall guard
scg install              # generates a fresh .scg-lock token for that session
# .scg-lock is NOT committed — it is regenerated per-session by every
# scg install / scg add / scg ci / scg update run. CI uses scg ci, which
# generates a fresh token before npm ci runs.
```

### Script hash binding

`scg policy approve-build esbuild@0.21.5` records a SHA-256 hash of the approved lifecycle scripts. Post-install inspection and `scg rebuild-approved` both re-read the installed scripts and verify the hash matches. A package that was compromised after approval (changed `postinstall`) will fail with:

```
✖ Script changed since approval — re-run: scg policy approve-build esbuild@0.21.5
```

This ensures the approval gate cannot be silently bypassed by a future update.
