# SCG Recipes

Optional patterns and snippets that work with `supply-chain-guard` but are
not part of the core install. Each recipe is self-contained — copy what
you need, leave the rest.

Recipes are NOT a security boundary. The actual protection scg provides
is enforced by the code in `src/` and the `.scg-lock` preinstall guard
injected by `scg init`. The patterns here are convenience layers that
make the right thing also be the easy thing.

---

## `./npm` and `./npm.cmd` — local muscle-memory shim

### What it does

If your team keeps reflexively typing `npm install` instead of `scg install`,
these two files give you a per-repo `./npm` command that routes the
dependency-changing subcommands through scg, while passing everything else
(`./npm test`, `./npm run build`, `./npm view ...`) through to real npm
unchanged.

```sh
./npm install         # → scg install
./npm ci              # → scg ci
./npm add lodash      # → scg add lodash
./npm update express  # → scg update express
./npm test            # → real npm test (unchanged)
./npm run build       # → real npm run build (unchanged)
./npm view react      # → real npm view (unchanged)
```

It also explicitly **blocks** two subcommands that would bypass scg:

- `./npm rebuild` → blocked, with a pointer to `scg rebuild-approved`
  (which performs the policy hash-binding check)
- `./npm exec` / `./npm x` → blocked, because npm exec fetches and runs
  code without going through `npm install`, so scg cannot intercept it

### What it is NOT

**This is not a security boundary.** A developer who runs `npm install`
directly (without `./`) is still blocked — the `.scg-lock` preinstall
guard runs regardless of whether you used the shim. The shim is purely
about convenience: making `./npm install` do the right thing so muscle
memory works for you instead of against you.

If someone replaces the shim with a malicious version that routes around
scg, the preinstall guard will still block the resulting raw `npm install`
because `SCG_ACTIVE` won't be set in the environment. The shim and the
guard are independent layers.

### Install

```bash
# From a clone of supply-chain-guard:
cp recipes/npm     /path/to/your/project/npm
cp recipes/npm.cmd /path/to/your/project/npm.cmd
chmod +x /path/to/your/project/npm
git -C /path/to/your/project add npm npm.cmd
git -C /path/to/your/project commit -m "chore: add scg muscle-memory shim"
```

The POSIX file (`npm`) handles macOS and Linux. The `.cmd` file handles
Windows (cmd.exe and PowerShell pick up `npm.cmd` automatically when you
run `.\npm install`). Commit both — they're harmless on the platform
they're not used on, and it means a teammate cloning the repo from the
other OS still gets the shim.

### How it finds the real npm

The POSIX shim searches `getconf PATH` first (the system-default PATH that
excludes user additions), then falls back to walking `$PATH` while
explicitly skipping its own directory and `.`. This avoids infinite
recursion if `.` is in PATH or if someone runs the shim from inside its
own directory. The Windows variant uses `where npm.cmd` and skips itself
by absolute path.

If neither lookup finds a real npm, the shim exits with code 127 and a
clear error message rather than trying to fall back silently.

### Why we ship this as a recipe instead of in `scg init`

Three reasons:

1. **Adoption signal**: building it into `scg init` would force the shim
   on every project that initialises scg. Some teams already have their
   own per-repo build scripts and don't want extra files in the root.
   Recipes are opt-in.

2. **Scope discipline**: scg is a security tool, not a dev-experience
   platform. Keeping the shim out of the core means scg's footprint stays
   small and the security claims stay simple to audit. The shim has zero
   security impact — there's no reason it should live next to the code
   that does have security impact.

3. **Honest intent**: the shim exists to address muscle memory, which is
   a UX problem we *think* might matter. Until users tell us otherwise,
   the recipe form lets us provide the answer without committing to
   maintaining it forever as a core feature.

If feedback shows that everyone copies the shim, the next version may
move it into `scg init --shim` or make it the default. For now: it's
right here, ready to copy.
