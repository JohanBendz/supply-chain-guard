# Contributing to supply-chain-guard

Thanks for your interest. A few notes to make contribution smooth.

## Reporting bugs

- **Security issues**: do NOT file public GitHub issues. See
  [SECURITY.md](SECURITY.md) for the disclosure process.
- **Functional bugs**: file a GitHub issue with reproduction steps,
  `node --version`, `npm --version`, and the output of `scg doctor`.

## Submitting changes

1. Fork and branch.
2. Make sure `npm test` passes with all 461+ tests green.
3. If you add functionality, add tests. We do not accept feature changes
   without test coverage.
4. If you fix a bug, add a regression test that fails before the fix
   and passes after it.
5. Keep the dependency count at one (`semver`). Zero would be better but
   semver is non-trivial and worth the single entry.
6. Follow existing code style: 2-space indent, single quotes, no
   semicolons at end of lines is fine (we're inconsistent, don't obsess).

## Philosophy

scg is a security tool that defends against a specific class of attacks
(install-time script execution, phantom-dependency injection, provenance
regression). It is deliberately not a general-purpose supply-chain
analyzer. When in doubt about whether a feature belongs here, ask first.

We prefer simple code we can reason about over clever code we can't.
We prefer to document a limitation honestly over to hide it behind
clever heuristics.

## Commit messages

Imperative mood: "fix tar parser desync" not "fixed" or "fixing".
Include a one-line summary, blank line, then details if needed.

## Questions

Open a GitHub discussion, not an issue.
