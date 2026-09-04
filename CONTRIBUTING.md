# Contributing to dig-store

Thanks for taking the time to contribute. This repo is a submodule of the DIG Network
ecosystem and follows the ecosystem-wide GitHub Flow described here.

## Filing an issue

- Search existing issues first to avoid duplicates.
- Describe the problem or proposal concretely: what you expected, what happened, and
  how to reproduce it (for a bug) or why it's needed (for a feature).
- Include crate version (`Cargo.toml` `version`, or `cargo tree -p dig-store`) and
  environment details for bug reports.

## Contributing code

1. **Fork or branch.** `main` is a protected branch — no direct pushes, no force-push,
   no direct commits. All work happens on a branch, named after its
   [Conventional Commit](https://www.conventionalcommits.org/) type
   (`feat/...`, `fix/...`, `docs/...`, `chore/...`, etc).
2. **Write a failing test first (TDD).** No production code without a failing test
   that expresses the desired behaviour. Fix a bug by first reproducing it with a
   regression test, then making it pass. Keep the regression test permanently.
3. **Keep coverage at or above the floor.** This repo's CI enforces a
   **≥80% line-coverage gate** — a PR that drops coverage below the floor
   fails the build. Cover real logic, branches, and error paths; don't chase
   coverage on generated/glue code.
4. **Bump the version.** Every PR that changes behaviour, fixes a bug, or otherwise
   warrants a release bumps `version` in the root `Cargo.toml` as the **last commit
   before merge**, following SemVer:
   - **patch** — a compatible fix, or a chore/docs/test/refactor with no behaviour
     change.
   - **minor** — a compatible new capability (backwards-compatible addition).
   - **major** — a breaking change (removed/renamed API, changed wire/format/schema,
     or a changed default).

   A CI gate fails any PR whose version does not increase over `main`. After bumping
   `Cargo.toml`, run `cargo update -w --offline` **before** staging `Cargo.lock`, so
   the lockfile's own record of this crate's version stays in sync.
5. **Conventional Commits.** Every commit message and PR title follows
   `type(scope): summary` (`feat|fix|docs|style|refactor|perf|test|build|ci|chore`).
   CI lints this — a non-conforming message fails the PR.
6. **Open a PR against `main`.** The PR body should state what changed and how you
   verified it. Once opened, `main` must be re-merged into your branch before merge
   (branch protection requires the PR be up to date) and every review thread —
   including any automated security-scanning comment — must be resolved.

## Required status checks

`main` is protected and requires every one of these checks to pass, at the current
commit, before a PR can merge:

- `Format / Clippy / Build / Docs`
- `Coverage (>=80% lines)`
- `Lint commit messages`
- `Check version increment`
- `Cargo.lock own-version matches Cargo.toml`

If a check doesn't exist yet in branch protection, see `.github/workflows/` for the
CI jobs this repo runs — new checks are added there as the pipeline grows.

## Review & merge

PRs are squash-merged only, producing exactly one Conventional Commit on `main`. A PR
merges only when every required check is green and every review thread is resolved —
there are no exceptions for "small" changes.
