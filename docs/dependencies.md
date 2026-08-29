# Dependency maintenance

yamldap uses [upd](https://github.com/rvben/upd) for reviewable dependency
maintenance. The automation produces rolling pull requests; it never writes to
the default branch and does not enable auto-merge.

## Update policy

- Rust dependencies in both `Cargo.toml` files and their lockfiles are updated
  together.
- GitHub Actions remain pinned to immutable commit SHAs. upd verifies the
  existing version annotation before moving the SHA and annotation together.
- Ordinary updates wait seven days after publication and are capped at minor
  releases. Breaking upgrades remain deliberate maintainer work.
- The proposed tree must pass formatting, compilation, strict Clippy, all
  tests, and documentation checks before upd may publish its rolling pull
  request. The pull request then runs the repository's full cross-platform CI.
- A separate daily OSV remediation workflow may bypass the cooldown and bump
  ceiling to reach the minimum known-safe Rust versions. Its publication
  boundary permits changes only to the two Cargo manifests and lockfiles.
- Docker base-image digests are outside upd's supported ecosystems and remain a
  deliberate, separately reviewed maintenance task.

The schedules and immutable reusable-workflow pins live in
`.github/workflows/dependencies.yml` and
`.github/workflows/dependency-security.yml`. Project defaults live in
`.updrc.toml`.

## Publication credentials

The reusable workflows prepare and validate proposals with read-only repository
access. Publication requires an independently installed GitHub App so that the
generated pull request can trigger normal repository checks, including when an
Actions workflow changes.

Configure:

- Repository or organization variable `UPD_APP_CLIENT_ID`.
- Repository or organization secret `UPD_APP_PRIVATE_KEY` containing the App's
  PEM private key.
- App repository permissions: Contents read/write, Pull requests read/write,
  and Workflows read/write.

Without those values the workflows remain fail-closed: they can validate an
eligible proposal but cannot publish it.

## Local use

```bash
make upd-check                 # preview eligible minor and patch updates
make upd-update                # apply them and refresh affected lockfiles
make upd-update UPD_MAX_BUMP=major  # deliberately include breaking upgrades
make upd-audit                 # query OSV without changing files
```

When checking Actions locally, set `GITHUB_TOKEN` to a read-only token if
GitHub's anonymous API rate limit is exhausted. Scheduled runs receive the
workflow's read-only token automatically.

Run `make ci` after a local update before opening a pull request.
