# Releases

Vership is the local release control plane. GitHub Actions is the execution
plane for cross-platform binaries, crates.io, Docker Hub, and GHCR.

The release workflow accepts exact stable SemVer tags only. Before any package,
image, checksum, attestation, or GitHub release is published, it requires the
same reusable verification workflow used by pull requests, validates the tag
against `Cargo.toml`, `Cargo.lock`, `CHANGELOG.md`, and `main`, builds every
binary, creates checksums, and runs a functional non-root container smoke test.

## Create a release

Start from a clean, up-to-date `main` branch with Vership installed, then run:

```sh
vership preflight
vership bump patch # or minor/major
vership verify
```

Vership runs the configured checks, updates `Cargo.toml`, `Cargo.lock`, and the
changelog, creates a Conventional Commit and tag, and pushes both. The tag
starts `.github/workflows/release.yml`.

`vership verify` checks the Git tag, GitHub release assets, crates.io package,
and GHCR image. Check Docker Hub separately because it is not currently a
Vership verification target.

To exercise the complete build and verification graph without publishing, run
the Release workflow manually. Manual runs are always dry runs; only an exact
`vMAJOR.MINOR.PATCH` tag push can reach publication jobs.

## Repository settings

Protect `main` in GitHub and require the reusable workflow's
`CI / Verification / Required` check before merging. Also require pull requests,
prevent force pushes and branch deletion, and restrict who can push matching
`v*` tags. These controls live in repository settings and cannot be enforced by
the workflow files themselves.

Publishing jobs should use a protected GitHub Environment if human approval is
desired. Keep the self-hosted ARM64 runner isolated and ephemeral where
possible because its binary becomes part of the public release.

## Publishing access

The `yamldap` crate trusts the GitHub publisher `rvben/yamldap` with workflow
filename `release.yml`. The publish job exchanges its GitHub OIDC identity for
a short-lived crates.io token; no long-lived crates.io secret is required.

The `ghcr.io/rvben/yamldap` package grants Actions access to the
`rvben/yamldap` repository. The workflow uses its scoped `GITHUB_TOKEN` with
`packages: write`; no personal access token is required.

## Failure policy

If a release fails before any release, artifact, container, package, checksum,
or attestation is published, delete and recreate the brief tag and retry the
same version. Once anything is published, preserve the tag and issue a patch
release instead. Retry an isolated failed publishing job when possible.
