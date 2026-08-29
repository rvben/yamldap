# Releases

Vership is the local release control plane. GitHub Actions is the execution
plane for cross-platform binaries, crates.io, Docker Hub, and GHCR.

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
