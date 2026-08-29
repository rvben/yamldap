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

## Failure policy

If a release fails before any release, artifact, container, package, checksum,
or attestation is published, delete and recreate the brief tag and retry the
same version. Once anything is published, preserve the tag and issue a patch
release instead. Retry an isolated failed publishing job when possible.
