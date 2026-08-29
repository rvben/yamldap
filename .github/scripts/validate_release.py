#!/usr/bin/env python3
"""Validate release metadata before any publication job can run."""

from __future__ import annotations

import re
import sys
import tomllib
from pathlib import Path


SEMVER_TAG = re.compile(r"^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$")


def fail(message: str) -> None:
    raise SystemExit(f"release validation failed: {message}")


def main() -> None:
    if len(sys.argv) != 2:
        fail("usage: validate_release.py vMAJOR.MINOR.PATCH")

    tag = sys.argv[1]
    match = SEMVER_TAG.fullmatch(tag)
    if match is None:
        fail(f"tag {tag!r} is not exact stable SemVer")
    version = tag[1:]

    with Path("Cargo.toml").open("rb") as cargo_file:
        cargo_version = tomllib.load(cargo_file)["package"]["version"]
    if cargo_version != version:
        fail(f"tag version {version} does not match Cargo.toml {cargo_version}")

    changelog = Path("CHANGELOG.md").read_text(encoding="utf-8")
    heading = re.compile(rf"^## \[{re.escape(version)}\](?:\(|\s|$)", re.MULTILINE)
    start_match = heading.search(changelog)
    if start_match is None:
        fail(f"CHANGELOG.md has no [{version}] release section")

    next_heading = re.search(r"^## \[", changelog[start_match.end() :], re.MULTILINE)
    section_end = (
        start_match.end() + next_heading.start() if next_heading is not None else len(changelog)
    )
    section = changelog[start_match.end() : section_end]
    if not re.search(r"^### ", section, re.MULTILINE):
        fail(f"CHANGELOG.md [{version}] section has no categorized release notes")
    if not re.search(r"^- \S", section, re.MULTILINE):
        fail(f"CHANGELOG.md [{version}] section has no release-note entries")

    print(version)


if __name__ == "__main__":
    main()
