#!/usr/bin/env python3
"""Prepare an exact, clean RustDesk checkout using public material only.

The input key is the public profile-verification key, never its private key.
The resulting tree deliberately has no usable profile or connection password.
Use a disposable checkout: this command refuses to modify dirty source trees.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys

UPSTREAM_COMMIT = "6c578292e8ebbbec708b76986ba8c4bc7c509747"
COMMON_COMMIT = "7e1c392c62d39c364127307cd408421dd5f8cfb0"
HERE = Path(__file__).resolve().parent


class PreparationError(Exception):
    pass


def git(directory: Path, *args: str) -> str:
    result = subprocess.run(
        ["git", "-C", str(directory), *args],
        check=False, capture_output=True, text=True,
    )
    if result.returncode:
        raise PreparationError("Git validation or patch application failed; use a fresh pinned checkout.")
    return result.stdout.strip()


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def check_checkout(directory: Path, expected: str) -> None:
    if not directory.is_dir():
        raise PreparationError("The source checkout or required hbb_common submodule is missing.")
    if Path(git(directory, "rev-parse", "--show-toplevel")).resolve() != directory.resolve():
        raise PreparationError("The source must be the root of its own Git checkout.")
    if git(directory, "rev-parse", "HEAD") != expected:
        raise PreparationError("The source revision does not match the pinned RustDesk revision.")
    if git(directory, "status", "--porcelain=v1", "--untracked-files=all"):
        raise PreparationError("The source checkout is dirty. Prepare a separate clean checkout.")


def source_files() -> list[tuple[Path, Path]]:
    files = [
        (HERE / "integration/retailcontrol.rs", Path("src/retailcontrol.rs")),
        (HERE / "integration/portable_profile.rs", Path("libs/portable/src/portable_profile.rs")),
        (HERE / "profile/Cargo.toml", Path("libs/retailcontrol-profile/Cargo.toml")),
    ]
    profile = HERE / "profile"
    for subdir in ("src", "tests"):
        directory = profile / subdir
        if directory.is_dir():
            files.extend(
                (path, Path("libs/retailcontrol-profile") / path.relative_to(profile))
                for path in sorted(directory.rglob("*")) if path.is_file()
            )
    if not any(dst == Path("libs/retailcontrol-profile/src/lib.rs") for _, dst in files):
        raise PreparationError("The shared profile crate is incomplete.")
    for src, _ in files:
        if not src.is_file() or src.is_symlink():
            raise PreparationError("A required integration source file is missing or is a symlink.")
    return files


def prepare(source: Path, public_key_file: Path) -> dict:
    source = source.resolve()
    common = source / "libs/hbb_common"
    check_checkout(source, UPSTREAM_COMMIT)
    check_checkout(common, COMMON_COMMIT)
    if public_key_file.is_symlink() or not public_key_file.is_file():
        raise PreparationError("Supply a regular file containing the 32-byte public verification key.")
    key = public_key_file.read_bytes()
    if len(key) != 32 or key == bytes(32):
        raise PreparationError("The public verification key must contain exactly 32 nonzero-key bytes.")

    files = source_files()
    patches = [
        (source, HERE / "patches/rustdesk.patch"),
        (common, HERE / "patches/hbb-common.patch"),
    ]
    for directory, patch in patches:
        if not patch.is_file() or patch.is_symlink():
            raise PreparationError("A pinned integration patch is missing.")
        git(directory, "apply", "--check", str(patch))
    for _, target in files:
        if (source / target).exists():
            raise PreparationError("An integration output already exists; use a fresh checkout.")

    # This file contains the vendor custom.txt signature verifier. Keeping the
    # entire file byte-identical is stronger than checking for its public key.
    vendor_hash = digest(source / "src/common.rs")
    for directory, patch in patches:
        git(directory, "apply", str(patch))
    for src, target in files:
        target = source / target
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(src, target)
    (source / "profile-public-key.bin").write_bytes(key)
    if digest(source / "src/common.rs") != vendor_hash:
        raise PreparationError("Upstream vendor configuration verification changed; preparation rejected.")

    manifest = {
        "schema_version": 1,
        "upstream_commit": UPSTREAM_COMMIT,
        "hbb_common_commit": COMMON_COMMIT,
        "profile_public_key_sha256": hashlib.sha256(key).hexdigest(),
        "vendor_common_rs_sha256": vendor_hash,
        "patch_sha256": {patch.name: digest(patch) for _, patch in patches},
        "integration_sha256": {
            target.as_posix(): digest(src) for src, target in files
        },
        "contains_private_profile": False,
    }
    (source / "retailcontrol-preparation.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return manifest


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-dir", type=Path, required=True)
    parser.add_argument("--public-key-file", type=Path, required=True)
    args = parser.parse_args()
    try:
        prepare(args.source_dir, args.public_key_file)
    except (PreparationError, OSError) as error:
        # Never dump command lines, file contents, or unexpected tracebacks.
        message = str(error) if isinstance(error, PreparationError) else "Could not read or write preparation files."
        print(f"Preparation failed: {message}", file=sys.stderr)
        return 1
    print("Prepared credential-free RetailControl source; vendor verification is unchanged.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
