#!/usr/bin/env python3
"""Bundle exact patched sources and generated bridge files without build outputs."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import tarfile
from source_files import native_files

GENERATED = ["src/bridge_generated.rs", "src/bridge_generated.io.rs",
             "flutter/lib/generated_bridge.dart", "flutter/lib/generated_bridge.freezed.dart",
             "flutter/macos/Runner/bridge_generated.h", "flutter/ios/Runner/bridge_generated.h",
             "Cargo.lock", "libs/portable/Cargo.lock", "flutter/pubspec.lock",
             "libs/portable/src/portable_profile.rs", "profile-public-key.bin"]


def bundle(source_dir, output_dir, native_dir):
    source_dir, output_dir = Path(source_dir).resolve(), Path(output_dir).resolve()
    native_dir = Path(native_dir).resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    names = subprocess.check_output(["git", "ls-files", "-z", "--recurse-submodules"],
                                    cwd=source_dir).decode().split("\0")
    files = {name: source_dir / name for name in names if name and (source_dir / name).is_file()}
    for name in GENERATED:
        file = source_dir / name
        if not file.is_file():
            raise ValueError("Required generated build source is missing: " + name)
        files[name] = file
    # Integration adds native modules and the shared crate outside the tracked upstream tree.
    for root in [source_dir / "libs/retailcontrol_profile", source_dir / "libs/retailcontrol-profile"]:
        if root.exists():
            for file in root.rglob("*"):
                if file.is_file() and "target" not in file.parts and file.suffix in {".rs", ".toml", ".lock"}:
                    files[str(file.relative_to(source_dir))] = file
    for file in source_dir.glob("src/retailcontrol*.rs"):
        files[str(file.relative_to(source_dir))] = file
    source_name = "RustDesk-Source.tar.gz"
    output = output_dir / source_name
    with tarfile.open(output, "x:gz") as archive:
        for name, file in sorted(files.items()):
            if file.is_symlink():
                # Preserve repository links, never follow them into unrelated data.
                archive.add(file, arcname="rustdesk/" + name, recursive=False)
            else:
                archive.add(file, arcname="rustdesk/" + name, recursive=False)
        for relative, file in native_files(native_dir):
            archive.add(file, arcname="retailcontrol-native/" + relative.as_posix(), recursive=False)
    license_file = source_dir / "LICENCE"
    if not license_file.is_file():
        license_file = source_dir / "LICENSE"
    (output_dir / "LICENSE.txt").write_bytes(license_file.read_bytes())
    (output_dir / "SOURCE.txt").write_text(
        "RetailControl Remote Support is a modified RustDesk client.\n"
        "RustDesk source: https://github.com/rustdesk/rustdesk\n"
        "RustDesk commit: 6c578292e8ebbbec708b76986ba8c4bc7c509747\n"
        "hbb_common commit: 7e1c392c62d39c364127307cd408421dd5f8cfb0\n"
        "This folder includes the AGPL-3.0 license and RustDesk-Source.tar.gz,\n"
        "containing patched source, generated bridge files, build inputs and lockfiles.\n"
        "The private preset and private signing key are not needed to rebuild the generic client.\n"
        "See retailcontrol-native/README.md in that archive for build instructions.\n"
        "Dependencies and toolchains referenced by the source must be fetched separately.\n")
    return {"source_archive": str(output), "sha256": hashlib.sha256(output.read_bytes()).hexdigest()}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ["source-dir", "output-dir", "native-dir"]:
        parser.add_argument("--" + name, required=True)
    args = parser.parse_args()
    print(json.dumps(bundle(args.source_dir, args.output_dir, args.native_dir), indent=2))
