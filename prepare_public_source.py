#!/usr/bin/env python3
"""Prepare a separate reviewable public build source tree; never publish it."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import shutil
from source_files import native_files


def prepare(native_dir, public_key_file, output_dir):
    native_dir, output_dir = Path(native_dir).resolve(), Path(output_dir).absolute()
    key = Path(public_key_file).read_bytes()
    if len(key) != 32:
        raise ValueError("Public profile key must contain exactly 32 bytes")
    if output_dir.exists():
        raise ValueError("Source export requires a new output directory")
    inventory = list(native_files(native_dir))
    for _, source in inventory:
        if re.search(br"(?m)^-----BEGIN (?:OPENSSH |RSA |EC |ENCRYPTED )?PRIVATE KEY-----", source.read_bytes()):
            raise ValueError("Source export found private key material")
    if not all((native_dir / name).is_file() for name in
               ["README.md", "LICENSE", "apply_patch.py", "profile/Cargo.toml",
                "profile/Cargo.lock", "windows-build.ps1", "workflows/windows-native.yml"]):
        raise ValueError("Native source package is incomplete")
    output_dir.mkdir(parents=True, mode=0o700)
    for relative, source in inventory:
        if relative.name == "profile-public-key.bin":
            continue
        target = output_dir / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, target)
    (output_dir / "profile-public-key.bin").write_bytes(key)
    # Explicitly activate only the one prepared workflow in this separate repository.
    workflows = output_dir / ".github/workflows"
    workflows.mkdir(parents=True)
    shutil.copyfile(output_dir / "workflows/windows-native.yml", workflows / "windows-native.yml")
    ignore = output_dir / ".gitignore"
    ignore.write_text(ignore.read_text().replace("profile-public-key.bin\n", ""))
    files = []
    for file in sorted(output_dir.rglob("*")):
        if file.is_file():
            data = file.read_bytes()
            if re.search(br"(?m)^-----BEGIN (?:OPENSSH |RSA |EC |ENCRYPTED )?PRIVATE KEY-----", data):
                raise ValueError("Source export found private key material")
            files.append({"path": str(file.relative_to(output_dir)), "bytes": len(data),
                          "sha256": hashlib.sha256(data).hexdigest()})
    manifest = {"published": False, "credentials_included": False,
                "profile_public_key_sha256": hashlib.sha256(key).hexdigest(), "files": files}
    (output_dir / "source-manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    return {"directory": str(output_dir), "files": len(files), "published": False,
            "profile_public_key_sha256": manifest["profile_public_key_sha256"]}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--native-dir", default=str(Path(__file__).parent))
    parser.add_argument("--public-key-file", required=True)
    parser.add_argument("--output-dir", required=True)
    args = parser.parse_args()
    print(json.dumps(prepare(args.native_dir, args.public_key_file, args.output_dir), indent=2))
