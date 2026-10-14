"""Allowlisted, credential-free native build source inventory."""
from pathlib import Path

ROOT_FILES = {
    "README.md", "LICENSE", ".gitignore", ".gitattributes", "pack.py", "apply_patch.py",
    "prepare_public_source.py", "make_source_bundle.py", "source_files.py",
    "windows-build.ps1", "windows-smoke.ps1", "profile-public-key.bin",
}
NESTED_FILES = {
    "patches/rustdesk.patch", "patches/hbb-common.patch",
    "integration/portable_profile.rs", "integration/retailcontrol.rs",
    "profile/Cargo.toml", "profile/Cargo.lock", "profile/src/lib.rs",
    "profile/src/bin/profile-check.rs", "tests/test_apply_patch.py",
    "tests/test_pack.py", "tests/test_source_export.py", "tests/windows_smoke_profile.py",
    "workflows/windows-native.yml", ".github/workflows/windows-native.yml",
}
EXCLUDED = {"target", "__pycache__", ".git", "build", "dist"}


def native_files(root):
    root = Path(root).resolve()
    for path in sorted(root.rglob("*")):
        relative = path.relative_to(root)
        if any(part in EXCLUDED for part in relative.parts):
            continue
        if relative.name in {".DS_Store", "source-manifest.json"}:
            continue
        allowed = relative.as_posix() in ROOT_FILES | NESTED_FILES
        if path.is_symlink():
            raise ValueError("Source export refuses symbolic links")
        if not path.is_file():
            continue
        if not allowed:
            raise ValueError("Unexpected file in native source; public export refused")
        yield relative, path
