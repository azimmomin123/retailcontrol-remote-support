#!/usr/bin/env python3
"""Exercise preparation against real disposable Git clones of the pinned source."""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("native_prepare", ROOT / "apply_patch.py")
prepare = importlib.util.module_from_spec(spec)
spec.loader.exec_module(prepare)
UPSTREAM = Path(os.environ.get("RC_RUSTDESK_SOURCE_DIR", "/tmp/rustdesk-client-audit-149")).resolve()


class PreparationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not (UPSTREAM / ".git").exists() or not (UPSTREAM / "libs/hbb_common/.git").exists():
            raise unittest.SkipTest(
                "Pinned source unavailable; set RC_RUSTDESK_SOURCE_DIR to a RustDesk checkout with hbb_common."
            )

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="retailcontrol-prepare-test-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.key = self.root / "synthetic-public-key.bin"
        # Synthetic public input only; no private key or production credential.
        self.key.write_bytes(bytes(range(1, 33)))

    def clone(self, name):
        dest = self.root / name
        for source, target in (
            (UPSTREAM, dest),
            (UPSTREAM / "libs/hbb_common", dest / "libs/hbb_common"),
        ):
            subprocess.run(
                ["git", "clone", "--shared", "--no-hardlinks", str(source), str(target)],
                check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            )
        return dest

    def test_repeatable_patch_preserves_vendor_and_copies_profile_sources(self):
        first, second = self.clone("first"), self.clone("second")
        vendor_bytes = (first / "src/common.rs").read_bytes()
        a = prepare.prepare(first, self.key)
        b = prepare.prepare(second, self.key)
        self.assertEqual(a, b)
        self.assertEqual(vendor_bytes, (first / "src/common.rs").read_bytes())
        self.assertEqual((first / "profile-public-key.bin").read_bytes(), self.key.read_bytes())
        self.assertFalse(a["contains_private_profile"])
        self.assertFalse(list(first.rglob("retailcontrol-profile.bin")))
        for target, digest in a["integration_sha256"].items():
            self.assertEqual(prepare.digest(first / target), digest)
            self.assertEqual((first / target).read_bytes(), (second / target).read_bytes())
        self.assertEqual(json.loads((first / "retailcontrol-preparation.json").read_text()), a)
        subprocess.run(["git", "-C", str(first), "diff", "--check"], check=True)
        subprocess.run(["git", "-C", str(first / "libs/hbb_common"), "diff", "--check"], check=True)

    def test_dirty_checkout_is_rejected_before_writes(self):
        source = self.clone("dirty")
        marker = source / "uncommitted.txt"
        marker.write_text("leave this alone\n")
        with self.assertRaisesRegex(prepare.PreparationError, "dirty"):
            prepare.prepare(source, self.key)
        self.assertFalse((source / "profile-public-key.bin").exists())
        self.assertEqual(marker.read_text(), "leave this alone\n")

    def test_native_install_names_the_executable_before_registering_it(self):
        source = self.clone("install-name")
        prepare.prepare(source, self.key)
        windows = (source / "src/platform/windows.rs").read_text()
        install = windows.split("pub fn install_me(", 1)[1].split(
            "\npub fn run_after_install(", 1
        )[0]
        commands = install.split("let cmds = format!(", 1)[1]
        # The Flutter payload is rustdesk.exe, while SCM/import/uninstall use
        # APP_NAME.exe. A successful XCOPY alone leaves a broken native install.
        # Guard the actual prepared script's dependency order. Windows smoke
        # separately verifies the resulting files and running service.
        sequence = ("{copy_exe}", "{rename_exe}", "{import_config}", "{after_install}")
        positions = [commands.index(item) for item in sequence]
        self.assertEqual(positions, sorted(positions))
        self.assertIn("rename_exe = rename_exe_cmd(&src_exe, &path)?", commands)
        self.assertEqual(windows.count("pub fn rename_exe_cmd("), 1)

    def test_dirty_submodule_is_rejected(self):
        source = self.clone("dirty-common")
        marker = source / "libs/hbb_common/src/config.rs"
        marker.write_text(marker.read_text() + "\n// synthetic local change\n")
        with self.assertRaisesRegex(prepare.PreparationError, "dirty"):
            prepare.prepare(source, self.key)
        self.assertFalse((source / "profile-public-key.bin").exists())

    def test_wrong_revision_and_invalid_key_are_rejected(self):
        source = self.clone("invalid")
        with self.assertRaisesRegex(prepare.PreparationError, "revision"):
            prepare.check_checkout(source, "0" * 40)
        self.key.write_bytes(b"not a public key")
        with self.assertRaisesRegex(prepare.PreparationError, "32"):
            prepare.prepare(source, self.key)
        self.assertFalse((source / "profile-public-key.bin").exists())


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--upstream", type=Path, required=True)
    args = parser.parse_args()
    UPSTREAM = args.upstream.resolve()
    unittest.main(argv=[__file__], verbosity=2)
