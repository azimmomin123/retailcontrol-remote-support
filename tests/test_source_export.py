from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from source_files import native_files
from prepare_public_source import prepare


class SourceExportTests(unittest.TestCase):
    def test_extra_private_notes_are_refused(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "profile").mkdir()
            (root / "profile/operator-notes.txt").write_text("synthetic private note")
            with self.assertRaises(ValueError):
                list(native_files(root))

    def test_encrypted_key_rejected_before_output_created(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / "source"
            root.mkdir()
            (root / "README.md").write_text("-----BEGIN ENCRYPTED PRIVATE KEY-----\nsynthetic\n")
            public = Path(temp) / "public.bin"
            public.write_bytes(bytes(range(32)))
            output = Path(temp) / "export"
            with self.assertRaisesRegex(ValueError, "private key"):
                prepare(root, public, output)
            self.assertFalse(output.exists())


if __name__ == "__main__":
    unittest.main()
