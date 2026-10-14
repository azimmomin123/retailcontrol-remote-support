import json
from pathlib import Path
import struct
import sys
import tempfile
from types import SimpleNamespace
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import pack


class PackagingTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.keys = pack.generate_key(self.root / "keys")
        self.public = Path(self.keys["public_key"])
        self.password = self.root / "preset"
        pack.write_new(self.password, b"Synthetic-Test-Only-Password")
        self.base = self.root / "base.exe"
        binary = bytearray(1024)
        binary[:2] = b"MZ"
        struct.pack_into("<I", binary, 0x3c, 128)
        binary[128:132] = b"PE\0\0"
        struct.pack_into("<H", binary, 132, 0x8664)
        self.base.write_bytes(binary)
        self.receipt = self.root / "base.json"
        self.receipt.write_text(json.dumps({"schema_version": 1,
            "app_identity": pack.APP_ID, "rustdesk_commit": pack.RUSTDESK_COMMIT,
            "hbb_common_commit": pack.HBB_COMMIT, "credential_free": True,
            "base_sha256": pack.digest(binary),
            "profile_public_key_sha256": pack.digest(self.public.read_bytes())}))
        self.config = self.root / "config.json"
        self.config.write_text(json.dumps({"host": "127.0.0.1", "api": "https://test.invalid",
                                         "key": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="}))
        self.args = SimpleNamespace(output_dir=self.root / "output", password_file=self.password,
            signing_key=self.keys["private_key"], public_key_file=self.public, base_exe=self.base,
            base_receipt=self.receipt, config_file=self.config)

    def tearDown(self):
        self.temp.cleanup()

    def test_signed_overlay_round_trip_and_no_plain_password(self):
        receipt = pack.package(self.args)
        data = (self.args.output_dir / receipt["file"]).read_bytes()
        self.assertEqual(data[-8:], pack.FOOTER)
        size = struct.unpack("<Q", data[-16:-8])[0]
        envelope = data[-16-size:-16]
        self.assertEqual(envelope[:8], pack.MAGIC)
        payload_size = struct.unpack("<I", envelope[8:12])[0]
        payload = envelope[12:12+payload_size]
        self.assertEqual(len(envelope), 12 + payload_size + 64)
        profile = json.loads(payload)
        self.assertTrue(profile["password_hash"].startswith("00"))
        self.assertNotIn(self.password.read_bytes(), data)
        self.assertNotIn(profile["password_hash"], json.dumps(receipt))
        message, signature, public_der = [self.root / name for name in ["message", "signature", "public.der"]]
        message.write_bytes(pack.DOMAIN + payload)
        signature.write_bytes(envelope[-64:])
        public_der.write_bytes(pack.PUBLIC_DER_PREFIX + self.public.read_bytes())
        pack.openssl(["pkeyutl", "-verify", "-rawin", "-pubin", "-keyform", "DER",
                      "-inkey", public_der, "-in", message, "-sigfile", signature])
        message.write_bytes(pack.DOMAIN + payload + b"tampered")
        with self.assertRaises(pack.BuildError):
            pack.openssl(["pkeyutl", "-verify", "-rawin", "-pubin", "-keyform", "DER",
                          "-inkey", public_der, "-in", message, "-sigfile", signature])
        self.assertEqual((self.args.output_dir / receipt["file"]).stat().st_mode & 0o777, 0o600)
        self.assertFalse(receipt["published"])

    def test_refuses_wrong_signing_key(self):
        other = pack.generate_key(self.root / "other")
        self.args.signing_key = other["private_key"]
        with self.assertRaises(pack.BuildError):
            pack.package(self.args)
        self.assertEqual(list(self.args.output_dir.glob("*.exe")), [])

    def test_refuses_tampered_base_and_public_private_input(self):
        self.base.write_bytes(self.base.read_bytes() + b"changed")
        with self.assertRaises(pack.BuildError):
            pack.package(self.args)
        self.password.chmod(0o644)
        with self.assertRaises(pack.BuildError):
            pack.package(self.args)

    def test_private_key_never_overwritten(self):
        before = Path(self.keys["private_key"]).read_bytes()
        with self.assertRaises(pack.BuildError):
            pack.generate_key(self.root / "keys")
        self.assertEqual(Path(self.keys["private_key"]).read_bytes(), before)

    def test_invalid_server_config_is_rejected_before_packaging(self):
        config = json.loads(self.config.read_text())
        for api in ["https://test.invalid:0", "https://test.invalid:65536",
                    "https://user@test.invalid", "https://test.invalid/path",
                    "https://-invalid.test", "https://999.999.1.1"]:
            config["api"] = api
            self.config.write_text(json.dumps(config))
            with self.assertRaises(pack.BuildError):
                pack.package(self.args)
        self.assertEqual(list(self.args.output_dir.glob("*.exe")), [])

    def test_private_outputs_and_inputs_refuse_repository_or_public_tree(self):
        repository = self.root / "repository"
        repository.mkdir()
        (repository / ".git").mkdir()
        for output in [repository / "private-output", self.root / "public" / "downloads"]:
            with self.assertRaises(pack.BuildError):
                pack.generate_key(output)
            self.assertFalse(output.exists())
        stored = repository / "password"
        pack.write_new(stored, b"Synthetic-Test-Only-Password")
        self.args.password_file = stored
        with self.assertRaises(pack.BuildError):
            pack.package(self.args)


if __name__ == "__main__":
    unittest.main()
