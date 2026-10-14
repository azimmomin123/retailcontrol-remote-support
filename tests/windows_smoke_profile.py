#!/usr/bin/env python3
"""Make disposable, loopback-only fixtures for the Windows native smoke test.

There are deliberately no signing-key, password, or server input arguments. The
private keys exist only while generating fixtures and are deleted before exit.
Nothing made by this helper is a store enrollment or a release artifact.
"""
import argparse
import base64
import hashlib
import json
from pathlib import Path
import secrets
import shutil
import struct
import subprocess
import tempfile

DOMAIN = b"RetailControl native profile v1\0"
PUBLIC_DER_PREFIX = bytes.fromhex("302a300506032b6570032100")
MARKER = "isolated-windows-smoke-v1"


def openssl(*args):
    preferred = Path("/opt/homebrew/opt/openssl@3/bin/openssl")
    binary = str(preferred) if preferred.is_file() else shutil.which("openssl")
    if not binary:
        raise RuntimeError("OpenSSL with Ed25519 support is required.")
    result = subprocess.run([binary, *map(str, args)], capture_output=True)
    if result.returncode:
        raise RuntimeError("Synthetic fixture signing failed.")
    return result.stdout


def create(folder):
    folder = Path(folder)
    folder.mkdir(parents=False, exist_ok=False)
    salt = secrets.token_hex(12)
    # Only the upstream H1 representation is retained. This password is unrelated
    # to any real client, and is never printed or accepted from an input file.
    password = secrets.token_urlsafe(32)
    profile = {
        "schema_version": 1,
        "build_id": secrets.token_hex(16),
        "rendezvous_server": "127.0.0.1:21116",
        "public_key": base64.b64encode(secrets.token_bytes(32)).decode("ascii"),
        "api_server": "https://127.0.0.1:9443",
        "password_hash": "00" + base64.b64encode(
            hashlib.sha256((password + salt).encode("ascii")).digest()
        ).decode("ascii"),
        "salt": salt,
    }
    payload = json.dumps(profile, sort_keys=True, separators=(",", ":")).encode()
    header = b"RCPROF01" + struct.pack("<I", len(payload)) + payload
    with tempfile.TemporaryDirectory(prefix="signing-", dir=folder) as temporary:
        temporary = Path(temporary)
        message = temporary / "message.bin"
        message.write_bytes(DOMAIN + payload)
        for label in ("valid", "wrong-key"):
            key, sig = temporary / (label + ".pem"), temporary / (label + ".sig")
            openssl("genpkey", "-algorithm", "ED25519", "-out", key)
            public = openssl("pkey", "-in", key, "-pubout", "-outform", "DER")
            if len(public) != 44 or not public.startswith(PUBLIC_DER_PREFIX):
                raise RuntimeError("Synthetic fixture key has an invalid format.")
            if label == "valid":
                (folder / "public-key.bin").write_bytes(public[-32:])
            openssl("pkeyutl", "-sign", "-rawin", "-inkey", key,
                    "-in", message, "-out", sig)
            signature = sig.read_bytes()
            if len(signature) != 64:
                raise RuntimeError("Synthetic fixture signature has an invalid format.")
            (folder / (label + ".bin")).write_bytes(header + signature)
    valid = (folder / "valid.bin").read_bytes()
    tampered = bytearray(valid)
    tampered[-1] ^= 1
    (folder / "tampered.bin").write_bytes(tampered)
    manifest = {
        "purpose": MARKER,
        "build_id": profile["build_id"],
        "profile_sha256": hashlib.sha256(valid).hexdigest(),
        "rendezvous_server": profile["rendezvous_server"],
        "api_server": profile["api_server"],
        "server_key": profile["public_key"],
    }
    (folder / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")


def append(folder, base, output):
    folder, base, output = Path(folder), Path(base), Path(output)
    manifest = json.loads((folder / "manifest.json").read_text(encoding="utf-8"))
    envelope = (folder / "valid.bin").read_bytes()
    if (manifest.get("purpose") != MARKER
            or manifest.get("rendezvous_server") != "127.0.0.1:21116"
            or manifest.get("api_server") != "https://127.0.0.1:9443"
            or manifest.get("profile_sha256") != hashlib.sha256(envelope).hexdigest()):
        raise RuntimeError("Not a synthetic smoke fixture.")
    if output.exists() or base.resolve() == output.resolve():
        raise RuntimeError("The synthetic output must be a new file.")
    with base.open("rb") as source, output.open("xb") as target:
        if source.read(2) != b"MZ":
            raise RuntimeError("Expected a native Windows executable.")
        source.seek(-8, 2)
        if source.read() == b"RCEND001":
            raise RuntimeError("The native base must not already have a profile.")
        source.seek(0)
        shutil.copyfileobj(source, target)
        target.write(envelope + struct.pack("<Q", len(envelope)) + b"RCEND001")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    create_parser = commands.add_parser("create")
    create_parser.add_argument("--directory", required=True)
    append_parser = commands.add_parser("append")
    append_parser.add_argument("--directory", required=True)
    append_parser.add_argument("--base", required=True)
    append_parser.add_argument("--output", required=True)
    args = parser.parse_args()
    if args.command == "create":
        create(args.directory)
    else:
        append(args.directory, args.base, args.output)


if __name__ == "__main__":
    try:
        main()
    except (OSError, RuntimeError, ValueError, KeyError, struct.error):
        raise SystemExit("Synthetic Windows smoke fixture operation failed.") from None
