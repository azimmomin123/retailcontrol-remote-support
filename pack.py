#!/usr/bin/env python3
"""Private profile signing and packaging. Never uploads credentials or binaries."""
import argparse
import base64
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import stat
import struct
import subprocess
import tempfile

APP_ID = "RetailControlRemoteSupport"
RUSTDESK_COMMIT = "6c578292e8ebbbec708b76986ba8c4bc7c509747"
HBB_COMMIT = "7e1c392c62d39c364127307cd408421dd5f8cfb0"
DOMAIN = b"RetailControl native profile v1\0"
MAGIC = b"RCPROF01"
FOOTER = b"RCEND001"
PUBLIC_DER_PREFIX = bytes.fromhex("302a300506032b6570032100")


class BuildError(Exception):
    """Only fixed, credential-free messages cross the command boundary."""


def digest(value):
    return hashlib.sha256(value).hexdigest()


def require_private_location(path):
    resolved = Path(path).resolve()
    for parent in (resolved, *resolved.parents):
        if (parent / ".git").exists():
            raise BuildError("Private inputs and outputs must stay outside Git repositories.")
    if any(part.lower() in {"public", "www", "wwwroot", "htdocs", "dist"}
           or "public-source" in part.lower() for part in resolved.parts):
        raise BuildError("Private inputs and outputs must stay outside public distribution directories.")


def read_private(path, limit=65536):
    require_private_location(path)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd, "rb") as source:
        info = os.fstat(source.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
            raise BuildError("Private input must be an owner-only regular file.")
        data = source.read(limit + 1)
        if len(data) > limit:
            raise BuildError("Private input exceeds its size limit.")
        return data


def write_new(path, data, mode=0o600):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    with os.fdopen(fd, "wb") as target:
        target.write(data)
        target.flush()
        os.fsync(target.fileno())


def private_directory(path):
    path = Path(path).absolute()
    require_private_location(path)
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    info = path.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
        raise BuildError("Output directory must be an owner-only directory.")
    return path


def openssl(args):
    preferred = "/opt/homebrew/opt/openssl@3/bin/openssl"
    binary = preferred if Path(preferred).is_file() else shutil.which("openssl")
    if not binary:
        raise BuildError("OpenSSL with Ed25519 support is required.")
    result = subprocess.run([binary, *map(str, args)], capture_output=True, check=False)
    if result.returncode:
        raise BuildError("Profile signing operation failed.")
    return result.stdout


def public_key(private_key):
    der = openssl(["pkey", "-in", private_key, "-pubout", "-outform", "DER"])
    if len(der) != len(PUBLIC_DER_PREFIX) + 32 or not der.startswith(PUBLIC_DER_PREFIX):
        raise BuildError("An Ed25519 profile signing key is required.")
    return der[-32:]


def generate_key(output_dir):
    folder = private_directory(output_dir)
    private = folder / "native-profile-signing.pem"
    public = folder / "native-profile-public-key.bin"
    if private.exists() or public.exists():
        raise BuildError("Signing key already exists; it will not be replaced.")
    with tempfile.TemporaryDirectory(prefix=".rc-key-", dir=folder) as temp:
        key = Path(temp) / "key.pem"
        openssl(["genpkey", "-algorithm", "ED25519", "-out", key])
        write_new(private, key.read_bytes())
        write_new(public, public_key(key))
    return {"private_key": str(private), "public_key": str(public),
            "profile_public_key_sha256": digest(public.read_bytes())}


def make_envelope(profile, key, temp):
    payload = json.dumps(profile, separators=(",", ":"), sort_keys=True).encode("utf-8")
    if len(payload) > 4096:
        raise BuildError("Profile exceeds its size limit.")
    message = Path(temp) / "message.bin"
    signature = Path(temp) / "signature.bin"
    write_new(message, DOMAIN + payload)
    openssl(["pkeyutl", "-sign", "-rawin", "-inkey", key,
             "-in", message, "-out", signature])
    sig = signature.read_bytes()
    if len(sig) != 64:
        raise BuildError("Invalid profile signature length.")
    return MAGIC + struct.pack("<I", len(payload)) + payload + sig


def valid_host(host):
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        pass
    if not host or len(host) > 253 or not host.isascii():
        return False
    if "." in host and all(char in "0123456789." for char in host):
        return False
    return all(re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?", part)
               for part in host.split("."))


def valid_authority(value, bare_ipv6=False):
    if not value or len(value) > 261 or not value.isascii():
        return False
    def port_ok(port):
        return port.isascii() and port.isdigit() and 0 < int(port) <= 65535
    if value.startswith("["):
        host, separator, suffix = value[1:].partition("]")
        try:
            ipaddress.IPv6Address(host)
        except ValueError:
            return False
        return bool(separator) and (not suffix or (suffix.startswith(":") and port_ok(suffix[1:])))
    if bare_ipv6:
        try:
            ipaddress.IPv6Address(value)
            return True
        except ValueError:
            pass
    host, separator, port = value.partition(":")
    return valid_host(host) and (not separator or port_ok(port))


def valid_public_config(config):
    try:
        key = base64.b64decode(config["key"], validate=True)
        api = config["api"]
        return (valid_authority(config["host"], True) and api.startswith("https://")
                and valid_authority(api[len("https://"):]) and len(key) == 32
                and base64.b64encode(key).decode("ascii") == config["key"])
    except (ValueError, KeyError, TypeError, AttributeError):
        return False


def validate_base(data, receipt, public):
    if (receipt.get("schema_version") != 1 or receipt.get("app_identity") != APP_ID
            or receipt.get("rustdesk_commit") != RUSTDESK_COMMIT
            or receipt.get("hbb_common_commit") != HBB_COMMIT
            or receipt.get("credential_free") is not True
            or receipt.get("base_sha256") != digest(data)
            or receipt.get("profile_public_key_sha256") != digest(public)):
        raise BuildError("Generic build receipt, source or trust key does not match.")
    if data.endswith(FOOTER) or len(data) < 128 or data[:2] != b"MZ":
        raise BuildError("Input must be an unprofiled native Windows executable.")
    offset = struct.unpack_from("<I", data, 0x3c)[0]
    if offset > len(data) - 26 or data[offset:offset + 4] != b"PE\0\0":
        raise BuildError("Input has an invalid Windows executable header.")
    if struct.unpack_from("<H", data, offset + 4)[0] != 0x8664:
        raise BuildError("Input must target 64-bit Windows.")


def package(args):
    folder = private_directory(args.output_dir)
    password = read_private(args.password_file).decode("ascii").strip()
    if not re.fullmatch(r"[A-Za-z0-9_-]{16,64}", password):
        raise BuildError("Preset must contain 16–64 letters, numbers, hyphens or underscores.")
    key_bytes = read_private(args.signing_key)
    public = Path(args.public_key_file).read_bytes()
    if len(public) != 32:
        raise BuildError("Public profile key must contain 32 bytes.")
    data = Path(args.base_exe).read_bytes()
    receipt = json.loads(Path(args.base_receipt).read_text())
    validate_base(data, receipt, public)
    config = json.loads(Path(args.config_file).read_text())
    if not valid_public_config(config):
        raise BuildError("Public server configuration is invalid.")
    build_id = secrets.token_hex(16)
    salt = secrets.token_hex(16)
    profile = {"schema_version": 1, "build_id": build_id,
               "rendezvous_server": config["host"], "public_key": config["key"],
               "api_server": config["api"], "salt": salt,
               "password_hash": "00" + base64.b64encode(
                   hashlib.sha256((password + salt).encode("ascii")).digest()).decode("ascii")}
    with tempfile.TemporaryDirectory(prefix=".rc-sign-", dir=folder) as temp:
        key = Path(temp) / "key.pem"
        write_new(key, key_bytes)
        if public_key(key) != public:
            raise BuildError("Private signing key does not match the generic client's trust key.")
        envelope = make_envelope(profile, key, temp)
    packaged = data + envelope + struct.pack("<Q", len(envelope)) + FOOTER
    name = f"RetailControl-Remote-Support-{build_id}-install.exe"
    output = folder / name
    result = {"schema_version": 1, "build_id": build_id, "file": name,
              "sha256": digest(packaged), "bytes": len(packaged),
              "base_sha256": digest(data), "profile_public_key_sha256": digest(public),
              "rustdesk_commit": RUSTDESK_COMMIT, "hbb_common_commit": HBB_COMMIT,
              "credential_bearing": True, "authenticode": "unsigned",
              "windows_acceptance": "not-tested", "published": False}
    write_new(output, packaged)
    write_new(output.with_suffix(".json"), (json.dumps(result, indent=2) + "\n").encode())
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    keygen = commands.add_parser("keygen")
    keygen.add_argument("--output-dir", required=True)
    pack = commands.add_parser("pack")
    for name in ["base-exe", "base-receipt", "public-key-file", "signing-key",
                 "password-file", "config-file", "output-dir"]:
        pack.add_argument("--" + name, required=True)
    args = parser.parse_args()
    try:
        result = generate_key(args.output_dir) if args.command == "keygen" else package(args)
        print(json.dumps(result, indent=2))
    except BuildError as error:
        parser.exit(1, str(error) + "\n")
    except Exception:
        parser.exit(1, "Private packaging failed; no upload was attempted.\n")


if __name__ == "__main__":
    main()
