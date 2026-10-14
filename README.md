# Native Windows support client

**Development candidate, not a verified Windows release.** This replaces the
RetailControl NSIS/PowerShell setup layer with a small source modification to
RustDesk's own client and portable installer.

## Intended store experience

1. Open the private RetailControl download and approve Windows installation.
2. RustDesk's own installation screen installs RetailControl Remote Support.
3. Its service uses the build's preset password and the existing private server.
4. The server registers the computer in the operator's native Mac address book.
5. The operator names the store and connects using the preset password.

Steps 2–5 still require an actual Windows acceptance test. This source does not
remove UAC, SmartScreen, antivirus checks, or password authentication. It does not
require a paid RustDesk account. It retains RustDesk's current UI and license.

## What changed

The native launcher verifies a signed profile appended locally to its EXE before
extracting anything. After extraction it copies that profile to a fixed sidecar.
The inner application and background service verify the same profile before
network startup. RustDesk's native installation copies the complete directory,
including the sidecar, to Program Files.

The fixed application/service/config identity is `RetailControlRemoteSupport`,
separate from an existing stock RustDesk installation. The launcher uses its own
cache directory and profile ID. Required server and authentication options come
from the verified profile. Filename-based server overrides and automatic
upstream replacement are disabled for this candidate. The upstream vendor's
`custom.txt` verification remains unchanged.

The preset uses the pinned RustDesk password format:
`00 + base64(SHA256(password || salt))`. That hash is credential material; hashing
does **not** make the final installer public-safe. Keep the finished installer,
private profile, original password, and signing key private. The generic build
contains only the profile **public** verification key and cannot run without a
valid profile. Our profile signature is not Windows Authenticode signing.

## REA evidence

REA 6.4.0 inspected the supplied AnyDesk sample and official RustDesk 1.4.9 on
2026-10-14 UTC. It confirmed native PE formats and resource identities. AnyDesk
has packed-code indicators; its service/enrollment internals were not recovered.
REA's installed binary-layout provider did not support this Mac/Windows pairing.
No AnyDesk code, private configuration, credentials, or signing identity is copied.

Static inspection of RustDesk's exact source and portable package established
that the outer EXE extracts and spawns the inner client without waiting. That is
why a profile on the outer file alone, or a successful outer process exit, is
insufficient. This implementation uses RustDesk's open-source installation and
service flow instead of attempting to clone AnyDesk's proprietary implementation.

## Build boundaries and cost

The prepared workflow is manual and restricted to a **public** repository on the
standard `windows-2022` runner. It does not run in the private RetailControl app
repository, use larger paid runners, or upload Actions artifacts/cache entries.
Only the generic executable and a receipt may be published as release assets.
No production preset, profile, private signing key, account token or store data
is an input to that workflow.

The public build source tree must be reviewed and its publication approved before
creating a public repository. `prepare_public_source.py` only writes a local,
allowlisted source tree and file inventory. It never creates repositories,
uploads data, triggers CI, or changes the public store download.

- [GitHub runner availability and limits](https://docs.github.com/en/actions/reference/runners/github-hosted-runners)
- [GitHub Actions billing](https://docs.github.com/en/billing/concepts/product-billing/github-actions)

The first complete Windows compile is still required to establish build fit and
compatibility. No claim of a working EXE follows from local profile tests.

Public customization source and free Windows builds are maintained at
[retailcontrol-remote-support](https://github.com/azimmomin123/retailcontrol-remote-support).
The store preset and profile signing key are applied locally after downloading
the generic build; they are never supplied to GitHub.

## Reproduce

Pinned RustDesk commit: `6c578292e8ebbbec708b76986ba8c4bc7c509747`.
Pinned hbb_common commit: `7e1c392c62d39c364127307cd408421dd5f8cfb0`.
The patch application tool refuses another revision or a dirty source checkout.

Create an owner-only local directory and signing key using Python 3 and OpenSSL
with Ed25519 support. The key is for this build profile only, not application
login or production sessions. Do not rotate it unintentionally: a generic binary
trusts only the public key compiled into it.

```sh
python3 pack.py keygen --output-dir "$HOME/.config/retailcontrol/native-signing"
python3 prepare_public_source.py \
  --public-key-file "$HOME/.config/retailcontrol/native-signing/native-profile-public-key.bin" \
  --output-dir "$HOME/.config/retailcontrol/native-public-source"
```

After approval, the exported tree can be its own public build repository. The
manual Windows workflow checks out the pinned upstream source and invokes
`windows-build.ps1`. For a local Windows development machine, use that script's
parameters with the same toolchain versions shown in the workflow.

After downloading the generic EXE and its receipt from that reviewed build,
package the private installer locally on macOS/Linux:

```sh
python3 pack.py pack \
  --base-exe /private/path/RetailControlRemoteSupport-base.exe \
  --base-receipt /private/path/build-receipt.json \
  --public-key-file "$HOME/.config/retailcontrol/native-signing/native-profile-public-key.bin" \
  --signing-key "$HOME/.config/retailcontrol/native-signing/native-profile-signing.pem" \
  --password-file "$HOME/.config/retailcontrol/remote-build-password" \
  --config-file /private/path/public-server-config.json \
  --output-dir "$HOME/.config/retailcontrol/private-builds"
```

The public server JSON contains `host`, `key` and HTTPS `api`. The password file
is owner-only and contains 16–64 ASCII letters, digits, underscores or hyphens.
The output is owner-only, unsigned and explicitly marked untested/unpublished.
The generic receipt binds the EXE hash, source revisions and public verification
key. Packaging fails if any of these disagree.

## Verification

```sh
cargo test --locked --manifest-path profile/Cargo.toml
python3 -m unittest discover -s tests -v
```

Tests use synthetic credentials only. They cover signature/key mismatch,
tampering, malformed and oversized profiles, path substitution, immutable
sidecars, binary/receipt binding, private file permissions and secret-free
receipts. The profile checker prints only success/failure.

The Windows release gate is separate: clean install and cancelled UAC, a path
with spaces, renamed download, coexistence with stock RustDesk, installed
sidecar integrity, actual service readiness, automatic Mac address-book entry,
correct-preset connection, wrong-password rejection, logoff/reboot, and uninstall.
Confirm each against the final file hash before enabling store distribution.
The current code preserves native installation behavior; it does not establish
those results. Existing per-computer password overrides and upgrades also need
explicit verification.

The public Windows workflow also runs `windows-smoke.ps1` after freezing the
generic release files. It builds an isolated test copy using a newly generated
synthetic key, with loopback routing, and checks native installation, service
startup and restart, profile persistence and rejection, and uninstall. The
original release files are checked for changes. Only the fixed
`windows-smoke.json` result is published; test credentials and test binaries
remain on the disposable runner. GitHub's Windows runner has UAC disabled, so
this cannot establish the real store's UAC, SmartScreen, Mac connection, or
reboot experience. Actual CI success is required; the presence of this harness
alone does not establish a passing result.

The payload includes `LICENSE.txt`, `SOURCE.txt` and the exact patched source
archive. Source export excludes the preset and private signing key; they are not
required to rebuild the generic client.
