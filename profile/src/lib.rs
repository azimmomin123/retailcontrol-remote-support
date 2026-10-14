//! Bounded, authenticated native profiles. Signatures provide authenticity, not
//! secrecy: the stored password hash must still be treated as a credential.
//! Files are immutable: an existing sidecar is accepted only if byte-identical.

use base64::{engine::general_purpose::STANDARD, Engine};
use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use std::{
    fmt,
    fs::{self, File, OpenOptions},
    io::{Read, Seek, SeekFrom, Write},
    net::{IpAddr, Ipv6Addr},
    path::{Component, Path, PathBuf},
};

pub const SIDECAR_NAME: &str = "retailcontrol-profile.bin";
pub const ENVELOPE_MAGIC: &[u8; 8] = b"RCPROF01";
pub const OVERLAY_MAGIC: &[u8; 8] = b"RCEND001";
pub const SIGNATURE_DOMAIN: &[u8] = b"RetailControl native profile v1\0";
pub const MAX_JSON_LEN: usize = 4096;
pub const MAX_ENVELOPE_LEN: usize = 12 + MAX_JSON_LEN + 64;

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Profile {
    pub schema_version: u32,
    pub build_id: String,
    pub rendezvous_server: String,
    pub public_key: String,
    pub api_server: String,
    /// Upstream hbb_common 7e1c392: "00" + base64(SHA256(password || salt)).
    /// This is the H1 storage form, not password_security's encrypted wrapper.
    pub password_hash: String,
    pub salt: String,
}

impl fmt::Debug for Profile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Profile { contents: [redacted] }")
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    MissingProfile,
    InvalidEnvelope,
    InvalidSignature,
    InvalidProfile,
    UnsafePath,
    ExistingSidecar,
    Io,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::MissingProfile => "profile missing",
            Self::InvalidEnvelope => "invalid profile envelope",
            Self::InvalidSignature => "invalid profile signature",
            Self::InvalidProfile => "invalid profile fields",
            Self::UnsafePath => "unsafe profile path",
            Self::ExistingSidecar => "unexpected existing profile",
            Self::Io => "profile file operation failed",
        })
    }
}
impl std::error::Error for Error {}

fn canonical_32(value: &str) -> bool {
    STANDARD
        .decode(value)
        .map(|decoded| decoded.len() == 32 && STANDARD.encode(decoded) == value)
        .unwrap_or(false)
}

fn port_valid(port: &str) -> bool {
    !port.is_empty()
        && port.bytes().all(|b| b.is_ascii_digit())
        && port.parse::<u16>().map(|p| p > 0).unwrap_or(false)
}

fn host_valid(host: &str) -> bool {
    if host.parse::<IpAddr>().is_ok() {
        return true;
    }
    if host.is_empty() || host.len() > 253 || !host.is_ascii() {
        return false;
    }
    // Do not interpret malformed dotted IPv4 as a numeric DNS name.
    if host.contains('.') && host.bytes().all(|b| b.is_ascii_digit() || b == b'.') {
        return false;
    }
    host.split('.').all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-')
    })
}

fn authority_valid(authority: &str, bare_ipv6: bool) -> bool {
    if authority.is_empty() || authority.len() > 261 || !authority.is_ascii() {
        return false;
    }
    if let Some(rest) = authority.strip_prefix('[') {
        let Some((host, suffix)) = rest.split_once(']') else {
            return false;
        };
        return host.parse::<Ipv6Addr>().is_ok()
            && (suffix.is_empty() || suffix.strip_prefix(':').map(port_valid).unwrap_or(false));
    }
    if bare_ipv6 && authority.parse::<Ipv6Addr>().is_ok() {
        return true;
    }
    match authority.split_once(':') {
        Some((host, port)) => host_valid(host) && port_valid(port),
        None => host_valid(authority),
    }
}

fn validate_profile(profile: &Profile) -> Result<(), Error> {
    let api_valid = profile
        .api_server
        .strip_prefix("https://")
        .map(|authority| authority_valid(authority, false))
        .unwrap_or(false);
    let hash_valid = profile
        .password_hash
        .strip_prefix("00")
        .map(canonical_32)
        .unwrap_or(false);
    if profile.schema_version != 1
        || profile.build_id.len() != 32
        || !profile
            .build_id
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        || !authority_valid(&profile.rendezvous_server, true)
        || !canonical_32(&profile.public_key)
        || !api_valid
        || !hash_valid
        || !(6..=64).contains(&profile.salt.len())
        || !profile.salt.bytes().all(|b| b.is_ascii_alphanumeric())
    {
        return Err(Error::InvalidProfile);
    }
    Ok(())
}

/// Verify the exact payload bytes before parsing; reject unknown/duplicate JSON
/// fields, unsupported versions, noncanonical keys and invalid server values.
pub fn verify_envelope(bytes: &[u8], key: &[u8; 32]) -> Result<Profile, Error> {
    if !(76..=MAX_ENVELOPE_LEN).contains(&bytes.len()) || &bytes[..8] != ENVELOPE_MAGIC {
        return Err(Error::InvalidEnvelope);
    }
    let payload_len = u32::from_le_bytes(
        bytes[8..12]
            .try_into()
            .map_err(|_| Error::InvalidEnvelope)?,
    ) as usize;
    if payload_len > MAX_JSON_LEN || bytes.len() != 12 + payload_len + 64 {
        return Err(Error::InvalidEnvelope);
    }
    let payload = &bytes[12..12 + payload_len];
    let signature =
        Signature::from_slice(&bytes[12 + payload_len..]).map_err(|_| Error::InvalidSignature)?;
    let key = VerifyingKey::from_bytes(key).map_err(|_| Error::InvalidSignature)?;
    let mut signed = Vec::with_capacity(SIGNATURE_DOMAIN.len() + payload.len());
    signed.extend_from_slice(SIGNATURE_DOMAIN);
    signed.extend_from_slice(payload);
    key.verify_strict(&signed, &signature)
        .map_err(|_| Error::InvalidSignature)?;
    let profile: Profile = serde_json::from_slice(payload).map_err(|_| Error::InvalidProfile)?;
    validate_profile(&profile)?;
    Ok(profile)
}

fn reparse_or_symlink(metadata: &fs::Metadata) -> bool {
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        metadata.file_attributes() & 0x400 != 0
    }
    #[cfg(not(windows))]
    {
        metadata.file_type().is_symlink()
    }
}

fn read_bounded(mut file: File) -> Result<Vec<u8>, Error> {
    let metadata = file.metadata().map_err(|_| Error::Io)?;
    if !metadata.is_file() || reparse_or_symlink(&metadata) {
        return Err(Error::UnsafePath);
    }
    if metadata.len() > MAX_ENVELOPE_LEN as u64 {
        return Err(Error::InvalidEnvelope);
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    Read::by_ref(&mut file)
        .take(MAX_ENVELOPE_LEN as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| Error::Io)?;
    if bytes.len() > MAX_ENVELOPE_LEN || bytes.len() as u64 != metadata.len() {
        return Err(Error::InvalidEnvelope);
    }
    Ok(bytes)
}

fn map_open_error(error: std::io::Error) -> Error {
    match error.kind() {
        std::io::ErrorKind::NotFound => Error::MissingProfile,
        std::io::ErrorKind::AlreadyExists => Error::ExistingSidecar,
        _ => Error::Io,
    }
}

/// Read only the fixed footer and bounded envelope, never the entire executable.
/// A missing footer is distinguishable from a present but invalid profile.
pub fn read_overlay(path: impl AsRef<Path>, key: &[u8; 32]) -> Result<(Profile, Vec<u8>), Error> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        options.custom_flags(0x00200000).share_mode(1); // no write/delete sharing
    }
    let mut file = options.open(path).map_err(map_open_error)?;
    let metadata = file.metadata().map_err(|_| Error::Io)?;
    if !metadata.is_file() || reparse_or_symlink(&metadata) {
        return Err(Error::UnsafePath);
    }
    let file_len = metadata.len();
    if file_len < 16 {
        return Err(Error::MissingProfile);
    }
    file.seek(SeekFrom::End(-16)).map_err(|_| Error::Io)?;
    let mut footer = [0u8; 16];
    file.read_exact(&mut footer).map_err(|_| Error::Io)?;
    if &footer[8..] != OVERLAY_MAGIC {
        return Err(Error::MissingProfile);
    }
    let envelope_len =
        u64::from_le_bytes(footer[..8].try_into().map_err(|_| Error::InvalidEnvelope)?);
    if !(76..=MAX_ENVELOPE_LEN as u64).contains(&envelope_len) || envelope_len > file_len - 16 {
        return Err(Error::InvalidEnvelope);
    }
    file.seek(SeekFrom::Start(file_len - 16 - envelope_len))
        .map_err(|_| Error::Io)?;
    let mut envelope = vec![0u8; envelope_len as usize];
    file.read_exact(&mut envelope).map_err(|_| Error::Io)?;
    if file.metadata().map_err(|_| Error::Io)?.len() != file_len {
        return Err(Error::InvalidEnvelope);
    }
    let profile = verify_envelope(&envelope, key)?;
    Ok((profile, envelope))
}

// Anchor sidecar operations to an opened, non-link directory. Unix openat keeps
// them attached to this inode across rename. Windows pins each ancestor against
// rename/deletion while the final path is used; handle inheritance is disabled
// by Rust's standard File implementation. This does not grant trust to a path:
// callers still choose an appropriate installation/cache directory.
struct Directory {
    #[cfg(unix)]
    file: File,
    #[cfg(windows)]
    path: PathBuf,
    #[cfg(windows)]
    _guards: Vec<File>,
}

fn absolute_components(path: &Path) -> Result<PathBuf, Error> {
    let path = if path.is_absolute() {
        path.to_owned()
    } else {
        std::env::current_dir().map_err(|_| Error::Io)?.join(path)
    };
    if path.components().any(|c| matches!(c, Component::ParentDir)) {
        return Err(Error::UnsafePath);
    }
    Ok(path)
}

#[cfg(unix)]
fn unix_open_at(parent: &File, name: &std::ffi::OsStr, flags: i32) -> Result<File, Error> {
    use std::{
        ffi::CString,
        os::{
            fd::{AsRawFd, FromRawFd},
            unix::ffi::OsStrExt,
        },
    };
    let name = CString::new(name.as_bytes()).map_err(|_| Error::UnsafePath)?;
    // SAFETY: the live parent fd and NUL-terminated component are valid; the
    // returned fd is owned once by File. O_NOFOLLOW forbids final symlinks.
    let fd = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            name.as_ptr(),
            flags | libc::O_CLOEXEC | libc::O_NOFOLLOW,
            0o600,
        )
    };
    if fd < 0 {
        return Err(map_open_error(std::io::Error::last_os_error()));
    }
    Ok(unsafe { File::from_raw_fd(fd) })
}

impl Directory {
    fn open(path: &Path) -> Result<Self, Error> {
        let path = absolute_components(path)?;
        #[cfg(unix)]
        {
            let mut file = File::open("/").map_err(|_| Error::Io)?;
            for component in path.components() {
                if let Component::Normal(name) = component {
                    file = unix_open_at(&file, name, libc::O_RDONLY | libc::O_DIRECTORY)?;
                }
            }
            Ok(Self { file })
        }
        #[cfg(windows)]
        {
            use std::os::windows::fs::OpenOptionsExt;
            let mut current = PathBuf::new();
            let mut guards = Vec::new();
            for component in path.components() {
                current.push(component.as_os_str());
                if !matches!(component, Component::Normal(_)) {
                    continue;
                }
                let file = OpenOptions::new()
                    .read(true)
                    .share_mode(3)
                    .custom_flags(0x02200000)
                    .open(&current)
                    .map_err(map_open_error)?;
                let metadata = file.metadata().map_err(|_| Error::Io)?;
                if !metadata.is_dir() || reparse_or_symlink(&metadata) {
                    return Err(Error::UnsafePath);
                }
                guards.push(file);
            }
            if guards.is_empty() {
                return Err(Error::UnsafePath);
            }
            Ok(Self {
                path,
                _guards: guards,
            })
        }
    }

    fn sidecar(&self, create: bool) -> Result<File, Error> {
        #[cfg(unix)]
        {
            let flags = if create {
                libc::O_RDWR | libc::O_CREAT | libc::O_EXCL
            } else {
                libc::O_RDONLY | libc::O_NONBLOCK
            };
            unix_open_at(&self.file, std::ffi::OsStr::new(SIDECAR_NAME), flags)
        }
        #[cfg(windows)]
        {
            use std::os::windows::fs::OpenOptionsExt;
            let mut options = OpenOptions::new();
            options
                .read(true)
                .write(create)
                .create_new(create)
                .share_mode(1)
                .custom_flags(0x00200000);
            let file = options
                .open(self.path.join(SIDECAR_NAME))
                .map_err(map_open_error)?;
            let metadata = file.metadata().map_err(|_| Error::Io)?;
            if !metadata.is_file() || reparse_or_symlink(&metadata) {
                return Err(Error::UnsafePath);
            }
            Ok(file)
        }
    }
}

pub fn read_sidecar(dir: impl AsRef<Path>, key: &[u8; 32]) -> Result<Profile, Error> {
    let directory = Directory::open(dir.as_ref())?;
    let bytes = read_bounded(directory.sidecar(false)?)?;
    verify_envelope(&bytes, key)
}

/// Validate before any filesystem mutation. Never overwrite an existing object.
/// A partial concurrent write cannot authenticate; interrupted writes may leave
/// an invalid sidecar that requires caller-directed cleanup. We do not unlink
/// on failure because the name might have been replaced by a different object.
pub fn write_sidecar(dir: impl AsRef<Path>, envelope: &[u8], key: &[u8; 32]) -> Result<(), Error> {
    verify_envelope(envelope, key)?;
    let directory = Directory::open(dir.as_ref())?;
    let mut file = match directory.sidecar(true) {
        Ok(file) => file,
        Err(Error::ExistingSidecar) => {
            let existing = read_bounded(directory.sidecar(false)?)?;
            if existing != envelope {
                return Err(Error::ExistingSidecar);
            }
            verify_envelope(&existing, key)?;
            return Ok(());
        }
        Err(error) => return Err(error),
    };
    file.write_all(envelope).map_err(|_| Error::Io)?;
    file.sync_all().map_err(|_| Error::Io)?;
    file.seek(SeekFrom::Start(0)).map_err(|_| Error::Io)?;
    // Verify our open object, then the current name. Never accept a changed name.
    let written = read_bounded(file)?;
    if written != envelope {
        return Err(Error::InvalidEnvelope);
    }
    verify_envelope(&written, key)?;
    let named = read_bounded(directory.sidecar(false)?)?;
    if named != envelope {
        return Err(Error::ExistingSidecar);
    }
    verify_envelope(&named, key)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use sha2::{Digest, Sha256};
    use tempfile::TempDir;

    // Synthetic signing key and credential; these are never product keys.
    fn signer() -> SigningKey {
        SigningKey::from_bytes(&[7u8; 32])
    }
    fn key() -> [u8; 32] {
        signer().verifying_key().to_bytes()
    }
    fn profile() -> Profile {
        Profile {
            schema_version: 1,
            build_id: "0123456789abcdef0123456789abcdef".into(),
            rendezvous_server: "support.example.test:21116".into(),
            public_key: STANDARD.encode([3u8; 32]),
            api_server: "https://support.example.test:443".into(),
            password_hash: format!(
                "00{}",
                STANDARD.encode(Sha256::digest(b"synthetic-passwordSalt1234"))
            ),
            salt: "Salt1234".into(),
        }
    }
    fn sign_payload(payload: &[u8]) -> Vec<u8> {
        let mut signed = SIGNATURE_DOMAIN.to_vec();
        signed.extend_from_slice(payload);
        let mut envelope = ENVELOPE_MAGIC.to_vec();
        envelope.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        envelope.extend_from_slice(payload);
        envelope.extend_from_slice(&signer().sign(&signed).to_bytes());
        envelope
    }
    fn envelope(profile: &Profile) -> Vec<u8> {
        sign_payload(&serde_json::to_vec(profile).unwrap())
    }
    fn directory() -> (TempDir, PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        // macOS's /var is itself a symlink. Tests supply an explicit real path,
        // matching the caller contract that sidecar ancestors are not links.
        let path = dir.path().canonicalize().unwrap();
        (dir, path)
    }
    fn append_overlay(file: &mut File, envelope: &[u8]) {
        file.seek(SeekFrom::End(0)).unwrap();
        file.write_all(envelope).unwrap();
        file.write_all(&(envelope.len() as u64).to_le_bytes())
            .unwrap();
        file.write_all(OVERLAY_MAGIC).unwrap();
    }

    #[test]
    fn authenticated_roundtrip_and_redacted_debug() {
        let expected = profile();
        assert_eq!(
            verify_envelope(&envelope(&expected), &key()).unwrap(),
            expected
        );
        let debug = format!("{expected:?}");
        assert_eq!(debug, "Profile { contents: [redacted] }");
        assert!(!debug.contains(&expected.password_hash));
        assert!(!debug.contains(&expected.salt));
    }

    #[test]
    fn rejects_tamper_wrong_key_and_weak_signature() {
        let original = envelope(&profile());
        for index in [12, original.len() - 1] {
            let mut altered = original.clone();
            altered[index] ^= 1;
            assert_eq!(
                verify_envelope(&altered, &key()).unwrap_err(),
                Error::InvalidSignature
            );
        }
        let wrong_key = SigningKey::from_bytes(&[9u8; 32])
            .verifying_key()
            .to_bytes();
        assert_eq!(
            verify_envelope(&original, &wrong_key).unwrap_err(),
            Error::InvalidSignature
        );
        // Identity public key and R, zero S: verify_strict must reject weak keys.
        let mut identity = [0u8; 32];
        identity[0] = 1;
        let mut weak = original.clone();
        let signature_offset = weak.len() - 64;
        weak[signature_offset..].fill(0);
        weak[signature_offset] = 1;
        assert_eq!(
            verify_envelope(&weak, &identity).unwrap_err(),
            Error::InvalidSignature
        );
    }

    #[test]
    fn signature_is_domain_separated() {
        let payload = serde_json::to_vec(&profile()).unwrap();
        let mut value = envelope(&profile());
        let offset = value.len() - 64;
        value[offset..].copy_from_slice(&signer().sign(&payload).to_bytes());
        assert_eq!(
            verify_envelope(&value, &key()).unwrap_err(),
            Error::InvalidSignature
        );
    }

    #[test]
    fn exact_envelope_lengths_and_json_bound() {
        let original = envelope(&profile());
        for length in [0, 7, 11, 75, original.len() - 1] {
            assert_eq!(
                verify_envelope(&original[..length], &key()).unwrap_err(),
                Error::InvalidEnvelope
            );
        }
        let mut trailing = original.clone();
        trailing.push(0);
        assert_eq!(
            verify_envelope(&trailing, &key()).unwrap_err(),
            Error::InvalidEnvelope
        );
        let mut overflow = original;
        overflow[8..12].copy_from_slice(&u32::MAX.to_le_bytes());
        assert_eq!(
            verify_envelope(&overflow, &key()).unwrap_err(),
            Error::InvalidEnvelope
        );
        let mut padded = serde_json::to_vec(&profile()).unwrap();
        padded.resize(MAX_JSON_LEN, b' ');
        assert!(verify_envelope(&sign_payload(&padded), &key()).is_ok());
        padded.push(b' ');
        assert_eq!(
            verify_envelope(&sign_payload(&padded), &key()).unwrap_err(),
            Error::InvalidEnvelope
        );
    }

    #[test]
    fn unknown_duplicate_missing_and_invalid_json_are_rejected_even_if_signed() {
        let mut unknown = serde_json::to_value(profile()).unwrap();
        unknown["password"] = "synthetic-unexpected-value".into();
        let ordinary = serde_json::to_string(&profile()).unwrap();
        let duplicate = ordinary.replacen('{', "{\"schema_version\":1,", 1);
        for payload in [
            serde_json::to_vec(&unknown).unwrap(),
            duplicate.into_bytes(),
            b"{}".to_vec(),
            b"not json".to_vec(),
        ] {
            assert_eq!(
                verify_envelope(&sign_payload(&payload), &key()).unwrap_err(),
                Error::InvalidProfile
            );
        }
    }

    #[test]
    fn strict_profile_fields_reject_signed_malformed_values() {
        let cases = [
            ("schema_version", serde_json::json!(2)),
            (
                "build_id",
                serde_json::json!("0123456789ABCDEF0123456789ABCDEF"),
            ),
            ("build_id", serde_json::json!("../escape")),
            ("salt", serde_json::json!("short")),
            ("salt", serde_json::json!("contains spaces")),
            ("salt", serde_json::json!("a".repeat(65))),
            (
                "password_hash",
                serde_json::json!(format!("02{}", STANDARD.encode([3u8; 32]))),
            ),
            ("password_hash", serde_json::json!("00not-base64")),
            (
                "password_hash",
                serde_json::json!(format!("00{}", STANDARD.encode([3u8; 31]))),
            ),
            (
                "public_key",
                serde_json::json!(STANDARD.encode([3u8; 32]).trim_end_matches('=')),
            ),
            ("public_key", serde_json::json!(STANDARD.encode([3u8; 33]))),
            ("rendezvous_server", serde_json::json!("https://host")),
            ("rendezvous_server", serde_json::json!("host/name")),
            ("rendezvous_server", serde_json::json!("white space")),
            ("rendezvous_server", serde_json::json!("host:0")),
            ("rendezvous_server", serde_json::json!("host:65536")),
            ("rendezvous_server", serde_json::json!("999.2.3.4")),
            ("rendezvous_server", serde_json::json!("-bad.example")),
            ("api_server", serde_json::json!("http://host")),
            ("api_server", serde_json::json!("https://host/")),
            ("api_server", serde_json::json!("https://user@host")),
            ("api_server", serde_json::json!("https://host?x=1")),
            ("api_server", serde_json::json!("https://host#fragment")),
            ("api_server", serde_json::json!("https://host\\path")),
            ("api_server", serde_json::json!("https://::1")),
        ];
        for (field, value) in cases {
            let mut p = serde_json::to_value(profile()).unwrap();
            p[field] = value;
            assert_eq!(
                verify_envelope(&sign_payload(&serde_json::to_vec(&p).unwrap()), &key())
                    .unwrap_err(),
                Error::InvalidProfile,
                "field: {field}"
            );
        }
    }

    #[test]
    fn accepts_explicit_ipv4_ipv6_and_dns_authorities() {
        for server in [
            "localhost",
            "support.example.test",
            "192.0.2.1:21116",
            "[2001:db8::1]:21116",
            "2001:db8::1",
        ] {
            let mut p = profile();
            p.rendezvous_server = server.into();
            p.api_server = "https://[2001:db8::2]:443".into();
            assert!(verify_envelope(&envelope(&p), &key()).is_ok());
        }
    }

    #[test]
    fn overlay_reads_large_sparse_binary_and_only_last_footer() {
        let (_temp, path) = directory();
        let executable = path.join("synthetic.exe");
        let mut file = File::create(&executable).unwrap();
        file.set_len(1 << 30).unwrap();
        let expected = envelope(&profile());
        append_overlay(&mut file, &expected);
        let (p, actual) = read_overlay(&executable, &key()).unwrap();
        assert_eq!(p, profile());
        assert_eq!(actual, expected);
        file.write_all(b"extra trailer").unwrap();
        assert_eq!(
            read_overlay(&executable, &key()).unwrap_err(),
            Error::MissingProfile
        );
    }

    #[test]
    fn overlay_bounds_reject_malformed_footer_without_allocating_claimed_length() {
        let (_temp, path) = directory();
        let executable = path.join("synthetic.exe");
        fs::write(&executable, b"MZ").unwrap();
        assert_eq!(
            read_overlay(&executable, &key()).unwrap_err(),
            Error::MissingProfile
        );
        for length in [0u64, 75, MAX_ENVELOPE_LEN as u64 + 1, u64::MAX] {
            let mut bytes = length.to_le_bytes().to_vec();
            bytes.extend_from_slice(OVERLAY_MAGIC);
            fs::write(&executable, bytes).unwrap();
            assert_eq!(
                read_overlay(&executable, &key()).unwrap_err(),
                Error::InvalidEnvelope
            );
        }
    }

    #[test]
    fn sidecar_is_validated_before_write_immutable_and_read_back() {
        let (_temp, path) = directory();
        let original = envelope(&profile());
        assert_eq!(
            write_sidecar(&path, b"unsigned", &key()).unwrap_err(),
            Error::InvalidEnvelope
        );
        assert!(!path.join(SIDECAR_NAME).exists());
        write_sidecar(&path, &original, &key()).unwrap();
        write_sidecar(&path, &original, &key()).unwrap();
        assert_eq!(read_sidecar(&path, &key()).unwrap(), profile());
        let mut different = profile();
        different.build_id = "f".repeat(32);
        assert_eq!(
            write_sidecar(&path, &envelope(&different), &key()).unwrap_err(),
            Error::ExistingSidecar
        );
        assert_eq!(fs::read(path.join(SIDECAR_NAME)).unwrap(), original);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(path.join(SIDECAR_NAME))
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o600
            );
        }
    }

    #[test]
    fn unexpected_sidecar_objects_are_never_overwritten() {
        let (_temp, path) = directory();
        let sidecar = path.join(SIDECAR_NAME);
        fs::write(&sidecar, b"truncated").unwrap();
        assert!(write_sidecar(&path, &envelope(&profile()), &key()).is_err());
        assert_eq!(fs::read(&sidecar).unwrap(), b"truncated");
        fs::remove_file(&sidecar).unwrap();
        fs::create_dir(&sidecar).unwrap();
        assert!(read_sidecar(&path, &key()).is_err());
        assert!(write_sidecar(&path, &envelope(&profile()), &key()).is_err());
        assert!(sidecar.is_dir());
    }

    #[test]
    fn sidecar_read_is_bounded() {
        let (_temp, path) = directory();
        File::create(path.join(SIDECAR_NAME))
            .unwrap()
            .set_len(1 << 30)
            .unwrap();
        assert_eq!(
            read_sidecar(&path, &key()).unwrap_err(),
            Error::InvalidEnvelope
        );
    }

    #[cfg(unix)]
    #[test]
    fn links_and_link_ancestors_are_refused_without_touching_targets() {
        use std::os::unix::fs::symlink;
        let (_temp, path) = directory();
        let real = path.join("real");
        fs::create_dir(&real).unwrap();
        let target = path.join("target");
        fs::write(&target, b"unchanged").unwrap();
        symlink(&target, real.join(SIDECAR_NAME)).unwrap();
        assert!(write_sidecar(&real, &envelope(&profile()), &key()).is_err());
        assert!(read_sidecar(&real, &key()).is_err());
        assert_eq!(fs::read(&target).unwrap(), b"unchanged");
        symlink(&real, path.join("link")).unwrap();
        assert!(read_sidecar(path.join("link"), &key()).is_err());
        assert!(write_sidecar(path.join("link"), &envelope(&profile()), &key()).is_err());
        fs::create_dir(real.join("child")).unwrap();
        assert!(write_sidecar(path.join("link/child"), &envelope(&profile()), &key()).is_err());
        assert!(read_overlay(real.join(SIDECAR_NAME), &key()).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn opened_directory_anchor_survives_rename_without_redirecting_write() {
        let (_temp, path) = directory();
        let source = path.join("source");
        let moved = path.join("moved");
        fs::create_dir(&source).unwrap();
        let directory = Directory::open(&source).unwrap();
        fs::rename(&source, &moved).unwrap();
        fs::create_dir(&source).unwrap();
        directory
            .sidecar(true)
            .unwrap()
            .write_all(b"anchored")
            .unwrap();
        assert!(!source.join(SIDECAR_NAME).exists());
        assert_eq!(fs::read(moved.join(SIDECAR_NAME)).unwrap(), b"anchored");
    }

    #[cfg(unix)]
    #[test]
    fn fifo_sidecar_is_rejected_without_blocking() {
        use std::{ffi::CString, os::unix::ffi::OsStrExt};
        let (_temp, path) = directory();
        let name = CString::new(path.join(SIDECAR_NAME).as_os_str().as_bytes()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o600) }, 0);
        assert_eq!(read_sidecar(&path, &key()).unwrap_err(), Error::UnsafePath);
        assert!(write_sidecar(&path, &envelope(&profile()), &key()).is_err());
    }
}
