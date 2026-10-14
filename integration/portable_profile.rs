//! Move the private profile from the outer launcher to the installed inner app.
use retailcontrol_profile::{read_overlay, write_sidecar};
use std::path::{Path, PathBuf};

const PROFILE_KEY: &[u8; 32] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../profile-public-key.bin"
));
const PROFILE_ERROR: &str =
    "RetailControl Remote Support could not prepare its setup profile. Download the installer again from your private support link.";

pub(crate) struct PreparedProfile {
    pub(crate) directory: PathBuf,
    envelope: Vec<u8>,
}

impl PreparedProfile {
    pub(crate) fn read_or_exit(prefix: &str) -> Self {
        match Self::read(prefix) {
            Some(profile) => profile,
            None => fail_closed(),
        }
    }

    fn read(prefix: &str) -> Option<Self> {
        let exe = std::env::current_exe().ok()?;
        let (profile, envelope) = read_overlay(exe, PROFILE_KEY).ok()?;
        let directory = dirs::data_local_dir()?.join(prefix).join(profile.build_id);
        Some(Self {
            directory,
            envelope,
        })
    }

    /// setup() can clear the extraction tree, so this MUST run after setup().
    /// Native installation copies this directory, including the verified sidecar.
    pub(crate) fn persist_or_exit(&self, executable: &Path) {
        let Some(directory) = executable.parent() else {
            fail_closed();
        };
        if write_sidecar(directory, &self.envelope, PROFILE_KEY).is_err() {
            fail_closed();
        }
    }
}

pub(crate) fn fail_closed() -> ! {
    use winapi::um::winuser::{MessageBoxW, MB_ICONERROR, MB_OK};
    let message: Vec<u16> = PROFILE_ERROR.encode_utf16().chain(Some(0)).collect();
    let title: Vec<u16> = "RetailControl Remote Support"
        .encode_utf16()
        .chain(Some(0))
        .collect();
    unsafe {
        MessageBoxW(
            std::ptr::null_mut(),
            message.as_ptr(),
            title.as_ptr(),
            MB_OK | MB_ICONERROR,
        );
    }
    eprintln!("RetailControl setup profile preparation failed.");
    std::process::exit(1);
}
