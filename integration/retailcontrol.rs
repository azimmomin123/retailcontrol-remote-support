//! RetailControl's own profile. The upstream vendor custom.txt verifier is unchanged.
use hbb_common::config;
use retailcontrol_profile::{read_sidecar, Profile};

const PRODUCT_NAME: &str = "RetailControlRemoteSupport";
const PROFILE_KEY: &[u8; 32] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/profile-public-key.bin"
));
const PROFILE_ERROR: &str =
    "RetailControl Remote Support could not verify its setup profile. Download the installer again from your private support link!";

/// Call before any config load in both the C++ bootstrap DLL and Flutter's DLL.
/// Installed services deliberately reload the sidecar beside their executable.
pub(crate) fn initialize_or_exit() {
    *config::APP_NAME.write().unwrap() = PRODUCT_NAME.to_owned();
    let profile = std::env::current_exe()
        .ok()
        .and_then(|exe| exe.parent().map(std::path::Path::to_path_buf))
        .and_then(|dir| read_sidecar(dir, PROFILE_KEY).ok());
    match profile {
        Some(profile) => apply_profile(profile),
        None => {
            // A LocalSystem service has no interactive desktop. Never strand it
            // on a dialog in session zero; exit unsuccessfully before networking.
            let background = std::env::args()
                .any(|arg| matches!(arg.as_str(), "--service" | "--server" | "--tray"));
            if !background {
                crate::platform::windows::message_box(PROFILE_ERROR);
            }
            eprintln!("RetailControl setup profile verification failed.");
            std::process::exit(1);
        }
    }
}

fn apply_profile(profile: Profile) {
    // EXE_RENDEZVOUS_SERVER has higher priority than normal options. The owned
    // build also disables legacy filename/env parsing in Windows bootstrap.
    *config::EXE_RENDEZVOUS_SERVER.write().unwrap() = profile.rendezvous_server.clone();
    let mut settings = config::OVERWRITE_SETTINGS.write().unwrap();
    for (key, value) in [
        ("custom-rendezvous-server", profile.rendezvous_server),
        ("key", profile.public_key),
        ("api-server", profile.api_server),
        ("verification-method", "use-permanent-password".to_owned()),
        ("approve-mode", "password".to_owned()),
        ("access-mode", "full".to_owned()),
        ("allow-auto-update", "N".to_owned()),
    ] {
        settings.insert(key.to_owned(), value);
    }
    drop(settings);

    // Native preset support takes H1 storage with the upstream "00" prefix.
    // It does not need a post-install --password command or a plaintext file.
    let mut hard = config::HARD_SETTINGS.write().unwrap();
    hard.insert("password".to_owned(), profile.password_hash);
    hard.insert("salt".to_owned(), profile.salt);
    drop(hard);

    let mut built_in = config::BUILTIN_SETTINGS.write().unwrap();
    built_in.insert("register-device".to_owned(), "Y".to_owned());
    built_in.insert(
        "disable-change-permanent-password".to_owned(),
        "Y".to_owned(),
    );
}
