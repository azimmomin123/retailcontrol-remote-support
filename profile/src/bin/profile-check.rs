//! Credential-free verification entry point for packaging interoperability checks.
use std::{fs::File, io::Read, path::Path, process::ExitCode};

fn check() -> Result<(), ()> {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    if args.len() != 3 {
        return Err(());
    }
    let mut key = Vec::new();
    File::open(&args[2])
        .map_err(|_| ())?
        .take(33)
        .read_to_end(&mut key)
        .map_err(|_| ())?;
    let key: [u8; 32] = key.try_into().map_err(|_| ())?;
    match args[0].to_str() {
        Some("overlay") => retailcontrol_profile::read_overlay(Path::new(&args[1]), &key)
            .map(|_| ())
            .map_err(|_| ()),
        Some("sidecar") => retailcontrol_profile::read_sidecar(Path::new(&args[1]), &key)
            .map(|_| ())
            .map_err(|_| ()),
        _ => Err(()),
    }
}

fn main() -> ExitCode {
    if check().is_ok() {
        println!("profile verification succeeded");
        ExitCode::SUCCESS
    } else {
        eprintln!("profile verification failed");
        ExitCode::FAILURE
    }
}
