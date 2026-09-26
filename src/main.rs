#![cfg_attr(all(windows, not(debug_assertions)), windows_subsystem = "windows")]

mod cipher;
mod decrypt;
mod error;
mod gui;
mod pe;
mod sha256;

use std::env;
use std::ffi::{OsStr, OsString};
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use error::{err, Result};

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            // A windowed release build has nowhere to print until the console is attached.
            // writeln, unlike eprintln, does not panic when the handle is missing.
            let _ = writeln!(io::stderr(), "{e}");
            ExitCode::from(1)
        }
    }
}

fn run() -> Result<()> {
    let args: Vec<OsString> = env::args_os().skip(1).collect();
    if args.is_empty() {
        return gui::run();
    }
    #[cfg(all(windows, not(debug_assertions)))]
    attach_parent_console();
    cli(&args)
}

fn cli(args: &[OsString]) -> Result<()> {
    let (input, output_flag) = parse_args(args)?;
    let output = match output_flag {
        Some(path) => path,
        None => decrypt::default_output(&input)?,
    };

    let pe_bytes = fs::read(&input).map_err(|e| err(format!("cannot read {}: {e}", input.display())))?;
    let report = decrypt::decrypt_pe(&pe_bytes)?;
    let digest = sha256::to_hex(&sha256::sha256(&report.plaintext));
    fs::write(&output, &report.plaintext)
        .map_err(|e| err(format!("cannot write {}: {e}", output.display())))?;

    emit_report(&report, &digest, &output);
    Ok(())
}

fn emit_report(report: &decrypt::Report, digest: &str, output: &Path) {
    let mut out = io::stdout();
    let _ = writeln!(
        out,
        "timestamp: {} ({} UTC)",
        report.timestamp, report.timestamp_utc
    );
    let _ = writeln!(out, "trailer: {}", report.trailer.join(", "));
    let _ = writeln!(out, "bytes: {}", report.plaintext.len());
    let _ = writeln!(out, "sha256: {digest}");
    let _ = writeln!(out, "wrote: {}", output.display());
}

fn parse_args(args: &[OsString]) -> Result<(PathBuf, Option<PathBuf>)> {
    let mut input: Option<PathBuf> = None;
    let mut output: Option<PathBuf> = None;
    let mut i = 0;
    while i < args.len() {
        let arg = &args[i];
        if arg == OsStr::new("-o") {
            i += 1;
            if i >= args.len() || output.is_some() {
                return Err(usage());
            }
            output = Some(PathBuf::from(&args[i]));
        } else if arg.to_string_lossy().starts_with('-') {
            return Err(usage());
        } else if input.is_some() {
            return Err(usage());
        } else {
            input = Some(PathBuf::from(arg));
        }
        i += 1;
    }
    let input = input.ok_or_else(usage)?;
    Ok((input, output))
}

fn usage() -> error::Error {
    err("usage: yaesu-ft3dr-decrypt <updater.exe> [-o output.bin]")
}

/// Release builds use the windows subsystem, so a console parent does not hand over
/// stdout. Rust reads the standard handles on each write. A pipe or an existing
/// console handle is left alone. If attach fails, the decrypt still runs.
#[cfg(all(windows, not(debug_assertions)))]
fn attach_parent_console() {
    use std::os::windows::ffi::OsStrExt;

    const STD_OUTPUT_HANDLE: u32 = 0xFFFFFFF5;
    const STD_ERROR_HANDLE: u32 = 0xFFFFFFF4;
    const ATTACH_PARENT_PROCESS: u32 = 0xFFFFFFFF;
    const GENERIC_READ: u32 = 0x80000000;
    const GENERIC_WRITE: u32 = 0x40000000;
    const FILE_SHARE_READ: u32 = 1;
    const FILE_SHARE_WRITE: u32 = 2;
    const OPEN_EXISTING: u32 = 3;

    #[link(name = "kernel32")]
    extern "system" {
        fn GetStdHandle(n_std_handle: u32) -> *mut core::ffi::c_void;
        fn SetStdHandle(n_std_handle: u32, handle: *mut core::ffi::c_void) -> i32;
        fn AttachConsole(process_id: u32) -> i32;
        fn CreateFileW(
            name: *const u16,
            access: u32,
            share: u32,
            security: *mut core::ffi::c_void,
            disposition: u32,
            flags: u32,
            template: *mut core::ffi::c_void,
        ) -> *mut core::ffi::c_void;
    }

    unsafe {
        let stdout = GetStdHandle(STD_OUTPUT_HANDLE);
        if !stdout.is_null() && stdout as isize != -1 {
            return;
        }
        if AttachConsole(ATTACH_PARENT_PROCESS) == 0 {
            return;
        }
        let mut name: Vec<u16> = OsStr::new("CONOUT$").encode_wide().collect();
        name.push(0);
        let handle = CreateFileW(
            name.as_ptr(),
            GENERIC_READ | GENERIC_WRITE,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            core::ptr::null_mut(),
            OPEN_EXISTING,
            0,
            core::ptr::null_mut(),
        );
        if handle.is_null() || handle as isize == -1 {
            return;
        }
        SetStdHandle(STD_OUTPUT_HANDLE, handle);
        SetStdHandle(STD_ERROR_HANDLE, handle);
    }
}
