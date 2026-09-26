mod cipher;
mod error;
mod pe;
mod sha256;

use std::env;
use std::ffi::{OsStr, OsString};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use error::{err, Result};

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("{e}");
            ExitCode::from(1)
        }
    }
}

fn run() -> Result<()> {
    let args: Vec<OsString> = env::args_os().skip(1).collect();
    let (input, output_flag) = parse_args(&args)?;
    let output = match output_flag {
        Some(path) => path,
        None => default_output(&input)?,
    };

    let pe_bytes = fs::read(&input).map_err(|e| err(format!("cannot read {}: {e}", input.display())))?;
    let blob = pe::extract_named_resource(&pe_bytes, 23, "RES_UPDATE_INFO")?;
    let (timestamp, ciphertext, trailer) = cipher::split_update(&blob)?;
    let tables = pe::find_tables(&pe_bytes)?;
    let mut decryptor = cipher::Decryptor::new(tables);
    // derive() installs the session key used for the payload.
    decryptor.derive(timestamp);
    let plain = decryptor.decrypt_payload(ciphertext)?;
    let digest = sha256::to_hex(&sha256::sha256(&plain));
    fs::write(&output, &plain).map_err(|e| err(format!("cannot write {}: {e}", output.display())))?;

    let text = cipher::timestamp_text(timestamp);
    let strings = cipher::trailer_strings(trailer);
    println!("timestamp: {timestamp} ({text} UTC)");
    println!("trailer: {}", strings.join(", "));
    println!("bytes: {}", plain.len());
    println!("sha256: {digest}");
    println!("wrote: {}", output.display());
    Ok(())
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

fn default_output(input: &Path) -> Result<PathBuf> {
    let stem = input
        .file_stem()
        .ok_or_else(|| err("input path has no file name"))?;
    let mut name = OsString::from(stem);
    name.push(".bin");
    let mut out = input.to_path_buf();
    out.set_file_name(name);
    Ok(out)
}
