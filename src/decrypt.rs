use std::ffi::OsString;
use std::path::{Path, PathBuf};

use crate::cipher;
use crate::error::{err, Result};
use crate::pe;

pub struct Report {
    pub timestamp: u32,
    /// `cipher::timestamp_text`: 14 digits, no ` UTC` suffix.
    pub timestamp_utc: String,
    pub trailer: Vec<String>,
    pub plaintext: Vec<u8>,
}

pub fn decrypt_pe(pe: &[u8]) -> Result<Report> {
    let blob = pe::extract_named_resource(pe, 23, "RES_UPDATE_INFO")?;
    let (timestamp, ciphertext, trailer) = cipher::split_update(&blob)?;
    let tables = pe::find_tables(pe)?;
    let mut decryptor = cipher::Decryptor::new(tables);
    // derive() installs the session key used for the payload.
    decryptor.derive(timestamp);
    let plaintext = decryptor.decrypt_payload(ciphertext)?;
    Ok(Report {
        timestamp,
        timestamp_utc: cipher::timestamp_text(timestamp),
        trailer: cipher::trailer_strings(trailer),
        plaintext,
    })
}

pub fn default_output(input: &Path) -> Result<PathBuf> {
    let stem = input
        .file_stem()
        .ok_or_else(|| err("input path has no file name"))?;
    let mut name = OsString::from(stem);
    name.push(".bin");
    let mut out = input.to_path_buf();
    out.set_file_name(name);
    Ok(out)
}
