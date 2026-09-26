use crate::error::{err, Result};

/// Sizes accepted in the trailer length dword, in the order they are tried.
const PAYLOAD_SIZES: [usize; 5] = [0x100000, 0x400000, 0x80000, 0x200000, 0x800000];

/// Six-bit groups inside one round. The last field selects a 256-byte region
/// of the substitution table.
const GROUPS: [(usize, usize, usize, usize, usize, usize, usize); 8] = [
    (0, 5, 1, 2, 3, 4, 0x000),
    (6, 11, 7, 8, 9, 10, 0x100),
    (12, 17, 13, 14, 15, 16, 0x200),
    (18, 23, 19, 20, 21, 22, 0x300),
    (24, 29, 25, 26, 27, 28, 0x400),
    (30, 35, 31, 32, 33, 34, 0x500),
    (36, 41, 37, 38, 39, 40, 0x600),
    (42, 47, 43, 44, 45, 46, 0x700),
];

pub struct StaticTables {
    pub key_config: [u8; 0x40],
    pub key_config2: [u8; 0x30],
    pub encryption_config: [u8; 0x30],
    pub encryption_config2: [u8; 0x800],
    pub encryption_config3: [u8; 0x20],
    pub timestamp_tables: [[u8; 56]; 4],
}

pub struct Decryptor {
    key_config: [u8; 0x40],
    key_config2: [u8; 0x30],
    enc_config: [u8; 0x30],
    enc_config2: [u8; 0x800],
    enc_config3: [u8; 0x20],
    timestamp_tables: [[u8; 56]; 4],
    key: [u8; 0x300],
}

pub fn timestamp_text(timestamp: u32) -> String {
    let secs = timestamp as u64;
    let days = (secs / 86_400) as i64;
    let tod = secs % 86_400;
    let hour = tod / 3_600;
    let min = (tod % 3_600) / 60;
    let sec = tod % 60;
    let (year, month, day) = civil_ymd(days);
    format!("{year:04}{month:02}{day:02}{hour:02}{min:02}{sec:02}")
}

/// Days since the Unix epoch to a civil year, month, day. Gregorian, UTC.
fn civil_ymd(days_since_unix: i64) -> (i64, u32, u32) {
    let z = days_since_unix + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    (y, m as u32, d as u32)
}

pub fn split_update(blob: &[u8]) -> Result<(u32, &[u8], &[u8])> {
    if blob.len() < 8 {
        return Err(err("update resource is too small"));
    }
    let timestamp = u32::from_le_bytes([blob[0], blob[1], blob[2], blob[3]]);
    for size in PAYLOAD_SIZES {
        let off = 4 + size;
        if off + 4 <= blob.len() {
            let n = u32::from_le_bytes([blob[off], blob[off + 1], blob[off + 2], blob[off + 3]]);
            if n as usize == size {
                return Ok((timestamp, &blob[4..off], &blob[off..]));
            }
        }
    }
    Err(err(
        "ciphertext length dword was not found in the trailer",
    ))
}

pub fn trailer_strings(trailer: &[u8]) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    for &b in trailer {
        if (32..127).contains(&b) {
            cur.push(b as char);
        } else {
            if cur.len() >= 3 {
                out.push(std::mem::take(&mut cur));
            } else {
                cur.clear();
            }
        }
    }
    if cur.len() >= 3 {
        out.push(cur);
    }
    out
}

impl Decryptor {
    pub fn new(tables: StaticTables) -> Self {
        Self {
            key_config: tables.key_config,
            key_config2: tables.key_config2,
            enc_config: tables.encryption_config,
            enc_config2: tables.encryption_config2,
            enc_config3: tables.encryption_config3,
            timestamp_tables: tables.timestamp_tables,
            key: [0; 0x300],
        }
    }

    /// `key_config` is sixteen little-endian dwords. Only the low byte is consulted.
    fn set_key(&mut self, key56: &[u8; 56]) {
        let mut scrambled = *key56;
        for i in 0..16 {
            let rounds = if self.key_config[i * 4] == 2 { 2 } else { 1 };
            for _ in 0..rounds {
                let temp = scrambled[0];
                scrambled.copy_within(1..28, 0);
                scrambled[27] = temp;
                let temp = scrambled[28];
                scrambled.copy_within(29..56, 28);
                scrambled[55] = temp;
            }
            let base = i * 48;
            for k in 0..48 {
                let idx = self.key_config2[k] as usize - 1;
                self.key[base + k] = scrambled[idx];
            }
        }
    }

    /// One block. Bits are bytes 0 or 1. `outbuf` is 64 of those bytes.
    /// Decrypt starts at schedule slot 15. The last round only XORs.
    fn decrypt_block(&self, outbuf: &mut [u8; 64], is_encrypt: bool) {
        let key = &self.key;
        let enc = &self.enc_config;
        let enc2 = &self.enc_config2;
        let enc3 = &self.enc_config3;
        let mut scratch = [0u8; 48];
        let mut multiplier: usize = if is_encrypt { 0 } else { 0xF };
        let mut remaining: u32 = 15;
        loop {
            for i in 0..8 {
                let iidx = i * 6;
                let lhs_base = 48 * multiplier + iidx;
                for j in 0..6 {
                    let rhs = outbuf[enc[iidx + j] as usize + 31];
                    scratch[iidx + j] = key[lhs_base + j] ^ rhs;
                }
            }

            let mut temps = [0u8; 32];
            for (n, &(a, b, c, d, e, f, off)) in GROUPS.iter().enumerate() {
                // `(x << n) + 2`. In Rust `+` binds tighter than `<<`.
                let idx = (((scratch[a] as u32) << 5) + 2)
                    | (((scratch[b] as u32) << 4) + 2)
                    | (((scratch[c] as u32) << 3) + 2)
                    | (((scratch[d] as u32) << 2) + 2)
                    | (((scratch[e] as u32) << 1) + 2)
                    | ((scratch[f] as u32) + 2);
                let idx = idx as usize;
                temps[n * 4..n * 4 + 4].copy_from_slice(&enc2[off + idx..off + idx + 4]);
            }
            let mut material = [0u8; 80];
            material[..32].copy_from_slice(&temps);
            material[32..].copy_from_slice(&scratch);

            let mut pos = 0usize;
            if remaining == 0 {
                for _ in 0..8 {
                    for j in 0..4 {
                        outbuf[pos + j] ^= material[enc3[pos + j] as usize - 1];
                    }
                    pos += 4;
                }
            } else {
                for _ in 0..8 {
                    let mut second = 0usize;
                    for first in 0x1C..0x20 {
                        let src = first + pos + 4;
                        let original = outbuf[src];
                        let constant = enc3[pos + second];
                        outbuf[src] = outbuf[pos + second] ^ material[constant as usize - 1];
                        outbuf[pos + second] = original;
                        second += 1;
                    }
                    pos += 4;
                }
            }

            if remaining == 0 {
                return;
            }
            remaining -= 1;
            if is_encrypt {
                multiplier += 1;
            } else {
                multiplier -= 1;
            }
        }
    }

    pub fn derive(&mut self, timestamp: u32) -> [u8; 56] {
        let text = timestamp_text(timestamp);
        let text = text.as_bytes();
        let mut outbuf = [0u8; 64];
        let mut pos = 0usize;
        let mut next_byte = || -> u8 {
            if pos < text.len() {
                let b = text[pos];
                pos += 1;
                b
            } else {
                0
            }
        };
        let mut curr = next_byte();
        for t in 0..4 {
            let table = self.timestamp_tables[t];
            self.set_key(&table);
            for byte_idx in 0..8 {
                let base = byte_idx * 8;
                for bit_idx in 0..8 {
                    let bit = (curr >> (7 - bit_idx)) & 1;
                    outbuf[base + bit_idx] ^= bit;
                }
                curr = next_byte();
            }
            self.decrypt_block(&mut outbuf, true);
        }
        let mut session = [0u8; 56];
        session.copy_from_slice(&outbuf[..56]);
        self.set_key(&session);
        session
    }

    pub fn decrypt_payload(&self, encrypted: &[u8]) -> Result<Vec<u8>> {
        if encrypted.len() % 8 != 0 {
            return Err(err("ciphertext length is not a multiple of 8"));
        }
        let mut decrypted = vec![0u8; encrypted.len()];
        let mut inflated = [0u8; 64];
        let mut out_i = 0usize;
        while out_i < encrypted.len() {
            for i in 0..8 {
                let b = encrypted[out_i + i];
                let bit = i * 8;
                inflated[bit] = b >> 7;
                inflated[bit + 1] = (b >> 6) & 1;
                inflated[bit + 2] = (b >> 5) & 1;
                inflated[bit + 3] = (b >> 4) & 1;
                inflated[bit + 4] = (b >> 3) & 1;
                inflated[bit + 5] = (b >> 2) & 1;
                inflated[bit + 6] = (b >> 1) & 1;
                inflated[bit + 7] = b & 1;
            }
            self.decrypt_block(&mut inflated, false);
            for i in 0..8 {
                let mut acc = 0u8;
                let base = i * 8;
                for shift in 0..8 {
                    acc |= inflated[7 - shift + base] << shift;
                }
                decrypted[out_i + i] = acc;
            }
            out_i += 8;
        }
        Ok(decrypted)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn utc_text_matches_the_format_string() {
        assert_eq!(timestamp_text(0), "19700101000000");
        assert_eq!(timestamp_text(1576569521), "20191217075841");
        assert_eq!(timestamp_text(1576569673), "20191217080113");
    }

    #[test]
    fn split_finds_the_length_dword() {
        let mut blob = vec![0u8; 4 + 0x80000 + 8];
        blob[0..4].copy_from_slice(&1_576_569_521u32.to_le_bytes());
        let off = 4 + 0x80000;
        blob[off..off + 4].copy_from_slice(&(0x80000u32).to_le_bytes());
        let (ts, ct, tr) = split_update(&blob).unwrap();
        assert_eq!(ts, 1_576_569_521);
        assert_eq!(ct.len(), 0x80000);
        assert_eq!(tr.len(), 8);
    }

    #[test]
    fn split_rejects_a_short_blob() {
        assert!(split_update(&[0, 1, 2, 3, 4]).is_err());
        assert!(split_update(&[0; 32]).is_err());
    }

    #[test]
    fn trailer_keeps_printable_runs_of_three() {
        let raw = b"\x00\x00\x10\x00FT3DR/E(MAIN)\x00EXP\x001.02\x00ab";
        let got = trailer_strings(raw);
        assert_eq!(got, vec!["FT3DR/E(MAIN)", "EXP", "1.02"]);
    }

    #[test]
    fn shift_add_stays_inside_the_parentheses() {
        let x = 1u32;
        let parenthesized = ((x << 5) + 2) | ((x << 4) + 2) | ((x << 3) + 2);
        let rust_default_binding = (x << (5 + 2)) | (x << (4 + 2)) | (x << (3 + 2));
        assert_eq!(parenthesized, 34 | 18 | 10);
        assert_ne!(parenthesized, rust_default_binding);
    }
}
