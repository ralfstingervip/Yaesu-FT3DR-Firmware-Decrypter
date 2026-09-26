use crate::cipher::StaticTables;
use crate::error::{err, Result};

struct Section {
    name: String,
    virtual_size: u32,
    virtual_address: u32,
    raw_size: u32,
    raw_ptr: u32,
}

struct Image<'a> {
    bytes: &'a [u8],
    image_base: u32,
    size_of_image: u32,
    sections: Vec<Section>,
}

impl<'a> Image<'a> {
    fn parse(bytes: &'a [u8]) -> Result<Self> {
        if bytes.len() < 0x40 || &bytes[0..2] != b"MZ" {
            return Err(err("not a PE file"));
        }
        let e_lfanew = u32::from_le_bytes([bytes[0x3C], bytes[0x3D], bytes[0x3E], bytes[0x3F]]) as usize;
        if bytes.get(e_lfanew..e_lfanew + 4) != Some(b"PE\0\0".as_ref()) {
            return Err(err("not a PE file"));
        }
        let coff = e_lfanew + 4;
        need(bytes, coff, 20)?;
        let nsec = u16_at(bytes, coff + 2) as usize;
        let optsz = u16_at(bytes, coff + 16) as usize;
        let opt = coff + 20;
        need(bytes, opt, optsz)?;
        if u16_at(bytes, opt) != 0x10B {
            return Err(err("expected a PE32 updater"));
        }
        if optsz < 120 {
            return Err(err("PE32 optional header is too small"));
        }
        let image_base = u32_at(bytes, opt + 28);
        let size_of_image = u32_at(bytes, opt + 56);
        let sec_off = opt + optsz;
        need(bytes, sec_off, nsec * 40)?;
        let mut sections = Vec::with_capacity(nsec);
        for i in 0..nsec {
            let off = sec_off + i * 40;
            let name_raw = &bytes[off..off + 8];
            let end = name_raw.iter().position(|&b| b == 0).unwrap_or(8);
            let name = String::from_utf8_lossy(&name_raw[..end]).into_owned();
            sections.push(Section {
                name,
                virtual_size: u32_at(bytes, off + 8),
                virtual_address: u32_at(bytes, off + 12),
                raw_size: u32_at(bytes, off + 16),
                raw_ptr: u32_at(bytes, off + 20),
            });
        }
        Ok(Self {
            bytes,
            image_base,
            size_of_image,
            sections,
        })
    }

    fn section_bytes(&self, name: &str) -> Result<&'a [u8]> {
        let matches: Vec<&Section> = self.sections.iter().filter(|s| s.name == name).collect();
        if matches.len() != 1 {
            return Err(err(format!("section {name} was not found once")));
        }
        let s = matches[0];
        let start = s.raw_ptr as usize;
        let end = start + s.raw_size as usize;
        if s.raw_size == 0 || end > self.bytes.len() {
            return Err(err(format!("section {name} is outside the file")));
        }
        Ok(&self.bytes[start..end])
    }

    fn rva_to_off(&self, rva: u32) -> Result<usize> {
        for s in &self.sections {
            let span = s.virtual_size.max(s.raw_size);
            let begin = s.virtual_address as u64;
            let end = begin + span as u64;
            if (rva as u64) >= begin && (rva as u64) < end {
                return Ok(s.raw_ptr as usize + (rva - s.virtual_address) as usize);
            }
        }
        Err(err(format!("resource RVA {rva:#x} is not in a section")))
    }

    fn read_va(&self, va: u64, len: usize) -> Option<&'a [u8]> {
        if va < self.image_base as u64 {
            return None;
        }
        let rva_u = va - self.image_base as u64;
        if rva_u > u32::MAX as u64 {
            return None;
        }
        let rva = rva_u as u32;
        if rva as u64 + len as u64 > self.size_of_image as u64 {
            return None;
        }
        for s in &self.sections {
            let span = s.virtual_size.max(s.raw_size);
            let begin = s.virtual_address as u64;
            let end = begin + span as u64;
            if (rva as u64) >= begin && (rva as u64) < end {
                let delta = (rva - s.virtual_address) as u64;
                if delta + len as u64 > s.raw_size as u64 {
                    return None;
                }
                let start = s.raw_ptr as usize + delta as usize;
                let stop = start + len;
                if stop > self.bytes.len() {
                    return None;
                }
                return Some(&self.bytes[start..stop]);
            }
        }
        None
    }
}

fn need(bytes: &[u8], off: usize, n: usize) -> Result<()> {
    if off.checked_add(n).map(|end| end <= bytes.len()) == Some(true) {
        Ok(())
    } else {
        Err(err("PE header is truncated"))
    }
}

fn u16_at(bytes: &[u8], off: usize) -> u16 {
    u16::from_le_bytes([bytes[off], bytes[off + 1]])
}

fn u32_at(bytes: &[u8], off: usize) -> u32 {
    u32::from_le_bytes([bytes[off], bytes[off + 1], bytes[off + 2], bytes[off + 3]])
}

pub fn extract_named_resource(pe: &[u8], type_id: u32, name: &str) -> Result<Vec<u8>> {
    let image = Image::parse(pe)?;
    if image.bytes.len() < 0x40 {
        return Err(err("not a PE file"));
    }
    let e_lfanew = u32_at(image.bytes, 0x3C) as usize;
    let opt = e_lfanew + 4 + 20;
    let rsrc_rva = u32_at(image.bytes, opt + 112);
    let base = image.rva_to_off(rsrc_rva)?;

    let root = read_dir(image.bytes, base)?;
    let mut matches = Vec::new();
    for i in 0..root.count {
        let (name_or_id, offset) = dir_entry(image.bytes, root.entries_at, i)?;
        let type_label = entry_id(&image, base, i, root.named, name_or_id)?;
        let is_type = match type_label {
            EntryId::Id(id) => id == type_id,
            EntryId::Name(_) => false,
        };
        if !is_type || offset & 0x8000_0000 == 0 {
            continue;
        }
        let toff = base + (offset & 0x7FFF_FFFF) as usize;
        let type_dir = read_dir(image.bytes, toff)?;
        for j in 0..type_dir.count {
            let (n2, o2) = dir_entry(image.bytes, type_dir.entries_at, j)?;
            let res_name = entry_id(&image, base, j, type_dir.named, n2)?;
            let name_ok = match res_name {
                EntryId::Name(s) => s == name,
                EntryId::Id(_) => false,
            };
            if !name_ok || o2 & 0x8000_0000 == 0 {
                continue;
            }
            let lang_off = base + (o2 & 0x7FFF_FFFF) as usize;
            let lang = read_dir(image.bytes, lang_off)?;
            if lang.count < 1 {
                continue;
            }
            let (_lang_id, data_dir) = dir_entry(image.bytes, lang.entries_at, 0)?;
            if data_dir & 0x8000_0000 != 0 {
                continue;
            }
            let doff = base + data_dir as usize;
            need(image.bytes, doff, 16)?;
            let data_rva = u32_at(image.bytes, doff);
            let size = u32_at(image.bytes, doff + 4) as usize;
            let fileoff = image.rva_to_off(data_rva)?;
            let end = fileoff.checked_add(size).ok_or_else(|| err("resource size overflows"))?;
            if end > image.bytes.len() {
                return Err(err("resource data extends past the file"));
            }
            matches.push(image.bytes[fileoff..end].to_vec());
        }
    }
    if matches.len() != 1 {
        return Err(err(format!(
            "resource {name} under type {type_id} not found once"
        )));
    }
    Ok(matches.pop().unwrap())
}

struct DirInfo {
    named: usize,
    count: usize,
    entries_at: usize,
}

fn read_dir(bytes: &[u8], off: usize) -> Result<DirInfo> {
    need(bytes, off, 16)?;
    let named = u16_at(bytes, off + 12) as usize;
    let ids = u16_at(bytes, off + 14) as usize;
    let count = named + ids;
    let entries_at = off + 16;
    need(bytes, entries_at, count * 8)?;
    Ok(DirInfo {
        named,
        count,
        entries_at,
    })
}

fn dir_entry(bytes: &[u8], entries_at: usize, index: usize) -> Result<(u32, u32)> {
    let off = entries_at + index * 8;
    need(bytes, off, 8)?;
    Ok((u32_at(bytes, off), u32_at(bytes, off + 4)))
}

enum EntryId {
    Name(String),
    Id(u32),
}

fn entry_id(image: &Image<'_>, base: usize, index: usize, named: usize, name_or_id: u32) -> Result<EntryId> {
    if index < named {
        Ok(EntryId::Name(read_res_name(image.bytes, base, name_or_id & 0x7FFF_FFFF)?))
    } else {
        Ok(EntryId::Id(name_or_id & 0xFFFF))
    }
}

fn read_res_name(bytes: &[u8], base: usize, rel: u32) -> Result<String> {
    let off = base
        .checked_add(rel as usize)
        .ok_or_else(|| err("resource name offset overflows"))?;
    need(bytes, off, 2)?;
    let n = u16_at(bytes, off) as usize;
    let nbytes = n.checked_mul(2).ok_or_else(|| err("resource name length overflows"))?;
    need(bytes, off + 2, nbytes)?;
    let raw = &bytes[off + 2..off + 2 + nbytes];
    let mut units = Vec::with_capacity(n);
    for i in 0..n {
        units.push(u16::from_le_bytes([raw[i * 2], raw[i * 2 + 1]]));
    }
    Ok(String::from_utf16_lossy(&units))
}

pub fn find_tables(pe: &[u8]) -> Result<StaticTables> {
    let image = Image::parse(pe)?;
    let rdata = image.section_bytes(".rdata")?;
    let text = image.section_bytes(".text")?;
    let key_off = find_key_config(rdata)?;
    let tables_end = key_off + 0x8C0;
    if tables_end > rdata.len() {
        return Err(err("key tables extend past .rdata"));
    }
    let raw = &rdata[key_off..tables_end];
    let mut key_config = [0u8; 0x40];
    let mut key_config2 = [0u8; 0x30];
    let mut encryption_config = [0u8; 0x30];
    let mut encryption_config2 = [0u8; 0x800];
    let mut encryption_config3 = [0u8; 0x20];
    key_config.copy_from_slice(&raw[0x00..0x40]);
    key_config2.copy_from_slice(&raw[0x40..0x70]);
    encryption_config.copy_from_slice(&raw[0x70..0xA0]);
    encryption_config2.copy_from_slice(&raw[0xA0..0x8A0]);
    encryption_config3.copy_from_slice(&raw[0x8A0..0x8C0]);
    if key_config2.iter().any(|&b| b < 1 || b > 56) {
        return Err(err("key_config2 is not a 1..56 index table"));
    }
    if encryption_config.iter().any(|&b| b < 1 || b > 32) {
        return Err(err("encryption_config is not a 1..32 index table"));
    }
    if encryption_config2.iter().any(|&b| b > 1) {
        return Err(err("encryption_config2 is not a 0/1 table"));
    }
    if !is_perm_1_through_32(&encryption_config3) {
        return Err(err("encryption_config3 is not a permutation of 1..32"));
    }
    let timestamp_tables = find_timestamp_tables(&image, text)?;
    Ok(StaticTables {
        key_config,
        key_config2,
        encryption_config,
        encryption_config2,
        encryption_config3,
        timestamp_tables,
    })
}

fn find_key_config(rdata: &[u8]) -> Result<usize> {
    let mut hits = Vec::new();
    if rdata.len() >= 0x40 {
        let limit = rdata.len() - 0x40;
        let mut off = 0usize;
        while off < limit {
            let mut twos = 0usize;
            let mut ok = true;
            for k in 0..16 {
                let at = off + k * 4;
                let v = u32_at(rdata, at);
                if v != 1 && v != 2 {
                    ok = false;
                    break;
                }
                if v == 2 {
                    twos += 1;
                }
            }
            if ok && twos >= 8 {
                hits.push(off);
            }
            off += 4;
        }
    }
    if hits.len() != 1 {
        return Err(err(format!(
            "expected one key-config dword run, found {}",
            hits.len()
        )));
    }
    Ok(hits[0])
}

fn is_perm_1_through_32(bytes: &[u8; 32]) -> bool {
    let mut seen = [false; 32];
    for &v in bytes {
        if v < 1 || v > 32 {
            return false;
        }
        let i = (v - 1) as usize;
        if seen[i] {
            return false;
        }
        seen[i] = true;
    }
    true
}

/// Pushes are the byte 0x68 plus a little-endian VA. All four encodings of
/// `ea`, `ea+56`, `ea+112`, and `ea+168` must sit in the 0x60-byte window
/// that starts at the push of `ea`.
fn find_timestamp_tables(image: &Image<'_>, text: &[u8]) -> Result<[[u8; 56]; 4]> {
    let mut found: Vec<[[u8; 56]; 4]> = Vec::new();
    if text.len() > 0x60 {
        let limit = text.len() - 0x60;
        let lo = image.image_base as u64;
        let hi = lo + image.size_of_image as u64;
        for i in 0..limit {
            if text[i] != 0x68 {
                continue;
            }
            let ea = u32::from_le_bytes([text[i + 1], text[i + 2], text[i + 3], text[i + 4]]) as u64;
            if ea < lo || ea + 168 >= hi {
                continue;
            }
            let mut addrs = [0u32; 4];
            let mut encodable = true;
            for k in 0..4 {
                let sum = ea + 56 * k as u64;
                if sum > u32::MAX as u64 {
                    encodable = false;
                    break;
                }
                addrs[k] = sum as u32;
            }
            if !encodable {
                continue;
            }
            let window = &text[i..i + 0x60];
            let mut all_pushed = true;
            for k in 0..4 {
                let mut needle = [0u8; 5];
                needle[0] = 0x68;
                needle[1..].copy_from_slice(&addrs[k].to_le_bytes());
                if !contains_slice(window, &needle) {
                    all_pushed = false;
                    break;
                }
            }
            if !all_pushed {
                continue;
            }
            let mut tables = [[0u8; 56]; 4];
            let mut ok = true;
            for k in 0..4 {
                let Some(block) = image.read_va(addrs[k] as u64, 56) else {
                    ok = false;
                    break;
                };
                if !mixed_bits(block) {
                    ok = false;
                    break;
                }
                tables[k].copy_from_slice(block);
            }
            if ok {
                found.push(tables);
            }
        }
    }
    if found.len() != 1 {
        return Err(err(format!(
            "expected one four-table push site, found {}",
            found.len()
        )));
    }
    Ok(found.pop().unwrap())
}

fn contains_slice(hay: &[u8], needle: &[u8]) -> bool {
    hay.windows(needle.len()).any(|w| w == needle)
}

fn mixed_bits(block: &[u8]) -> bool {
    let mut seen0 = false;
    let mut seen1 = false;
    for &b in block {
        match b {
            0 => seen0 = true,
            1 => seen1 = true,
            _ => return false,
        }
    }
    seen0 && seen1
}
