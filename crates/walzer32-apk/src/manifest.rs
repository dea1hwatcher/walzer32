use byteorder::{ByteOrder, LittleEndian};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum ManifestError {
    #[error("Invalid Android Binary XML header (expected 0x0003, got 0x{0:04x})")]
    InvalidHeader(u16),
    #[error("String pool chunk not found")]
    StringPoolNotFound,
    #[error("Truncated manifest data at offset {0}")]
    Truncated(usize),
}

/// Extracted package and component metadata from AndroidManifest.xml
#[derive(Debug, Clone, Default)]
pub struct ManifestInfo {
    pub package_name: String,
    pub version_code: Option<u32>,
    pub version_name: Option<String>,
    pub min_sdk_version: Option<u32>,
    pub target_sdk_version: Option<u32>,
    pub application_name: Option<String>,
    pub activities: Vec<String>,
    pub main_activity: Option<String>,
    pub permissions: Vec<String>,
}

pub struct ManifestParser<'a> {
    data: &'a [u8],
    strings: Vec<String>,
}

impl<'a> ManifestParser<'a> {
    pub fn parse(data: &'a [u8]) -> Result<ManifestInfo, ManifestError> {
        let mut parser = Self {
            data,
            strings: Vec::new(),
        };

        parser.read_header_and_strings()?;
        parser.parse_elements()
    }

    fn read_header_and_strings(&mut self) -> Result<(), ManifestError> {
        if self.data.len() < 8 {
            return Err(ManifestError::Truncated(0));
        }

        let chunk_type = LittleEndian::read_u16(&self.data[0..2]);
        if chunk_type != 0x0003 {
            return Err(ManifestError::InvalidHeader(chunk_type));
        }

        let header_size = LittleEndian::read_u16(&self.data[2..4]) as usize;
        let mut cur = header_size;

        // Search for string pool chunk (0x0001)
        while cur + 8 <= self.data.len() {
            let c_type = LittleEndian::read_u16(&self.data[cur..cur + 2]);
            let c_size = LittleEndian::read_u32(&self.data[cur + 4..cur + 8]) as usize;

            if c_type == 0x0001 {
                // String pool
                self.parse_string_pool(cur)?;
                return Ok(());
            }

            if c_size == 0 {
                break;
            }
            cur += c_size;
        }

        Err(ManifestError::StringPoolNotFound)
    }

    fn parse_string_pool(&mut self, base: usize) -> Result<(), ManifestError> {
        if base + 28 > self.data.len() {
            return Err(ManifestError::Truncated(base));
        }

        let string_count = LittleEndian::read_u32(&self.data[base + 8..base + 12]) as usize;
        let flags = LittleEndian::read_u32(&self.data[base + 16..base + 20]);
        let strings_start = base + LittleEndian::read_u32(&self.data[base + 20..base + 24]) as usize;
        let is_utf8 = (flags & (1 << 8)) != 0;

        let mut offsets = Vec::with_capacity(string_count);
        for i in 0..string_count {
            let off_pos = base + 28 + (i * 4);
            if off_pos + 4 > self.data.len() {
                break;
            }
            offsets.push(LittleEndian::read_u32(&self.data[off_pos..off_pos + 4]) as usize);
        }

        for &off in &offsets {
            let s_pos = strings_start + off;
            if s_pos >= self.data.len() {
                self.strings.push(String::new());
                continue;
            }

            if is_utf8 {
                // UTF-8 string: length encoded, then bytes
                let mut p = s_pos;
                // Skip character count
                if (self.data[p] & 0x80) != 0 {
                    p += 2;
                } else {
                    p += 1;
                }
                // Read byte count
                let byte_len = if (self.data[p] & 0x80) != 0 {
                    let len = (((self.data[p] & 0x7F) as usize) << 8) | (self.data[p + 1] as usize);
                    p += 2;
                    len
                } else {
                    let len = self.data[p] as usize;
                    p += 1;
                    len
                };

                if p + byte_len <= self.data.len() {
                    let s = String::from_utf8_lossy(&self.data[p..p + byte_len]).to_string();
                    self.strings.push(s);
                } else {
                    self.strings.push(String::new());
                }
            } else {
                // UTF-16 string
                let mut p = s_pos;
                let char_len = if (LittleEndian::read_u16(&self.data[p..p + 2]) & 0x8000) != 0 {
                    let h = (LittleEndian::read_u16(&self.data[p..p + 2]) & 0x7FFF) as usize;
                    let l = LittleEndian::read_u16(&self.data[p + 2..p + 4]) as usize;
                    p += 4;
                    (h << 16) | l
                } else {
                    let len = LittleEndian::read_u16(&self.data[p..p + 2]) as usize;
                    p += 2;
                    len
                };

                let byte_len = char_len * 2;
                if p + byte_len <= self.data.len() {
                    let u16s: Vec<u16> = self.data[p..p + byte_len]
                        .as_chunks::<2>().0
                        .iter()
                        .map(|c| u16::from_le_bytes(*c))
                        .collect();
                    let s = String::from_utf16_lossy(&u16s);
                    self.strings.push(s);
                } else {
                    self.strings.push(String::new());
                }
            }
        }

        Ok(())
    }

    fn parse_elements(&self) -> Result<ManifestInfo, ManifestError> {
        let mut info = ManifestInfo::default();
        let mut cur = 8;
        let mut is_in_main_intent = false;
        let mut current_activity = String::new();

        while cur + 8 <= self.data.len() {
            let chunk_type = LittleEndian::read_u16(&self.data[cur..cur + 2]);
            let chunk_size = LittleEndian::read_u32(&self.data[cur + 4..cur + 8]) as usize;

            if chunk_size == 0 || cur + chunk_size > self.data.len() {
                break;
            }

            match chunk_type {
                0x0102 => {
                    // START_ELEMENT
                    if cur + 20 <= self.data.len() {
                        let name_idx = LittleEndian::read_u32(&self.data[cur + 20..cur + 24]) as usize;
                        let attr_count = LittleEndian::read_u16(&self.data[cur + 28..cur + 30]) as usize;

                        let current_element = self.get_string(name_idx).to_string();

                        let attr_start = cur + 36;
                        for i in 0..attr_count {
                            let a_pos = attr_start + (i * 20);
                            if a_pos + 20 > cur + chunk_size {
                                break;
                            }

                            let attr_name_idx = LittleEndian::read_u32(&self.data[a_pos + 4..a_pos + 8]) as usize;
                            let attr_val_idx = LittleEndian::read_u32(&self.data[a_pos + 8..a_pos + 12]) as usize;
                            let typed_data = LittleEndian::read_u32(&self.data[a_pos + 16..a_pos + 20]);

                            let attr_name = self.get_string(attr_name_idx);
                            let attr_val = if attr_val_idx < self.strings.len() {
                                self.get_string(attr_val_idx).to_string()
                            } else {
                                typed_data.to_string()
                            };

                            match (current_element.as_str(), attr_name) {
                                ("manifest", "package") => info.package_name = attr_val,
                                ("manifest", "versionCode") => info.version_code = Some(typed_data),
                                ("manifest", "versionName") => info.version_name = Some(attr_val),
                                ("uses-sdk", "minSdkVersion") => info.min_sdk_version = Some(typed_data),
                                ("uses-sdk", "targetSdkVersion") => info.target_sdk_version = Some(typed_data),
                                ("application", "name") => info.application_name = Some(attr_val),
                                ("activity", "name") => {
                                    current_activity = attr_val.clone();
                                    info.activities.push(attr_val);
                                }
                                ("uses-permission", "name") => info.permissions.push(attr_val),
                                ("action", "name") => {
                                    if attr_val == "android.intent.action.MAIN" {
                                        is_in_main_intent = true;
                                    }
                                }
                                ("category", "name") if attr_val == "android.intent.category.LAUNCHER" && is_in_main_intent => {
                                    info.main_activity = Some(current_activity.clone());
                                }
                                _ => {}
                            }
                        }
                    }
                }
                0x0103 => {
                    // END_ELEMENT
                    let name_idx = LittleEndian::read_u32(&self.data[cur + 20..cur + 24]) as usize;
                    let elem = self.get_string(name_idx);
                    if elem == "intent-filter" {
                        is_in_main_intent = false;
                    }
                }
                _ => {}
            }

            cur += chunk_size;
        }

        // If no launcher activity explicitly matched, use the first declared activity
        if info.main_activity.is_none() && !info.activities.is_empty() {
            info.main_activity = Some(info.activities[0].clone());
        }

        Ok(info)
    }

    fn get_string(&self, idx: usize) -> &str {
        if idx < self.strings.len() {
            &self.strings[idx]
        } else {
            ""
        }
    }

}

const ATTR_EXTRACT_NATIVE_LIBS: u32 = 0x0101_04EA;
const ANDROID_NS_URI: &str = "http://schemas.android.com/apk/res/android";

/// Reads `<application android:extractNativeLibs="...">` from an AXML buffer, if present.
pub fn has_extract_native_libs(data: &[u8]) -> Result<Option<bool>, ManifestError> {
    // Extract strings into owned vec, then drop the parser to release the borrow on `data`.
    let strings: Vec<String> = {
        let mut p = ManifestParser { data, strings: Vec::new() };
        p.read_header_and_strings()?;
        p.strings
    };
    let res_map = read_resource_map_free(data);
    let get_str = |idx: usize| -> &str {
        strings.get(idx).map(|s| s.as_str()).unwrap_or("")
    };
    let mut cur = LittleEndian::read_u16(&data[2..4]) as usize;
    while cur + 8 <= data.len() {
        let chunk_type = LittleEndian::read_u16(&data[cur..cur + 2]);
        let chunk_size = LittleEndian::read_u32(&data[cur + 4..cur + 8]) as usize;
        if chunk_size == 0 || cur + chunk_size > data.len() {
            break;
        }
        if chunk_type == 0x0102 && cur + 36 <= data.len() {
            let name_idx = LittleEndian::read_u32(&data[cur + 20..cur + 24]) as usize;
            if get_str(name_idx) == "application" {
                let attr_count = LittleEndian::read_u16(&data[cur + 28..cur + 30]) as usize;
                for i in 0..attr_count {
                    let a_pos = cur + 36 + i * 20;
                    if a_pos + 20 > cur + chunk_size {
                        break;
                    }
                    let attr_name_idx = LittleEndian::read_u32(&data[a_pos + 4..a_pos + 8]) as usize;
                    let is_extract = get_str(attr_name_idx) == "extractNativeLibs"
                        || res_map.get(attr_name_idx).copied() == Some(ATTR_EXTRACT_NATIVE_LIBS);
                    if is_extract {
                        let val_type = data[a_pos + 15];
                        let typed_data = LittleEndian::read_u32(&data[a_pos + 16..a_pos + 20]);
                        if val_type == 0x12 {
                            return Ok(Some(typed_data != 0));
                        } else {
                            return Ok(Some(get_str(typed_data as usize) == "true"));
                        }
                    }
                }
                return Ok(None);
            }
        }
        cur += chunk_size;
    }
    Ok(None)
}

fn read_resource_map_free(data: &[u8]) -> Vec<u32> {
    if data.len() < 8 {
        return Vec::new();
    }
    let mut cur = LittleEndian::read_u16(&data[2..4]) as usize;
    while cur + 8 <= data.len() {
        let c_type = LittleEndian::read_u16(&data[cur..cur + 2]);
        let c_size = LittleEndian::read_u32(&data[cur + 4..cur + 8]) as usize;
        if c_size == 0 || cur + c_size > data.len() {
            break;
        }
        if c_type == 0x0180 {
            let mut map = Vec::with_capacity((c_size - 8) / 4);
            for off in (cur + 8..cur + c_size).step_by(4) {
                map.push(LittleEndian::read_u32(&data[off..off + 4]));
            }
            return map;
        }
        cur += c_size;
    }
    Vec::new()
}

fn encode_string_pool(strings: &[String], flags: u32, styles_data: &[u8], style_count: u32, style_offsets: &[u32]) -> Vec<u8> {
    let is_utf8 = (flags & (1 << 8)) != 0;
    let mut offsets = Vec::with_capacity(strings.len());
    let mut blob = Vec::new();
    for s in strings {
        offsets.push(blob.len() as u32);
        if is_utf8 {
            let char_len = s.chars().count();
            let bytes = s.as_bytes();
            let byte_len = bytes.len();
            if char_len > 0x7F {
                blob.push(((char_len >> 8) as u8) | 0x80);
                blob.push((char_len & 0xFF) as u8);
            } else {
                blob.push(char_len as u8);
            }
            if byte_len > 0x7F {
                blob.push(((byte_len >> 8) as u8) | 0x80);
                blob.push((byte_len & 0xFF) as u8);
            } else {
                blob.push(byte_len as u8);
            }
            blob.extend_from_slice(bytes);
            blob.push(0);
        } else {
            let u16s: Vec<u16> = s.encode_utf16().collect();
            let len = u16s.len();
            if len > 0x7FFF {
                let hi = ((len >> 16) as u16) | 0x8000;
                let lo = (len & 0xFFFF) as u16;
                blob.extend_from_slice(&hi.to_le_bytes());
                blob.extend_from_slice(&lo.to_le_bytes());
            } else {
                blob.extend_from_slice(&(len as u16).to_le_bytes());
            }
            for ch in u16s {
                blob.extend_from_slice(&ch.to_le_bytes());
            }
            blob.extend_from_slice(&0u16.to_le_bytes());
        }
    }
    while blob.len() % 4 != 0 {
        blob.push(0);
    }

    let hdr_size = 28usize;
    let offsets_bytes = (strings.len() + style_offsets.len()) * 4;
    let strings_start = hdr_size + offsets_bytes;
    let styles_start = if style_count > 0 {
        strings_start + blob.len()
    } else {
        0
    };
    let mut total_size = strings_start + blob.len() + styles_data.len();
    while total_size % 4 != 0 {
        total_size += 1;
    }

    let mut out = vec![0u8; total_size];
    LittleEndian::write_u16(&mut out[0..2], 0x0001);
    LittleEndian::write_u16(&mut out[2..4], hdr_size as u16);
    LittleEndian::write_u32(&mut out[4..8], total_size as u32);
    LittleEndian::write_u32(&mut out[8..12], strings.len() as u32);
    LittleEndian::write_u32(&mut out[12..16], style_count);
    LittleEndian::write_u32(&mut out[16..20], flags);
    LittleEndian::write_u32(&mut out[20..24], strings_start as u32);
    LittleEndian::write_u32(&mut out[24..28], styles_start as u32);

    for (i, &off) in offsets.iter().enumerate() {
        let p = hdr_size + i * 4;
        LittleEndian::write_u32(&mut out[p..p + 4], off);
    }
    for (i, &off) in style_offsets.iter().enumerate() {
        let p = hdr_size + (strings.len() + i) * 4;
        LittleEndian::write_u32(&mut out[p..p + 4], off);
    }
    out[strings_start..strings_start + blob.len()].copy_from_slice(&blob);
    if !styles_data.is_empty() {
        out[strings_start + blob.len()..strings_start + blob.len() + styles_data.len()]
            .copy_from_slice(styles_data);
    }
    out
}

fn remap_idx_u32(slice: &mut [u8], insert_at: u32) {
    let v = LittleEndian::read_u32(slice);
    if v != 0xFFFF_FFFF && v >= insert_at {
        LittleEndian::write_u32(slice, v + 1);
    }
}

/// Patches an Android binary `AndroidManifest.xml` (AXML) so `<application android:extractNativeLibs="...">`
/// matches `enable` (`true` allows Bionic to extract bundled ARM64 proxies cleanly from the APK).
pub fn patch_manifest_extract_native_libs(data: &[u8], enable: bool) -> Result<Vec<u8>, ManifestError> {
    let mut parser = ManifestParser {
        data,
        strings: Vec::new(),
    };
    parser.read_header_and_strings()?;
    let bool_data = if enable { 0xFFFF_FFFFu32 } else { 0u32 };

    // Locate chunks
    let hdr_size = LittleEndian::read_u16(&data[2..4]) as usize;
    let mut sp_range = None;
    let mut rm_range = None;
    let mut xml_chunks: Vec<(usize, usize)> = Vec::new();
    let mut cur = hdr_size;
    while cur + 8 <= data.len() {
        let c_type = LittleEndian::read_u16(&data[cur..cur + 2]);
        let c_size = LittleEndian::read_u32(&data[cur + 4..cur + 8]) as usize;
        if c_size == 0 || cur + c_size > data.len() {
            return Err(ManifestError::Truncated(cur));
        }
        match c_type {
            0x0001 if sp_range.is_none() => sp_range = Some((cur, cur + c_size)),
            0x0180 if rm_range.is_none() => rm_range = Some((cur, cur + c_size)),
            _ => xml_chunks.push((cur, cur + c_size)),
        }
        cur += c_size;
    }
    let (sp_start, sp_end) = sp_range.ok_or(ManifestError::StringPoolNotFound)?;
    let res_map = rm_range
        .map(|(s, e)| {
            (s + 8..e)
                .step_by(4)
                .map(|p| LittleEndian::read_u32(&data[p..p + 4]))
                .collect::<Vec<u32>>()
        })
        .unwrap_or_default();

    // Fast path: attribute already present on <application> -> patch in place
    for &(c_s, c_e) in &xml_chunks {
        let c_type = LittleEndian::read_u16(&data[c_s..c_s + 2]);
        if c_type == 0x0102 && c_s + 36 <= c_e {
            let name_idx = LittleEndian::read_u32(&data[c_s + 20..c_s + 24]) as usize;
            if parser.get_string(name_idx) == "application" {
                let attr_count = LittleEndian::read_u16(&data[c_s + 28..c_s + 30]) as usize;
                for i in 0..attr_count {
                    let a = c_s + 36 + i * 20;
                    if a + 20 > c_e {
                        break;
                    }
                    let attr_name_idx = LittleEndian::read_u32(&data[a + 4..a + 8]) as usize;
                    let is_extract = parser.get_string(attr_name_idx) == "extractNativeLibs"
                        || res_map.get(attr_name_idx).copied() == Some(ATTR_EXTRACT_NATIVE_LIBS);
                    if is_extract {
                        let mut out = data.to_vec();
                        LittleEndian::write_u32(&mut out[a + 8..a + 12], 0xFFFF_FFFF);
                        LittleEndian::write_u16(&mut out[a + 12..a + 14], 8);
                        out[a + 14] = 0;
                        out[a + 15] = 0x12; // TYPE_INT_BOOLEAN
                        LittleEndian::write_u32(&mut out[a + 16..a + 20], bool_data);
                        return Ok(out);
                    }
                }
            }
        }
    }

    // Slow path: insert "extractNativeLibs" into StringPool (+ ResourceMap entry 0x010104EA) and add attribute to <application>
    let mut strings = parser.strings;
    let mut new_res_map = res_map;
    let insert_at = new_res_map.len().min(strings.len());
    strings.insert(insert_at, "extractNativeLibs".to_string());
    new_res_map.insert(insert_at, ATTR_EXTRACT_NATIVE_LIBS);
    let insert_at_u32 = insert_at as u32;

    let orig_str_count = LittleEndian::read_u32(&data[sp_start + 8..sp_start + 12]) as usize;
    let orig_style_count = LittleEndian::read_u32(&data[sp_start + 12..sp_start + 16]);
    let sp_flags = LittleEndian::read_u32(&data[sp_start + 16..sp_start + 20]);
    let orig_styles_start = LittleEndian::read_u32(&data[sp_start + 24..sp_start + 28]) as usize;
    let mut style_offsets = Vec::with_capacity(orig_style_count as usize);
    for i in 0..orig_style_count as usize {
        let p = sp_start + 28 + (orig_str_count + i) * 4;
        if p + 4 <= sp_end {
            style_offsets.push(LittleEndian::read_u32(&data[p..p + 4]));
        }
    }
    let styles_blob = if orig_style_count > 0 && orig_styles_start > 0 && sp_start + orig_styles_start < sp_end {
        &data[sp_start + orig_styles_start..sp_end]
    } else {
        &[]
    };
    let sp_bytes = encode_string_pool(&strings, sp_flags, styles_blob, orig_style_count, &style_offsets);

    let mut rm_bytes = vec![0u8; 8 + new_res_map.len() * 4];
    LittleEndian::write_u16(&mut rm_bytes[0..2], 0x0180);
    LittleEndian::write_u16(&mut rm_bytes[2..4], 8);
    let rm_total = rm_bytes.len() as u32;
    LittleEndian::write_u32(&mut rm_bytes[4..8], rm_total);
    for (i, &id) in new_res_map.iter().enumerate() {
        LittleEndian::write_u32(&mut rm_bytes[8 + i * 4..12 + i * 4], id);
    }

    // Find android namespace URI string index after shift
    let android_ns_idx = strings
        .iter()
        .position(|s| s == ANDROID_NS_URI)
        .map(|i| i as u32)
        .unwrap_or(0xFFFF_FFFF);

    let mut rebuilt_xml = Vec::new();
    let mut patched_app = false;
    for &(c_s, c_e) in &xml_chunks {
        let mut chunk = data[c_s..c_e].to_vec();
        let c_type = LittleEndian::read_u16(&chunk[0..2]);
        // Common ResXMLTree_node header comment at +12
        if chunk.len() >= 16 {
            remap_idx_u32(&mut chunk[12..16], insert_at_u32);
        }
        match c_type {
            0x0100 | 0x0101 if chunk.len() >= 24 => {
                remap_idx_u32(&mut chunk[16..20], insert_at_u32);
                remap_idx_u32(&mut chunk[20..24], insert_at_u32);
            }
            0x0102 if chunk.len() >= 36 => {
                remap_idx_u32(&mut chunk[16..20], insert_at_u32);
                remap_idx_u32(&mut chunk[20..24], insert_at_u32);
                let elem_name_idx = LittleEndian::read_u32(&chunk[20..24]) as usize;
                let attr_count = LittleEndian::read_u16(&chunk[28..30]) as usize;
                for i in 0..attr_count {
                    let a = 36 + i * 20;
                    if a + 20 > chunk.len() {
                        break;
                    }
                    remap_idx_u32(&mut chunk[a..a + 4], insert_at_u32);
                    remap_idx_u32(&mut chunk[a + 4..a + 8], insert_at_u32);
                    remap_idx_u32(&mut chunk[a + 8..a + 12], insert_at_u32);
                    if chunk[a + 15] == 0x03 {
                        remap_idx_u32(&mut chunk[a + 16..a + 20], insert_at_u32);
                    }
                }
                if !patched_app && strings.get(elem_name_idx).map(|s| s.as_str()) == Some("application") {
                    patched_app = true;
                    let mut attr = [0u8; 20];
                    LittleEndian::write_u32(&mut attr[0..4], android_ns_idx);
                    LittleEndian::write_u32(&mut attr[4..8], insert_at_u32);
                    LittleEndian::write_u32(&mut attr[8..12], 0xFFFF_FFFF);
                    LittleEndian::write_u16(&mut attr[12..14], 8);
                    attr[14] = 0;
                    attr[15] = 0x12;
                    LittleEndian::write_u32(&mut attr[16..20], bool_data);
                    chunk.extend_from_slice(&attr);
                    let new_count = (attr_count + 1) as u16;
                    LittleEndian::write_u16(&mut chunk[28..30], new_count);
                    let new_size = chunk.len() as u32;
                    LittleEndian::write_u32(&mut chunk[4..8], new_size);
                }
            }
            0x0103 if chunk.len() >= 24 => {
                remap_idx_u32(&mut chunk[16..20], insert_at_u32);
                remap_idx_u32(&mut chunk[20..24], insert_at_u32);
            }
            0x0104 if chunk.len() >= 28 => {
                remap_idx_u32(&mut chunk[16..20], insert_at_u32);
            }
            _ => {}
        }
        rebuilt_xml.extend_from_slice(&chunk);
    }

    let total_size = 8 + sp_bytes.len() + rm_bytes.len() + rebuilt_xml.len();
    let mut out = Vec::with_capacity(total_size);
    out.extend_from_slice(&0x0003u16.to_le_bytes());
    out.extend_from_slice(&8u16.to_le_bytes());
    out.extend_from_slice(&(total_size as u32).to_le_bytes());
    out.extend_from_slice(&sp_bytes);
    out.extend_from_slice(&rm_bytes);
    out.extend_from_slice(&rebuilt_xml);
    Ok(out)
}
