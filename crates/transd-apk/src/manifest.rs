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
