use byteorder::{ByteOrder, LittleEndian};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum DexError {
    #[error("Invalid DEX magic header: {0:?}")]
    InvalidMagic(Vec<u8>),
    #[error("Truncated DEX file at offset {0}")]
    Truncated(usize),
    #[error("Invalid ULEB128 encoding")]
    InvalidUleb128,
}

pub const ACC_PUBLIC: u32 = 0x0001;
pub const ACC_PRIVATE: u32 = 0x0002;
pub const ACC_STATIC: u32 = 0x0008;
pub const ACC_FINAL: u32 = 0x0010;
pub const ACC_NATIVE: u32 = 0x0100;

/// Information about a native method declared in DEX bytecode
#[derive(Debug, Clone)]
pub struct DexNativeMethod {
    pub class_name: String,
    pub method_name: String,
    pub return_type: String,
    pub is_static: bool,
    /// JNI standard mangled C function symbol name (e.g. Java_com_example_MainActivity_nativeInit)
    pub jni_symbol: String,
}

/// Parsed Dalvik Executable (classes.dex)
#[derive(Debug, Clone)]
pub struct DexFile {
    pub classes: Vec<String>,
    pub native_methods: Vec<DexNativeMethod>,
}

pub struct DexParser<'a> {
    data: &'a [u8],
    strings: Vec<String>,
    types: Vec<String>,
    methods: Vec<(usize, usize, usize)>, // (class_idx, proto_idx, name_idx)
}

impl<'a> DexParser<'a> {
    pub fn parse(data: &'a [u8]) -> Result<DexFile, DexError> {
        if data.len() < 112 {
            return Err(DexError::Truncated(0));
        }

        // 1. Verify Magic
        let magic = &data[0..8];
        if &magic[0..4] != b"dex\n" || magic[7] != 0 {
            return Err(DexError::InvalidMagic(magic.to_vec()));
        }

        let mut parser = Self {
            data,
            strings: Vec::new(),
            types: Vec::new(),
            methods: Vec::new(),
        };

        parser.read_tables()?;
        parser.parse_classes()
    }

    fn read_tables(&mut self) -> Result<(), DexError> {
        let string_ids_size = LittleEndian::read_u32(&self.data[56..60]) as usize;
        let string_ids_off = LittleEndian::read_u32(&self.data[60..64]) as usize;

        let type_ids_size = LittleEndian::read_u32(&self.data[64..68]) as usize;
        let type_ids_off = LittleEndian::read_u32(&self.data[68..72]) as usize;

        let method_ids_size = LittleEndian::read_u32(&self.data[88..92]) as usize;
        let method_ids_off = LittleEndian::read_u32(&self.data[92..96]) as usize;

        // 1. Read String Table
        for i in 0..string_ids_size {
            let entry_off = string_ids_off + (i * 4);
            if entry_off + 4 > self.data.len() {
                break;
            }
            let data_off = LittleEndian::read_u32(&self.data[entry_off..entry_off + 4]) as usize;
            if data_off < self.data.len() {
                let s = Self::read_string_data(self.data, data_off);
                self.strings.push(s);
            } else {
                self.strings.push(String::new());
            }
        }

        // 2. Read Type Table
        for i in 0..type_ids_size {
            let entry_off = type_ids_off + (i * 4);
            if entry_off + 4 > self.data.len() {
                break;
            }
            let descriptor_idx = LittleEndian::read_u32(&self.data[entry_off..entry_off + 4]) as usize;
            let type_str = if descriptor_idx < self.strings.len() {
                self.strings[descriptor_idx].clone()
            } else {
                String::new()
            };
            self.types.push(type_str);
        }

        // 3. Read Method IDs Table
        for i in 0..method_ids_size {
            let entry_off = method_ids_off + (i * 8);
            if entry_off + 8 > self.data.len() {
                break;
            }
            let class_idx = LittleEndian::read_u16(&self.data[entry_off..entry_off + 2]) as usize;
            let proto_idx = LittleEndian::read_u16(&self.data[entry_off + 2..entry_off + 4]) as usize;
            let name_idx = LittleEndian::read_u32(&self.data[entry_off + 4..entry_off + 8]) as usize;
            self.methods.push((class_idx, proto_idx, name_idx));
        }

        Ok(())
    }

    fn read_string_data(data: &[u8], mut offset: usize) -> String {
        // Read ULEB128 utf16 size
        let (_utf16_len, bytes_read) = Self::read_uleb128(data, offset);
        offset += bytes_read;

        let mut bytes = Vec::new();
        while offset < data.len() {
            let b = data[offset];
            if b == 0 {
                break;
            }
            bytes.push(b);
            offset += 1;
        }

        String::from_utf8_lossy(&bytes).to_string()
    }

    fn read_uleb128(data: &[u8], mut offset: usize) -> (u32, usize) {
        let mut result = 0u32;
        let mut shift = 0;
        let mut count = 0;

        while offset < data.len() {
            let byte = data[offset];
            offset += 1;
            count += 1;

            result |= ((byte & 0x7F) as u32) << shift;
            if (byte & 0x80) == 0 {
                break;
            }
            shift += 7;
            if shift >= 35 {
                break;
            }
        }

        (result, count)
    }

    fn parse_classes(&self) -> Result<DexFile, DexError> {
        let class_defs_size = LittleEndian::read_u32(&self.data[96..100]) as usize;
        let class_defs_off = LittleEndian::read_u32(&self.data[100..104]) as usize;

        let mut class_names = Vec::new();
        let mut native_methods = Vec::new();

        for i in 0..class_defs_size {
            let entry_off = class_defs_off + (i * 32);
            if entry_off + 32 > self.data.len() {
                break;
            }

            let class_idx = LittleEndian::read_u32(&self.data[entry_off..entry_off + 4]) as usize;
            let class_data_off = LittleEndian::read_u32(&self.data[entry_off + 24..entry_off + 28]) as usize;

            let raw_class_type = if class_idx < self.types.len() {
                &self.types[class_idx]
            } else {
                ""
            };

            let clean_class_name = Self::clean_type_name(raw_class_type);
            class_names.push(clean_class_name.clone());

            if class_data_off == 0 || class_data_off >= self.data.len() {
                continue;
            }

            // Parse Class Data Item
            let mut cur = class_data_off;
            let (static_fields_size, r) = Self::read_uleb128(self.data, cur);
            cur += r;
            let (instance_fields_size, r) = Self::read_uleb128(self.data, cur);
            cur += r;
            let (direct_methods_size, r) = Self::read_uleb128(self.data, cur);
            cur += r;
            let (virtual_methods_size, r) = Self::read_uleb128(self.data, cur);
            cur += r;

            // Skip static fields (field_idx_diff, access_flags)
            for _ in 0..static_fields_size {
                let (_, r1) = Self::read_uleb128(self.data, cur);
                cur += r1;
                let (_, r2) = Self::read_uleb128(self.data, cur);
                cur += r2;
            }

            // Skip instance fields
            for _ in 0..instance_fields_size {
                let (_, r1) = Self::read_uleb128(self.data, cur);
                cur += r1;
                let (_, r2) = Self::read_uleb128(self.data, cur);
                cur += r2;
            }

            // Parse direct methods and virtual methods
            let mut last_method_idx = 0usize;
            for _ in 0..(direct_methods_size + virtual_methods_size) {
                let (diff, r1) = Self::read_uleb128(self.data, cur);
                cur += r1;
                let (access_flags, r2) = Self::read_uleb128(self.data, cur);
                cur += r2;
                let (code_off, r3) = Self::read_uleb128(self.data, cur);
                cur += r3;

                last_method_idx += diff as usize;

                if (access_flags & ACC_NATIVE) != 0 {
                    if last_method_idx < self.methods.len() {
                        let (_, _, name_idx) = self.methods[last_method_idx];
                        let method_name = if name_idx < self.strings.len() {
                            self.strings[name_idx].clone()
                        } else {
                            format!("method_{}", last_method_idx)
                        };

                        let jni_symbol = Self::mangle_jni_symbol(&clean_class_name, &method_name);
                        let is_static = (access_flags & ACC_STATIC) != 0;

                        native_methods.push(DexNativeMethod {
                            class_name: clean_class_name.clone(),
                            method_name,
                            return_type: "V".to_string(),
                            is_static,
                            jni_symbol,
                        });
                    }
                }
                let _ = code_off;
            }
        }

        Ok(DexFile {
            classes: class_names,
            native_methods,
        })
    }

    /// Converts Dalvik type descriptor 'Lcom/example/MyClass;' -> 'com.example.MyClass'
    fn clean_type_name(desc: &str) -> String {
        let trimmed = desc.trim_start_matches('L').trim_end_matches(';');
        trimmed.replace('/', ".")
    }

    /// Generates JNI standard C function symbol:
    /// e.g. "com.example.app.MainActivity" + "nativeInit" -> "Java_com_example_app_MainActivity_nativeInit"
    pub fn mangle_jni_symbol(class_name: &str, method_name: &str) -> String {
        let mut s = String::from("Java_");

        for c in class_name.chars() {
            match c {
                '.' => s.push('_'),
                '_' => s.push_str("_1"),
                '$' => s.push_str("_00024"),
                other => s.push(other),
            }
        }

        s.push('_');

        for c in method_name.chars() {
            match c {
                '_' => s.push_str("_1"),
                '$' => s.push_str("_00024"),
                other => s.push(other),
            }
        }

        s
    }
}
