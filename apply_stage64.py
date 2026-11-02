#!/usr/bin/env python3
"""Stage 64: String & Printf family
  printf, fprintf, sscanf, vprintf, vfprintf, vsprintf, vsnprintf,
  asprintf, vasprintf, strtof, strtod, strtold,
  strdup, strndup, strtok, strtok_r,
  strpbrk, strcspn, strspn, memmem
"""

PATH = r"crates/transd-bridge/src/bionic.rs"

with open(PATH, "r", encoding="utf-8") as f:
    src = f.read()

# ── 1. ENUM VARIANTS ──────────────────────────────────────────────────────────
ENUM_ANCHOR = "    Seekdir  = 448,\n"
ENUM_INSERT = """\
    Seekdir  = 448,

    // String & Printf family (Stage 64)
    Printf    = 450,
    Fprintf   = 451,
    Sscanf    = 452,
    Vprintf   = 453,
    Vfprintf  = 454,
    Vsprintf  = 455,
    Vsnprintf = 456,
    Asprintf  = 457,
    Vasprintf = 458,
    Strtof    = 459,
    Strtod    = 460,
    Strtold   = 461,
    Strdup    = 462,
    Strndup   = 463,
    Strtok    = 464,
    StrtokR   = 465,
    Strpbrk   = 466,
    Strcspn   = 467,
    Strspn    = 468,
    Memmem    = 469,
"""
assert ENUM_ANCHOR in src, "ENUM_ANCHOR not found"
src = src.replace(ENUM_ANCHOR, ENUM_INSERT, 1)

# ── 2. from_u32 MAPPINGS ──────────────────────────────────────────────────────
FROM_ANCHOR = "            448 => Some(Self::Seekdir),\n"
FROM_INSERT = """\
            448 => Some(Self::Seekdir),
            450 => Some(Self::Printf),
            451 => Some(Self::Fprintf),
            452 => Some(Self::Sscanf),
            453 => Some(Self::Vprintf),
            454 => Some(Self::Vfprintf),
            455 => Some(Self::Vsprintf),
            456 => Some(Self::Vsnprintf),
            457 => Some(Self::Asprintf),
            458 => Some(Self::Vasprintf),
            459 => Some(Self::Strtof),
            460 => Some(Self::Strtod),
            461 => Some(Self::Strtold),
            462 => Some(Self::Strdup),
            463 => Some(Self::Strndup),
            464 => Some(Self::Strtok),
            465 => Some(Self::StrtokR),
            466 => Some(Self::Strpbrk),
            467 => Some(Self::Strcspn),
            468 => Some(Self::Strspn),
            469 => Some(Self::Memmem),
"""
assert FROM_ANCHOR in src, "FROM_ANCHOR not found"
src = src.replace(FROM_ANCHOR, FROM_INSERT, 1)

# ── 3. STRUCT FIELDS — add strtok state ───────────────────────────────────────
STRUCT_ANCHOR = "    pub next_dir_handle: u32,\n"
STRUCT_INSERT = """\
    pub next_dir_handle: u32,
    // strtok internal saved pointer (R0=0 means "continue from saved")
    pub strtok_saved: Option<GuestAddr>,
"""
assert STRUCT_ANCHOR in src, "STRUCT_ANCHOR not found"
src = src.replace(STRUCT_ANCHOR, STRUCT_INSERT, 1)

# ── 4. STRUCT INITIALISER ─────────────────────────────────────────────────────
INIT_ANCHOR = "            next_dir_handle: 200, // Guest DIR* handles start at 200\n"
INIT_INSERT = """\
            next_dir_handle: 200, // Guest DIR* handles start at 200
            strtok_saved: None,
"""
assert INIT_ANCHOR in src, "INIT_ANCHOR not found"
src = src.replace(INIT_ANCHOR, INIT_INSERT, 1)

# ── 5. HEAP ALLOC HELPER METHOD ───────────────────────────────────────────────
HEAP_ANCHOR = "    /// Registers a loaded DSO into the in-process linker registry\n"
HEAP_INSERT = """\
    /// Allocates an aligned buffer from the guest heap, returning GuestAddr(0) on OOM
    pub fn heap_alloc(&mut self, size: u32) -> GuestAddr {
        let align_size = (size + 7) & !7;
        if self.heap_current.add(align_size) <= self.heap_limit {
            let ptr = self.heap_current;
            self.heap_current = self.heap_current.add(align_size);
            ptr
        } else {
            GuestAddr::new(0)
        }
    }

    /// Registers a loaded DSO into the in-process linker registry
"""
assert HEAP_ANCHOR in src, "HEAP_ANCHOR not found"
src = src.replace(HEAP_ANCHOR, HEAP_INSERT, 1)

# ── 6. REGISTER KNOWN SYMBOLS ─────────────────────────────────────────────────
SYM_ANCHOR = '            ("seekdir",   BionicFuncId::Seekdir),\n'
SYM_INSERT = """\
            ("seekdir",   BionicFuncId::Seekdir),
            ("printf",    BionicFuncId::Printf),
            ("fprintf",   BionicFuncId::Fprintf),
            ("sscanf",    BionicFuncId::Sscanf),
            ("vprintf",   BionicFuncId::Vprintf),
            ("vfprintf",  BionicFuncId::Vfprintf),
            ("vsprintf",  BionicFuncId::Vsprintf),
            ("vsnprintf", BionicFuncId::Vsnprintf),
            ("asprintf",  BionicFuncId::Asprintf),
            ("vasprintf", BionicFuncId::Vasprintf),
            ("strtof",    BionicFuncId::Strtof),
            ("strtod",    BionicFuncId::Strtod),
            ("strtold",   BionicFuncId::Strtold),
            ("strdup",    BionicFuncId::Strdup),
            ("strndup",   BionicFuncId::Strndup),
            ("strtok",    BionicFuncId::Strtok),
            ("strtok_r",  BionicFuncId::StrtokR),
            ("strpbrk",   BionicFuncId::Strpbrk),
            ("strcspn",   BionicFuncId::Strcspn),
            ("strspn",    BionicFuncId::Strspn),
            ("memmem",    BionicFuncId::Memmem),
"""
assert SYM_ANCHOR in src, "SYM_ANCHOR not found"
src = src.replace(SYM_ANCHOR, SYM_INSERT, 1)

# ── 7. INSTALL_STUBS ──────────────────────────────────────────────────────────
STUBS_ANCHOR = """\
            BionicFuncId::Cbrt,
            BionicFuncId::Ldexp,
        ] {
"""
STUBS_INSERT = """\
            BionicFuncId::Cbrt,
            BionicFuncId::Ldexp,
            // Directory enumeration (Stage 63)
            BionicFuncId::Opendir,
            BionicFuncId::Closedir,
            BionicFuncId::Readdir,
            BionicFuncId::Readdir64,
            BionicFuncId::Fdopendir,
            BionicFuncId::Dirfd,
            BionicFuncId::Rewinddir,
            BionicFuncId::Telldir,
            BionicFuncId::Seekdir,
            // String & Printf family (Stage 64)
            BionicFuncId::Printf,
            BionicFuncId::Fprintf,
            BionicFuncId::Sscanf,
            BionicFuncId::Vprintf,
            BionicFuncId::Vfprintf,
            BionicFuncId::Vsprintf,
            BionicFuncId::Vsnprintf,
            BionicFuncId::Asprintf,
            BionicFuncId::Vasprintf,
            BionicFuncId::Strtof,
            BionicFuncId::Strtod,
            BionicFuncId::Strtold,
            BionicFuncId::Strdup,
            BionicFuncId::Strndup,
            BionicFuncId::Strtok,
            BionicFuncId::StrtokR,
            BionicFuncId::Strpbrk,
            BionicFuncId::Strcspn,
            BionicFuncId::Strspn,
            BionicFuncId::Memmem,
        ] {
"""
assert STUBS_ANCHOR in src, "STUBS_ANCHOR not found"
src = src.replace(STUBS_ANCHOR, STUBS_INSERT, 1)

# ── 8. HANDLE_SVC ARMS ────────────────────────────────────────────────────────
SVC_ANCHOR = "            _ => {}\n"
SVC_INSERT = """\
            // ── Stage 64: String & Printf family ────────────────────────────

            // printf(fmt, ...) → writes formatted string to bridge.logs, returns char count
            BionicFuncId::Printf | BionicFuncId::Vprintf => {
                let fmt_ptr = GuestAddr::new(cpu.reg(Reg::R0));
                let fmt = Self::read_c_string(mem, fmt_ptr).unwrap_or_default();
                let len = fmt.len() as u32;
                self.logs.push(LogMessage {
                    priority: 3,
                    tag: "stdout".to_string(),
                    text: fmt,
                });
                cpu.set_reg(Reg::R0, len);
            }

            // fprintf(FILE* stream, fmt, ...) → same as printf but ignores stream
            BionicFuncId::Fprintf | BionicFuncId::Vfprintf => {
                let fmt_ptr = GuestAddr::new(cpu.reg(Reg::R1));
                let fmt = Self::read_c_string(mem, fmt_ptr).unwrap_or_default();
                let len = fmt.len() as u32;
                self.logs.push(LogMessage {
                    priority: 3,
                    tag: "stderr".to_string(),
                    text: fmt,
                });
                cpu.set_reg(Reg::R0, len);
            }

            // sscanf(str, fmt, ...) → stub returning 0 (no items matched)
            BionicFuncId::Sscanf => {
                cpu.set_reg(Reg::R0, 0);
            }

            // vsprintf(buf, fmt, va_list) → copy fmt into buf
            BionicFuncId::Vsprintf => {
                let buf_ptr  = GuestAddr::new(cpu.reg(Reg::R0));
                let fmt_ptr  = GuestAddr::new(cpu.reg(Reg::R1));
                let fmt = Self::read_c_string(mem, fmt_ptr).unwrap_or_default();
                let bytes = fmt.as_bytes();
                for (i, &b) in bytes.iter().enumerate() {
                    mem.write_u8(buf_ptr.add(i as u32), b)?;
                }
                mem.write_u8(buf_ptr.add(bytes.len() as u32), 0)?;
                cpu.set_reg(Reg::R0, bytes.len() as u32);
            }

            // vsnprintf(buf, size, fmt, va_list) → copy fmt into buf up to size
            BionicFuncId::Vsnprintf => {
                let buf_ptr  = GuestAddr::new(cpu.reg(Reg::R0));
                let size     = cpu.reg(Reg::R1) as usize;
                let fmt_ptr  = GuestAddr::new(cpu.reg(Reg::R2));
                let fmt = Self::read_c_string(mem, fmt_ptr).unwrap_or_default();
                let bytes = fmt.as_bytes();
                let to_write = if size > 0 { (bytes.len()).min(size - 1) } else { 0 };
                for i in 0..to_write {
                    mem.write_u8(buf_ptr.add(i as u32), bytes[i])?;
                }
                if size > 0 {
                    mem.write_u8(buf_ptr.add(to_write as u32), 0)?;
                }
                cpu.set_reg(Reg::R0, bytes.len() as u32);
            }

            // asprintf(char** strp, fmt, ...) → allocate heap buffer with fmt copy
            BionicFuncId::Asprintf | BionicFuncId::Vasprintf => {
                let strp_ptr = GuestAddr::new(cpu.reg(Reg::R0));
                let fmt_ptr  = GuestAddr::new(cpu.reg(Reg::R1));
                let fmt = Self::read_c_string(mem, fmt_ptr).unwrap_or_default();
                let bytes = fmt.as_bytes();
                let buf = self.heap_alloc(bytes.len() as u32 + 1);
                if buf.as_u32() != 0 {
                    for (i, &b) in bytes.iter().enumerate() {
                        mem.write_u8(buf.add(i as u32), b)?;
                    }
                    mem.write_u8(buf.add(bytes.len() as u32), 0)?;
                    if strp_ptr.as_u32() != 0 {
                        mem.write_u32(strp_ptr, buf.as_u32())?;
                    }
                    cpu.set_reg(Reg::R0, bytes.len() as u32);
                } else {
                    cpu.set_reg(Reg::R0, u32::MAX); // -1 on error
                }
            }

            // strtof(str, endptr) → parse f32
            BionicFuncId::Strtof => {
                let s_ptr    = GuestAddr::new(cpu.reg(Reg::R0));
                let endptr   = GuestAddr::new(cpu.reg(Reg::R1));
                let s = Self::read_c_string(mem, s_ptr).unwrap_or_default();
                let s_trim = s.trim_start();
                let (val, consumed) = parse_f64_prefix(s_trim);
                if endptr.as_u32() != 0 {
                    let end_addr = if consumed > 0 {
                        let spaces = (s.len() - s_trim.len()) as u32;
                        s_ptr.add(spaces + consumed as u32)
                    } else {
                        s_ptr
                    };
                    mem.write_u32(endptr, end_addr.as_u32())?;
                }
                let vf = val as f32;
                cpu.set_reg(Reg::R0, vf.to_bits());
                cpu.set_s_reg(0, vf);
            }

            // strtod(str, endptr) → parse f64
            BionicFuncId::Strtod | BionicFuncId::Strtold => {
                let s_ptr    = GuestAddr::new(cpu.reg(Reg::R0));
                let endptr   = GuestAddr::new(cpu.reg(Reg::R1));
                let s = Self::read_c_string(mem, s_ptr).unwrap_or_default();
                let s_trim = s.trim_start();
                let (val, consumed) = parse_f64_prefix(s_trim);
                if endptr.as_u32() != 0 {
                    let end_addr = if consumed > 0 {
                        let spaces = (s.len() - s_trim.len()) as u32;
                        s_ptr.add(spaces + consumed as u32)
                    } else {
                        s_ptr
                    };
                    mem.write_u32(endptr, end_addr.as_u32())?;
                }
                let bits = val.to_bits();
                cpu.set_reg(Reg::R0, bits as u32);
                cpu.set_reg(Reg::R1, (bits >> 32) as u32);
                cpu.set_d_reg(0, val);
            }

            // strdup(s) → heap-allocate copy
            BionicFuncId::Strdup => {
                let s_ptr = GuestAddr::new(cpu.reg(Reg::R0));
                let s = Self::read_c_string(mem, s_ptr).unwrap_or_default();
                let bytes = s.as_bytes();
                let buf = self.heap_alloc(bytes.len() as u32 + 1);
                if buf.as_u32() != 0 {
                    for (i, &b) in bytes.iter().enumerate() {
                        mem.write_u8(buf.add(i as u32), b)?;
                    }
                    mem.write_u8(buf.add(bytes.len() as u32), 0)?;
                }
                cpu.set_reg(Reg::R0, buf.as_u32());
            }

            // strndup(s, n) → heap-allocate up to n bytes
            BionicFuncId::Strndup => {
                let s_ptr = GuestAddr::new(cpu.reg(Reg::R0));
                let n     = cpu.reg(Reg::R1) as usize;
                let s = Self::read_c_string(mem, s_ptr).unwrap_or_default();
                let bytes = s.as_bytes();
                let len = bytes.len().min(n);
                let buf = self.heap_alloc(len as u32 + 1);
                if buf.as_u32() != 0 {
                    for i in 0..len {
                        mem.write_u8(buf.add(i as u32), bytes[i])?;
                    }
                    mem.write_u8(buf.add(len as u32), 0)?;
                }
                cpu.set_reg(Reg::R0, buf.as_u32());
            }

            // strtok(str, delim) / strtok_r(str, delim, saveptr)
            BionicFuncId::Strtok => {
                let str_ptr   = GuestAddr::new(cpu.reg(Reg::R0));
                let delim_ptr = GuestAddr::new(cpu.reg(Reg::R1));
                let delim = Self::read_c_string(mem, delim_ptr).unwrap_or_default();
                let cur = if str_ptr.as_u32() != 0 {
                    str_ptr
                } else if let Some(saved) = self.strtok_saved {
                    saved
                } else {
                    cpu.set_reg(Reg::R0, 0);
                    return Ok(true);
                };
                // Skip leading delimiters
                let s = Self::read_c_string(mem, cur).unwrap_or_default();
                let s_after_lead = s.trim_start_matches(|c: char| delim.contains(c));
                if s_after_lead.is_empty() {
                    self.strtok_saved = None;
                    cpu.set_reg(Reg::R0, 0);
                    return Ok(true);
                }
                let lead_skip = (s.len() - s_after_lead.len()) as u32;
                let token_start = cur.add(lead_skip);
                let token_len = s_after_lead.find(|c: char| delim.contains(c)).unwrap_or(s_after_lead.len());
                if token_len < s_after_lead.len() {
                    mem.write_u8(token_start.add(token_len as u32), 0)?;
                    self.strtok_saved = Some(token_start.add(token_len as u32 + 1));
                } else {
                    self.strtok_saved = None;
                }
                cpu.set_reg(Reg::R0, token_start.as_u32());
            }

            BionicFuncId::StrtokR => {
                let str_ptr    = GuestAddr::new(cpu.reg(Reg::R0));
                let delim_ptr  = GuestAddr::new(cpu.reg(Reg::R1));
                let saveptr    = GuestAddr::new(cpu.reg(Reg::R2));
                let delim = Self::read_c_string(mem, delim_ptr).unwrap_or_default();
                let saved_val = if saveptr.as_u32() != 0 { mem.read_u32(saveptr).unwrap_or(0) } else { 0 };
                let cur = if str_ptr.as_u32() != 0 {
                    str_ptr
                } else if saved_val != 0 {
                    GuestAddr::new(saved_val)
                } else {
                    cpu.set_reg(Reg::R0, 0);
                    return Ok(true);
                };
                let s = Self::read_c_string(mem, cur).unwrap_or_default();
                let s_after_lead = s.trim_start_matches(|c: char| delim.contains(c));
                if s_after_lead.is_empty() {
                    if saveptr.as_u32() != 0 {
                        mem.write_u32(saveptr, 0)?;
                    }
                    cpu.set_reg(Reg::R0, 0);
                    return Ok(true);
                }
                let lead_skip = (s.len() - s_after_lead.len()) as u32;
                let token_start = cur.add(lead_skip);
                let token_len = s_after_lead.find(|c: char| delim.contains(c)).unwrap_or(s_after_lead.len());
                if token_len < s_after_lead.len() {
                    mem.write_u8(token_start.add(token_len as u32), 0)?;
                    if saveptr.as_u32() != 0 {
                        mem.write_u32(saveptr, token_start.add(token_len as u32 + 1).as_u32())?;
                    }
                } else {
                    if saveptr.as_u32() != 0 {
                        mem.write_u32(saveptr, 0)?;
                    }
                }
                cpu.set_reg(Reg::R0, token_start.as_u32());
            }

            // strpbrk(s, accept) → pointer to first char in s that is in accept, or NULL
            BionicFuncId::Strpbrk => {
                let s_ptr      = GuestAddr::new(cpu.reg(Reg::R0));
                let accept_ptr = GuestAddr::new(cpu.reg(Reg::R1));
                let s      = Self::read_c_string(mem, s_ptr).unwrap_or_default();
                let accept = Self::read_c_string(mem, accept_ptr).unwrap_or_default();
                if let Some(pos) = s.find(|c: char| accept.contains(c)) {
                    cpu.set_reg(Reg::R0, s_ptr.add(pos as u32).as_u32());
                } else {
                    cpu.set_reg(Reg::R0, 0);
                }
            }

            // strcspn(s, reject) → length of prefix not containing any char in reject
            BionicFuncId::Strcspn => {
                let s_ptr      = GuestAddr::new(cpu.reg(Reg::R0));
                let reject_ptr = GuestAddr::new(cpu.reg(Reg::R1));
                let s      = Self::read_c_string(mem, s_ptr).unwrap_or_default();
                let reject = Self::read_c_string(mem, reject_ptr).unwrap_or_default();
                let span = s.find(|c: char| reject.contains(c)).unwrap_or(s.len());
                cpu.set_reg(Reg::R0, span as u32);
            }

            // strspn(s, accept) → length of prefix containing only chars in accept
            BionicFuncId::Strspn => {
                let s_ptr      = GuestAddr::new(cpu.reg(Reg::R0));
                let accept_ptr = GuestAddr::new(cpu.reg(Reg::R1));
                let s      = Self::read_c_string(mem, s_ptr).unwrap_or_default();
                let accept = Self::read_c_string(mem, accept_ptr).unwrap_or_default();
                let span = s.find(|c: char| !accept.contains(c)).unwrap_or(s.len());
                cpu.set_reg(Reg::R0, span as u32);
            }

            // memmem(haystack, haystacklen, needle, needlelen) → pointer or NULL
            BionicFuncId::Memmem => {
                let hay_ptr  = GuestAddr::new(cpu.reg(Reg::R0));
                let hay_len  = cpu.reg(Reg::R1) as usize;
                let ndl_ptr  = GuestAddr::new(cpu.reg(Reg::R2));
                let ndl_len  = cpu.reg(Reg::R3) as usize;
                if ndl_len == 0 {
                    cpu.set_reg(Reg::R0, hay_ptr.as_u32());
                } else if hay_len < ndl_len {
                    cpu.set_reg(Reg::R0, 0);
                } else {
                    let mut hay = vec![0u8; hay_len];
                    for i in 0..hay_len {
                        hay[i] = mem.read_u8(hay_ptr.add(i as u32)).unwrap_or(0);
                    }
                    let mut ndl = vec![0u8; ndl_len];
                    for i in 0..ndl_len {
                        ndl[i] = mem.read_u8(ndl_ptr.add(i as u32)).unwrap_or(0);
                    }
                    if let Some(pos) = hay.windows(ndl_len).position(|w| w == ndl.as_slice()) {
                        cpu.set_reg(Reg::R0, hay_ptr.add(pos as u32).as_u32());
                    } else {
                        cpu.set_reg(Reg::R0, 0);
                    }
                }
            }
            _ => {}
"""
assert SVC_ANCHOR in src, "WILDCARD_ANCHOR not found"
src = src.replace(SVC_ANCHOR, SVC_INSERT, 1)

# ── 9. PARSE_F64_PREFIX HELPER ───────────────────────────────────────────────
TAIL_ANCHOR = """\
fn parse_strtoul(s: &str, base: u32) -> (u32, usize) {
    let (val, consumed) = parse_strtol(s, base);
    (val as u32, consumed)
}
"""
TAIL_INSERT = """\
fn parse_strtoul(s: &str, base: u32) -> (u32, usize) {
    let (val, consumed) = parse_strtol(s, base);
    (val as u32, consumed)
}

fn parse_f64_prefix(s: &str) -> (f64, usize) {
    if s.is_empty() {
        return (0.0, 0);
    }
    let lower = s.to_ascii_lowercase();
    let (sign_str, rest) = if lower.starts_with('+') {
        ("+", &lower[1..])
    } else if lower.starts_with('-') {
        ("-", &lower[1..])
    } else {
        ("", lower.as_str())
    };

    if rest.starts_with("infinity") {
        let len = sign_str.len() + 8;
        let val = if sign_str == "-" { f64::NEG_INFINITY } else { f64::INFINITY };
        return (val, len);
    }
    if rest.starts_with("inf") {
        let len = sign_str.len() + 3;
        let val = if sign_str == "-" { f64::NEG_INFINITY } else { f64::INFINITY };
        return (val, len);
    }
    if rest.starts_with("nan") {
        let len = sign_str.len() + 3;
        return (f64::NAN, len);
    }

    let bytes = s.as_bytes();
    let mut end = 0;
    let mut has_exp = false;
    let mut has_dot = false;
    for (i, &b) in bytes.iter().enumerate() {
        if b == b'+' || b == b'-' {
            if i == 0 || (has_exp && (bytes[i - 1] == b'e' || bytes[i - 1] == b'E')) {
                end = i + 1;
            } else {
                break;
            }
        } else if b == b'.' {
            if !has_dot && !has_exp {
                has_dot = true;
                end = i + 1;
            } else {
                break;
            }
        } else if b == b'e' || b == b'E' {
            if !has_exp && i > 0 && (bytes[i - 1].is_ascii_digit() || bytes[i - 1] == b'.') {
                has_exp = true;
                end = i + 1;
            } else {
                break;
            }
        } else if b.is_ascii_digit() {
            end = i + 1;
        } else {
            break;
        }
    }

    while end > 0 {
        let slice = &s[..end];
        if let Ok(val) = slice.parse::<f64>() {
            return (val, end);
        }
        let norm = if slice.starts_with('.') {
            format!("0{}", slice)
        } else if slice.starts_with("+.") {
            format!("+0{}", &slice[1..])
        } else if slice.starts_with("-.") {
            format!("-0{}", &slice[1..])
        } else {
            slice.to_string()
        };
        if let Ok(val) = norm.parse::<f64>() {
            return (val, end);
        }
        end -= 1;
    }
    (0.0, 0)
}
"""
assert TAIL_ANCHOR in src, "TAIL_ANCHOR not found"
src = src.replace(TAIL_ANCHOR, TAIL_INSERT, 1)

with open(PATH, "w", encoding="utf-8") as f:
    f.write(src)

print("Stage 64 patch applied successfully.")
