#!/usr/bin/env python3
"""Stage 65: Character Classification & Locale / Wide-Character family
  isalnum, isalpha, isblank, iscntrl, isdigit, isgraph, islower, isprint,
  ispunct, isspace, isupper, isxdigit, tolower, toupper, isascii, toascii,
  setlocale, localeconv, mbstowcs, wcstombs, mbtowc, wctomb,
  wcslen, wcscpy, wcscmp
"""

PATH = r"crates/transd-bridge/src/bionic.rs"

with open(PATH, "r", encoding="utf-8") as f:
    src = f.read()

# ── 1. ENUM VARIANTS ──────────────────────────────────────────────────────────
ENUM_ANCHOR = "    Memmem    = 469,\n"
ENUM_INSERT = """\
    Memmem    = 469,

    // Character classification & Locale / Wide-Char (Stage 65)
    Isalnum   = 470,
    Isalpha   = 471,
    Isblank   = 472,
    Iscntrl   = 473,
    Isdigit   = 474,
    Isgraph   = 475,
    Islower   = 476,
    Isprint   = 477,
    Ispunct   = 478,
    Isspace   = 479,
    Isupper   = 480,
    Isxdigit  = 481,
    Tolower   = 482,
    Toupper   = 483,
    Isascii   = 484,
    Toascii   = 485,
    Setlocale = 486,
    Localeconv = 487,
    Mbstowcs  = 488,
    Wcstombs  = 489,
    Mbtowc    = 490,
    Wctomb    = 491,
    Wcslen    = 492,
    Wcscpy    = 493,
    Wcscmp    = 494,
"""
assert ENUM_ANCHOR in src, "ENUM_ANCHOR not found"
src = src.replace(ENUM_ANCHOR, ENUM_INSERT, 1)

# ── 2. from_u32 MAPPINGS ──────────────────────────────────────────────────────
FROM_ANCHOR = "            469 => Some(Self::Memmem),\n"
FROM_INSERT = """\
            469 => Some(Self::Memmem),
            470 => Some(Self::Isalnum),
            471 => Some(Self::Isalpha),
            472 => Some(Self::Isblank),
            473 => Some(Self::Iscntrl),
            474 => Some(Self::Isdigit),
            475 => Some(Self::Isgraph),
            476 => Some(Self::Islower),
            477 => Some(Self::Isprint),
            478 => Some(Self::Ispunct),
            479 => Some(Self::Isspace),
            480 => Some(Self::Isupper),
            481 => Some(Self::Isxdigit),
            482 => Some(Self::Tolower),
            483 => Some(Self::Toupper),
            484 => Some(Self::Isascii),
            485 => Some(Self::Toascii),
            486 => Some(Self::Setlocale),
            487 => Some(Self::Localeconv),
            488 => Some(Self::Mbstowcs),
            489 => Some(Self::Wcstombs),
            490 => Some(Self::Mbtowc),
            491 => Some(Self::Wctomb),
            492 => Some(Self::Wcslen),
            493 => Some(Self::Wcscpy),
            494 => Some(Self::Wcscmp),
"""
assert FROM_ANCHOR in src, "FROM_ANCHOR not found"
src = src.replace(FROM_ANCHOR, FROM_INSERT, 1)

# ── 3. REGISTER KNOWN SYMBOLS ─────────────────────────────────────────────────
SYM_ANCHOR = '            ("memmem",    BionicFuncId::Memmem),\n'
SYM_INSERT = """\
            ("memmem",    BionicFuncId::Memmem),
            ("isalnum",   BionicFuncId::Isalnum),
            ("isalpha",   BionicFuncId::Isalpha),
            ("isblank",   BionicFuncId::Isblank),
            ("iscntrl",   BionicFuncId::Iscntrl),
            ("isdigit",   BionicFuncId::Isdigit),
            ("isgraph",   BionicFuncId::Isgraph),
            ("islower",   BionicFuncId::Islower),
            ("isprint",   BionicFuncId::Isprint),
            ("ispunct",   BionicFuncId::Ispunct),
            ("isspace",   BionicFuncId::Isspace),
            ("isupper",   BionicFuncId::Isupper),
            ("isxdigit",  BionicFuncId::Isxdigit),
            ("tolower",   BionicFuncId::Tolower),
            ("toupper",   BionicFuncId::Toupper),
            ("isascii",   BionicFuncId::Isascii),
            ("toascii",   BionicFuncId::Toascii),
            ("setlocale", BionicFuncId::Setlocale),
            ("localeconv", BionicFuncId::Localeconv),
            ("mbstowcs",  BionicFuncId::Mbstowcs),
            ("wcstombs",  BionicFuncId::Wcstombs),
            ("mbtowc",    BionicFuncId::Mbtowc),
            ("wctomb",    BionicFuncId::Wctomb),
            ("wcslen",    BionicFuncId::Wcslen),
            ("wcscpy",    BionicFuncId::Wcscpy),
            ("wcscmp",    BionicFuncId::Wcscmp),
"""
assert SYM_ANCHOR in src, "SYM_ANCHOR not found"
src = src.replace(SYM_ANCHOR, SYM_INSERT, 1)

# ── 4. INSTALL_STUBS ──────────────────────────────────────────────────────────
STUBS_ANCHOR = "            BionicFuncId::Memmem,\n        ] {\n"
STUBS_INSERT = """\
            BionicFuncId::Memmem,
            BionicFuncId::Isalnum,
            BionicFuncId::Isalpha,
            BionicFuncId::Isblank,
            BionicFuncId::Iscntrl,
            BionicFuncId::Isdigit,
            BionicFuncId::Isgraph,
            BionicFuncId::Islower,
            BionicFuncId::Isprint,
            BionicFuncId::Ispunct,
            BionicFuncId::Isspace,
            BionicFuncId::Isupper,
            BionicFuncId::Isxdigit,
            BionicFuncId::Tolower,
            BionicFuncId::Toupper,
            BionicFuncId::Isascii,
            BionicFuncId::Toascii,
            BionicFuncId::Setlocale,
            BionicFuncId::Localeconv,
            BionicFuncId::Mbstowcs,
            BionicFuncId::Wcstombs,
            BionicFuncId::Mbtowc,
            BionicFuncId::Wctomb,
            BionicFuncId::Wcslen,
            BionicFuncId::Wcscpy,
            BionicFuncId::Wcscmp,
        ] {
"""
assert STUBS_ANCHOR in src, "STUBS_ANCHOR not found"
src = src.replace(STUBS_ANCHOR, STUBS_INSERT, 1)

# Also in install_stubs, initialize locale structures
CANARY_ANCHOR = "        mem.write_u32(self.stack_chk_guard_addr, 0x000A_0DFF)?;\n        Ok(())\n"
CANARY_INSERT = """\
        mem.write_u32(self.stack_chk_guard_addr, 0x000A_0DFF)?;

        // Initialize locale strings & localeconv structure
        let locale_str_addr = self.stub_base.add(0xB00);
        let dot_addr        = self.stub_base.add(0xB10);
        let empty_addr      = self.stub_base.add(0xB18);
        let lconv_addr      = self.stub_base.add(0xB40);

        mem.write_bytes(locale_str_addr, b"C.UTF-8\\0")?;
        mem.write_bytes(dot_addr, b".\\0")?;
        mem.write_u8(empty_addr, 0)?;

        // decimal_point -> dot_addr
        mem.write_u32(lconv_addr, dot_addr.as_u32())?;
        // thousands_sep through negative_sign (9 pointers) -> empty_addr
        for i in 1..10 {
            mem.write_u32(lconv_addr.add((i * 4) as u32), empty_addr.as_u32())?;
        }
        // numeric / monetary formats: 127 (CHAR_MAX)
        for i in 40..48 {
            mem.write_u8(lconv_addr.add(i as u32), 127)?;
        }

        Ok(())
"""
assert CANARY_ANCHOR in src, "CANARY_ANCHOR not found"
src = src.replace(CANARY_ANCHOR, CANARY_INSERT, 1)

# ── 5. HANDLE_SVC ARMS ────────────────────────────────────────────────────────
SVC_ANCHOR = "            _ => {}\n"
SVC_INSERT = """\
            // ── Stage 65: Character Classification & Locale / Wide-Char ────
            BionicFuncId::Isalnum => {
                let c = cpu.reg(Reg::R0) as i32;
                let ok = if (0..=255).contains(&c) { (c as u8).is_ascii_alphanumeric() } else { false };
                cpu.set_reg(Reg::R0, if ok { 1 } else { 0 });
            }
            BionicFuncId::Isalpha => {
                let c = cpu.reg(Reg::R0) as i32;
                let ok = if (0..=255).contains(&c) { (c as u8).is_ascii_alphabetic() } else { false };
                cpu.set_reg(Reg::R0, if ok { 1 } else { 0 });
            }
            BionicFuncId::Isblank => {
                let c = cpu.reg(Reg::R0) as i32;
                let ok = if (0..=255).contains(&c) { let b = c as u8; b == b' ' || b == b'\\t' } else { false };
                cpu.set_reg(Reg::R0, if ok { 1 } else { 0 });
            }
            BionicFuncId::Iscntrl => {
                let c = cpu.reg(Reg::R0) as i32;
                let ok = if (0..=255).contains(&c) { (c as u8).is_ascii_control() } else { false };
                cpu.set_reg(Reg::R0, if ok { 1 } else { 0 });
            }
            BionicFuncId::Isdigit => {
                let c = cpu.reg(Reg::R0) as i32;
                let ok = if (0..=255).contains(&c) { (c as u8).is_ascii_digit() } else { false };
                cpu.set_reg(Reg::R0, if ok { 1 } else { 0 });
            }
            BionicFuncId::Isgraph => {
                let c = cpu.reg(Reg::R0) as i32;
                let ok = if (0..=255).contains(&c) { (c as u8).is_ascii_graphic() } else { false };
                cpu.set_reg(Reg::R0, if ok { 1 } else { 0 });
            }
            BionicFuncId::Islower => {
                let c = cpu.reg(Reg::R0) as i32;
                let ok = if (0..=255).contains(&c) { (c as u8).is_ascii_lowercase() } else { false };
                cpu.set_reg(Reg::R0, if ok { 1 } else { 0 });
            }
            BionicFuncId::Isprint => {
                let c = cpu.reg(Reg::R0) as i32;
                let ok = if (0..=255).contains(&c) { let b = c as u8; b.is_ascii_graphic() || b == b' ' } else { false };
                cpu.set_reg(Reg::R0, if ok { 1 } else { 0 });
            }
            BionicFuncId::Ispunct => {
                let c = cpu.reg(Reg::R0) as i32;
                let ok = if (0..=255).contains(&c) { (c as u8).is_ascii_punctuation() } else { false };
                cpu.set_reg(Reg::R0, if ok { 1 } else { 0 });
            }
            BionicFuncId::Isspace => {
                let c = cpu.reg(Reg::R0) as i32;
                let ok = if (0..=255).contains(&c) { (c as u8).is_ascii_whitespace() } else { false };
                cpu.set_reg(Reg::R0, if ok { 1 } else { 0 });
            }
            BionicFuncId::Isupper => {
                let c = cpu.reg(Reg::R0) as i32;
                let ok = if (0..=255).contains(&c) { (c as u8).is_ascii_uppercase() } else { false };
                cpu.set_reg(Reg::R0, if ok { 1 } else { 0 });
            }
            BionicFuncId::Isxdigit => {
                let c = cpu.reg(Reg::R0) as i32;
                let ok = if (0..=255).contains(&c) { (c as u8).is_ascii_hexdigit() } else { false };
                cpu.set_reg(Reg::R0, if ok { 1 } else { 0 });
            }
            BionicFuncId::Tolower => {
                let c = cpu.reg(Reg::R0) as i32;
                let res = if (0..=255).contains(&c) { (c as u8).to_ascii_lowercase() as u32 } else { c as u32 };
                cpu.set_reg(Reg::R0, res);
            }
            BionicFuncId::Toupper => {
                let c = cpu.reg(Reg::R0) as i32;
                let res = if (0..=255).contains(&c) { (c as u8).to_ascii_uppercase() as u32 } else { c as u32 };
                cpu.set_reg(Reg::R0, res);
            }
            BionicFuncId::Isascii => {
                let c = cpu.reg(Reg::R0) as i32;
                let ok = (0..=127).contains(&c);
                cpu.set_reg(Reg::R0, if ok { 1 } else { 0 });
            }
            BionicFuncId::Toascii => {
                let c = cpu.reg(Reg::R0);
                cpu.set_reg(Reg::R0, c & 0x7F);
            }
            BionicFuncId::Setlocale => {
                let locale_addr = self.stub_base.add(0xB00);
                cpu.set_reg(Reg::R0, locale_addr.as_u32());
            }
            BionicFuncId::Localeconv => {
                let lconv_addr = self.stub_base.add(0xB40);
                cpu.set_reg(Reg::R0, lconv_addr.as_u32());
            }
            BionicFuncId::Mbstowcs => {
                let dest_ptr = GuestAddr::new(cpu.reg(Reg::R0));
                let src_ptr  = GuestAddr::new(cpu.reg(Reg::R1));
                let n        = cpu.reg(Reg::R2) as usize;
                let s = Self::read_c_string(mem, src_ptr).unwrap_or_default();
                let chars: Vec<u32> = s.chars().map(|c| c as u32).collect();
                if dest_ptr.as_u32() == 0 {
                    cpu.set_reg(Reg::R0, chars.len() as u32);
                } else {
                    let to_write = chars.len().min(n);
                    for i in 0..to_write {
                        mem.write_u32(dest_ptr.add((i * 4) as u32), chars[i])?;
                    }
                    if to_write < n {
                        mem.write_u32(dest_ptr.add((to_write * 4) as u32), 0)?;
                    }
                    cpu.set_reg(Reg::R0, to_write as u32);
                }
            }
            BionicFuncId::Wcstombs => {
                let dest_ptr = GuestAddr::new(cpu.reg(Reg::R0));
                let src_ptr  = GuestAddr::new(cpu.reg(Reg::R1));
                let n        = cpu.reg(Reg::R2) as usize;
                let mut wchars = Vec::new();
                let mut i = 0u32;
                loop {
                    let wc = mem.read_u32(src_ptr.add(i * 4)).unwrap_or(0);
                    if wc == 0 { break; }
                    wchars.push(wc);
                    i += 1;
                }
                let mut bytes = Vec::new();
                for wc in wchars {
                    if let Some(ch) = char::from_u32(wc) {
                        let mut buf = [0u8; 4];
                        bytes.extend_from_slice(ch.encode_utf8(&mut buf).as_bytes());
                    } else {
                        bytes.push(b'?');
                    }
                }
                if dest_ptr.as_u32() == 0 {
                    cpu.set_reg(Reg::R0, bytes.len() as u32);
                } else {
                    let to_write = bytes.len().min(n);
                    for j in 0..to_write {
                        mem.write_u8(dest_ptr.add(j as u32), bytes[j])?;
                    }
                    if to_write < n {
                        mem.write_u8(dest_ptr.add(to_write as u32), 0)?;
                    }
                    cpu.set_reg(Reg::R0, to_write as u32);
                }
            }
            BionicFuncId::Mbtowc => {
                let pwc_ptr = GuestAddr::new(cpu.reg(Reg::R0));
                let s_ptr   = GuestAddr::new(cpu.reg(Reg::R1));
                let n       = cpu.reg(Reg::R2) as usize;
                if s_ptr.as_u32() == 0 {
                    cpu.set_reg(Reg::R0, 0);
                } else if n == 0 {
                    cpu.set_reg(Reg::R0, u32::MAX);
                } else {
                    let b = mem.read_u8(s_ptr)?;
                    if b == 0 {
                        if pwc_ptr.as_u32() != 0 {
                            mem.write_u32(pwc_ptr, 0)?;
                        }
                        cpu.set_reg(Reg::R0, 0);
                    } else {
                        if pwc_ptr.as_u32() != 0 {
                            mem.write_u32(pwc_ptr, b as u32)?;
                        }
                        cpu.set_reg(Reg::R0, 1);
                    }
                }
            }
            BionicFuncId::Wctomb => {
                let s_ptr = GuestAddr::new(cpu.reg(Reg::R0));
                let wc    = cpu.reg(Reg::R1);
                if s_ptr.as_u32() == 0 {
                    cpu.set_reg(Reg::R0, 0);
                } else if wc == 0 {
                    mem.write_u8(s_ptr, 0)?;
                    cpu.set_reg(Reg::R0, 1);
                } else if let Some(ch) = char::from_u32(wc) {
                    let mut buf = [0u8; 4];
                    let enc = ch.encode_utf8(&mut buf).as_bytes();
                    for (i, &b) in enc.iter().enumerate() {
                        mem.write_u8(s_ptr.add(i as u32), b)?;
                    }
                    cpu.set_reg(Reg::R0, enc.len() as u32);
                } else {
                    cpu.set_reg(Reg::R0, u32::MAX);
                }
            }
            BionicFuncId::Wcslen => {
                let s_ptr = GuestAddr::new(cpu.reg(Reg::R0));
                let mut len = 0u32;
                loop {
                    let wc = mem.read_u32(s_ptr.add(len * 4)).unwrap_or(0);
                    if wc == 0 { break; }
                    len += 1;
                }
                cpu.set_reg(Reg::R0, len);
            }
            BionicFuncId::Wcscpy => {
                let dest_ptr = GuestAddr::new(cpu.reg(Reg::R0));
                let src_ptr  = GuestAddr::new(cpu.reg(Reg::R1));
                let mut i = 0u32;
                loop {
                    let wc = mem.read_u32(src_ptr.add(i * 4)).unwrap_or(0);
                    mem.write_u32(dest_ptr.add(i * 4), wc)?;
                    if wc == 0 { break; }
                    i += 1;
                }
                cpu.set_reg(Reg::R0, dest_ptr.as_u32());
            }
            BionicFuncId::Wcscmp => {
                let s1_ptr = GuestAddr::new(cpu.reg(Reg::R0));
                let s2_ptr = GuestAddr::new(cpu.reg(Reg::R1));
                let mut i = 0u32;
                let res = loop {
                    let c1 = mem.read_u32(s1_ptr.add(i * 4)).unwrap_or(0);
                    let c2 = mem.read_u32(s2_ptr.add(i * 4)).unwrap_or(0);
                    if c1 != c2 || c1 == 0 {
                        break (c1 as i32) - (c2 as i32);
                    }
                    i += 1;
                };
                cpu.set_reg(Reg::R0, res as u32);
            }
            _ => {}
"""
assert SVC_ANCHOR in src, "WILDCARD_ANCHOR not found"
src = src.replace(SVC_ANCHOR, SVC_INSERT, 1)

with open(PATH, "w", encoding="utf-8") as f:
    f.write(src)

print("Stage 65 patch applied successfully.")
