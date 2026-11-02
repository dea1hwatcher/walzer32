#!/usr/bin/env python3
"""Stage 66: Time & Date APIs
  time, difftime, clock, times,
  gmtime, gmtime_r, localtime, localtime_r, mktime,
  asctime, asctime_r, ctime, ctime_r, strftime, strptime
"""

PATH = r"crates/transd-bridge/src/bionic.rs"

with open(PATH, "r", encoding="utf-8") as f:
    src = f.read()

# ── 1. ENUM VARIANTS ──────────────────────────────────────────────────────────
ENUM_ANCHOR = "    Wcscmp    = 494,\n"
ENUM_INSERT = """\
    Wcscmp    = 494,

    // Time & Date (Stage 66)
    Time        = 500,
    Difftime    = 501,
    Clock       = 502,
    Times       = 503,
    Gmtime      = 504,
    GmtimeR     = 505,
    Localtime   = 506,
    LocaltimeR  = 507,
    Mktime      = 508,
    Asctime     = 509,
    AsctimeR    = 510,
    Ctime       = 511,
    CtimeR      = 512,
    Strftime    = 513,
    Strptime    = 514,
"""
assert ENUM_ANCHOR in src, "ENUM_ANCHOR not found"
src = src.replace(ENUM_ANCHOR, ENUM_INSERT, 1)

# ── 2. from_u32 MAPPINGS ──────────────────────────────────────────────────────
FROM_ANCHOR = "            494 => Some(Self::Wcscmp),\n"
FROM_INSERT = """\
            494 => Some(Self::Wcscmp),
            500 => Some(Self::Time),
            501 => Some(Self::Difftime),
            502 => Some(Self::Clock),
            503 => Some(Self::Times),
            504 => Some(Self::Gmtime),
            505 => Some(Self::GmtimeR),
            506 => Some(Self::Localtime),
            507 => Some(Self::LocaltimeR),
            508 => Some(Self::Mktime),
            509 => Some(Self::Asctime),
            510 => Some(Self::AsctimeR),
            511 => Some(Self::Ctime),
            512 => Some(Self::CtimeR),
            513 => Some(Self::Strftime),
            514 => Some(Self::Strptime),
"""
assert FROM_ANCHOR in src, "FROM_ANCHOR not found"
src = src.replace(FROM_ANCHOR, FROM_INSERT, 1)

# ── 3. REGISTER KNOWN SYMBOLS ─────────────────────────────────────────────────
SYM_ANCHOR = '            ("wcscmp",    BionicFuncId::Wcscmp),\n'
SYM_INSERT = """\
            ("wcscmp",      BionicFuncId::Wcscmp),
            ("time",        BionicFuncId::Time),
            ("difftime",    BionicFuncId::Difftime),
            ("clock",       BionicFuncId::Clock),
            ("times",       BionicFuncId::Times),
            ("gmtime",      BionicFuncId::Gmtime),
            ("gmtime_r",    BionicFuncId::GmtimeR),
            ("localtime",   BionicFuncId::Localtime),
            ("localtime_r", BionicFuncId::LocaltimeR),
            ("mktime",      BionicFuncId::Mktime),
            ("asctime",     BionicFuncId::Asctime),
            ("asctime_r",   BionicFuncId::AsctimeR),
            ("ctime",       BionicFuncId::Ctime),
            ("ctime_r",     BionicFuncId::CtimeR),
            ("strftime",    BionicFuncId::Strftime),
            ("strptime",    BionicFuncId::Strptime),
"""
assert SYM_ANCHOR in src, "SYM_ANCHOR not found"
src = src.replace(SYM_ANCHOR, SYM_INSERT, 1)

# ── 4. INSTALL_STUBS ──────────────────────────────────────────────────────────
STUBS_ANCHOR = "            BionicFuncId::Wcscmp,\n        ] {\n"
STUBS_INSERT = """\
            BionicFuncId::Wcscmp,
            BionicFuncId::Time,
            BionicFuncId::Difftime,
            BionicFuncId::Clock,
            BionicFuncId::Times,
            BionicFuncId::Gmtime,
            BionicFuncId::GmtimeR,
            BionicFuncId::Localtime,
            BionicFuncId::LocaltimeR,
            BionicFuncId::Mktime,
            BionicFuncId::Asctime,
            BionicFuncId::AsctimeR,
            BionicFuncId::Ctime,
            BionicFuncId::CtimeR,
            BionicFuncId::Strftime,
            BionicFuncId::Strptime,
        ] {
"""
assert STUBS_ANCHOR in src, "STUBS_ANCHOR not found"
src = src.replace(STUBS_ANCHOR, STUBS_INSERT, 1)

# ── 5. HANDLE_SVC ARMS ────────────────────────────────────────────────────────
SVC_ANCHOR = "            _ => {}\n"
SVC_INSERT = """\
            // ── Stage 66: Time & Date APIs ─────────────────────────────────
            BionicFuncId::Time => {
                let tloc = GuestAddr::new(cpu.reg(Reg::R0));
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs() as u32;
                if tloc.as_u32() != 0 {
                    mem.write_u32(tloc, now)?;
                }
                cpu.set_reg(Reg::R0, now);
            }
            BionicFuncId::Difftime => {
                let t1 = cpu.reg(Reg::R0) as i64;
                let t0 = cpu.reg(Reg::R1) as i64;
                let diff = (t1 - t0) as f64;
                let bits = diff.to_bits();
                cpu.set_reg(Reg::R0, bits as u32);
                cpu.set_reg(Reg::R1, (bits >> 32) as u32);
                cpu.set_d_reg(0, diff);
            }
            BionicFuncId::Clock => {
                let elapsed = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_micros() as u32;
                cpu.set_reg(Reg::R0, elapsed);
            }
            BionicFuncId::Times => {
                let buf = GuestAddr::new(cpu.reg(Reg::R0));
                let elapsed = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_millis() as u32;
                if buf.as_u32() != 0 {
                    mem.write_u32(buf, elapsed / 2)?;
                    mem.write_u32(buf.add(4), elapsed / 4)?;
                    mem.write_u32(buf.add(8), 0)?;
                    mem.write_u32(buf.add(12), 0)?;
                }
                cpu.set_reg(Reg::R0, elapsed);
            }
            BionicFuncId::Gmtime | BionicFuncId::GmtimeR => {
                let time_ptr = GuestAddr::new(cpu.reg(Reg::R0));
                let out_ptr = if func_id == BionicFuncId::GmtimeR {
                    GuestAddr::new(cpu.reg(Reg::R1))
                } else {
                    self.stub_base.add(0xB80)
                };
                let secs = if time_ptr.as_u32() != 0 {
                    mem.read_u32(time_ptr).unwrap_or(0) as i64
                } else {
                    0
                };
                let (sec, min, hour, mday, mon, year, wday, yday) = secs_to_tm(secs);
                write_tm_struct(mem, out_ptr, sec, min, hour, mday, mon, year, wday, yday, 0)?;
                cpu.set_reg(Reg::R0, out_ptr.as_u32());
            }
            BionicFuncId::Localtime | BionicFuncId::LocaltimeR => {
                let time_ptr = GuestAddr::new(cpu.reg(Reg::R0));
                let out_ptr = if func_id == BionicFuncId::LocaltimeR {
                    GuestAddr::new(cpu.reg(Reg::R1))
                } else {
                    self.stub_base.add(0xBC0)
                };
                let secs = if time_ptr.as_u32() != 0 {
                    mem.read_u32(time_ptr).unwrap_or(0) as i64
                } else {
                    0
                };
                let (sec, min, hour, mday, mon, year, wday, yday) = secs_to_tm(secs);
                write_tm_struct(mem, out_ptr, sec, min, hour, mday, mon, year, wday, yday, 0)?;
                cpu.set_reg(Reg::R0, out_ptr.as_u32());
            }
            BionicFuncId::Mktime => {
                let tm_ptr = GuestAddr::new(cpu.reg(Reg::R0));
                if tm_ptr.as_u32() != 0 {
                    let sec  = mem.read_u32(tm_ptr)? as i32;
                    let min  = mem.read_u32(tm_ptr.add(4))? as i32;
                    let hour = mem.read_u32(tm_ptr.add(8))? as i32;
                    let mday = mem.read_u32(tm_ptr.add(12))? as i32;
                    let mon  = mem.read_u32(tm_ptr.add(16))? as i32;
                    let year = mem.read_u32(tm_ptr.add(20))? as i32;
                    let secs = tm_to_secs(year, mon, mday, hour, min, sec);
                    let (s, mi, h, md, mo, y, wd, yd) = secs_to_tm(secs);
                    write_tm_struct(mem, tm_ptr, s, mi, h, md, mo, y, wd, yd, 0)?;
                    cpu.set_reg(Reg::R0, secs as u32);
                } else {
                    cpu.set_reg(Reg::R0, u32::MAX);
                }
            }
            BionicFuncId::Asctime | BionicFuncId::AsctimeR => {
                let tm_ptr = GuestAddr::new(cpu.reg(Reg::R0));
                let out_ptr = if func_id == BionicFuncId::AsctimeR {
                    GuestAddr::new(cpu.reg(Reg::R1))
                } else {
                    self.stub_base.add(0xC00)
                };
                if tm_ptr.as_u32() != 0 && out_ptr.as_u32() != 0 {
                    let sec  = mem.read_u32(tm_ptr).unwrap_or(0);
                    let min  = mem.read_u32(tm_ptr.add(4)).unwrap_or(0);
                    let hour = mem.read_u32(tm_ptr.add(8)).unwrap_or(0);
                    let mday = mem.read_u32(tm_ptr.add(12)).unwrap_or(1);
                    let mon  = mem.read_u32(tm_ptr.add(16)).unwrap_or(0);
                    let year = mem.read_u32(tm_ptr.add(20)).unwrap_or(70) + 1900;
                    let wday = mem.read_u32(tm_ptr.add(24)).unwrap_or(0);
                    let days = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];
                    let mons = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
                    let day_str = days.get(wday as usize % 7).unwrap_or(&"Sun");
                    let mon_str = mons.get(mon as usize % 12).unwrap_or(&"Jan");
                    let s = format!("{} {} {:2} {:02}:{:02}:{:02} {}\\n", day_str, mon_str, mday, hour, min, sec, year);
                    let bytes = s.as_bytes();
                    for (i, &b) in bytes.iter().enumerate() {
                        mem.write_u8(out_ptr.add(i as u32), b)?;
                    }
                    mem.write_u8(out_ptr.add(bytes.len() as u32), 0)?;
                    cpu.set_reg(Reg::R0, out_ptr.as_u32());
                } else {
                    cpu.set_reg(Reg::R0, 0);
                }
            }
            BionicFuncId::Ctime | BionicFuncId::CtimeR => {
                let time_ptr = GuestAddr::new(cpu.reg(Reg::R0));
                let out_ptr = if func_id == BionicFuncId::CtimeR {
                    GuestAddr::new(cpu.reg(Reg::R1))
                } else {
                    self.stub_base.add(0xC00)
                };
                if time_ptr.as_u32() != 0 && out_ptr.as_u32() != 0 {
                    let secs = mem.read_u32(time_ptr).unwrap_or(0) as i64;
                    let (sec, min, hour, mday, mon, year_since_1900, wday, _) = secs_to_tm(secs);
                    let year = year_since_1900 + 1900;
                    let days = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];
                    let mons = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
                    let day_str = days.get(wday as usize % 7).unwrap_or(&"Sun");
                    let mon_str = mons.get(mon as usize % 12).unwrap_or(&"Jan");
                    let s = format!("{} {} {:2} {:02}:{:02}:{:02} {}\\n", day_str, mon_str, mday, hour, min, sec, year);
                    let bytes = s.as_bytes();
                    for (i, &b) in bytes.iter().enumerate() {
                        mem.write_u8(out_ptr.add(i as u32), b)?;
                    }
                    mem.write_u8(out_ptr.add(bytes.len() as u32), 0)?;
                    cpu.set_reg(Reg::R0, out_ptr.as_u32());
                } else {
                    cpu.set_reg(Reg::R0, 0);
                }
            }
            BionicFuncId::Strftime => {
                let s_ptr   = GuestAddr::new(cpu.reg(Reg::R0));
                let max     = cpu.reg(Reg::R1) as usize;
                let fmt_ptr = GuestAddr::new(cpu.reg(Reg::R2));
                let tm_ptr  = GuestAddr::new(cpu.reg(Reg::R3));
                let fmt = Self::read_c_string(mem, fmt_ptr).unwrap_or_default();
                if tm_ptr.as_u32() == 0 || s_ptr.as_u32() == 0 || max == 0 {
                    cpu.set_reg(Reg::R0, 0);
                } else {
                    let sec  = mem.read_u32(tm_ptr).unwrap_or(0);
                    let min  = mem.read_u32(tm_ptr.add(4)).unwrap_or(0);
                    let hour = mem.read_u32(tm_ptr.add(8)).unwrap_or(0);
                    let mday = mem.read_u32(tm_ptr.add(12)).unwrap_or(1);
                    let mon  = mem.read_u32(tm_ptr.add(16)).unwrap_or(0);
                    let year = mem.read_u32(tm_ptr.add(20)).unwrap_or(70) + 1900;
                    let wday = mem.read_u32(tm_ptr.add(24)).unwrap_or(0);
                    let yday = mem.read_u32(tm_ptr.add(28)).unwrap_or(0);
                    let days = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];
                    let mons = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
                    let day_str = days.get(wday as usize % 7).unwrap_or(&"Sun");
                    let mon_str = mons.get(mon as usize % 12).unwrap_or(&"Jan");

                    let mut out = String::new();
                    let mut chars = fmt.chars().peekable();
                    while let Some(c) = chars.next() {
                        if c == '%' {
                            match chars.next() {
                                Some('Y') => out.push_str(&format!("{:04}", year)),
                                Some('y') => out.push_str(&format!("{:02}", year % 100)),
                                Some('m') => out.push_str(&format!("{:02}", mon + 1)),
                                Some('d') => out.push_str(&format!("{:02}", mday)),
                                Some('e') => out.push_str(&format!("{:2}", mday)),
                                Some('H') => out.push_str(&format!("{:02}", hour)),
                                Some('M') => out.push_str(&format!("{:02}", min)),
                                Some('S') => out.push_str(&format!("{:02}", sec)),
                                Some('F') => out.push_str(&format!("{:04}-{:02}-{:02}", year, mon + 1, mday)),
                                Some('T') => out.push_str(&format!("{:02}:{:02}:{:02}", hour, min, sec)),
                                Some('R') => out.push_str(&format!("{:02}:{:02}", hour, min)),
                                Some('a') => out.push_str(day_str),
                                Some('b') | Some('h') => out.push_str(mon_str),
                                Some('j') => out.push_str(&format!("{:03}", yday + 1)),
                                Some('w') => out.push_str(&format!("{}", wday)),
                                Some('u') => out.push_str(&format!("{}", if wday == 0 { 7 } else { wday })),
                                Some('%') => out.push('%'),
                                Some(other) => { out.push('%'); out.push(other); }
                                None => out.push('%'),
                            }
                        } else {
                            out.push(c);
                        }
                    }

                    let bytes = out.as_bytes();
                    if bytes.len() < max {
                        for (i, &b) in bytes.iter().enumerate() {
                            mem.write_u8(s_ptr.add(i as u32), b)?;
                        }
                        mem.write_u8(s_ptr.add(bytes.len() as u32), 0)?;
                        cpu.set_reg(Reg::R0, bytes.len() as u32);
                    } else {
                        cpu.set_reg(Reg::R0, 0);
                    }
                }
            }
            BionicFuncId::Strptime => {
                let s_ptr   = GuestAddr::new(cpu.reg(Reg::R0));
                let fmt_ptr = GuestAddr::new(cpu.reg(Reg::R1));
                let tm_ptr  = GuestAddr::new(cpu.reg(Reg::R2));
                let s = Self::read_c_string(mem, s_ptr).unwrap_or_default();
                let fmt = Self::read_c_string(mem, fmt_ptr).unwrap_or_default();
                let consumed = parse_strptime_simple(&s, &fmt, mem, tm_ptr);
                if consumed > 0 {
                    cpu.set_reg(Reg::R0, s_ptr.add(consumed as u32).as_u32());
                } else {
                    cpu.set_reg(Reg::R0, 0);
                }
            }
            _ => {}
"""
assert SVC_ANCHOR in src, "WILDCARD_ANCHOR not found"
src = src.replace(SVC_ANCHOR, SVC_INSERT, 1)

# ── 6. TAIL HELPERS ───────────────────────────────────────────────────────────
TAIL_ANCHOR = """\
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
TAIL_INSERT = """\
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

fn secs_to_tm(secs: i64) -> (i32, i32, i32, i32, i32, i32, i32, i32) {
    let s = secs.rem_euclid(86400) as i32;
    let sec = s % 60;
    let min = (s / 60) % 60;
    let hour = s / 3600;

    let mut days = secs.div_euclid(86400) as i32;
    let wday = (days + 4).rem_euclid(7);

    let mut year = 1970;
    loop {
        let is_leap = (year % 4 == 0 && year % 100 != 0) || (year % 400 == 0);
        let days_in_year = if is_leap { 366 } else { 365 };
        if days >= days_in_year {
            days -= days_in_year;
            year += 1;
        } else if days < 0 {
            year -= 1;
            let prev_leap = (year % 4 == 0 && year % 100 != 0) || (year % 400 == 0);
            days += if prev_leap { 366 } else { 365 };
        } else {
            break;
        }
    }
    let yday = days;
    let is_leap = (year % 4 == 0 && year % 100 != 0) || (year % 400 == 0);
    let month_days = [31, if is_leap { 29 } else { 28 }, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
    let mut mon = 0;
    for &md in &month_days {
        if days < md {
            break;
        }
        days -= md;
        mon += 1;
    }
    let mday = days + 1;
    (sec, min, hour, mday, mon, year - 1900, wday, yday)
}

fn tm_to_secs(year_since_1900: i32, mon: i32, mday: i32, hour: i32, min: i32, sec: i32) -> i64 {
    let year = year_since_1900 + 1900;
    let mut days = 0i64;
    for y in 1970..year {
        let is_leap = (y % 4 == 0 && y % 100 != 0) || (y % 400 == 0);
        days += if is_leap { 366 } else { 365 };
    }
    for y in (year..1970).rev() {
        let is_leap = (y % 4 == 0 && y % 100 != 0) || (y % 400 == 0);
        days -= if is_leap { 366 } else { 365 };
    }
    let is_leap = (year % 4 == 0 && year % 100 != 0) || (year % 400 == 0);
    let month_days = [31, if is_leap { 29 } else { 28 }, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
    for m in 0..(mon as usize).min(11) {
        days += month_days[m] as i64;
    }
    days += (mday - 1) as i64;
    days * 86400 + (hour as i64) * 3600 + (min as i64) * 60 + (sec as i64)
}

fn write_tm_struct(
    mem: &mut impl Memory,
    addr: GuestAddr,
    sec: i32,
    min: i32,
    hour: i32,
    mday: i32,
    mon: i32,
    year: i32,
    wday: i32,
    yday: i32,
    isdst: i32,
) -> Result<(), MemoryError> {
    mem.write_u32(addr, sec as u32)?;
    mem.write_u32(addr.add(4), min as u32)?;
    mem.write_u32(addr.add(8), hour as u32)?;
    mem.write_u32(addr.add(12), mday as u32)?;
    mem.write_u32(addr.add(16), mon as u32)?;
    mem.write_u32(addr.add(20), year as u32)?;
    mem.write_u32(addr.add(24), wday as u32)?;
    mem.write_u32(addr.add(28), yday as u32)?;
    mem.write_u32(addr.add(32), isdst as u32)?;
    mem.write_u32(addr.add(36), 0)?;
    mem.write_u32(addr.add(40), 0)?;
    Ok(())
}

fn parse_strptime_simple(s: &str, fmt: &str, mem: &mut impl Memory, tm_ptr: GuestAddr) -> usize {
    let mut s_idx = 0;
    let s_chars: Vec<char> = s.chars().collect();
    let fmt_chars: Vec<char> = fmt.chars().collect();
    let mut f_idx = 0;

    let mut year = 1970;
    let mut mon = 0;
    let mut mday = 1;
    let mut hour = 0;
    let mut min = 0;
    let mut sec = 0;

    while f_idx < fmt_chars.len() && s_idx < s_chars.len() {
        if fmt_chars[f_idx] == '%' && f_idx + 1 < fmt_chars.len() {
            f_idx += 1;
            let spec = fmt_chars[f_idx];
            f_idx += 1;
            let mut num_str = String::new();
            while s_idx < s_chars.len() && s_chars[s_idx].is_ascii_digit() {
                num_str.push(s_chars[s_idx]);
                s_idx += 1;
            }
            let val = num_str.parse::<i32>().unwrap_or(0);
            match spec {
                'Y' => year = val,
                'm' => mon = (val - 1).max(0),
                'd' => mday = val,
                'H' => hour = val,
                'M' => min = val,
                'S' => sec = val,
                _ => {}
            }
        } else {
            if s_chars[s_idx] == fmt_chars[f_idx] {
                s_idx += 1;
                f_idx += 1;
            } else {
                return 0;
            }
        }
    }

    if tm_ptr.as_u32() != 0 {
        let (s, mi, h, md, mo, y, wd, yd) = secs_to_tm(tm_to_secs(year - 1900, mon, mday, hour, min, sec));
        let _ = write_tm_struct(mem, tm_ptr, s, mi, h, md, mo, y, wd, yd, 0);
    }
    s_idx
}
"""
assert TAIL_ANCHOR in src, "TAIL_ANCHOR not found"
src = src.replace(TAIL_ANCHOR, TAIL_INSERT, 1)

with open(PATH, "w", encoding="utf-8") as f:
    f.write(src)

print("Stage 66 patch applied successfully.")
