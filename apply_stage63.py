#!/usr/bin/env python3
"""Stage 63: Directory enumeration — opendir, readdir, readdir64, closedir,
fdopendir, dirfd, rewinddir, telldir, seekdir"""

import sys, re

PATH = r"crates/transd-bridge/src/bionic.rs"

with open(PATH, "r", encoding="utf-8") as f:
    src = f.read()

orig = src

# ── 1. ENUM VARIANTS ──────────────────────────────────────────────────────────
ENUM_ANCHOR = "    Ldexp = 435,\n"
ENUM_INSERT = """\
    Ldexp = 435,

    // Directory enumeration
    Opendir  = 440,
    Closedir = 441,
    Readdir  = 442,
    Readdir64 = 443,
    Fdopendir = 444,
    Dirfd    = 445,
    Rewinddir = 446,
    Telldir  = 447,
    Seekdir  = 448,
"""
assert ENUM_ANCHOR in src, "ENUM_ANCHOR not found"
src = src.replace(ENUM_ANCHOR, ENUM_INSERT, 1)

# ── 2. from_u32 MAPPINGS ──────────────────────────────────────────────────────
FROM_ANCHOR = "            435 => Some(Self::Ldexp),\n"
FROM_INSERT = """\
            435 => Some(Self::Ldexp),
            440 => Some(Self::Opendir),
            441 => Some(Self::Closedir),
            442 => Some(Self::Readdir),
            443 => Some(Self::Readdir64),
            444 => Some(Self::Fdopendir),
            445 => Some(Self::Dirfd),
            446 => Some(Self::Rewinddir),
            447 => Some(Self::Telldir),
            448 => Some(Self::Seekdir),
"""
assert FROM_ANCHOR in src, "FROM_ANCHOR not found"
src = src.replace(FROM_ANCHOR, FROM_INSERT, 1)

# ── 3. STRUCT FIELDS ──────────────────────────────────────────────────────────
# Add dir_handles and next_dir_handle after next_pipe_fd
STRUCT_ANCHOR = "    pub next_pipe_fd: u32,\n"
STRUCT_INSERT = """\
    pub next_pipe_fd: u32,
    // Directory handle table: guest_dir_handle -> (vfs_path, entry_index)
    pub dir_handles: std::collections::HashMap<u32, (String, usize)>,
    pub next_dir_handle: u32,
"""
assert STRUCT_ANCHOR in src, "STRUCT_ANCHOR not found"
src = src.replace(STRUCT_ANCHOR, STRUCT_INSERT, 1)

# ── 4. STRUCT INITIALISER ────────────────────────────────────────────────────
INIT_ANCHOR = "            next_pipe_fd: 100, // Guest pipe FDs start at 100\n"
INIT_INSERT = """\
            next_pipe_fd: 100, // Guest pipe FDs start at 100
            dir_handles: std::collections::HashMap::new(),
            next_dir_handle: 200, // Guest DIR* handles start at 200
"""
assert INIT_ANCHOR in src, "INIT_ANCHOR not found"
src = src.replace(INIT_ANCHOR, INIT_INSERT, 1)

# ── 5. REGISTER KNOWN SYMBOLS ─────────────────────────────────────────────────
SYM_ANCHOR = '            ("ldexp", BionicFuncId::Ldexp),\n'
SYM_INSERT = """\
            ("ldexp", BionicFuncId::Ldexp),
            ("opendir",   BionicFuncId::Opendir),
            ("closedir",  BionicFuncId::Closedir),
            ("readdir",   BionicFuncId::Readdir),
            ("readdir64", BionicFuncId::Readdir64),
            ("fdopendir", BionicFuncId::Fdopendir),
            ("dirfd",     BionicFuncId::Dirfd),
            ("rewinddir", BionicFuncId::Rewinddir),
            ("telldir",   BionicFuncId::Telldir),
            ("seekdir",   BionicFuncId::Seekdir),
"""
assert SYM_ANCHOR in src, "SYM_ANCHOR not found"
src = src.replace(SYM_ANCHOR, SYM_INSERT, 1)

# ── 6. HANDLE_SVC ARMS ────────────────────────────────────────────────────────
# Insert before the wildcard `_ => {}` arm (after the Ldexp block)
SVC_ANCHOR = "            BionicFuncId::Ldexp => {\n"
# Find the end of the Ldexp arm (closing brace + blank lines + wildcard)
# We insert NEW arms BEFORE the `            _ => {}\n` catch-all
WILDCARD_ANCHOR = "            _ => {}\n"
WILDCARD_INSERT = """\
            // ── Stage 63: Directory enumeration ─────────────────────────────
            BionicFuncId::Opendir => {
                // opendir(const char *name) -> DIR* (guest handle, 0 on error)
                let path_ptr = GuestAddr::new(cpu.reg(Reg::R0));
                let path = Self::read_c_string(mem, path_ptr).unwrap_or_default();
                // Check if VFS has any entry with this prefix
                let norm = if path.ends_with('/') { path.clone() } else { format!("{}/", path) };
                let exists = self.vfs.list_dir(&norm).is_some()
                    || self.vfs.list_dir(&path).is_some()
                    || path == "/" || path == "/proc" || path == "/sys" || path == "/data";
                if exists {
                    let handle = self.next_dir_handle;
                    self.next_dir_handle += 1;
                    let dir_path = if path.ends_with('/') { path } else { format!("{}/", path) };
                    self.dir_handles.insert(handle, (dir_path, 0));
                    cpu.set_reg(Reg::R0, handle);
                } else {
                    cpu.set_reg(Reg::R0, 0); // NULL = error
                }
            }
            BionicFuncId::Closedir => {
                // closedir(DIR *dirp) -> int (0 ok, -1 err)
                let handle = cpu.reg(Reg::R0);
                if self.dir_handles.remove(&handle).is_some() {
                    cpu.set_reg(Reg::R0, 0);
                } else {
                    cpu.set_reg(Reg::R0, u32::MAX); // -1
                }
            }
            BionicFuncId::Readdir | BionicFuncId::Readdir64 => {
                // readdir(DIR *dirp) -> struct dirent* (0 at end)
                // We write a 280-byte dirent into a fixed scratch area and return its address.
                // Layout (ARM32 dirent64): ino(8), off(8), reclen(2), type(1), name[256]
                let handle = cpu.reg(Reg::R0);
                if let Some((dir_path, idx)) = self.dir_handles.get_mut(&handle) {
                    let entries = self.vfs.list_dir(dir_path).unwrap_or_default();
                    if *idx < entries.len() {
                        let name = entries[*idx].clone();
                        *idx += 1;
                        // Write dirent into static scratch area: stub_base + 0x1800
                        let dirent_addr = self.stub_base.add(0x1800);
                        // ino = idx as u64
                        let ino: u64 = *idx as u64;
                        mem.write_u32(dirent_addr,               ino as u32)?;
                        mem.write_u32(dirent_addr.add(4),        (ino >> 32) as u32)?;
                        // off = 0
                        mem.write_u32(dirent_addr.add(8),        0)?;
                        mem.write_u32(dirent_addr.add(12),       0)?;
                        // reclen = 280
                        mem.write_u16(dirent_addr.add(16),       280u16)?;
                        // type = 8 (DT_REG) or 4 (DT_DIR) — assume DT_REG for simplicity
                        mem.write_u8(dirent_addr.add(18),        8u8)?;
                        // name (null-terminated)
                        let name_addr = dirent_addr.add(19);
                        let nb = name.as_bytes();
                        let len = nb.len().min(255);
                        for i in 0..len {
                            mem.write_u8(name_addr.add(i as u32), nb[i])?;
                        }
                        mem.write_u8(name_addr.add(len as u32), 0)?;
                        cpu.set_reg(Reg::R0, dirent_addr.raw());
                    } else {
                        cpu.set_reg(Reg::R0, 0); // end of directory
                    }
                } else {
                    cpu.set_reg(Reg::R0, 0);
                }
            }
            BionicFuncId::Fdopendir => {
                // fdopendir(int fd) -> DIR*  — we synthesise a path from VFS fd
                let guest_fd = cpu.reg(Reg::R0);
                let path = self.vfs.fd_path(guest_fd).unwrap_or_default();
                if !path.is_empty() {
                    let handle = self.next_dir_handle;
                    self.next_dir_handle += 1;
                    let dir_path = if path.ends_with('/') { path } else { format!("{}/", path) };
                    self.dir_handles.insert(handle, (dir_path, 0));
                    cpu.set_reg(Reg::R0, handle);
                } else {
                    cpu.set_reg(Reg::R0, 0);
                }
            }
            BionicFuncId::Dirfd => {
                // dirfd(DIR *dirp) -> int fd  — return -1 (not backed by real fd)
                cpu.set_reg(Reg::R0, u32::MAX);
            }
            BionicFuncId::Rewinddir => {
                // rewinddir(DIR *dirp) — reset index to 0
                let handle = cpu.reg(Reg::R0);
                if let Some((_, idx)) = self.dir_handles.get_mut(&handle) {
                    *idx = 0;
                }
            }
            BionicFuncId::Telldir => {
                // telldir(DIR *dirp) -> long  — return current index
                let handle = cpu.reg(Reg::R0);
                let pos = self.dir_handles.get(&handle).map(|(_, i)| *i as u32).unwrap_or(0);
                cpu.set_reg(Reg::R0, pos);
            }
            BionicFuncId::Seekdir => {
                // seekdir(DIR *dirp, long loc)
                let handle = cpu.reg(Reg::R0);
                let loc = cpu.reg(Reg::R1) as usize;
                if let Some((_, idx)) = self.dir_handles.get_mut(&handle) {
                    *idx = loc;
                }
            }
            _ => {}
"""
assert WILDCARD_ANCHOR in src, "WILDCARD_ANCHOR not found"
src = src.replace(WILDCARD_ANCHOR, WILDCARD_INSERT, 1)

with open(PATH, "w", encoding="utf-8") as f:
    f.write(src)

print("Stage 63 patch applied successfully.")
