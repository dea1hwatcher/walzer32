use std::collections::HashMap;
use std::fmt::Write as FmtWrite;
use std::fs;
use std::path::Path;
use walzer32_core::{CpuState, GuestAddr, Memory, Reg};
use walzer32_decoder::decode_next;

/// Android crash signal classification
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TombstoneSignal {
    SigSegv { code: u32, fault_addr: GuestAddr },
    SigBus { code: u32, fault_addr: GuestAddr },
    SigIll { code: u32, fault_addr: GuestAddr },
    SigFpe { code: u32 },
    SigAbrt,
    Trap { message: String },
}

impl TombstoneSignal {
    pub fn name(&self) -> &'static str {
        match self {
            Self::SigSegv { .. } => "SIGSEGV",
            Self::SigBus { .. } => "SIGBUS",
            Self::SigIll { .. } => "SIGILL",
            Self::SigFpe { .. } => "SIGFPE",
            Self::SigAbrt => "SIGABRT",
            Self::Trap { .. } => "SIGTRAP",
        }
    }

    pub fn number(&self) -> u32 {
        match self {
            Self::SigSegv { .. } => 11,
            Self::SigBus { .. } => 7,
            Self::SigIll { .. } => 4,
            Self::SigFpe { .. } => 8,
            Self::SigAbrt => 6,
            Self::Trap { .. } => 5,
        }
    }

    pub fn code_description(&self) -> &'static str {
        match self {
            Self::SigSegv { code, .. } => match code {
                1 => "SEGV_MAPERR (Address not mapped to object)",
                2 => "SEGV_ACCERR (Invalid permissions for mapped object)",
                _ => "SEGV_UNKNOWN",
            },
            Self::SigBus { code, .. } => match code {
                1 => "BUS_ADRALN (Invalid address alignment)",
                2 => "BUS_ADRERR (Non-existent physical address)",
                _ => "BUS_UNKNOWN",
            },
            Self::SigIll { code, .. } => match code {
                1 => "ILL_ILLOPC (Illegal opcode)",
                2 => "ILL_ILLOPN (Illegal operand)",
                _ => "ILL_UNKNOWN",
            },
            Self::SigFpe { code } => match code {
                1 => "FPE_INTDIV (Integer divide by zero)",
                _ => "FPE_UNKNOWN",
            },
            Self::SigAbrt => "SI_USER (Abort triggered from user space / abort() call)",
            Self::Trap { .. } => "TRAP_BRKPT (Breakpoint / trap exception)",
        }
    }

    pub fn fault_addr(&self) -> Option<GuestAddr> {
        match self {
            Self::SigSegv { fault_addr, .. }
            | Self::SigBus { fault_addr, .. }
            | Self::SigIll { fault_addr, .. } => Some(*fault_addr),
            _ => None,
        }
    }
}

/// Metadata about a loaded 32-bit ELF library for symbol resolution
#[derive(Debug, Clone)]
pub struct LibraryInfo {
    pub name: String,
    pub base: GuestAddr,
    pub size: usize,
    pub symbols: HashMap<String, GuestAddr>,
}

impl LibraryInfo {
    pub fn new(name: &str, base: GuestAddr, size: usize) -> Self {
        Self {
            name: name.to_string(),
            base,
            size,
            symbols: HashMap::new(),
        }
    }

    pub fn add_symbol(&mut self, name: &str, addr: GuestAddr) {
        self.symbols.insert(name.to_string(), addr);
    }

    pub fn contains(&self, addr: GuestAddr) -> bool {
        addr >= self.base && (addr.as_u32() as usize) < (self.base.as_u32() as usize + self.size)
    }

    /// Resolves the nearest symbol whose address is <= addr
    pub fn resolve_symbol(&self, addr: GuestAddr) -> Option<(String, u32)> {
        let mut best: Option<(&String, u32, u32)> = None; // (name, sym_addr, offset)
        for (sym_name, &sym_addr) in &self.symbols {
            if sym_addr <= addr {
                let offset = addr.as_u32() - sym_addr.as_u32();
                if let Some((_, _, best_offset)) = best {
                    if offset < best_offset {
                        best = Some((sym_name, sym_addr.as_u32(), offset));
                    }
                } else {
                    best = Some((sym_name, sym_addr.as_u32(), offset));
                }
            }
        }

        // Only accept symbols within 128KB of target address
        best.filter(|(_, _, offset)| *offset < 0x20000)
            .map(|(name, _, offset)| (name.clone(), offset))
    }
}

/// A single resolved stack frame in the guest callstack backtrace
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BacktraceFrame {
    pub frame_idx: usize,
    pub pc: GuestAddr,
    pub lib_name: String,
    pub relative_pc: u32,
    pub symbol: Option<(String, u32)>,
}

/// Disassembled line of guest code around the faulting PC
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CodeDumpLine {
    pub addr: GuestAddr,
    pub hex_bytes: String,
    pub disasm: String,
    pub is_pc: bool,
}

/// A line of guest stack memory (4 32-bit words = 16 bytes)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StackDumpLine {
    pub addr: GuestAddr,
    pub words: [u32; 4],
}

/// Android Tombstone Crash Report
#[derive(Debug, Clone)]
pub struct TombstoneReport {
    pub pid: u32,
    pub tid: u32,
    pub thread_name: String,
    pub signal: TombstoneSignal,
    pub abort_message: Option<String>,
    pub cpu: CpuState,
    pub backtrace: Vec<BacktraceFrame>,
    pub code_dump: Vec<CodeDumpLine>,
    pub stack_dump: Vec<StackDumpLine>,
    pub loaded_libraries: Vec<LibraryInfo>,
}

impl TombstoneReport {
    /// Generates a complete tombstone crash report from the current machine state
    pub fn capture(
        cpu: &CpuState,
        mem: &dyn Memory,
        signal: TombstoneSignal,
        libraries: &[LibraryInfo],
        thread_name: &str,
        pid: u32,
        tid: u32,
        abort_message: Option<&str>,
    ) -> Self {
        // 1. Resolve Backtrace
        let mut backtrace = Vec::new();
        let mut seen_pcs = Vec::new();

        let resolve_frame = |idx: usize, pc: GuestAddr| -> BacktraceFrame {
            for lib in libraries {
                if lib.contains(pc) {
                    let rel_pc = pc.as_u32() - lib.base.as_u32();
                    let sym = lib.resolve_symbol(pc);
                    return BacktraceFrame {
                        frame_idx: idx,
                        pc,
                        lib_name: lib.name.clone(),
                        relative_pc: rel_pc,
                        symbol: sym,
                    };
                }
            }
            BacktraceFrame {
                frame_idx: idx,
                pc,
                lib_name: "<unknown>".to_string(),
                relative_pc: pc.as_u32(),
                symbol: None,
            }
        };

        // Frame #00: Current faulting PC
        let pc = cpu.pc();
        backtrace.push(resolve_frame(0, pc));
        seen_pcs.push(pc);

        // Frame #01: Link Register (LR) if valid
        let lr = GuestAddr::new(cpu.reg(Reg::LR));
        if lr.as_u32() != 0 && lr != pc {
            backtrace.push(resolve_frame(1, lr));
            seen_pcs.push(lr);
        }

        // Frame #02+: Scan guest stack for return addresses
        let sp = cpu.sp();
        let sp_addr = GuestAddr::new(sp);
        let mut frame_idx = backtrace.len();

        for word_offset in 0..64 {
            let curr_sp = sp_addr.add(word_offset * 4);
            if let Ok(candidate_val) = mem.read_u32(curr_sp) {
                let candidate = GuestAddr::new(candidate_val);
                // Check if candidate matches any loaded library code segment
                for lib in libraries {
                    if lib.contains(candidate) && !seen_pcs.contains(&candidate) {
                        seen_pcs.push(candidate);
                        backtrace.push(resolve_frame(frame_idx, candidate));
                        frame_idx += 1;
                        break;
                    }
                }
                if frame_idx >= 16 {
                    break;
                }
            }
        }

        // 2. Disassemble Code Around PC
        let mut code_dump = Vec::new();
        let is_thumb = cpu.is_thumb();
        let start_pc = pc.sub(16);
        let mut curr_addr = start_pc;

        while curr_addr < pc.add(20) {
            match decode_next(mem, curr_addr, is_thumb) {
                Ok((inst, len)) => {
                    let hex_bytes = if len == 2 {
                        let b = mem.read_u16(curr_addr).unwrap_or(0);
                        format!("{:04x}", b)
                    } else {
                        let b = mem.read_u32(curr_addr).unwrap_or(0);
                        format!("{:08x}", b)
                    };

                    code_dump.push(CodeDumpLine {
                        addr: curr_addr,
                        hex_bytes,
                        disasm: format!("{:?}", inst),
                        is_pc: curr_addr == pc,
                    });
                    curr_addr = curr_addr.add(len as u32);
                }
                Err(_) => {
                    curr_addr = curr_addr.add(if is_thumb { 2 } else { 4 });
                }
            }
        }

        // 3. Dump Stack Words
        let mut stack_dump = Vec::new();
        for line_idx in 0..8 {
            let line_addr = sp_addr.add(line_idx * 16);
            let mut words = [0u32; 4];
            for w in 0..4 {
                words[w] = mem.read_u32(line_addr.add((w * 4) as u32)).unwrap_or(0);
            }
            stack_dump.push(StackDumpLine {
                addr: line_addr,
                words,
            });
        }

        Self {
            pid,
            tid,
            thread_name: thread_name.to_string(),
            signal,
            abort_message: abort_message.map(|s| s.to_string()),
            cpu: cpu.clone(),
            backtrace,
            code_dump,
            stack_dump,
            loaded_libraries: libraries.to_vec(),
        }
    }

    /// Formats the tombstone crash report in the official Android tombstone style
    pub fn format_tombstone(&self) -> String {
        let mut out = String::with_capacity(4096);

        let _ = writeln!(out, "*** *** *** *** *** *** *** *** *** *** *** *** *** *** *** ***");
        let _ = writeln!(out, "Build fingerprint: 'google/walzer32/arm64:14/WALZER32.2026/1:user/release-keys'");
        let _ = writeln!(out, "Revision: '0'");
        let _ = writeln!(out, "ABI: 'arm' (32-bit ARMv7-A execution under Walzer32 DBT on ARM64 silicon)");
        let _ = writeln!(
            out,
            "pid: {}, tid: {}, name: {}  >>> Walzer32 DBT Guest Process <<<",
            self.pid, self.tid, self.thread_name
        );

        let fault_str = match self.signal.fault_addr() {
            Some(f) => format!(", fault addr 0x{:08x}", f.as_u32()),
            None => String::new(),
        };

        let _ = writeln!(
            out,
            "signal {} ({}), code {} ({}){}",
            self.signal.number(),
            self.signal.name(),
            match &self.signal {
                TombstoneSignal::SigSegv { code, .. }
                | TombstoneSignal::SigBus { code, .. }
                | TombstoneSignal::SigIll { code, .. }
                | TombstoneSignal::SigFpe { code } => *code,
                _ => 0,
            },
            self.signal.code_description(),
            fault_str
        );

        if let Some(ref msg) = self.abort_message {
            let _ = writeln!(out, "Abort message: '{}'", msg);
        }

        let _ = writeln!(out);
        let _ = writeln!(
            out,
            "    r0  {:08x}  r1  {:08x}  r2  {:08x}  r3  {:08x}",
            self.cpu.reg(Reg::R0),
            self.cpu.reg(Reg::R1),
            self.cpu.reg(Reg::R2),
            self.cpu.reg(Reg::R3)
        );
        let _ = writeln!(
            out,
            "    r4  {:08x}  r5  {:08x}  r6  {:08x}  r7  {:08x}",
            self.cpu.reg(Reg::R4),
            self.cpu.reg(Reg::R5),
            self.cpu.reg(Reg::R6),
            self.cpu.reg(Reg::R7)
        );
        let _ = writeln!(
            out,
            "    r8  {:08x}  r9  {:08x}  r10 {:08x}  r11 {:08x}",
            self.cpu.reg(Reg::R8),
            self.cpu.reg(Reg::R9),
            self.cpu.reg(Reg::R10),
            self.cpu.reg(Reg::R11)
        );
        let _ = writeln!(
            out,
            "    ip  {:08x}  sp  {:08x}  lr  {:08x}  pc  {:08x}",
            self.cpu.reg(Reg::R12),
            self.cpu.reg(Reg::SP),
            self.cpu.reg(Reg::LR),
            self.cpu.reg(Reg::PC)
        );

        let n = if self.cpu.cpsr.contains(walzer32_core::Cpsr::N) { 'N' } else { '-' };
        let z = if self.cpu.cpsr.contains(walzer32_core::Cpsr::Z) { 'Z' } else { '-' };
        let c = if self.cpu.cpsr.contains(walzer32_core::Cpsr::C) { 'C' } else { '-' };
        let v = if self.cpu.cpsr.contains(walzer32_core::Cpsr::V) { 'V' } else { '-' };
        let t = if self.cpu.is_thumb() { 1 } else { 0 };

        let _ = writeln!(
            out,
            "    cpsr {:08x} (flags: {}{}{}{}  Thumb: {}  Mode: USR_32)",
            self.cpu.cpsr.bits(), n, z, c, v, t
        );
        let _ = writeln!(out, "    fpscr {:08x}", self.cpu.fpscr);

        // VFP / NEON registers dump (first 8 doubles)
        for i in 0..4 {
            let d_a = self.cpu.vfp[i * 2];
            let d_b = self.cpu.vfp[i * 2 + 1];
            let _ = writeln!(
                out,
                "    d{:02}  {:016x}  d{:02}  {:016x}",
                i * 2,
                d_a,
                i * 2 + 1,
                d_b
            );
        }

        // Backtrace table
        let _ = writeln!(out, "\nbacktrace:");
        for frame in &self.backtrace {
            let sym_str = match &frame.symbol {
                Some((name, off)) => format!(" ({}+0x{:x})", name, off),
                None => String::new(),
            };
            let _ = writeln!(
                out,
                "    #{:02} pc {:08x}  {}{}",
                frame.frame_idx, frame.relative_pc, frame.lib_name, sym_str
            );
        }

        // Code around PC
        if !self.code_dump.is_empty() {
            let _ = writeln!(out, "\ncode around pc:");
            for line in &self.code_dump {
                let marker = if line.is_pc { "---->" } else { "     " };
                let _ = writeln!(
                    out,
                    "{} {:08x}  {:8}  {}",
                    marker,
                    line.addr.as_u32(),
                    line.hex_bytes,
                    line.disasm
                );
            }
        }

        // Stack around SP
        if !self.stack_dump.is_empty() {
            let _ = writeln!(
                out,
                "\nstack around sp ({:08x}):",
                self.cpu.reg(Reg::SP)
            );
            for line in &self.stack_dump {
                let _ = writeln!(
                    out,
                    "    {:08x}: {:08x} {:08x} {:08x} {:08x}",
                    line.addr.as_u32(),
                    line.words[0],
                    line.words[1],
                    line.words[2],
                    line.words[3]
                );
            }
        }

        // Memory map of loaded libraries
        let _ = writeln!(out, "\nmemory map (loaded 32-bit ELF libraries):");
        for lib in &self.loaded_libraries {
            let start = lib.base.as_u32();
            let end = start + lib.size as u32;
            let _ = writeln!(
                out,
                "    {:08x}-{:08x} r-xp  {:8} KB  {}",
                start,
                end,
                lib.size / 1024,
                lib.name
            );
        }

        out
    }

    /// Writes tombstone report to a file on disk (matching /data/tombstones/tombstone_XX)
    pub fn write_to_file<P: AsRef<Path>>(&self, path: P) -> std::io::Result<()> {
        let text = self.format_tombstone();
        fs::write(path, text)
    }
}
