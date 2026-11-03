use std::collections::HashSet;
use transd_core::{Cond, GuestAddr, Memory, MemoryError};
use transd_decoder::ArmInst;
use crate::ir::BlockExit;
use crate::lifter::Lifter;

pub const DEFAULT_MAX_TRACE_BLOCKS: usize = 8;
pub const DEFAULT_MAX_TRACE_INSTS: usize = 128;

/// A side exit guard along a Superblock trace.
/// If `cond` is satisfied, execution bails out of the superblock to `target`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SideExit {
    /// Flattened instruction index in the superblock where this guard is tested
    pub inst_index: usize,
    /// Condition under which this side exit is TAKEN (bail out)
    pub cond: Cond,
    /// Target guest address to resume DBT execution at if taken
    pub target: GuestAddr,
}

/// A Superblock represents an optimized linear trace spanning multiple basic blocks
/// with a single entry point and multiple exits (guarded side exits + final exit).
#[derive(Debug, Clone)]
pub struct Superblock {
    /// Entry guest address of the superblock
    pub entry: GuestAddr,
    /// Execution mode (ARM vs Thumb)
    pub is_thumb: bool,
    /// Flattened instruction stream across all traced blocks
    pub insts: Vec<ArmInst>,
    /// Exact guest address of each instruction in this superblock
    pub inst_addrs: Vec<GuestAddr>,
    /// Guarded side exits along the trace
    pub side_exits: Vec<SideExit>,
    /// Final exit of the superblock
    pub exit: BlockExit,
    /// Number of basic blocks merged into this superblock
    pub block_count: usize,
    /// Total guest code byte size across all merged blocks
    pub byte_size: usize,
    /// Whether the superblock forms a closed loop jumping back to entry
    pub is_loop: bool,
}

impl Superblock {
    pub fn new(entry: GuestAddr, is_thumb: bool) -> Self {
        Self {
            entry,
            is_thumb,
            insts: Vec::new(),
            inst_addrs: Vec::new(),
            side_exits: Vec::new(),
            exit: BlockExit::Invalid(entry),
            block_count: 0,
            byte_size: 0,
            is_loop: false,
        }
    }

    /// Resolves the guest address for the instruction at `idx`
    pub fn inst_pc(&self, idx: usize) -> GuestAddr {
        if let Some(&addr) = self.inst_addrs.get(idx) {
            addr
        } else if self.is_thumb {
            self.entry.add((idx * 2) as u32)
        } else {
            self.entry.add((idx * 4) as u32)
        }
    }

    /// Computes the architectural PC read value for instruction `idx` (+8 for ARM, +4 for Thumb)
    pub fn pc_read_val(&self, idx: usize) -> u32 {
        let addr = self.inst_pc(idx).as_u32();
        if self.is_thumb {
            addr + 4
        } else {
            addr + 8
        }
    }

    /// Computes PC value for PC-relative memory operations (+8 for ARM, (addr + 4) & !3 for Thumb)
    pub fn pc_mem_read_val(&self, idx: usize) -> u32 {
        let addr = self.inst_pc(idx).as_u32();
        if self.is_thumb {
            (addr + 4) & !3
        } else {
            addr + 8
        }
    }
}

pub struct TraceBuilder;

impl TraceBuilder {
    /// Builds a Superblock starting at `entry` using default block and instruction limits
    pub fn build_trace(
        mem: &impl Memory,
        entry: GuestAddr,
        is_thumb: bool,
    ) -> Result<Superblock, MemoryError> {
        Self::build_trace_with_limit(
            mem,
            entry,
            is_thumb,
            DEFAULT_MAX_TRACE_BLOCKS,
            DEFAULT_MAX_TRACE_INSTS,
        )
    }

    /// Builds a Superblock starting at `entry` with explicit trace limits
    pub fn build_trace_with_limit(
        mem: &impl Memory,
        entry: GuestAddr,
        is_thumb: bool,
        max_blocks: usize,
        max_insts: usize,
    ) -> Result<Superblock, MemoryError> {
        let mut sb = Superblock::new(entry, is_thumb);
        let mut cur_pc = entry;
        let mut visited = HashSet::new();

        while sb.block_count < max_blocks && sb.insts.len() < max_insts {
            if visited.contains(&cur_pc) {
                if cur_pc == entry {
                    sb.is_loop = true;
                }
                break;
            }
            visited.insert(cur_pc);

            let remaining_insts = max_insts - sb.insts.len();
            let block = Lifter::lift_block_with_limit(mem, cur_pc, is_thumb, remaining_insts)?;
            if block.insts.is_empty() {
                break;
            }

            sb.block_count += 1;
            sb.byte_size += block.byte_size;

            let exit = block.exit.clone();

            match exit {
                BlockExit::Direct(target) => {
                    sb.insts.extend(block.insts);
                    sb.inst_addrs.extend(block.inst_addrs);
                    if target == entry {
                        sb.is_loop = true;
                        sb.exit = BlockExit::Direct(target);
                        break;
                    }
                    cur_pc = target;
                    sb.exit = BlockExit::Direct(target);
                }
                BlockExit::BranchCond { cond, target, fallthrough } => {
                    if target == entry {
                        // Loop backedge taken
                        sb.insts.extend(block.insts);
                        sb.inst_addrs.extend(block.inst_addrs);
                        sb.is_loop = true;
                        sb.exit = BlockExit::BranchCond { cond, target, fallthrough };
                        break;
                    }

                    // Otherwise, continue down fallthrough on trace,
                    // turning the taken branch into a guarded side exit.
                    let inst_count = block.insts.len();
                    if inst_count > 1 {
                        sb.insts.extend_from_slice(&block.insts[..inst_count - 1]);
                        sb.inst_addrs.extend_from_slice(&block.inst_addrs[..inst_count - 1]);
                    }
                    let guard_index = sb.insts.len();
                    sb.side_exits.push(SideExit {
                        inst_index: guard_index,
                        cond,
                        target,
                    });
                    cur_pc = fallthrough;
                    sb.exit = BlockExit::Direct(fallthrough);
                }
                _ => {
                    // Indirect, SVC, BKPT, Invalid terminate the trace
                    sb.insts.extend(block.insts);
                    sb.inst_addrs.extend(block.inst_addrs);
                    sb.exit = exit;
                    break;
                }
            }
        }

        Ok(sb)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use transd_core::FlatMemory;
    use crate::opt::SuperblockOptimizer;

    #[test]
    fn test_trace_builder_multi_block_direct() {
        let mut mem = FlatMemory::new(GuestAddr::new(0x1000), 0x1000);
        // Block 1 at 0x1000:
        // 0x1000: MOV r1, #10 (0xE3A0_100A)
        // 0x1004: B 0x1008    (0xEA00_0000 -> target = 0x1004 + 8 + 0 = 0x100C? Note offset in words is (target - pc - 8) / 4)
        // For target 0x1008: offset = (0x1008 - 0x1004 - 8) / 4 = -1 -> 0xEAFF_FFFF
        mem.write_u32(GuestAddr::new(0x1000), 0xE3A0_100A).unwrap();
        mem.write_u32(GuestAddr::new(0x1004), 0xEAFF_FFFF).unwrap();

        // Block 2 at 0x1008:
        // 0x1008: ADD r0, r1, #20 (0xE281_0014)
        // 0x100C: SVC 0           (0xEF00_0000)
        mem.write_u32(GuestAddr::new(0x1008), 0xE281_0014).unwrap();
        mem.write_u32(GuestAddr::new(0x100C), 0xEF00_0000).unwrap();

        let sb = TraceBuilder::build_trace(&mem, GuestAddr::new(0x1000), false).unwrap();
        assert_eq!(sb.block_count, 2);
        assert_eq!(sb.entry, GuestAddr::new(0x1000));
        assert!(sb.insts.len() >= 3);
        assert!(matches!(sb.exit, BlockExit::Svc { imm: 0, .. }));
    }

    #[test]
    fn test_trace_builder_loop_detection() {
        let mut mem = FlatMemory::new(GuestAddr::new(0x2000), 0x1000);
        // Loop at 0x2000:
        // 0x2000: SUBS r0, r0, #1 (0xE250_0001)
        // 0x2004: BNE 0x2000      (target = 0x2000, pc=0x2004, offset = (0x2000 - 0x2004 - 8) / 4 = -3 -> 0x1AFF_FFFD)
        mem.write_u32(GuestAddr::new(0x2000), 0xE250_0001).unwrap();
        mem.write_u32(GuestAddr::new(0x2004), 0x1AFF_FFFD).unwrap();

        let sb = TraceBuilder::build_trace(&mem, GuestAddr::new(0x2000), false).unwrap();
        assert!(sb.is_loop);
        assert_eq!(sb.entry, GuestAddr::new(0x2000));
    }

    #[test]
    fn test_superblock_peephole_optimizer() {
        let mut mem = FlatMemory::new(GuestAddr::new(0x3000), 0x1000);
        // 0x3000: MOV r0, r0 (self-move) -> 0xE1A0_0000
        // 0x3004: MOV r1, r2            -> 0xE1A0_1002
        // 0x3008: MOV r2, r1 (inverse)  -> 0xE1A0_2001
        // 0x300C: SVC 0                 -> 0xEF00_0000
        mem.write_u32(GuestAddr::new(0x3000), 0xE1A0_0000).unwrap();
        mem.write_u32(GuestAddr::new(0x3004), 0xE1A0_1002).unwrap();
        mem.write_u32(GuestAddr::new(0x3008), 0xE1A0_2001).unwrap();
        mem.write_u32(GuestAddr::new(0x300C), 0xEF00_0000).unwrap();

        let mut sb = TraceBuilder::build_trace(&mem, GuestAddr::new(0x3000), false).unwrap();
        assert_eq!(sb.insts.len(), 4);

        SuperblockOptimizer::optimize(&mut sb);
        // MOV r0, r0 eliminated, and MOV r2, r1 collapsed -> 2 instructions left (MOV r1, r2 and SVC 0)!
        assert_eq!(sb.insts.len(), 2);
    }
}
