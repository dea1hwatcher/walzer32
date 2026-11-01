pub mod ir;
pub mod lifter;
pub mod opt;
pub mod superblock;

pub use ir::{BlockExit, IrBlock};
pub use lifter::{Lifter, DEFAULT_MAX_BLOCK_INSTS};
pub use opt::SuperblockOptimizer;
pub use superblock::{SideExit, Superblock, TraceBuilder, DEFAULT_MAX_TRACE_BLOCKS, DEFAULT_MAX_TRACE_INSTS};
