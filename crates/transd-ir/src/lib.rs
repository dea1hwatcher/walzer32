pub mod ir;
pub mod lifter;

pub use ir::{BlockExit, IrBlock};
pub use lifter::{Lifter, DEFAULT_MAX_BLOCK_INSTS};
