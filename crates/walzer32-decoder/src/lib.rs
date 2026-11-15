pub mod arm;
pub mod thumb;
pub mod types;

pub use arm::ArmDecoder;
pub use thumb::ThumbDecoder;
pub use types::*;

use walzer32_core::{GuestAddr, Memory, MemoryError};

/// Generic decoder that inspects CPU state/mode (ARM vs Thumb) and fetches/decodes from memory
pub fn decode_next(
    mem: &(impl Memory + ?Sized),
    addr: GuestAddr,
    is_thumb: bool,
) -> Result<(ArmInst, usize), MemoryError> {
    if is_thumb {
        let aligned = GuestAddr::new(addr.as_u32() & !1);
        let hw1 = mem.read_u16(aligned)?;
        let prefix = (hw1 >> 11) & 0x1F;
        if prefix == 0b11101 || prefix == 0b11110 || prefix == 0b11111 {
            let hw2 = mem.read_u16(aligned.add(2))?;
            Ok(ThumbDecoder::decode(hw1, Some(hw2)))
        } else {
            Ok(ThumbDecoder::decode(hw1, None))
        }
    } else {
        let aligned = GuestAddr::new(addr.as_u32() & !3);
        let raw = mem.read_u32(aligned)?;
        Ok((ArmDecoder::decode(raw), 4))
    }
}
