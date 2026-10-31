#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u8)]
pub enum Reg {
    R0 = 0,
    R1 = 1,
    R2 = 2,
    R3 = 3,
    R4 = 4,
    R5 = 5,
    R6 = 6,
    R7 = 7,  // Syscall number on Android/Linux ARM32
    R8 = 8,
    R9 = 9,
    R10 = 10,
    R11 = 11, // Frame Pointer (FP)
    R12 = 12, // Intra-procedure-call scratch (IP)
    SP = 13,  // Stack Pointer (R13)
    LR = 14,  // Link Register (R14)
    PC = 15,  // Program Counter (R15)
}

impl Reg {
    #[inline(always)]
    pub const fn from_u8(val: u8) -> Option<Self> {
        match val {
            0 => Some(Reg::R0),
            1 => Some(Reg::R1),
            2 => Some(Reg::R2),
            3 => Some(Reg::R3),
            4 => Some(Reg::R4),
            5 => Some(Reg::R5),
            6 => Some(Reg::R6),
            7 => Some(Reg::R7),
            8 => Some(Reg::R8),
            9 => Some(Reg::R9),
            10 => Some(Reg::R10),
            11 => Some(Reg::R11),
            12 => Some(Reg::R12),
            13 => Some(Reg::SP),
            14 => Some(Reg::LR),
            15 => Some(Reg::PC),
            _ => None,
        }
    }

    #[inline(always)]
    pub const fn index(self) -> usize {
        self as usize
    }

    #[inline(always)]
    pub const fn is_pc(self) -> bool {
        matches!(self, Reg::PC)
    }

    #[inline(always)]
    pub const fn is_sp(self) -> bool {
        matches!(self, Reg::SP)
    }

    #[inline(always)]
    pub const fn is_lr(self) -> bool {
        matches!(self, Reg::LR)
    }
}

impl std::fmt::Display for Reg {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Reg::SP => write!(f, "sp"),
            Reg::LR => write!(f, "lr"),
            Reg::PC => write!(f, "pc"),
            Reg::R11 => write!(f, "fp"),
            Reg::R12 => write!(f, "ip"),
            r => write!(f, "r{}", *r as u8),
        }
    }
}
