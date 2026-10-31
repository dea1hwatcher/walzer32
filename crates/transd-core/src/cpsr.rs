use bitflags::bitflags;

bitflags! {
    /// Current Program Status Register (CPSR / APSR)
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
    pub struct Cpsr: u32 {
        /// Negative condition flag
        const N = 1 << 31;
        /// Zero condition flag
        const Z = 1 << 30;
        /// Carry condition flag
        const C = 1 << 29;
        /// Overflow condition flag
        const V = 1 << 28;
        /// Sticky saturation flag (Q)
        const Q = 1 << 27;

        /// Endianness execution state bit (0 = Little-endian, 1 = Big-endian)
        const E = 1 << 9;
        /// Asynchronous abort disable
        const A = 1 << 8;
        /// IRQ disable
        const I = 1 << 7;
        /// FIQ disable
        const F = 1 << 6;
        /// Thumb execution state bit (0 = ARM state, 1 = Thumb state)
        const T = 1 << 5;
    }
}

/// ARM Condition Codes (4-bit field in instructions)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
#[repr(u8)]
pub enum Cond {
    EQ = 0b0000, // Equal (Z = 1)
    NE = 0b0001, // Not equal (Z = 0)
    CS = 0b0010, // Carry set / Unsigned higher or same (C = 1)
    CC = 0b0011, // Carry clear / Unsigned lower (C = 0)
    MI = 0b0100, // Minus / Negative (N = 1)
    PL = 0b0101, // Plus / Positive or zero (N = 0)
    VS = 0b0110, // Overflow (V = 1)
    VC = 0b0111, // No overflow (V = 0)
    HI = 0b1000, // Unsigned higher (C = 1 and Z = 0)
    LS = 0b1001, // Unsigned lower or same (C = 0 or Z = 1)
    GE = 0b1010, // Signed greater than or equal (N == V)
    LT = 0b1011, // Signed less than (N != V)
    GT = 0b1100, // Signed greater than (Z = 0 and N == V)
    LE = 0b1101, // Signed less than or equal (Z = 1 or N != V)
    #[default]
    AL = 0b1110, // Always (unconditional execution)
    NV = 0b1111, // Never / Special extension space in ARMv7
}

impl Cond {
    #[inline(always)]
    pub const fn from_u8(val: u8) -> Self {
        match val & 0xF {
            0b0000 => Cond::EQ,
            0b0001 => Cond::NE,
            0b0010 => Cond::CS,
            0b0011 => Cond::CC,
            0b0100 => Cond::MI,
            0b0101 => Cond::PL,
            0b0110 => Cond::VS,
            0b0111 => Cond::VC,
            0b1000 => Cond::HI,
            0b1001 => Cond::LS,
            0b1010 => Cond::GE,
            0b1011 => Cond::LT,
            0b1100 => Cond::GT,
            0b1101 => Cond::LE,
            0b1110 => Cond::AL,
            _ => Cond::NV,
        }
    }

    /// Evaluates whether the condition is satisfied given the current CPSR flags
    #[inline(always)]
    pub fn is_satisfied(self, cpsr: Cpsr) -> bool {
        let n = cpsr.contains(Cpsr::N);
        let z = cpsr.contains(Cpsr::Z);
        let c = cpsr.contains(Cpsr::C);
        let v = cpsr.contains(Cpsr::V);

        match self {
            Cond::EQ => z,
            Cond::NE => !z,
            Cond::CS => c,
            Cond::CC => !c,
            Cond::MI => n,
            Cond::PL => !n,
            Cond::VS => v,
            Cond::VC => !v,
            Cond::HI => c && !z,
            Cond::LS => !c || z,
            Cond::GE => n == v,
            Cond::LT => n != v,
            Cond::GT => !z && (n == v),
            Cond::LE => z || (n != v),
            Cond::AL => true,
            Cond::NV => false,
        }
    }

    #[inline(always)]
    pub const fn is_always(self) -> bool {
        matches!(self, Cond::AL)
    }

    /// Inverts condition (e.g. EQ <-> NE, GE <-> LT)
    pub const fn invert(self) -> Option<Self> {
        match self {
            Cond::EQ => Some(Cond::NE),
            Cond::NE => Some(Cond::EQ),
            Cond::CS => Some(Cond::CC),
            Cond::CC => Some(Cond::CS),
            Cond::MI => Some(Cond::PL),
            Cond::PL => Some(Cond::MI),
            Cond::VS => Some(Cond::VC),
            Cond::VC => Some(Cond::VS),
            Cond::HI => Some(Cond::LS),
            Cond::LS => Some(Cond::HI),
            Cond::GE => Some(Cond::LT),
            Cond::LT => Some(Cond::GE),
            Cond::GT => Some(Cond::LE),
            Cond::LE => Some(Cond::GT),
            Cond::AL | Cond::NV => None,
        }
    }
}

impl std::fmt::Display for Cond {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Cond::EQ => write!(f, "eq"),
            Cond::NE => write!(f, "ne"),
            Cond::CS => write!(f, "cs"),
            Cond::CC => write!(f, "cc"),
            Cond::MI => write!(f, "mi"),
            Cond::PL => write!(f, "pl"),
            Cond::VS => write!(f, "vs"),
            Cond::VC => write!(f, "vc"),
            Cond::HI => write!(f, "hi"),
            Cond::LS => write!(f, "ls"),
            Cond::GE => write!(f, "ge"),
            Cond::LT => write!(f, "lt"),
            Cond::GT => write!(f, "gt"),
            Cond::LE => write!(f, "le"),
            Cond::AL => write!(f, ""),
            Cond::NV => write!(f, "nv"),
        }
    }
}
