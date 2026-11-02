//! Stage 75 integration tests: Advanced Terminal / TTY & IOCTL APIs
//! Tests: isatty, ttyname, ttyname_r, tcgetattr, tcsetattr, tcflush,
//!        tcsendbreak, tcdrain, tcflow, cfgetispeed, cfgetospeed,
//!        cfsetispeed, cfsetospeed, cfmakeraw, ioctl

use transd_bridge::bionic::{BionicBridge, BionicFuncId, BIONIC_SVC_MAGIC};
use transd_core::{ArenaMemory, CpuState, GuestAddr, Memory, MemoryError, Reg};
use transd_elf::loader::SymbolResolver;

const STUB_BASE: u32 = 0x0001_0000;
const HEAP_START: u32 = 0x0002_0000;

fn call_bionic(
    bridge: &mut BionicBridge,
    func_id: BionicFuncId,
    cpu: &mut CpuState,
    mem: &mut impl Memory,
) -> Result<bool, MemoryError> {
    bridge.handle_svc(BIONIC_SVC_MAGIC | (func_id as u32), cpu, mem)
}

fn setup() -> (BionicBridge, ArenaMemory, CpuState) {
    let mut mem = ArenaMemory::new().expect("arena");
    let stub_base = GuestAddr::new(STUB_BASE);
    let heap_start = GuestAddr::new(HEAP_START);

    mem.commit_range(stub_base, 0x0008_0000).expect("commit stub");
    mem.commit_range(heap_start, 0x0010_0000).expect("commit heap");

    let bridge = BionicBridge::new(stub_base, heap_start, 0x0010_0000);
    bridge.install_stubs(&mut mem).expect("stubs");

    let mut cpu = CpuState::new();
    cpu.set_reg(Reg::SP, HEAP_START + 0x0008_0000);

    (bridge, mem, cpu)
}

fn read_c_str(mem: &impl Memory, mut addr: GuestAddr) -> String {
    let mut bytes = Vec::new();
    loop {
        let b = mem.read_u8(addr).unwrap();
        if b == 0 {
            break;
        }
        bytes.push(b);
        addr = addr.add(1);
    }
    String::from_utf8_lossy(&bytes).to_string()
}

#[test]
fn test_isatty_and_ttyname() {
    let (mut bridge, mut mem, mut cpu) = setup();

    // isatty: 0, 1, 2 should return 1; 3, 10 should return 0
    cpu.set_reg(Reg::R0, 0);
    call_bionic(&mut bridge, BionicFuncId::Isatty, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 1);

    cpu.set_reg(Reg::R0, 1);
    call_bionic(&mut bridge, BionicFuncId::Isatty, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 1);

    cpu.set_reg(Reg::R0, 2);
    call_bionic(&mut bridge, BionicFuncId::Isatty, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 1);

    cpu.set_reg(Reg::R0, 3);
    call_bionic(&mut bridge, BionicFuncId::Isatty, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 0);

    // ttyname: fd=0 returns "/dev/pts/0"
    cpu.set_reg(Reg::R0, 0);
    call_bionic(&mut bridge, BionicFuncId::Ttyname, &mut cpu, &mut mem).unwrap();
    let ptr = GuestAddr::new(cpu.reg(Reg::R0));
    assert_ne!(ptr.as_u32(), 0);
    let s = read_c_str(&mem, ptr);
    assert_eq!(s, "/dev/pts/0");

    // ttyname: fd=4 returns NULL
    cpu.set_reg(Reg::R0, 4);
    call_bionic(&mut bridge, BionicFuncId::Ttyname, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 0);

    // ttyname_r: success
    let buf_addr = GuestAddr::new(HEAP_START + 0x1000);
    cpu.set_reg(Reg::R0, 1);
    cpu.set_reg(Reg::R1, buf_addr.as_u32());
    cpu.set_reg(Reg::R2, 64);
    call_bionic(&mut bridge, BionicFuncId::TtynameR, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 0);
    let s = read_c_str(&mem, buf_addr);
    assert_eq!(s, "/dev/pts/0");

    // ttyname_r: ERANGE (buflen < 11)
    cpu.set_reg(Reg::R0, 1);
    cpu.set_reg(Reg::R1, buf_addr.as_u32());
    cpu.set_reg(Reg::R2, 5);
    call_bionic(&mut bridge, BionicFuncId::TtynameR, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 34); // ERANGE

    // ttyname_r: ENOTTY (fd > 2)
    cpu.set_reg(Reg::R0, 10);
    cpu.set_reg(Reg::R1, buf_addr.as_u32());
    cpu.set_reg(Reg::R2, 64);
    call_bionic(&mut bridge, BionicFuncId::TtynameR, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 25); // ENOTTY
}

#[test]
fn test_termios_and_baud_rates() {
    let (mut bridge, mut mem, mut cpu) = setup();
    let termios_addr = GuestAddr::new(HEAP_START + 0x2000);

    // tcgetattr
    cpu.set_reg(Reg::R0, 0);
    cpu.set_reg(Reg::R1, termios_addr.as_u32());
    call_bionic(&mut bridge, BionicFuncId::Tcgetattr, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 0);

    let iflag = mem.read_u32(termios_addr).unwrap();
    let oflag = mem.read_u32(termios_addr.add(4)).unwrap();
    let cflag = mem.read_u32(termios_addr.add(8)).unwrap();
    let lflag = mem.read_u32(termios_addr.add(12)).unwrap();
    assert_eq!(iflag, 0x0500);
    assert_eq!(oflag, 0x0005);
    assert_eq!(cflag, 0x00BF);
    assert_eq!(lflag, 0x8A3B);

    // cfgetospeed & cfgetispeed: default 0x0F (B38400)
    cpu.set_reg(Reg::R0, termios_addr.as_u32());
    call_bionic(&mut bridge, BionicFuncId::Cfgetospeed, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 0x000F);

    cpu.set_reg(Reg::R0, termios_addr.as_u32());
    call_bionic(&mut bridge, BionicFuncId::Cfgetispeed, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 0x000F);

    // cfsetospeed: set to 0x000D (B9600)
    cpu.set_reg(Reg::R0, termios_addr.as_u32());
    cpu.set_reg(Reg::R1, 0x000D);
    call_bionic(&mut bridge, BionicFuncId::Cfsetospeed, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 0);

    cpu.set_reg(Reg::R0, termios_addr.as_u32());
    call_bionic(&mut bridge, BionicFuncId::Cfgetospeed, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 0x000D);

    // cfsetispeed: set to 0x000E (B19200)
    cpu.set_reg(Reg::R0, termios_addr.as_u32());
    cpu.set_reg(Reg::R1, 0x000E);
    call_bionic(&mut bridge, BionicFuncId::Cfsetispeed, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 0);

    cpu.set_reg(Reg::R0, termios_addr.as_u32());
    call_bionic(&mut bridge, BionicFuncId::Cfgetispeed, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 0x000E);

    // cfmakeraw
    cpu.set_reg(Reg::R0, termios_addr.as_u32());
    call_bionic(&mut bridge, BionicFuncId::Cfmakeraw, &mut cpu, &mut mem).unwrap();
    let raw_iflag = mem.read_u32(termios_addr).unwrap();
    let raw_oflag = mem.read_u32(termios_addr.add(4)).unwrap();
    let raw_lflag = mem.read_u32(termios_addr.add(12)).unwrap();
    assert_eq!(raw_iflag & 0x05FF, 0);
    assert_eq!(raw_oflag & 0x0001, 0);
    assert_eq!(raw_lflag & 0x804B, 0);

    // VTIME and VMIN
    let vtime = mem.read_u8(termios_addr.add(17 + 5)).unwrap();
    let vmin = mem.read_u8(termios_addr.add(17 + 6)).unwrap();
    assert_eq!(vtime, 0);
    assert_eq!(vmin, 1);

    // tcsetattr, tcflush, tcsendbreak, tcdrain, tcflow
    cpu.set_reg(Reg::R0, 0);
    cpu.set_reg(Reg::R1, 0);
    cpu.set_reg(Reg::R2, termios_addr.as_u32());
    call_bionic(&mut bridge, BionicFuncId::Tcsetattr, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 0);

    cpu.set_reg(Reg::R0, 0);
    cpu.set_reg(Reg::R1, 0);
    call_bionic(&mut bridge, BionicFuncId::Tcflush, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 0);

    cpu.set_reg(Reg::R0, 0);
    cpu.set_reg(Reg::R1, 0);
    call_bionic(&mut bridge, BionicFuncId::Tcsendbreak, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 0);

    cpu.set_reg(Reg::R0, 0);
    call_bionic(&mut bridge, BionicFuncId::Tcdrain, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 0);

    cpu.set_reg(Reg::R0, 0);
    cpu.set_reg(Reg::R1, 0);
    call_bionic(&mut bridge, BionicFuncId::Tcflow, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 0);
}

#[test]
fn test_ioctl_operations() {
    let (mut bridge, mut mem, mut cpu) = setup();
    let ioctl_buf = GuestAddr::new(HEAP_START + 0x3000);

    // TIOCGWINSZ (0x5413): returns ws_row=24, ws_col=80
    cpu.set_reg(Reg::R0, 0);
    cpu.set_reg(Reg::R1, 0x5413);
    cpu.set_reg(Reg::R2, ioctl_buf.as_u32());
    call_bionic(&mut bridge, BionicFuncId::Ioctl, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 0);

    let mut row_bytes = [0u8; 2];
    mem.read_bytes(ioctl_buf, &mut row_bytes).unwrap();
    let row = u16::from_le_bytes(row_bytes);

    let mut col_bytes = [0u8; 2];
    mem.read_bytes(ioctl_buf.add(2), &mut col_bytes).unwrap();
    let col = u16::from_le_bytes(col_bytes);

    assert_eq!(row, 24);
    assert_eq!(col, 80);

    // FIONREAD (0x541B): bytes available = 0
    cpu.set_reg(Reg::R0, 0);
    cpu.set_reg(Reg::R1, 0x541B);
    cpu.set_reg(Reg::R2, ioctl_buf.as_u32());
    call_bionic(&mut bridge, BionicFuncId::Ioctl, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 0);
    assert_eq!(mem.read_u32(ioctl_buf).unwrap(), 0);

    // TIOCSWINSZ (0x5414) & FIONBIO (0x5421)
    cpu.set_reg(Reg::R0, 0);
    cpu.set_reg(Reg::R1, 0x5414);
    cpu.set_reg(Reg::R2, ioctl_buf.as_u32());
    call_bionic(&mut bridge, BionicFuncId::Ioctl, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 0);

    cpu.set_reg(Reg::R0, 0);
    cpu.set_reg(Reg::R1, 0x5421);
    cpu.set_reg(Reg::R2, 1);
    call_bionic(&mut bridge, BionicFuncId::Ioctl, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 0);
}

#[test]
fn test_symbol_resolution() {
    let (bridge, _mem, _cpu) = setup();

    let symbols = [
        "isatty", "ttyname", "ttyname_r", "tcgetattr", "tcsetattr",
        "tcflush", "tcsendbreak", "tcdrain", "tcflow",
        "cfgetispeed", "cfgetospeed", "cfsetispeed", "cfsetospeed",
        "cfmakeraw", "ioctl",
    ];

    for sym in symbols {
        let addr = bridge.resolve(sym);
        assert!(addr.is_some(), "Symbol {} must be resolved", sym);
        assert_ne!(addr.unwrap().as_u32(), 0);
    }
}
