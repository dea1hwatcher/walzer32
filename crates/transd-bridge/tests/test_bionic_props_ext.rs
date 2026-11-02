//! Stage 69 integration tests: Bionic System Properties & Runtime Extensions
//! Tests: __system_property_set, __system_property_area_init, __system_property_add,
//!        __system_property_update, __system_property_wait, __system_property_wait_any,
//!        __system_property_serial, __system_property_foreach,
//!        android_set_abort_message, android_get_abort_message

use transd_bridge::bionic::{BionicBridge, BionicFuncId, BIONIC_SVC_MAGIC};
use transd_core::{ArenaMemory, CpuState, GuestAddr, Memory, MemoryError, Reg};

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

    mem.commit_range(stub_base, 0x0001_0000).unwrap();
    mem.commit_range(heap_start, 0x0010_0000).unwrap();

    let bridge = BionicBridge::new(stub_base, heap_start, 512 * 1024);
    bridge.install_stubs(&mut mem).unwrap();
    let cpu = CpuState::new();
    (bridge, mem, cpu)
}

fn scratch(offset: u32) -> GuestAddr {
    GuestAddr::new(HEAP_START + 0x8000 + offset)
}

// ── System Property Set & Get ─────────────────────────────────────────────────

#[test]
fn test_system_property_set_and_get() {
    let (mut bridge, mut mem, mut cpu) = setup();

    let key_str = scratch(0x100);
    let val_str = scratch(0x130);
    let out_buf = scratch(0x160);

    mem.write_bytes(key_str, b"transd.test.key\0").unwrap();
    mem.write_bytes(val_str, b"hello_props\0").unwrap();

    // 1. __system_property_set("transd.test.key", "hello_props")
    cpu.set_reg(Reg::R0, key_str.as_u32());
    cpu.set_reg(Reg::R1, val_str.as_u32());
    call_bionic(&mut bridge, BionicFuncId::SystemPropertySet, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 0);

    // 2. __system_property_get("transd.test.key", out_buf)
    cpu.set_reg(Reg::R0, key_str.as_u32());
    cpu.set_reg(Reg::R1, out_buf.as_u32());
    call_bionic(&mut bridge, BionicFuncId::SystemPropertyGet, &mut cpu, &mut mem).unwrap();
    let len = cpu.reg(Reg::R0);
    assert_eq!(len, 11);

    let mut buf = [0u8; 12];
    mem.read_bytes(out_buf, &mut buf).unwrap();
    assert_eq!(&buf[..11], b"hello_props");
}

#[test]
fn test_system_property_find_and_update_and_serial() {
    let (mut bridge, mut mem, mut cpu) = setup();

    let key_str = scratch(0x200);
    let new_val_str = scratch(0x230);
    let name_out = scratch(0x260);
    let val_out = scratch(0x290);

    mem.write_bytes(key_str, b"ro.product.model\0").unwrap();
    mem.write_bytes(new_val_str, b"Transd Custom Device\0").unwrap();

    // 1. __system_property_find("ro.product.model")
    cpu.set_reg(Reg::R0, key_str.as_u32());
    call_bionic(&mut bridge, BionicFuncId::SystemPropertyFind, &mut cpu, &mut mem).unwrap();
    let pi_addr = cpu.reg(Reg::R0);
    assert_ne!(pi_addr, 0);

    // 2. __system_property_serial(pi_addr) -> initially 1
    cpu.set_reg(Reg::R0, pi_addr);
    call_bionic(&mut bridge, BionicFuncId::SystemPropertySerial, &mut cpu, &mut mem).unwrap();
    let serial1 = cpu.reg(Reg::R0);
    assert_eq!(serial1, 1);

    // 3. __system_property_update(pi_addr, "Transd Custom Device", 20)
    cpu.set_reg(Reg::R0, pi_addr);
    cpu.set_reg(Reg::R1, new_val_str.as_u32());
    cpu.set_reg(Reg::R2, 20);
    call_bionic(&mut bridge, BionicFuncId::SystemPropertyUpdate, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 0);

    // 4. __system_property_serial(pi_addr) -> now 2
    cpu.set_reg(Reg::R0, pi_addr);
    call_bionic(&mut bridge, BionicFuncId::SystemPropertySerial, &mut cpu, &mut mem).unwrap();
    let serial2 = cpu.reg(Reg::R0);
    assert_eq!(serial2, 2);

    // 5. __system_property_read(pi_addr, name_out, val_out)
    cpu.set_reg(Reg::R0, pi_addr);
    cpu.set_reg(Reg::R1, name_out.as_u32());
    cpu.set_reg(Reg::R2, val_out.as_u32());
    call_bionic(&mut bridge, BionicFuncId::SystemPropertyRead, &mut cpu, &mut mem).unwrap();
    let val_len = cpu.reg(Reg::R0);
    assert_eq!(val_len, 20);

    let mut read_name = [0u8; 16];
    mem.read_bytes(name_out, &mut read_name).unwrap();
    assert_eq!(&read_name[..16], b"ro.product.model");

    let mut read_val = [0u8; 20];
    mem.read_bytes(val_out, &mut read_val).unwrap();
    assert_eq!(&read_val[..20], b"Transd Custom Device");
}

#[test]
fn test_system_property_add_and_area_init_and_foreach() {
    let (mut bridge, mut mem, mut cpu) = setup();

    // 1. __system_property_area_init() -> returns 0
    call_bionic(&mut bridge, BionicFuncId::SystemPropertyAreaInit, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 0);

    // 2. __system_property_add("custom.prop", 11, "alpha_val", 9)
    let key_str = scratch(0x300);
    let val_str = scratch(0x330);
    mem.write_bytes(key_str, b"custom.prop\0").unwrap();
    mem.write_bytes(val_str, b"alpha_val\0").unwrap();

    cpu.set_reg(Reg::R0, key_str.as_u32());
    cpu.set_reg(Reg::R1, 11);
    cpu.set_reg(Reg::R2, val_str.as_u32());
    cpu.set_reg(Reg::R3, 9);
    call_bionic(&mut bridge, BionicFuncId::SystemPropertyAdd, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 0);

    // Read back via __system_property_get
    let out_buf = scratch(0x360);
    cpu.set_reg(Reg::R0, key_str.as_u32());
    cpu.set_reg(Reg::R1, out_buf.as_u32());
    call_bionic(&mut bridge, BionicFuncId::SystemPropertyGet, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 9);

    let mut buf = [0u8; 10];
    mem.read_bytes(out_buf, &mut buf).unwrap();
    assert_eq!(&buf[..9], b"alpha_val");

    // 3. __system_property_foreach() -> returns 0
    cpu.set_reg(Reg::R0, 0);
    cpu.set_reg(Reg::R1, 0);
    call_bionic(&mut bridge, BionicFuncId::SystemPropertyForeach, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 0);
}

#[test]
fn test_system_property_wait_and_wait_any() {
    let (mut bridge, mut mem, mut cpu) = setup();

    let seq_ptr = scratch(0x400);
    let new_seq_ptr = scratch(0x410);

    // 1. __system_property_wait_any(*seq = 10, *new_seq) -> *new_seq = 11, returns 1
    mem.write_u32(seq_ptr, 10).unwrap();
    mem.write_u32(new_seq_ptr, 0).unwrap();

    cpu.set_reg(Reg::R0, seq_ptr.as_u32());
    cpu.set_reg(Reg::R1, new_seq_ptr.as_u32());
    cpu.set_reg(Reg::R2, 0); // rel_timeout = NULL
    call_bionic(&mut bridge, BionicFuncId::SystemPropertyWaitAny, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 1);
    assert_eq!(mem.read_u32(new_seq_ptr).unwrap(), 11);

    // 2. __system_property_wait(pi = 0, *seq = 20, *new_seq) -> *new_seq = 21, returns 1
    mem.write_u32(seq_ptr, 20).unwrap();
    mem.write_u32(new_seq_ptr, 0).unwrap();

    cpu.set_reg(Reg::R0, 0); // pi = NULL
    cpu.set_reg(Reg::R1, seq_ptr.as_u32());
    cpu.set_reg(Reg::R2, new_seq_ptr.as_u32());
    cpu.set_reg(Reg::R3, 0); // rel_timeout = NULL
    call_bionic(&mut bridge, BionicFuncId::SystemPropertyWait, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 1);
    assert_eq!(mem.read_u32(new_seq_ptr).unwrap(), 21);
}

// ── android_set_abort_message & android_get_abort_message ─────────────────────

#[test]
fn test_android_abort_message_lifecycle() {
    let (mut bridge, mut mem, mut cpu) = setup();

    // 1. Before set, get returns 0
    call_bionic(&mut bridge, BionicFuncId::AndroidGetAbortMessage, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 0);
    assert!(bridge.abort_message.is_none());

    // 2. Set abort message
    let msg_str = scratch(0x500);
    mem.write_bytes(msg_str, b"fatal JNI exception in NativeEngine.init()\0").unwrap();

    cpu.set_reg(Reg::R0, msg_str.as_u32());
    call_bionic(&mut bridge, BionicFuncId::AndroidSetAbortMessage, &mut cpu, &mut mem).unwrap();

    assert_eq!(
        bridge.abort_message.as_deref(),
        Some("fatal JNI exception in NativeEngine.init()")
    );

    let last_log = bridge.logs.last().expect("abort log");
    assert_eq!(last_log.priority, 7); // ANDROID_LOG_FATAL
    assert_eq!(last_log.tag, "abort");
    assert_eq!(last_log.text, "fatal JNI exception in NativeEngine.init()");

    // 3. Get abort message returns pointer to abort_message_t
    call_bionic(&mut bridge, BionicFuncId::AndroidGetAbortMessage, &mut cpu, &mut mem).unwrap();
    let msg_ptr = GuestAddr::new(cpu.reg(Reg::R0));
    assert_ne!(msg_ptr.as_u32(), 0);

    let size = mem.read_u32(msg_ptr).unwrap();
    assert_eq!(size, 42); // string length

    let mut buf = [0u8; 42];
    mem.read_bytes(msg_ptr.add(4), &mut buf).unwrap();
    assert_eq!(&buf[..42], b"fatal JNI exception in NativeEngine.init()");
}
