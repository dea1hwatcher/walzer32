use walzer32_core::{GuestAddr, Memory};

#[test]
fn test_inspect_gsarray_init() {
    let lib_path = if std::path::Path::new("test_libs/libfoundation.so").exists() {
        "test_libs/libfoundation.so"
    } else if std::path::Path::new("../../test_libs/libfoundation.so").exists() {
        "../../test_libs/libfoundation.so"
    } else {
        eprintln!("Skipping test: test_libs/libfoundation.so not found");
        return;
    };
    let bytes = std::fs::read(lib_path).expect("read foundation");
    let base = GuestAddr::new(0x7100_0000);
    let mut mem = walzer32_core::FlatMemory::new(base, 0x100_0000);
    mem.write_bytes(base, &bytes).expect("write bytes");

    let mut pc = base.add(0x102fc0);
    let end_pc = base.add(0x103118);
    while pc < end_pc {
        let block = match walzer32_ir::Lifter::lift_block(&mem, pc, true) {
            Ok(b) => b,
            Err(e) => {
                println!("Lift err at 0x{:08x}: {:?}", pc.as_u32(), e);
                break;
            }
        };
        println!("\n=== BLOCK AT 0x{:08x} (offset 0x{:x}, {} insts, exit={:?}) ===",
            pc.as_u32(), pc.as_u32() - base.as_u32(), block.insts.len(), block.exit);
        for (i, inst) in block.insts.iter().enumerate() {
            let ipc = block.inst_pc(i);
            println!("  pc=0x{:08x} cond={:?} => {:?}", ipc.as_u32(), inst.cond, inst.op);
        }
        if block.byte_size == 0 {
            pc = pc.add(2);
        } else {
            pc = pc.add(block.byte_size as u32);
        }
    }
}