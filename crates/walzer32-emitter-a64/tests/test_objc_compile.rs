use std::fs;
use walzer32_core::{FlatMemory, GuestAddr, Memory};
use walzer32_emitter_a64::A64Compiler;
use walzer32_ir::Lifter;

#[test]
fn test_compile_objc_skip_typespec_b17e() {
    let data = match fs::read("../../test_libs/libobjc.so").or_else(|_| fs::read("test_libs/libobjc.so")) {
        Ok(d) => d,
        Err(_) => {
            eprintln!("Skipping test: test_libs/libobjc.so not found");
            return;
        }
    };
    let base = 0x7112_0000u32;
    let mut mem = FlatMemory::new(GuestAddr::new(base), data.len() + 0x1000);
    mem.write_bytes(GuestAddr::new(base), &data).expect("write bytes");

    let entry = GuestAddr::new(base + 0xb17e);
    let block = Lifter::lift_block(&mem, entry, true).expect("lift block");
    println!("\n=== Block at 0x{:08x} ===", entry.as_u32());
    for (i, inst) in block.insts.iter().enumerate() {
        println!("  [{}] {:?}", i, inst.op);
    }
    println!("Exit: {:?}", block.exit);

    let compiled = A64Compiler::compile(&block);
    print!("COMPILED_HEX_B17E:");
    for b in &compiled.code_bytes {
        print!("{:02x}", b);
    }
    println!();
}
