use walzer32_core::{CpuState, FlatMemory, GuestAddr, Reg};
use walzer32_elf::SymbolResolver;
use walzer32_bridge::{GlesBridge, GlesFuncId, GLES_SVC_MAGIC};

fn call_gles(
    bridge: &mut GlesBridge,
    func_id: GlesFuncId,
    cpu: &mut CpuState,
    mem: &mut FlatMemory,
) -> Result<bool, String> {
    let svc_imm = GLES_SVC_MAGIC | (func_id as u32);
    bridge
        .handle_svc(svc_imm, cpu, mem)
        .map_err(|e| format!("{:?}", e))
}

#[test]
fn test_gles1_fixed_function_pipeline_and_state() {
    let mut mem = FlatMemory::new(GuestAddr::new(0x7000_0000), 0x200_000);
    let mut gles = GlesBridge::new(
        GuestAddr::new(0x7000_0000),
        GuestAddr::new(0x7005_0000),
    );
    gles.install_stubs(&mut mem).unwrap();

    let mut cpu = CpuState::new();

    // 1. Verify symbol resolution for GLES 1.1 entry points
    let symbols = [
        "glMatrixMode",
        "glLoadIdentity",
        "glLoadMatrixf",
        "glPushMatrix",
        "glPopMatrix",
        "glOrthof",
        "glFrustumf",
        "glTranslatef",
        "glScalef",
        "glRotatef",
        "glEnableClientState",
        "glDisableClientState",
        "glVertexPointer",
        "glColorPointer",
        "glTexCoordPointer",
        "glNormalPointer",
        "glAlphaFunc",
        "glColor4f",
        "glColor4ub",
        "glClientActiveTexture",
        "glShadeModel",
        "glTexEnvf",
        "glLightf",
        "glMaterialf",
        "glFogf",
    ];

    for &name in &symbols {
        let addr = gles.resolve(name);
        assert!(addr.is_some(), "Symbol {} must resolve in GlesBridge!", name);
        assert!(addr.unwrap().as_u32() >= 0x7000_0000);
    }

    // 2. Test glMatrixMode (GL_PROJECTION = 0x1701)
    cpu.set_reg(Reg::R0, 0x1701);
    call_gles(&mut gles, GlesFuncId::GlMatrixMode, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 0);
    assert_eq!(gles.matrix_mode, 0x1701);

    // 3. Test glEnableClientState & glDisableClientState (GL_VERTEX_ARRAY = 0x8074)
    cpu.set_reg(Reg::R0, 0x8074);
    call_gles(&mut gles, GlesFuncId::GlEnableClientState, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 0);
    let flag = 1 << (0x8074 & 0x1F);
    assert_ne!(gles.client_states & flag, 0);

    cpu.set_reg(Reg::R0, 0x8074);
    call_gles(&mut gles, GlesFuncId::GlDisableClientState, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 0);
    assert_eq!(gles.client_states & flag, 0);

    // 4. Test glClientActiveTexture (GL_TEXTURE1 = 0x84C1)
    cpu.set_reg(Reg::R0, 0x84C1);
    call_gles(&mut gles, GlesFuncId::GlClientActiveTexture, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 0);
    assert_eq!(gles.client_active_texture, 0x84C1);

    // 5. Test fixed-function transforms & states return success
    call_gles(&mut gles, GlesFuncId::GlLoadIdentity, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 0);

    call_gles(&mut gles, GlesFuncId::GlPushMatrix, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 0);

    call_gles(&mut gles, GlesFuncId::GlPopMatrix, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 0);

    call_gles(&mut gles, GlesFuncId::GlAlphaFunc, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 0);

    call_gles(&mut gles, GlesFuncId::GlColor4f, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 0);
}
