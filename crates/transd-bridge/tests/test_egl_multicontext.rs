use transd_core::{CpuState, FlatMemory, GuestAddr, Memory, Reg};
use transd_bridge::{
    GlesBridge, GlesFuncId, SurfaceKind,
    EGL_BAD_PARAMETER, EGL_CONDITION_SATISFIED_KHR, EGL_DRAW, EGL_HEIGHT, EGL_NONE,
    EGL_READ, EGL_SIGNALED_KHR, EGL_SYNC_FENCE_KHR, EGL_SYNC_STATUS_KHR, EGL_TRUE,
    EGL_WIDTH, GL_RGBA, GL_TEXTURE_2D,
};

#[test]
fn test_egl_pbuffer_surface() {
    let mut mem = FlatMemory::new(GuestAddr::new(0x7000_0000), 0x100_000);
    let mut gles = GlesBridge::new(GuestAddr::new(0x7000_0000), GuestAddr::new(0x7005_0000));
    gles.install_stubs(&mut mem).unwrap();

    // Write attrib list at 0x7001_0000: [EGL_WIDTH, 512, EGL_HEIGHT, 256, EGL_NONE]
    let attrib_addr = GuestAddr::new(0x7001_0000);
    mem.write_u32(attrib_addr, EGL_WIDTH).unwrap();
    mem.write_u32(attrib_addr.add(4), 512).unwrap();
    mem.write_u32(attrib_addr.add(8), EGL_HEIGHT).unwrap();
    mem.write_u32(attrib_addr.add(12), 256).unwrap();
    mem.write_u32(attrib_addr.add(16), EGL_NONE).unwrap();

    let mut cpu = CpuState::default();
    cpu.set_reg(Reg::R0, 0x1000); // dpy
    cpu.set_reg(Reg::R1, 0x2001); // config
    cpu.set_reg(Reg::R2, attrib_addr.as_u32()); // attrib_list

    let handled = gles.handle_svc(
        transd_bridge::GLES_SVC_MAGIC | (GlesFuncId::EglCreatePbufferSurface as u32),
        &mut cpu,
        &mut mem,
    ).unwrap();
    assert!(handled);

    let pbuffer_id = cpu.reg(Reg::R0);
    assert_ne!(pbuffer_id, 0);

    let surface = gles.egl_surfaces.get(&pbuffer_id).unwrap();
    assert_eq!(surface.kind, SurfaceKind::Pbuffer);
    assert_eq!(surface.width, 512);
    assert_eq!(surface.height, 256);

    // Destroy surface
    cpu.set_reg(Reg::R0, 0x1000);
    cpu.set_reg(Reg::R1, pbuffer_id);
    let destroyed = gles.handle_svc(
        transd_bridge::GLES_SVC_MAGIC | (GlesFuncId::EglDestroySurface as u32),
        &mut cpu,
        &mut mem,
    ).unwrap();
    assert!(destroyed);
    assert_eq!(cpu.reg(Reg::R0), EGL_TRUE);
    assert!(!gles.egl_surfaces.contains_key(&pbuffer_id));
}

#[test]
fn test_egl_multithreaded_context_sharing_and_bindings() {
    let mut mem = FlatMemory::new(GuestAddr::new(0x7000_0000), 0x200_000);
    let mut gles = GlesBridge::new(GuestAddr::new(0x7000_0000), GuestAddr::new(0x7005_0000));
    gles.install_stubs(&mut mem).unwrap();

    // 1. Thread 1 (Main Render Thread): tls_ptr = 0x1000_0000
    let mut cpu_t1 = CpuState::default();
    cpu_t1.tls_ptr = 0x1000_0000;

    // Create Context 1 (share_context = 0)
    cpu_t1.set_reg(Reg::R0, 0x1000); // dpy
    cpu_t1.set_reg(Reg::R1, 0x2001); // config
    cpu_t1.set_reg(Reg::R2, 0);      // share_context = NULL
    cpu_t1.set_reg(Reg::R3, 0);      // attribs
    gles.handle_svc(
        transd_bridge::GLES_SVC_MAGIC | (GlesFuncId::EglCreateContext as u32),
        &mut cpu_t1,
        &mut mem,
    ).unwrap();
    let ctx1 = cpu_t1.reg(Reg::R0);

    // Create Window Surface 1
    cpu_t1.set_reg(Reg::R0, 0x1000);
    cpu_t1.set_reg(Reg::R1, 0x2001);
    cpu_t1.set_reg(Reg::R2, 0x3000_0001); // native window
    gles.handle_svc(
        transd_bridge::GLES_SVC_MAGIC | (GlesFuncId::EglCreateWindowSurface as u32),
        &mut cpu_t1,
        &mut mem,
    ).unwrap();
    let surf1 = cpu_t1.reg(Reg::R0);

    // Thread 1: eglMakeCurrent(dpy, surf1, surf1, ctx1)
    cpu_t1.set_reg(Reg::R0, 0x1000);
    cpu_t1.set_reg(Reg::R1, surf1);
    cpu_t1.set_reg(Reg::R2, surf1);
    cpu_t1.set_reg(Reg::R3, ctx1);
    gles.handle_svc(
        transd_bridge::GLES_SVC_MAGIC | (GlesFuncId::EglMakeCurrent as u32),
        &mut cpu_t1,
        &mut mem,
    ).unwrap();

    // 2. Thread 2 (Background Asset/Worker Thread): tls_ptr = 0x2000_0000
    let mut cpu_t2 = CpuState::default();
    cpu_t2.tls_ptr = 0x2000_0000;

    // Create Context 2 sharing with Context 1!
    cpu_t2.set_reg(Reg::R0, 0x1000);
    cpu_t2.set_reg(Reg::R1, 0x2001);
    cpu_t2.set_reg(Reg::R2, ctx1); // share_context = ctx1
    cpu_t2.set_reg(Reg::R3, 0);
    gles.handle_svc(
        transd_bridge::GLES_SVC_MAGIC | (GlesFuncId::EglCreateContext as u32),
        &mut cpu_t2,
        &mut mem,
    ).unwrap();
    let ctx2 = cpu_t2.reg(Reg::R0);
    assert_ne!(ctx1, ctx2);

    // Both contexts must share the exact same share_group_id
    let group1 = gles.egl_contexts.get(&ctx1).unwrap().share_group_id;
    let group2 = gles.egl_contexts.get(&ctx2).unwrap().share_group_id;
    assert_eq!(group1, group2, "Contexts must belong to the same share group");

    // Create Pbuffer Surface 2 for Thread 2
    cpu_t2.set_reg(Reg::R0, 0x1000);
    cpu_t2.set_reg(Reg::R1, 0x2001);
    cpu_t2.set_reg(Reg::R2, 0);
    gles.handle_svc(
        transd_bridge::GLES_SVC_MAGIC | (GlesFuncId::EglCreatePbufferSurface as u32),
        &mut cpu_t2,
        &mut mem,
    ).unwrap();
    let surf2 = cpu_t2.reg(Reg::R0);

    // Thread 2: eglMakeCurrent(dpy, surf2, surf2, ctx2)
    cpu_t2.set_reg(Reg::R0, 0x1000);
    cpu_t2.set_reg(Reg::R1, surf2);
    cpu_t2.set_reg(Reg::R2, surf2);
    cpu_t2.set_reg(Reg::R3, ctx2);
    gles.handle_svc(
        transd_bridge::GLES_SVC_MAGIC | (GlesFuncId::EglMakeCurrent as u32),
        &mut cpu_t2,
        &mut mem,
    ).unwrap();

    // 3. Verify Thread-Isolation of Current Context and Surface:
    // When queried from Thread 1:
    gles.handle_svc(
        transd_bridge::GLES_SVC_MAGIC | (GlesFuncId::EglGetCurrentContext as u32),
        &mut cpu_t1,
        &mut mem,
    ).unwrap();
    assert_eq!(cpu_t1.reg(Reg::R0), ctx1);

    cpu_t1.set_reg(Reg::R0, EGL_DRAW);
    gles.handle_svc(
        transd_bridge::GLES_SVC_MAGIC | (GlesFuncId::EglGetCurrentSurface as u32),
        &mut cpu_t1,
        &mut mem,
    ).unwrap();
    assert_eq!(cpu_t1.reg(Reg::R0), surf1);

    // When queried from Thread 2:
    gles.handle_svc(
        transd_bridge::GLES_SVC_MAGIC | (GlesFuncId::EglGetCurrentContext as u32),
        &mut cpu_t2,
        &mut mem,
    ).unwrap();
    assert_eq!(cpu_t2.reg(Reg::R0), ctx2);

    cpu_t2.set_reg(Reg::R0, EGL_READ);
    gles.handle_svc(
        transd_bridge::GLES_SVC_MAGIC | (GlesFuncId::EglGetCurrentSurface as u32),
        &mut cpu_t2,
        &mut mem,
    ).unwrap();
    assert_eq!(cpu_t2.reg(Reg::R0), surf2);

    // 4. Thread 2 releases its binding
    gles.handle_svc(
        transd_bridge::GLES_SVC_MAGIC | (GlesFuncId::EglReleaseThread as u32),
        &mut cpu_t2,
        &mut mem,
    ).unwrap();

    gles.handle_svc(
        transd_bridge::GLES_SVC_MAGIC | (GlesFuncId::EglGetCurrentContext as u32),
        &mut cpu_t2,
        &mut mem,
    ).unwrap();
    assert_eq!(cpu_t2.reg(Reg::R0), 0);

    // Thread 1 still maintains its context
    gles.handle_svc(
        transd_bridge::GLES_SVC_MAGIC | (GlesFuncId::EglGetCurrentContext as u32),
        &mut cpu_t1,
        &mut mem,
    ).unwrap();
    assert_eq!(cpu_t1.reg(Reg::R0), ctx1);
}

#[test]
fn test_shared_texture_upload_and_cross_context_visibility() {
    let mut mem = FlatMemory::new(GuestAddr::new(0x7000_0000), 0x200_000);
    let mut gles = GlesBridge::new(GuestAddr::new(0x7000_0000), GuestAddr::new(0x7005_0000));
    gles.install_stubs(&mut mem).unwrap();

    // Create Context 1 & Context 2 with shared group
    let mut cpu1 = CpuState::default();
    cpu1.tls_ptr = 0x1111_0000;
    cpu1.set_reg(Reg::R0, 0x1000);
    cpu1.set_reg(Reg::R1, 0x2001);
    cpu1.set_reg(Reg::R2, 0);
    cpu1.set_reg(Reg::R3, 0);
    gles.handle_svc(
        transd_bridge::GLES_SVC_MAGIC | (GlesFuncId::EglCreateContext as u32),
        &mut cpu1,
        &mut mem,
    ).unwrap();
    let ctx1 = cpu1.reg(Reg::R0);

    let mut cpu2 = CpuState::default();
    cpu2.tls_ptr = 0x2222_0000;
    cpu2.set_reg(Reg::R0, 0x1000);
    cpu2.set_reg(Reg::R1, 0x2001);
    cpu2.set_reg(Reg::R2, ctx1); // Shared with ctx1
    cpu2.set_reg(Reg::R3, 0);
    gles.handle_svc(
        transd_bridge::GLES_SVC_MAGIC | (GlesFuncId::EglCreateContext as u32),
        &mut cpu2,
        &mut mem,
    ).unwrap();
    let ctx2 = cpu2.reg(Reg::R0);

    // Thread 2 binds ctx2
    cpu2.set_reg(Reg::R0, 0x1000);
    cpu2.set_reg(Reg::R1, 100);
    cpu2.set_reg(Reg::R2, 100);
    cpu2.set_reg(Reg::R3, ctx2);
    gles.handle_svc(
        transd_bridge::GLES_SVC_MAGIC | (GlesFuncId::EglMakeCurrent as u32),
        &mut cpu2,
        &mut mem,
    ).unwrap();

    // Thread 2 generates textures
    let tex_ptr = GuestAddr::new(0x7002_0000);
    cpu2.set_reg(Reg::R0, 1);
    cpu2.set_reg(Reg::R1, tex_ptr.as_u32());
    gles.handle_svc(
        transd_bridge::GLES_SVC_MAGIC | (GlesFuncId::GlGenTextures as u32),
        &mut cpu2,
        &mut mem,
    ).unwrap();
    let tex_id = mem.read_u32(tex_ptr).unwrap();

    // Thread 2 binds texture
    cpu2.set_reg(Reg::R0, GL_TEXTURE_2D);
    cpu2.set_reg(Reg::R1, tex_id);
    gles.handle_svc(
        transd_bridge::GLES_SVC_MAGIC | (GlesFuncId::GlBindTexture as u32),
        &mut cpu2,
        &mut mem,
    ).unwrap();

    // Prepare 2x2 RGBA raw image data (16 bytes) at 0x7003_0000:
    // Pixel 0: Red, Pixel 1: Green, Pixel 2: Blue, Pixel 3: White
    let pixel_addr = GuestAddr::new(0x7003_0000);
    let raw_pixels: [u8; 16] = [
        255, 0, 0, 255,     // Red
        0, 255, 0, 255,     // Green
        0, 0, 255, 255,     // Blue
        255, 255, 255, 255, // White
    ];
    mem.write_bytes(pixel_addr, &raw_pixels).unwrap();

    // Thread 2 calls glTexImage2D(GL_TEXTURE_2D, 0, GL_RGBA, 2, 2, 0, GL_RGBA, GL_UNSIGNED_BYTE, pixel_addr)
    let sp = GuestAddr::new(0x7004_0000);
    cpu2.set_sp(sp.as_u32());
    // Stack arguments: height, border, format, type, pixels
    mem.write_u32(sp, 2).unwrap();                 // height
    mem.write_u32(sp.add(4), 0).unwrap();          // border
    mem.write_u32(sp.add(8), GL_RGBA).unwrap();    // format
    mem.write_u32(sp.add(12), 0x1401).unwrap();    // type = GL_UNSIGNED_BYTE
    mem.write_u32(sp.add(16), pixel_addr.as_u32()).unwrap(); // pixels

    cpu2.set_reg(Reg::R0, GL_TEXTURE_2D);
    cpu2.set_reg(Reg::R1, 0); // level
    cpu2.set_reg(Reg::R2, GL_RGBA); // internal format
    cpu2.set_reg(Reg::R3, 2); // width
    gles.handle_svc(
        transd_bridge::GLES_SVC_MAGIC | (GlesFuncId::GlTexImage2D as u32),
        &mut cpu2,
        &mut mem,
    ).unwrap();

    // Now verify that Context 1 (render thread) can see the uploaded texture in its shared group!
    let shared_tex = gles.get_shared_texture_for_context(ctx1, tex_id);
    assert!(shared_tex.is_some(), "Context 1 must see Context 2's texture");
    let tex = shared_tex.unwrap();
    assert_eq!(tex.width, 2);
    assert_eq!(tex.height, 2);
    assert_eq!(tex.format, GL_RGBA);
    assert_eq!(tex.data.as_ref().unwrap(), &raw_pixels);
}

#[test]
fn test_egl_khr_sync_fence_and_proc_address() {
    let mut mem = FlatMemory::new(GuestAddr::new(0x7000_0000), 0x200_000);
    let mut gles = GlesBridge::new(GuestAddr::new(0x7000_0000), GuestAddr::new(0x7005_0000));
    gles.install_stubs(&mut mem).unwrap();

    let mut cpu = CpuState::default();

    // 1. Test eglGetProcAddress for standard and extension functions
    let query_addr = GuestAddr::new(0x7001_0000);
    mem.write_bytes(query_addr, b"eglCreateSyncKHR\0").unwrap();
    cpu.set_reg(Reg::R0, query_addr.as_u32());
    gles.handle_svc(
        transd_bridge::GLES_SVC_MAGIC | (GlesFuncId::EglGetProcAddress as u32),
        &mut cpu,
        &mut mem,
    ).unwrap();
    let proc_addr = cpu.reg(Reg::R0);
    assert_ne!(proc_addr, 0, "eglCreateSyncKHR must resolve via eglGetProcAddress");

    // Invalid proc name returns 0
    let invalid_addr = GuestAddr::new(0x7001_0050);
    mem.write_bytes(invalid_addr, b"nonExistentGlExt\0").unwrap();
    cpu.set_reg(Reg::R0, invalid_addr.as_u32());
    gles.handle_svc(
        transd_bridge::GLES_SVC_MAGIC | (GlesFuncId::EglGetProcAddress as u32),
        &mut cpu,
        &mut mem,
    ).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 0);

    // 2. Test eglCreateSyncKHR
    cpu.set_reg(Reg::R0, 0x1000); // dpy
    cpu.set_reg(Reg::R1, EGL_SYNC_FENCE_KHR);
    cpu.set_reg(Reg::R2, 0); // attrib_list
    gles.handle_svc(
        transd_bridge::GLES_SVC_MAGIC | (GlesFuncId::EglCreateSyncKHR as u32),
        &mut cpu,
        &mut mem,
    ).unwrap();
    let sync_id = cpu.reg(Reg::R0);
    assert_ne!(sync_id, 0);

    // 3. Test eglGetSyncAttribKHR
    let status_out = GuestAddr::new(0x7001_0100);
    cpu.set_reg(Reg::R0, 0x1000);
    cpu.set_reg(Reg::R1, sync_id);
    cpu.set_reg(Reg::R2, EGL_SYNC_STATUS_KHR);
    cpu.set_reg(Reg::R3, status_out.as_u32());
    gles.handle_svc(
        transd_bridge::GLES_SVC_MAGIC | (GlesFuncId::EglGetSyncAttribKHR as u32),
        &mut cpu,
        &mut mem,
    ).unwrap();
    assert_eq!(cpu.reg(Reg::R0), EGL_TRUE);
    assert_eq!(mem.read_u32(status_out).unwrap(), EGL_SIGNALED_KHR);

    // 4. Test eglClientWaitSyncKHR
    cpu.set_reg(Reg::R0, 0x1000);
    cpu.set_reg(Reg::R1, sync_id);
    cpu.set_reg(Reg::R2, 0); // flags
    cpu.set_reg(Reg::R3, 1000); // timeout
    gles.handle_svc(
        transd_bridge::GLES_SVC_MAGIC | (GlesFuncId::EglClientWaitSyncKHR as u32),
        &mut cpu,
        &mut mem,
    ).unwrap();
    assert_eq!(cpu.reg(Reg::R0), EGL_CONDITION_SATISFIED_KHR);

    // 5. Test eglDestroySyncKHR
    cpu.set_reg(Reg::R0, 0x1000);
    cpu.set_reg(Reg::R1, sync_id);
    gles.handle_svc(
        transd_bridge::GLES_SVC_MAGIC | (GlesFuncId::EglDestroySyncKHR as u32),
        &mut cpu,
        &mut mem,
    ).unwrap();
    assert_eq!(cpu.reg(Reg::R0), EGL_TRUE);

    // Subsequent wait fails with EGL_BAD_PARAMETER
    cpu.set_reg(Reg::R0, 0x1000);
    cpu.set_reg(Reg::R1, sync_id);
    gles.handle_svc(
        transd_bridge::GLES_SVC_MAGIC | (GlesFuncId::EglClientWaitSyncKHR as u32),
        &mut cpu,
        &mut mem,
    ).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 0);
    assert_eq!(gles.last_egl_error, EGL_BAD_PARAMETER);
}
