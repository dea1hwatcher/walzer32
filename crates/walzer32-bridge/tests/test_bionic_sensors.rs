//! Stage 97 integration tests: Android Motion & Environmental Sensors NDK Subsystem
//! Tests: ASensorManager_getInstance, ASensorManager_getInstanceForPackage,
//!        ASensorManager_getSensorList, ASensorManager_getDefaultSensor,
//!        ASensorManager_getDefaultSensorEx, ASensorManager_createEventQueue,
//!        ASensorManager_destroyEventQueue, ASensorEventQueue_enableSensor,
//!        ASensorEventQueue_disableSensor, ASensorEventQueue_setEventRate,
//!        ASensorEventQueue_hasEvents, ASensorEventQueue_getEvents,
//!        ASensor_getName, ASensor_getVendor, ASensor_getType,
//!        ASensor_getResolution, ASensor_getMinDelay

use walzer32_bridge::bionic::{BionicBridge, BionicFuncId, BIONIC_SVC_MAGIC};
use walzer32_core::{ArenaMemory, CpuState, GuestAddr, Memory, MemoryError, Reg};
use walzer32_elf::loader::SymbolResolver;

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

#[test]
fn test_sensor_symbols() {
    let (bridge, _mem, _cpu) = setup();

    let symbols = [
        "ASensorManager_getInstance",
        "ASensorManager_getInstanceForPackage",
        "ASensorManager_getSensorList",
        "ASensorManager_getDefaultSensor",
        "ASensorManager_getDefaultSensorEx",
        "ASensorManager_createEventQueue",
        "ASensorManager_destroyEventQueue",
        "ASensorEventQueue_enableSensor",
        "ASensorEventQueue_disableSensor",
        "ASensorEventQueue_setEventRate",
        "ASensorEventQueue_hasEvents",
        "ASensorEventQueue_getEvents",
        "ASensor_getName",
        "ASensor_getVendor",
        "ASensor_getType",
        "ASensor_getResolution",
        "ASensor_getMinDelay",
    ];

    for sym in symbols {
        assert!(
            bridge.resolve(sym).is_some(),
            "Symbol {} not resolved by BionicBridge",
            sym
        );
    }
}

#[test]
fn test_sensor_manager_and_sensor_properties() {
    let (mut bridge, mut mem, mut cpu) = setup();

    // 1. ASensorManager_getInstance()
    call_bionic(&mut bridge, BionicFuncId::ASensorManagerGetInstance, &mut cpu, &mut mem).unwrap();
    let mgr = cpu.reg(Reg::R0);
    assert_ne!(mgr, 0);

    // 2. ASensorManager_getSensorList(mgr, &list_ptr)
    let list_ptr_addr = GuestAddr::new(HEAP_START + 0x0100);
    cpu.set_reg(Reg::R0, mgr);
    cpu.set_reg(Reg::R1, list_ptr_addr.as_u32());
    call_bionic(&mut bridge, BionicFuncId::ASensorManagerGetSensorList, &mut cpu, &mut mem).unwrap();
    let count = cpu.reg(Reg::R0) as usize;
    assert_eq!(count, 5);

    let list_array = GuestAddr::new(mem.read_u32(list_ptr_addr).unwrap());
    assert_ne!(list_array.as_u32(), 0);

    // 3. ASensorManager_getDefaultSensor(mgr, type = 1: ACCELEROMETER)
    cpu.set_reg(Reg::R0, mgr);
    cpu.set_reg(Reg::R1, 1);
    call_bionic(&mut bridge, BionicFuncId::ASensorManagerGetDefaultSensor, &mut cpu, &mut mem).unwrap();
    let accel = cpu.reg(Reg::R0);
    assert_ne!(accel, 0);

    // ASensor_getType(accel) -> 1
    cpu.set_reg(Reg::R0, accel);
    call_bionic(&mut bridge, BionicFuncId::ASensorGetType, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 1);

    // ASensor_getName(accel) -> "Virtual Accelerometer"
    cpu.set_reg(Reg::R0, accel);
    call_bionic(&mut bridge, BionicFuncId::ASensorGetName, &mut cpu, &mut mem).unwrap();
    let name_ptr = GuestAddr::new(cpu.reg(Reg::R0));
    let mut name_buf = [0u8; 21];
    mem.read_bytes(name_ptr, &mut name_buf).unwrap();
    assert_eq!(&name_buf, b"Virtual Accelerometer");

    // ASensor_getVendor(accel) -> "walzer32"
    cpu.set_reg(Reg::R0, accel);
    call_bionic(&mut bridge, BionicFuncId::ASensorGetVendor, &mut cpu, &mut mem).unwrap();
    let vendor_ptr = GuestAddr::new(cpu.reg(Reg::R0));
    let mut vendor_buf = [0u8; 8];
    mem.read_bytes(vendor_ptr, &mut vendor_buf).unwrap();
    assert_eq!(&vendor_buf, b"walzer32");

    // ASensor_getResolution(accel) -> 0.001
    cpu.set_reg(Reg::R0, accel);
    call_bionic(&mut bridge, BionicFuncId::ASensorGetResolution, &mut cpu, &mut mem).unwrap();
    let res = f32::from_bits(cpu.reg(Reg::R0));
    assert!((res - 0.001).abs() < 1e-6);

    // ASensor_getMinDelay(accel) -> 10000 us
    cpu.set_reg(Reg::R0, accel);
    call_bionic(&mut bridge, BionicFuncId::ASensorGetMinDelay, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 10000);

    // 4. Default sensor for non-existent type (999) -> NULL
    cpu.set_reg(Reg::R0, mgr);
    cpu.set_reg(Reg::R1, 999);
    call_bionic(&mut bridge, BionicFuncId::ASensorManagerGetDefaultSensor, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 0);
}

#[test]
fn test_sensor_event_queue_lifecycle_and_events() {
    let (mut bridge, mut mem, mut cpu) = setup();

    // 1. ASensorManager_getInstance()
    call_bionic(&mut bridge, BionicFuncId::ASensorManagerGetInstance, &mut cpu, &mut mem).unwrap();
    let mgr = cpu.reg(Reg::R0);

    // 2. ASensorManager_createEventQueue(mgr, looper=1, ident=10, cb=NULL, data=NULL)
    cpu.set_reg(Reg::R0, mgr);
    cpu.set_reg(Reg::R1, 1);
    cpu.set_reg(Reg::R2, 10);
    cpu.set_reg(Reg::R3, 0);
    call_bionic(&mut bridge, BionicFuncId::ASensorManagerCreateEventQueue, &mut cpu, &mut mem).unwrap();
    let queue = cpu.reg(Reg::R0);
    assert_ne!(queue, 0);

    // 3. Initially hasEvents is 0
    cpu.set_reg(Reg::R0, queue);
    call_bionic(&mut bridge, BionicFuncId::ASensorEventQueueHasEvents, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 0);

    // 4. Get default accelerometer sensor
    cpu.set_reg(Reg::R0, mgr);
    cpu.set_reg(Reg::R1, 1); // ASENSOR_TYPE_ACCELEROMETER
    call_bionic(&mut bridge, BionicFuncId::ASensorManagerGetDefaultSensor, &mut cpu, &mut mem).unwrap();
    let accel = cpu.reg(Reg::R0);

    // 5. ASensorEventQueue_enableSensor(queue, accel)
    cpu.set_reg(Reg::R0, queue);
    cpu.set_reg(Reg::R1, accel);
    call_bionic(&mut bridge, BionicFuncId::ASensorEventQueueEnableSensor, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 0);

    // 6. ASensorEventQueue_setEventRate(queue, accel, usec=20000)
    cpu.set_reg(Reg::R0, queue);
    cpu.set_reg(Reg::R1, accel);
    cpu.set_reg(Reg::R2, 20000);
    call_bionic(&mut bridge, BionicFuncId::ASensorEventQueueSetEventRate, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 0);

    // 7. Push a simulated sensor reading into bridge: gravity 9.81 on Y axis
    let delivered = bridge.push_sensor_event(1, [0.0, 9.81, 0.0], 1_500_000_000);
    assert_eq!(delivered, 1);

    // 8. ASensorEventQueue_hasEvents(queue) -> returns 1
    cpu.set_reg(Reg::R0, queue);
    call_bionic(&mut bridge, BionicFuncId::ASensorEventQueueHasEvents, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 1);

    // 9. ASensorEventQueue_getEvents(queue, events_buf, count=1)
    let ev_buf = GuestAddr::new(HEAP_START + 0x0200);
    cpu.set_reg(Reg::R0, queue);
    cpu.set_reg(Reg::R1, ev_buf.as_u32());
    cpu.set_reg(Reg::R2, 1);
    call_bionic(&mut bridge, BionicFuncId::ASensorEventQueueGetEvents, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 1); // 1 event received

    // Verify fields of ASensorEvent:
    let ev_version = mem.read_u32(ev_buf).unwrap();
    let ev_sensor = mem.read_u32(ev_buf.add(4)).unwrap();
    let ev_type = mem.read_u32(ev_buf.add(8)).unwrap();
    let ts_low = mem.read_u32(ev_buf.add(16)).unwrap() as u64;
    let ts_high = mem.read_u32(ev_buf.add(20)).unwrap() as u64;
    let timestamp = (ts_low | (ts_high << 32)) as i64;

    let x = f32::from_bits(mem.read_u32(ev_buf.add(24)).unwrap());
    let y = f32::from_bits(mem.read_u32(ev_buf.add(28)).unwrap());
    let z = f32::from_bits(mem.read_u32(ev_buf.add(32)).unwrap());

    assert_eq!(ev_version, 104);
    assert_eq!(ev_sensor, 1);
    assert_eq!(ev_type, 1);
    assert_eq!(timestamp, 1_500_000_000);
    assert!((x - 0.0).abs() < 1e-6);
    assert!((y - 9.81).abs() < 1e-5);
    assert!((z - 0.0).abs() < 1e-6);

    // 10. Queue is now empty
    cpu.set_reg(Reg::R0, queue);
    call_bionic(&mut bridge, BionicFuncId::ASensorEventQueueHasEvents, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 0);

    // 11. Disable sensor
    cpu.set_reg(Reg::R0, queue);
    cpu.set_reg(Reg::R1, accel);
    call_bionic(&mut bridge, BionicFuncId::ASensorEventQueueDisableSensor, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 0);

    // Push event while disabled -> not delivered
    let delivered_disabled = bridge.push_sensor_event(1, [0.0, 9.81, 0.0], 2_000_000_000);
    assert_eq!(delivered_disabled, 0);

    // 12. Destroy event queue
    cpu.set_reg(Reg::R0, mgr);
    cpu.set_reg(Reg::R1, queue);
    call_bionic(&mut bridge, BionicFuncId::ASensorManagerDestroyEventQueue, &mut cpu, &mut mem).unwrap();
    assert_eq!(cpu.reg(Reg::R0), 0);
    assert!(bridge.sensor_queues.get(&queue).is_none());
}
