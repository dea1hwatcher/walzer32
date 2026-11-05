use std::time::Duration;
use walzer32_core::GuestAddr;
use walzer32_android::Walzer32Session;

#[test]
fn test_session_enable_and_flush_async_jit() {
    let mut session = Walzer32Session::new(GuestAddr::new(0x7000_0000), 0x200_0000).unwrap();

    // Enable background asynchronous JIT with 2 worker threads
    session.enable_async_jit(2);

    assert!(session.async_jit_stats().is_some());
    let stats = session.async_jit_stats().unwrap();
    assert_eq!(stats.worker_count, 2);

    // Flush async JIT (empty queue should return immediately)
    let promoted = session.flush_async_jit(Duration::from_millis(50));
    assert_eq!(promoted, 0);

    // Disable async JIT
    session.disable_async_jit();
    assert!(session.async_jit_stats().is_none());
}
