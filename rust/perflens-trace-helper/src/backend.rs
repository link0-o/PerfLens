//! Fixed libbpf backend for target-filtered scheduler and lock trace events.
//!
//! All libbpf calls and the ring-buffer callback are isolated in this module.  No caller can
//! provide BPF bytes, program names, tracepoints, map names, output paths, or attach scope.

#![allow(unsafe_code)]

use std::ffi::{CStr, CString, c_char, c_int, c_long, c_void};
use std::fs;
use std::io;
use std::mem::size_of;
use std::path::Path;
use std::ptr::{self, NonNull};
use std::time::{Duration, Instant};

use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::{TraceHelperTarget, TraceMode};

const SCHED_BPF_OBJECT: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/perflens_sched.bpf.o"));
const LOCK_BPF_OBJECT: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/perflens_lock.bpf.o"));
const BPF_ANY: u64 = 0;
const COUNTER_LOST_KEY: u32 = 1;
const RELATED_EXTERNAL_REDACTED: u32 = 1;

const SCHED_ATTACHMENTS: &[Attachment] = &[
    Attachment::raw("perflens_sched_process_fork", "sched_process_fork"),
    Attachment::tracepoint("perflens_sched_process_exit", "sched", "sched_process_exit"),
    Attachment::tracepoint("perflens_sched_switch", "sched", "sched_switch"),
    Attachment::tracepoint("perflens_sched_waking", "sched", "sched_waking"),
    Attachment::tracepoint("perflens_sched_wakeup", "sched", "sched_wakeup"),
    Attachment::tracepoint("perflens_sched_wakeup_new", "sched", "sched_wakeup_new"),
    Attachment::tracepoint("perflens_sched_migrate", "sched", "sched_migrate_task"),
];

const LOCK_ATTACHMENTS: &[Attachment] = &[
    Attachment::raw("perflens_lock_process_fork", "sched_process_fork"),
    Attachment::tracepoint("perflens_lock_process_exit", "sched", "sched_process_exit"),
    Attachment::tracepoint("perflens_lock_contention_begin", "lock", "contention_begin"),
    Attachment::tracepoint("perflens_lock_contention_end", "lock", "contention_end"),
    Attachment::tracepoint("perflens_sys_enter_futex", "syscalls", "sys_enter_futex"),
];

#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct RawEvent {
    timestamp_ns: u64,
    sequence: u64,
    object_address: u64,
    value: i64,
    kind: u32,
    cpu: u32,
    target_tid: u32,
    related_target_tid: u32,
    flags: u32,
    reserved: u32,
}

#[repr(C)]
struct TargetConfig {
    target_tgid: u32,
    target_uid: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct NormalizedKernelEvent {
    pub schema_version: &'static str,
    pub sequence: u64,
    pub timestamp_ns: u64,
    pub cpu: u32,
    pub kind: &'static str,
    pub target_tid: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub related_target_tid: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub related_scope: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub previous_state: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target_cpu: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub origin_cpu: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub destination_cpu: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lock_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lock_flags: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub wait_result: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub futex_operation: Option<&'static str>,
}

#[derive(Debug)]
pub struct CaptureOutput {
    pub events: Vec<NormalizedKernelEvent>,
    pub lost_event_count: u64,
    pub truncated: bool,
    pub started_at_monotonic_nanoseconds: u64,
    pub finished_at_monotonic_nanoseconds: u64,
}

pub fn probe(mode: TraceMode) -> bool {
    let (object_bytes, attachments) = match mode {
        TraceMode::Sched | TraceMode::OffCpu => (SCHED_BPF_OBJECT, SCHED_ATTACHMENTS),
        TraceMode::Lock => (LOCK_BPF_OBJECT, LOCK_ATTACHMENTS),
    };
    let Ok(object) = Object::open_and_load(object_bytes) else {
        return false;
    };
    let mut links = Vec::with_capacity(attachments.len());
    for attachment in attachments {
        let Ok(link) = object.attach(attachment) else {
            return false;
        };
        links.push(link);
    }
    true
}

pub fn capture(
    mode: TraceMode,
    target: &TraceHelperTarget,
    duration: Duration,
    max_output_bytes: u64,
    lock_identity_key: &[u8; 32],
) -> io::Result<CaptureOutput> {
    let object_bytes = match mode {
        TraceMode::Sched | TraceMode::OffCpu => SCHED_BPF_OBJECT,
        TraceMode::Lock => LOCK_BPF_OBJECT,
    };
    let attachments = match mode {
        TraceMode::Sched | TraceMode::OffCpu => SCHED_ATTACHMENTS,
        TraceMode::Lock => LOCK_ATTACHMENTS,
    };
    let object = Object::open_and_load(object_bytes)?;
    object.configure_target(target)?;

    let mut links = Vec::with_capacity(attachments.len());
    // Fork tracking is attached before the /proc snapshot.  Threads that already exist appear in
    // the snapshot, while threads created after this point are inserted by the kernel program.
    links.push(object.attach(&attachments[0])?);
    let initial_tids = enumerate_target_tids(target)?;
    for tid in &initial_tids {
        object.add_target_tid(*tid)?;
    }
    for attachment in &attachments[1..] {
        links.push(object.attach(attachment)?);
    }

    let max_raw_events = usize::try_from(max_output_bytes / size_of::<RawEvent>() as u64)
        .unwrap_or(usize::MAX)
        .max(1);
    let mut callback = RingEventContext {
        events: Vec::with_capacity(max_raw_events.min(65_536)),
        max_events: max_raw_events,
        truncated: false,
    };
    let mut ring = object.ring_buffer(&mut callback)?;
    let start = monotonic_nanoseconds()?;
    let deadline = Instant::now() + duration;
    while Instant::now() < deadline {
        let remaining = deadline.saturating_duration_since(Instant::now());
        let timeout = i32::try_from(remaining.as_millis().clamp(1, 100)).unwrap_or(100);
        ring.poll(timeout)?;
    }
    let finish = monotonic_nanoseconds()?;
    drop(ring);
    drop(links);
    assert_target_identity(target)?;

    callback
        .events
        .sort_unstable_by_key(|event| (event.timestamp_ns, event.sequence));
    let mut events = Vec::with_capacity(callback.events.len());
    for (sequence, raw) in callback.events.into_iter().enumerate() {
        events.push(normalize_event(
            raw,
            u64::try_from(sequence).unwrap_or(u64::MAX),
            lock_identity_key,
        )?);
    }
    Ok(CaptureOutput {
        events,
        lost_event_count: object.lost_event_count()?,
        truncated: callback.truncated,
        started_at_monotonic_nanoseconds: start,
        finished_at_monotonic_nanoseconds: finish,
    })
}

fn normalize_event(
    raw: RawEvent,
    sequence: u64,
    lock_identity_key: &[u8; 32],
) -> io::Result<NormalizedKernelEvent> {
    if raw.reserved != 0 || raw.target_tid == 0 {
        return Err(invalid_data("kernel trace event violates its fixed layout"));
    }
    let related_scope = if raw.related_target_tid != 0 {
        Some("target")
    } else if raw.flags & RELATED_EXTERNAL_REDACTED != 0 {
        Some("external_redacted")
    } else {
        None
    };
    let mut event = NormalizedKernelEvent {
        schema_version: "1.0",
        sequence,
        timestamp_ns: raw.timestamp_ns,
        cpu: raw.cpu,
        kind: "",
        target_tid: raw.target_tid,
        related_target_tid: (raw.related_target_tid != 0).then_some(raw.related_target_tid),
        related_scope,
        previous_state: None,
        target_cpu: None,
        origin_cpu: None,
        destination_cpu: None,
        lock_id: None,
        lock_flags: None,
        wait_result: None,
        futex_operation: None,
    };
    match raw.kind {
        1 => {
            event.kind = "sched_switch_out";
            event.previous_state = Some(raw.value);
        }
        2 => event.kind = "sched_switch_in",
        3 => {
            event.kind = "sched_switch_both";
            event.previous_state = Some(raw.value);
        }
        4 => {
            event.kind = "sched_waking";
            event.target_cpu = u32::try_from(raw.value).ok();
        }
        5 => {
            event.kind = "sched_wakeup";
            event.target_cpu = u32::try_from(raw.value).ok();
        }
        6 => {
            event.kind = "sched_wakeup_new";
            event.target_cpu = u32::try_from(raw.value).ok();
        }
        7 => {
            event.kind = "sched_migrate";
            event.origin_cpu = Some((raw.value.cast_unsigned() >> 32) as u32);
            event.destination_cpu = Some(
                u32::try_from(raw.value.cast_unsigned() & u64::from(u32::MAX))
                    .expect("masked destination CPU fits u32"),
            );
        }
        20 => {
            event.kind = "lock_wait";
            event.lock_id = Some(private_lock_id(lock_identity_key, raw.object_address));
            event.lock_flags = Some(raw.flags);
        }
        21 => {
            event.kind = "lock_wait_ended";
            event.lock_id = Some(private_lock_id(lock_identity_key, raw.object_address));
            event.wait_result = Some(raw.value);
        }
        22 | 23 => {
            event.kind = if raw.kind == 22 {
                "futex_wait"
            } else {
                "futex_wake"
            };
            event.lock_id = Some(private_lock_id(lock_identity_key, raw.object_address));
            event.futex_operation = Some(match raw.flags {
                0 => "wait",
                1 => "wake",
                3 => "requeue",
                9 => "wait_bitset",
                10 => "wake_bitset",
                11 => "wait_requeue_pi",
                _ => {
                    return Err(invalid_data(
                        "kernel trace futex operation is not allowlisted",
                    ));
                }
            });
        }
        _ => return Err(invalid_data("kernel trace event kind is not allowlisted")),
    }
    Ok(event)
}

fn private_lock_id(key: &[u8; 32], address: u64) -> String {
    let mut inner_key = [0x36_u8; 64];
    let mut outer_key = [0x5c_u8; 64];
    for (index, byte) in key.iter().enumerate() {
        inner_key[index] ^= byte;
        outer_key[index] ^= byte;
    }
    let mut inner = Sha256::new();
    inner.update(inner_key);
    inner.update(address.to_be_bytes());
    let inner_digest = inner.finalize();
    let mut outer = Sha256::new();
    outer.update(outer_key);
    outer.update(inner_digest);
    let digest = outer.finalize();
    format!("lock-{}", hex_prefix(&digest, 20))
}

fn hex_prefix(bytes: &[u8], characters: usize) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(characters);
    for byte in bytes.iter().take(characters.div_ceil(2)) {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        if output.len() < characters {
            output.push(char::from(HEX[usize::from(byte & 0x0f)]));
        }
    }
    output
}

fn enumerate_target_tids(target: &TraceHelperTarget) -> io::Result<Vec<u32>> {
    assert_target_identity(target)?;
    let mut tids = Vec::new();
    for entry in fs::read_dir(Path::new("/proc").join(target.pid.to_string()).join("task"))? {
        let name = entry?.file_name();
        let Some(name) = name.to_str() else {
            return Err(invalid_data(
                "target task directory contains a non-UTF-8 name",
            ));
        };
        let tid = name
            .parse::<u32>()
            .map_err(|_error| invalid_data("target task directory contains an invalid TID"))?;
        if tid == 0 || tid > i32::MAX.cast_unsigned() {
            return Err(invalid_data(
                "target task directory contains an invalid TID",
            ));
        }
        tids.push(tid);
    }
    tids.sort_unstable();
    tids.dedup();
    if tids.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            "target has no tasks",
        ));
    }
    assert_target_identity(target)?;
    Ok(tids)
}

fn assert_target_identity(target: &TraceHelperTarget) -> io::Result<()> {
    crate::assert_pid_identity(target)
}

fn monotonic_nanoseconds() -> io::Result<u64> {
    let mut timestamp = libc_timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: `timestamp` is a valid writable timespec and CLOCK_MONOTONIC requires no borrowed
    // memory.  The return value is checked before either initialized field is consumed.
    let result = unsafe { clock_gettime(CLOCK_MONOTONIC, &raw mut timestamp) };
    if result != 0 {
        return Err(io::Error::last_os_error());
    }
    let seconds = u64::try_from(timestamp.tv_sec)
        .map_err(|_error| invalid_data("monotonic clock returned a negative second"))?;
    let nanoseconds = u64::try_from(timestamp.tv_nsec)
        .map_err(|_error| invalid_data("monotonic clock returned a negative nanosecond"))?;
    seconds
        .checked_mul(1_000_000_000)
        .and_then(|value| value.checked_add(nanoseconds))
        .ok_or_else(|| invalid_data("monotonic timestamp overflowed"))
}

fn invalid_data(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

#[derive(Clone, Copy)]
enum AttachmentKind {
    Tracepoint { category: &'static str },
    Raw,
}

#[derive(Clone, Copy)]
struct Attachment {
    program: &'static str,
    event: &'static str,
    kind: AttachmentKind,
}

impl Attachment {
    const fn tracepoint(
        program: &'static str,
        category: &'static str,
        event: &'static str,
    ) -> Self {
        Self {
            program,
            event,
            kind: AttachmentKind::Tracepoint { category },
        }
    }

    const fn raw(program: &'static str, event: &'static str) -> Self {
        Self {
            program,
            event,
            kind: AttachmentKind::Raw,
        }
    }
}

struct Object(NonNull<ffi::BpfObject>);

impl Object {
    fn open_and_load(bytes: &[u8]) -> io::Result<Self> {
        // SAFETY: the embedded ELF slice is immutable for the duration of the call.  A null opts
        // pointer selects libbpf defaults.  The returned object is uniquely owned by this wrapper.
        let raw =
            unsafe { ffi::bpf_object__open_mem(bytes.as_ptr().cast(), bytes.len(), ptr::null()) };
        let object = NonNull::new(raw).ok_or_else(io::Error::last_os_error)?;
        // SAFETY: `object` came from bpf_object__open_mem and remains owned until Drop.
        let status = unsafe { ffi::bpf_object__load(object.as_ptr()) };
        if status != 0 {
            // SAFETY: load failure does not consume the object.
            unsafe { ffi::bpf_object__close(object.as_ptr()) };
            return Err(errno_error(c_long::from(status)));
        }
        Ok(Self(object))
    }

    fn map_fd(&self, name: &'static CStr) -> io::Result<c_int> {
        // SAFETY: both pointers remain valid and libbpf does not retain `name`.
        let descriptor =
            unsafe { ffi::bpf_object__find_map_fd_by_name(self.0.as_ptr(), name.as_ptr()) };
        if descriptor < 0 {
            Err(errno_error(c_long::from(descriptor)))
        } else {
            Ok(descriptor)
        }
    }

    fn configure_target(&self, target: &TraceHelperTarget) -> io::Result<()> {
        let key = 0_u32;
        let value = TargetConfig {
            target_tgid: target.pid,
            target_uid: target.uid,
        };
        update_map(
            self.map_fd(c"target_config")?,
            (&raw const key).cast(),
            (&raw const value).cast(),
        )
    }

    fn add_target_tid(&self, tid: u32) -> io::Result<()> {
        let present = 1_u8;
        update_map(
            self.map_fd(c"target_tids")?,
            (&raw const tid).cast(),
            (&raw const present).cast(),
        )
    }

    fn lost_event_count(&self) -> io::Result<u64> {
        let key = COUNTER_LOST_KEY;
        let mut value = 0_u64;
        let descriptor = self.map_fd(c"counters")?;
        // SAFETY: key/value have exactly the key/value sizes declared by the fixed map.
        let status = unsafe {
            ffi::bpf_map_lookup_elem(descriptor, (&raw const key).cast(), (&raw mut value).cast())
        };
        if status == 0 {
            Ok(value)
        } else {
            Err(io::Error::last_os_error())
        }
    }

    fn attach(&self, attachment: &Attachment) -> io::Result<Link> {
        let program_name = CString::new(attachment.program).expect("fixed program has no NUL");
        // SAFETY: object/program-name pointers are valid and not retained beyond object lifetime.
        let program = unsafe {
            ffi::bpf_object__find_program_by_name(self.0.as_ptr(), program_name.as_ptr())
        };
        let program = NonNull::new(program)
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "BPF program is absent"))?;
        let event = CString::new(attachment.event).expect("fixed event has no NUL");
        // SAFETY: fixed C strings and loaded program stay valid; returned link is uniquely owned.
        let link = unsafe {
            match attachment.kind {
                AttachmentKind::Tracepoint { category } => {
                    let category = CString::new(category).expect("fixed category has no NUL");
                    ffi::bpf_program__attach_tracepoint(
                        program.as_ptr(),
                        category.as_ptr(),
                        event.as_ptr(),
                    )
                }
                AttachmentKind::Raw => {
                    ffi::bpf_program__attach_raw_tracepoint(program.as_ptr(), event.as_ptr())
                }
            }
        };
        pointer_result(link).map(Link)
    }

    fn ring_buffer<'events>(
        &self,
        events: &'events mut RingEventContext,
    ) -> io::Result<RingBuffer<'events>> {
        let descriptor = self.map_fd(c"events")?;
        // SAFETY: the callback context remains borrowed mutably for `RingBuffer`'s lifetime.  The
        // callback copies fixed-size records and libbpf invokes it synchronously from poll.
        let raw = unsafe {
            ffi::ring_buffer__new(
                descriptor,
                Some(consume_ring_event),
                ptr::from_mut(events).cast(),
                ptr::null(),
            )
        };
        pointer_result(raw).map(|pointer| RingBuffer {
            pointer,
            _events: std::marker::PhantomData,
        })
    }
}

impl Drop for Object {
    fn drop(&mut self) {
        // SAFETY: this wrapper uniquely owns the object and closes it exactly once.
        unsafe { ffi::bpf_object__close(self.0.as_ptr()) };
    }
}

struct Link(NonNull<ffi::BpfLink>);

impl Drop for Link {
    fn drop(&mut self) {
        // SAFETY: this wrapper uniquely owns the link and destroys it exactly once.
        unsafe { ffi::bpf_link__destroy(self.0.as_ptr()) };
    }
}

struct RingBuffer<'events> {
    pointer: NonNull<ffi::RingBuffer>,
    _events: std::marker::PhantomData<&'events mut RingEventContext>,
}

impl RingBuffer<'_> {
    fn poll(&mut self, timeout_milliseconds: i32) -> io::Result<()> {
        // SAFETY: pointer is a live ring-buffer manager and callback context is still borrowed.
        let status = unsafe { ffi::ring_buffer__poll(self.pointer.as_ptr(), timeout_milliseconds) };
        if status >= 0 || status == -4 {
            Ok(())
        } else {
            Err(errno_error(c_long::from(status)))
        }
    }
}

impl Drop for RingBuffer<'_> {
    fn drop(&mut self) {
        // SAFETY: this wrapper uniquely owns the manager and frees it exactly once.
        unsafe { ffi::ring_buffer__free(self.pointer.as_ptr()) };
    }
}

fn update_map(descriptor: c_int, key: *const c_void, value: *const c_void) -> io::Result<()> {
    // SAFETY: callers pass fixed-layout keys/values matching the named embedded maps.
    let status = unsafe { ffi::bpf_map_update_elem(descriptor, key, value, BPF_ANY) };
    if status == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

fn pointer_result<T>(pointer: *mut T) -> io::Result<NonNull<T>> {
    // SAFETY: libbpf_get_error accepts null, valid, and ERR_PTR-style pointers without dereference.
    let error = unsafe { ffi::libbpf_get_error(pointer.cast()) };
    if error != 0 {
        Err(errno_error(error))
    } else {
        NonNull::new(pointer).ok_or_else(io::Error::last_os_error)
    }
}

fn errno_error(value: c_long) -> io::Error {
    let errno = i32::try_from(value.unsigned_abs()).unwrap_or(5);
    io::Error::from_raw_os_error(errno)
}

unsafe extern "C" fn consume_ring_event(
    context: *mut c_void,
    data: *mut c_void,
    size: usize,
) -> c_int {
    if context.is_null() || data.is_null() || size != size_of::<RawEvent>() {
        return -22;
    }
    // SAFETY: ring_buffer__new received a live `RingEventContext` pointer and poll holds the sole
    // mutable borrow.  libbpf supplies at least `size_of::<RawEvent>()` initialized bytes.
    let context = unsafe { &mut *context.cast::<RingEventContext>() };
    if context.events.len() >= context.max_events {
        context.truncated = true;
        return 0;
    }
    // SAFETY: alignment is not promised by the C callback, so use an unaligned value copy.
    let event = unsafe { ptr::read_unaligned(data.cast::<RawEvent>()) };
    context.events.push(event);
    0
}

struct RingEventContext {
    events: Vec<RawEvent>,
    max_events: usize,
    truncated: bool,
}

#[repr(C)]
struct libc_timespec {
    tv_sec: i64,
    tv_nsec: i64,
}

const CLOCK_MONOTONIC: c_int = 1;

unsafe extern "C" {
    fn clock_gettime(clock_id: c_int, timestamp: *mut libc_timespec) -> c_int;
}

#[allow(unsafe_code)]
mod ffi {
    use super::{c_char, c_int, c_long, c_void};

    pub enum BpfObject {}
    pub enum BpfProgram {}
    pub enum BpfLink {}
    pub enum RingBuffer {}

    pub type RingBufferSample =
        Option<unsafe extern "C" fn(context: *mut c_void, data: *mut c_void, size: usize) -> c_int>;

    #[link(name = "bpf")]
    unsafe extern "C" {
        pub fn bpf_object__open_mem(
            bytes: *const c_void,
            size: usize,
            options: *const c_void,
        ) -> *mut BpfObject;
        pub fn bpf_object__load(object: *mut BpfObject) -> c_int;
        pub fn bpf_object__close(object: *mut BpfObject);
        pub fn bpf_object__find_map_fd_by_name(
            object: *const BpfObject,
            name: *const c_char,
        ) -> c_int;
        pub fn bpf_object__find_program_by_name(
            object: *const BpfObject,
            name: *const c_char,
        ) -> *mut BpfProgram;
        pub fn bpf_program__attach_tracepoint(
            program: *const BpfProgram,
            category: *const c_char,
            name: *const c_char,
        ) -> *mut BpfLink;
        pub fn bpf_program__attach_raw_tracepoint(
            program: *const BpfProgram,
            name: *const c_char,
        ) -> *mut BpfLink;
        pub fn bpf_link__destroy(link: *mut BpfLink) -> c_int;
        pub fn bpf_map_update_elem(
            descriptor: c_int,
            key: *const c_void,
            value: *const c_void,
            flags: u64,
        ) -> c_int;
        pub fn bpf_map_lookup_elem(
            descriptor: c_int,
            key: *const c_void,
            value: *mut c_void,
        ) -> c_int;
        pub fn ring_buffer__new(
            map_descriptor: c_int,
            callback: RingBufferSample,
            context: *mut c_void,
            options: *const c_void,
        ) -> *mut RingBuffer;
        pub fn ring_buffer__poll(buffer: *mut RingBuffer, timeout_milliseconds: c_int) -> c_int;
        pub fn ring_buffer__free(buffer: *mut RingBuffer);
        pub fn libbpf_get_error(pointer: *const c_void) -> c_long;
    }
}

#[cfg(test)]
mod tests {
    use super::{RawEvent, normalize_event, private_lock_id};

    fn raw(kind: u32) -> RawEvent {
        RawEvent {
            timestamp_ns: 100,
            sequence: 9,
            object_address: 0,
            value: 0,
            kind,
            cpu: 2,
            target_tid: 123,
            related_target_tid: 0,
            flags: 0,
            reserved: 0,
        }
    }

    #[test]
    fn normalizes_only_fixed_target_safe_fields() {
        let mut value = raw(1);
        value.value = 2;
        value.flags = 1;
        let event = normalize_event(value, 0, &[7; 32]).expect("normalized event");
        assert_eq!(event.kind, "sched_switch_out");
        assert_eq!(event.related_scope, Some("external_redacted"));
        assert_eq!(event.previous_state, Some(2));
        let json = serde_json::to_string(&event).expect("serialize event");
        assert!(!json.contains("comm"));
        assert!(!json.contains("object_address"));
    }

    #[test]
    fn lock_identity_is_stable_per_key_and_not_an_address() {
        let first = private_lock_id(&[1; 32], 0xdead_beef);
        assert_eq!(first, private_lock_id(&[1; 32], 0xdead_beef));
        assert_ne!(first, private_lock_id(&[2; 32], 0xdead_beef));
        assert!(first.starts_with("lock-"));
        assert!(!first.contains("deadbeef"));
    }

    #[test]
    fn rejects_unknown_kernel_event_kind() {
        assert!(normalize_event(raw(999), 0, &[1; 32]).is_err());
    }
}
