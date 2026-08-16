#ifndef PERFLENS_COMMON_BPF_H
#define PERFLENS_COMMON_BPF_H

#include <stdbool.h>
#include <linux/bpf.h>
#include <linux/types.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>

struct trace_entry___perflens {
    unsigned short type;
    unsigned char flags;
    unsigned char preempt_count;
    int pid;
} __attribute__((preserve_access_index));

struct perflens_target_config {
    __u32 target_tgid;
    __u32 target_uid;
};

struct perflens_raw_event {
    __u64 timestamp_ns;
    __u64 sequence;
    __u64 object_address;
    __s64 value;
    __u32 kind;
    __u32 cpu;
    __u32 target_tid;
    __u32 related_target_tid;
    __u32 flags;
    __u32 reserved;
};

enum perflens_event_kind {
    PERFLENS_SCHED_SWITCH_OUT = 1,
    PERFLENS_SCHED_SWITCH_IN = 2,
    PERFLENS_SCHED_SWITCH_BOTH = 3,
    PERFLENS_SCHED_WAKING = 4,
    PERFLENS_SCHED_WAKEUP = 5,
    PERFLENS_SCHED_WAKEUP_NEW = 6,
    PERFLENS_SCHED_MIGRATE = 7,
    PERFLENS_LOCK_WAIT = 20,
    PERFLENS_LOCK_WAIT_ENDED = 21,
    PERFLENS_FUTEX_WAIT = 22,
    PERFLENS_FUTEX_WAKE = 23,
};

enum perflens_event_flags {
    PERFLENS_RELATED_EXTERNAL_REDACTED = 1U << 0,
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct perflens_target_config);
} target_config SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key, __u32);
    __type(value, __u8);
} target_tids SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 2);
    __type(key, __u32);
    __type(value, __u64);
} counters SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 16 * 1024 * 1024);
} events SEC(".maps");

static __always_inline bool perflens_is_target_tid(__u32 tid)
{
    return bpf_map_lookup_elem(&target_tids, &tid) != 0;
}

static __always_inline bool perflens_current_uid_matches(void)
{
    __u32 key = 0;
    struct perflens_target_config *config = bpf_map_lookup_elem(&target_config, &key);
    __u32 uid = (__u32)bpf_get_current_uid_gid();

    return config != 0 && uid == config->target_uid;
}

static __always_inline void perflens_note_lost(void)
{
    __u32 key = 1;
    __u64 *lost = bpf_map_lookup_elem(&counters, &key);

    if (lost != 0)
        __sync_fetch_and_add(lost, 1);
}

static __always_inline void perflens_emit(
    __u32 kind,
    __u32 target_tid,
    __u32 related_target_tid,
    __u32 flags,
    __u64 object_address,
    __s64 value)
{
    struct perflens_raw_event *event;
    __u32 key = 0;
    __u64 *sequence;

    event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (event == 0) {
        perflens_note_lost();
        return;
    }
    sequence = bpf_map_lookup_elem(&counters, &key);
    event->timestamp_ns = bpf_ktime_get_ns();
    event->sequence = sequence == 0 ? 0 : __sync_fetch_and_add(sequence, 1);
    event->object_address = object_address;
    event->value = value;
    event->kind = kind;
    event->cpu = bpf_get_smp_processor_id();
    event->target_tid = target_tid;
    event->related_target_tid = related_target_tid;
    event->flags = flags;
    event->reserved = 0;
    bpf_ringbuf_submit(event, 0);
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";

#endif
