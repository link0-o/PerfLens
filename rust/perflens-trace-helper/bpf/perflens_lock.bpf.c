#include "perflens_common.bpf.h"

struct task_struct___perflens {
    int pid;
    int tgid;
} __attribute__((preserve_access_index));

struct bpf_raw_tracepoint_args___perflens {
    __u64 args[0];
};

struct trace_event_raw_contention_begin___perflens {
    struct trace_entry___perflens ent;
    void *lock_addr;
    unsigned int flags;
} __attribute__((preserve_access_index));

struct trace_event_raw_contention_end___perflens {
    struct trace_entry___perflens ent;
    void *lock_addr;
    int ret;
} __attribute__((preserve_access_index));

struct trace_event_raw_sys_enter___perflens {
    struct trace_entry___perflens ent;
    long id;
    unsigned long args[6];
} __attribute__((preserve_access_index));

SEC("tracepoint/lock/contention_begin")
int perflens_lock_contention_begin(
    struct trace_event_raw_contention_begin___perflens *context)
{
    __u32 tid = (__u32)bpf_get_current_pid_tgid();

    if (!perflens_is_target_tid(tid) || !perflens_current_uid_matches())
        return 0;
    perflens_emit(PERFLENS_LOCK_WAIT, tid, 0, BPF_CORE_READ(context, flags),
                  (__u64)BPF_CORE_READ(context, lock_addr), 0);
    return 0;
}

SEC("tracepoint/lock/contention_end")
int perflens_lock_contention_end(
    struct trace_event_raw_contention_end___perflens *context)
{
    __u32 tid = (__u32)bpf_get_current_pid_tgid();

    if (!perflens_is_target_tid(tid) || !perflens_current_uid_matches())
        return 0;
    perflens_emit(PERFLENS_LOCK_WAIT_ENDED, tid, 0, 0,
                  (__u64)BPF_CORE_READ(context, lock_addr),
                  BPF_CORE_READ(context, ret));
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_futex")
int perflens_sys_enter_futex(struct trace_event_raw_sys_enter___perflens *context)
{
    __u32 tid = (__u32)bpf_get_current_pid_tgid();
    __u64 address;
    __s64 operation;
    __u32 command;
    __u32 kind;

    if (!perflens_is_target_tid(tid) || !perflens_current_uid_matches())
        return 0;
    address = BPF_CORE_READ(context, args[0]);
    operation = (__s64)BPF_CORE_READ(context, args[1]);
    command = (__u32)operation & 0x7f;
    if (command == 0 || command == 9 || command == 11)
        kind = PERFLENS_FUTEX_WAIT;
    else if (command == 1 || command == 3 || command == 10)
        kind = PERFLENS_FUTEX_WAKE;
    else
        return 0;
    perflens_emit(kind, tid, 0, command, address, 0);
    return 0;
}

SEC("raw_tp/sched_process_fork")
int perflens_lock_process_fork(struct bpf_raw_tracepoint_args___perflens *context)
{
    struct task_struct___perflens *child =
        (struct task_struct___perflens *)context->args[1];
    __u32 key = 0;
    struct perflens_target_config *config = bpf_map_lookup_elem(&target_config, &key);
    __u32 child_tgid;
    __u32 child_tid;
    __u8 present = 1;

    if (config == 0 || child == 0)
        return 0;
    child_tgid = (__u32)BPF_CORE_READ(child, tgid);
    if (child_tgid != config->target_tgid)
        return 0;
    child_tid = (__u32)BPF_CORE_READ(child, pid);
    bpf_map_update_elem(&target_tids, &child_tid, &present, BPF_ANY);
    return 0;
}

SEC("tracepoint/sched/sched_process_exit")
int perflens_lock_process_exit(void *context)
{
    __u32 tid = (__u32)bpf_get_current_pid_tgid();

    (void)context;
    if (perflens_is_target_tid(tid))
        bpf_map_delete_elem(&target_tids, &tid);
    return 0;
}
