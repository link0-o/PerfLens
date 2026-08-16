#include "perflens_common.bpf.h"

struct trace_event_raw_sched_switch___perflens {
    struct trace_entry___perflens ent;
    char prev_comm[16];
    int prev_pid;
    int prev_prio;
    long prev_state;
    char next_comm[16];
    int next_pid;
    int next_prio;
} __attribute__((preserve_access_index));

struct trace_event_raw_sched_wakeup_template___perflens {
    struct trace_entry___perflens ent;
    char comm[16];
    int pid;
    int prio;
    int target_cpu;
} __attribute__((preserve_access_index));

struct trace_event_raw_sched_migrate_task___perflens {
    struct trace_entry___perflens ent;
    char comm[16];
    int pid;
    int prio;
    int orig_cpu;
    int dest_cpu;
} __attribute__((preserve_access_index));

struct task_struct___perflens {
    int pid;
    int tgid;
} __attribute__((preserve_access_index));

struct bpf_raw_tracepoint_args___perflens {
    __u64 args[0];
};

SEC("tracepoint/sched/sched_switch")
int perflens_sched_switch(struct trace_event_raw_sched_switch___perflens *context)
{
    __u32 previous_tid = (__u32)BPF_CORE_READ(context, prev_pid);
    __u32 next_tid = (__u32)BPF_CORE_READ(context, next_pid);
    long previous_state;

    /*
     * Keep map lookup results in separate control-flow branches.  Clang may
     * otherwise lower a boolean OR of two map-value-or-null results to a
     * pointer bitwise OR, which the kernel BPF verifier correctly rejects.
     */
    if (perflens_is_target_tid(previous_tid)) {
        previous_state = BPF_CORE_READ(context, prev_state);
        if (perflens_is_target_tid(next_tid)) {
            perflens_emit(PERFLENS_SCHED_SWITCH_BOTH, previous_tid, next_tid, 0, 0,
                          previous_state);
            return 0;
        }
        perflens_emit(PERFLENS_SCHED_SWITCH_OUT, previous_tid, 0,
                      PERFLENS_RELATED_EXTERNAL_REDACTED, 0, previous_state);
        return 0;
    }
    if (perflens_is_target_tid(next_tid)) {
        perflens_emit(PERFLENS_SCHED_SWITCH_IN, next_tid, 0,
                      PERFLENS_RELATED_EXTERNAL_REDACTED, 0, 0);
    }
    return 0;
}

static __always_inline int perflens_wakeup(
    struct trace_event_raw_sched_wakeup_template___perflens *context,
    __u32 kind)
{
    __u32 woken_tid = (__u32)BPF_CORE_READ(context, pid);
    __u32 current_tid;
    __u32 related_tid = 0;
    __u32 flags = PERFLENS_RELATED_EXTERNAL_REDACTED;

    if (!perflens_is_target_tid(woken_tid))
        return 0;
    if (kind == PERFLENS_SCHED_WAKING) {
        current_tid = (__u32)bpf_get_current_pid_tgid();
        if (perflens_is_target_tid(current_tid) && perflens_current_uid_matches()) {
            related_tid = current_tid;
            flags = 0;
        }
    } else {
        flags = 0;
    }
    perflens_emit(kind, woken_tid, related_tid, flags, 0,
                  BPF_CORE_READ(context, target_cpu));
    return 0;
}

SEC("tracepoint/sched/sched_waking")
int perflens_sched_waking(struct trace_event_raw_sched_wakeup_template___perflens *context)
{
    return perflens_wakeup(context, PERFLENS_SCHED_WAKING);
}

SEC("tracepoint/sched/sched_wakeup")
int perflens_sched_wakeup(struct trace_event_raw_sched_wakeup_template___perflens *context)
{
    return perflens_wakeup(context, PERFLENS_SCHED_WAKEUP);
}

SEC("tracepoint/sched/sched_wakeup_new")
int perflens_sched_wakeup_new(struct trace_event_raw_sched_wakeup_template___perflens *context)
{
    return perflens_wakeup(context, PERFLENS_SCHED_WAKEUP_NEW);
}

SEC("tracepoint/sched/sched_migrate_task")
int perflens_sched_migrate(struct trace_event_raw_sched_migrate_task___perflens *context)
{
    __u32 tid = (__u32)BPF_CORE_READ(context, pid);

    if (!perflens_is_target_tid(tid))
        return 0;
    perflens_emit(PERFLENS_SCHED_MIGRATE, tid, 0, 0, 0,
                  ((__s64)(__u32)BPF_CORE_READ(context, orig_cpu) << 32) |
                      (__u32)BPF_CORE_READ(context, dest_cpu));
    return 0;
}

SEC("raw_tp/sched_process_fork")
int perflens_sched_process_fork(struct bpf_raw_tracepoint_args___perflens *context)
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
int perflens_sched_process_exit(void *context)
{
    __u32 tid = (__u32)bpf_get_current_pid_tgid();

    (void)context;
    if (perflens_is_target_tid(tid))
        bpf_map_delete_elem(&target_tids, &tid);
    return 0;
}
