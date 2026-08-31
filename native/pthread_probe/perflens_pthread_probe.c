/*
 * PerfLens bounded glibc pthread LD_PRELOAD probe.
 *
 * Security and evidence notes:
 * - The probe accepts one already-open output descriptor, never a path.
 * - Event emission uses only fixed-size TLS/global storage and raw syscalls.
 * - pthread object addresses are SipHash-2-4 keyed with getrandom() material;
 *   only the 16-hex source-local token reaches the private stream.
 * - Public RuntimeLock Evidence must be produced by the strict PerfLens
 *   converter, which replaces this token with an Artifact-local identity.
 * - This library covers dynamically linked calls through the exported glibc
 *   pthread API.  It does not claim visibility into static, musl, custom,
 *   inline, spin, or runtime-internal locks.
 */
#define _GNU_SOURCE 1

#include "perflens_pthread_probe.h"

#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <gnu/libc-version.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/random.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

#define PROBE_CONSTRUCTOR __attribute__((constructor))
#define PROBE_DESTRUCTOR __attribute__((destructor))
#define PROBE_PUBLIC __attribute__((visibility("default")))
#define PROBE_UNUSED __attribute__((unused))

#define PROBE_DEFAULT_THRESHOLD_NS UINT64_C(1000)
#define PROBE_HARD_EVENT_LIMIT UINT64_C(20000)
#define PROBE_MAX_FD UINT64_C(1023)
#define PROBE_LINE_BYTES 1024U
#define PROBE_HELD_SLOTS 128U
#define PROBE_PROC_STAT_BYTES 2048U

const uint32_t perflens_pthread_probe_abi_version PROBE_PUBLIC =
    PERFLENS_PTHREAD_PROBE_ABI_VERSION;
const char perflens_pthread_probe_protocol_version[] PROBE_PUBLIC =
    PERFLENS_PTHREAD_PROBE_PROTOCOL_VERSION;

enum probe_lock_kind {
    PROBE_LOCK_MUTEX,
    PROBE_LOCK_RECURSIVE_MUTEX,
    PROBE_LOCK_RWLOCK_READ,
    PROBE_LOCK_RWLOCK_WRITE,
    PROBE_LOCK_CONDITION,
};

struct probe_builder {
    char data[PROBE_LINE_BYTES];
    size_t length;
    bool overflow;
};

struct probe_held_lock {
    uint64_t token;
    uint64_t acquire_sequence;
    uint64_t acquired_ns;
    enum probe_lock_kind kind;
};

struct probe_state {
    int output_fd;
    pid_t pid;
    uid_t uid;
    uint64_t target_start_time_ticks;
    uint64_t key[2];
    uint64_t sequence;
    uint64_t emitted_events;
    uint64_t lost_events;
    uint64_t max_events;
    uint64_t threshold_ns;
    uint64_t fork_generation;
    atomic_bool configured;
    atomic_bool active;
    atomic_bool truncated;
    atomic_flag output_lock;
    bool exact;
    char glibc_version[32];
};

struct probe_real_functions {
    int (*mutex_lock)(pthread_mutex_t *);
    int (*mutex_trylock)(pthread_mutex_t *);
    int (*mutex_timedlock)(pthread_mutex_t *, const struct timespec *);
    int (*mutex_clocklock)(pthread_mutex_t *, clockid_t, const struct timespec *);
    int (*mutex_unlock)(pthread_mutex_t *);
    int (*rwlock_rdlock)(pthread_rwlock_t *);
    int (*rwlock_tryrdlock)(pthread_rwlock_t *);
    int (*rwlock_timedrdlock)(pthread_rwlock_t *, const struct timespec *);
    int (*rwlock_clockrdlock)(pthread_rwlock_t *, clockid_t, const struct timespec *);
    int (*rwlock_wrlock)(pthread_rwlock_t *);
    int (*rwlock_trywrlock)(pthread_rwlock_t *);
    int (*rwlock_timedwrlock)(pthread_rwlock_t *, const struct timespec *);
    int (*rwlock_clockwrlock)(pthread_rwlock_t *, clockid_t, const struct timespec *);
    int (*rwlock_unlock)(pthread_rwlock_t *);
    int (*cond_wait)(pthread_cond_t *, pthread_mutex_t *);
    int (*cond_timedwait)(pthread_cond_t *, pthread_mutex_t *, const struct timespec *);
    int (*cond_clockwait)(pthread_cond_t *, pthread_mutex_t *, clockid_t,
                          const struct timespec *);
};

static struct probe_state probe = {
    .output_fd = -1,
    .output_lock = ATOMIC_FLAG_INIT,
};
static struct probe_real_functions real_functions;
static _Thread_local bool probe_recursing;
static _Thread_local struct probe_held_lock held_locks[PROBE_HELD_SLOTS];
static _Thread_local size_t held_lock_count;

static void builder_bytes(struct probe_builder *builder, const char *value, size_t length) {
    size_t index;
    if (builder->overflow || length > sizeof(builder->data) - builder->length) {
        builder->overflow = true;
        return;
    }
    for (index = 0; index < length; ++index) {
        builder->data[builder->length + index] = value[index];
    }
    builder->length += length;
}

#define BUILDER_LITERAL(builder, value) builder_bytes((builder), (value), sizeof(value) - 1U)

static void builder_u64(struct probe_builder *builder, uint64_t value) {
    char digits[32];
    size_t count = 0;
    do {
        digits[count] = (char)('0' + (value % UINT64_C(10)));
        ++count;
        value /= UINT64_C(10);
    } while (value != 0U);
    while (count != 0U) {
        --count;
        builder_bytes(builder, &digits[count], 1U);
    }
}

static void builder_hex64(struct probe_builder *builder, uint64_t value) {
    static const char hex[] = "0123456789abcdef";
    char output[16];
    size_t index;
    for (index = 0; index < sizeof(output); ++index) {
        unsigned int shift = (unsigned int)((sizeof(output) - index - 1U) * 4U);
        output[index] = hex[(value >> shift) & UINT64_C(0xf)];
    }
    builder_bytes(builder, output, sizeof(output));
}

static void builder_bool(struct probe_builder *builder, bool value) {
    if (value) {
        BUILDER_LITERAL(builder, "true");
    } else {
        BUILDER_LITERAL(builder, "false");
    }
}

static bool safe_version_character(char value) {
    return (value >= '0' && value <= '9') || value == '.' || value == '-';
}

static void builder_safe_version(struct probe_builder *builder, const char *value) {
    size_t index = 0;
    while (value[index] != '\0' && index < 31U && safe_version_character(value[index])) {
        builder_bytes(builder, &value[index], 1U);
        ++index;
    }
}

static const char *lock_kind_name(enum probe_lock_kind kind) {
    switch (kind) {
    case PROBE_LOCK_MUTEX:
        return "mutex";
    case PROBE_LOCK_RECURSIVE_MUTEX:
        return "recursive_mutex";
    case PROBE_LOCK_RWLOCK_READ:
        return "rwlock_read";
    case PROBE_LOCK_RWLOCK_WRITE:
        return "rwlock_write";
    case PROBE_LOCK_CONDITION:
        return "condition";
    }
    return "mutex";
}

static void builder_fixed_string(struct probe_builder *builder, const char *value) {
    size_t length = 0;
    while (value[length] != '\0') {
        ++length;
    }
    BUILDER_LITERAL(builder, "\"");
    builder_bytes(builder, value, length);
    BUILDER_LITERAL(builder, "\"");
}

static pid_t raw_pid(void) { return (pid_t)syscall(SYS_getpid); }
static pid_t raw_tid(void) { return (pid_t)syscall(SYS_gettid); }
static uid_t raw_uid(void) { return (uid_t)syscall(SYS_getuid); }

static uint64_t monotonic_ns(void) {
    struct timespec now;
    if (syscall(SYS_clock_gettime, CLOCK_MONOTONIC, &now) != 0) {
        return 0U;
    }
    if (now.tv_sec < 0 || now.tv_nsec < 0) {
        return 0U;
    }
    return (uint64_t)now.tv_sec * UINT64_C(1000000000) + (uint64_t)now.tv_nsec;
}

static uint64_t rotate_left(uint64_t value, unsigned int shift) {
    return (value << shift) | (value >> (64U - shift));
}

#define SIP_ROUND(v0, v1, v2, v3)                                                               \
    do {                                                                                         \
        (v0) += (v1);                                                                            \
        (v1) = rotate_left((v1), 13U);                                                           \
        (v1) ^= (v0);                                                                            \
        (v0) = rotate_left((v0), 32U);                                                           \
        (v2) += (v3);                                                                            \
        (v3) = rotate_left((v3), 16U);                                                           \
        (v3) ^= (v2);                                                                            \
        (v0) += (v3);                                                                            \
        (v3) = rotate_left((v3), 21U);                                                           \
        (v3) ^= (v0);                                                                            \
        (v2) += (v1);                                                                            \
        (v1) = rotate_left((v1), 17U);                                                           \
        (v1) ^= (v2);                                                                            \
        (v2) = rotate_left((v2), 32U);                                                           \
    } while (false)

static uint64_t siphash_words(uint64_t word0, uint64_t word1, uint64_t word2) {
    uint64_t v0 = UINT64_C(0x736f6d6570736575) ^ probe.key[0];
    uint64_t v1 = UINT64_C(0x646f72616e646f6d) ^ probe.key[1];
    uint64_t v2 = UINT64_C(0x6c7967656e657261) ^ probe.key[0];
    uint64_t v3 = UINT64_C(0x7465646279746573) ^ probe.key[1];
    uint64_t words[4] = {word0, word1, word2, UINT64_C(24) << 56U};
    size_t index;
    for (index = 0; index < 4U; ++index) {
        v3 ^= words[index];
        SIP_ROUND(v0, v1, v2, v3);
        SIP_ROUND(v0, v1, v2, v3);
        v0 ^= words[index];
    }
    v2 ^= UINT64_C(0xff);
    SIP_ROUND(v0, v1, v2, v3);
    SIP_ROUND(v0, v1, v2, v3);
    SIP_ROUND(v0, v1, v2, v3);
    SIP_ROUND(v0, v1, v2, v3);
    return v0 ^ v1 ^ v2 ^ v3;
}

static uint64_t lock_token(const void *lock, enum probe_lock_kind kind) {
    uint64_t scope = ((uint64_t)(uint32_t)probe.pid << 32U) | (uint64_t)(unsigned int)kind;
    return siphash_words((uint64_t)(uintptr_t)lock, scope, probe.fork_generation);
}

static void output_lock_acquire(void) {
    while (atomic_flag_test_and_set_explicit(&probe.output_lock, memory_order_acquire)) {
        (void)syscall(SYS_sched_yield);
    }
}

static void output_lock_release(void) {
    atomic_flag_clear_explicit(&probe.output_lock, memory_order_release);
}

static bool write_line_unlocked(struct probe_builder *builder) {
    ssize_t written;
    if (builder->overflow || builder->length == 0U ||
        builder->length >= sizeof(builder->data)) {
        return false;
    }
    builder->data[builder->length] = '\n';
    ++builder->length;
    do {
        written = (ssize_t)syscall(SYS_write, probe.output_fd, builder->data, builder->length);
    } while (written < 0 && errno == EINTR);
    return written == (ssize_t)builder->length;
}

static bool randomize_key(void) {
    unsigned char *destination = (unsigned char *)probe.key;
    size_t remaining = sizeof(probe.key);
    while (remaining != 0U) {
        ssize_t received =
            (ssize_t)syscall(SYS_getrandom, destination, remaining, GRND_NONBLOCK);
        if (received < 0 && errno == EINTR) {
            continue;
        }
        if (received <= 0) {
            return false;
        }
        destination += (size_t)received;
        remaining -= (size_t)received;
    }
    return true;
}

static bool parse_u64(const char *value, uint64_t minimum, uint64_t maximum,
                      uint64_t *parsed) {
    uint64_t result = 0U;
    size_t index = 0U;
    if (value == NULL || value[0] == '\0') {
        return false;
    }
    while (value[index] != '\0') {
        uint64_t digit;
        if (value[index] < '0' || value[index] > '9') {
            return false;
        }
        digit = (uint64_t)(unsigned int)(value[index] - '0');
        if (result > (maximum - digit) / UINT64_C(10)) {
            return false;
        }
        result = result * UINT64_C(10) + digit;
        ++index;
    }
    if (result < minimum || result > maximum) {
        return false;
    }
    *parsed = result;
    return true;
}

static bool read_start_time_ticks(uint64_t *result) {
    char buffer[PROBE_PROC_STAT_BYTES];
    ssize_t count;
    size_t close_parenthesis = 0U;
    size_t index;
    unsigned int field = 3U;
    int fd = (int)syscall(SYS_openat, AT_FDCWD, "/proc/self/stat",
                          O_RDONLY | O_CLOEXEC | O_NOFOLLOW, 0U);
    if (fd < 0) {
        return false;
    }
    do {
        count = (ssize_t)syscall(SYS_read, fd, buffer, sizeof(buffer) - 1U);
    } while (count < 0 && errno == EINTR);
    (void)syscall(SYS_close, fd);
    if (count <= 0 || (size_t)count >= sizeof(buffer)) {
        return false;
    }
    buffer[(size_t)count] = '\0';
    for (index = 0U; index < (size_t)count; ++index) {
        if (buffer[index] == ')') {
            close_parenthesis = index;
        }
    }
    if (close_parenthesis == 0U || close_parenthesis + 2U >= (size_t)count) {
        return false;
    }
    index = close_parenthesis + 2U;
    while (field <= 22U) {
        size_t begin;
        uint64_t value = 0U;
        while (buffer[index] == ' ') {
            ++index;
        }
        begin = index;
        while (buffer[index] != '\0' && buffer[index] != ' ' && buffer[index] != '\n') {
            if (field == 22U) {
                if (buffer[index] < '0' || buffer[index] > '9') {
                    return false;
                }
                value = value * UINT64_C(10) +
                        (uint64_t)(unsigned int)(buffer[index] - '0');
            }
            ++index;
        }
        if (index == begin) {
            return false;
        }
        if (field == 22U) {
            if (value == 0U) {
                return false;
            }
            *result = value;
            return true;
        }
        ++field;
    }
    return false;
}

static void copy_glibc_version(void) {
    const char *version = gnu_get_libc_version();
    size_t index = 0U;
    while (version[index] != '\0' && index + 1U < sizeof(probe.glibc_version) &&
           safe_version_character(version[index])) {
        probe.glibc_version[index] = version[index];
        ++index;
    }
    if (index == 0U || version[index] != '\0') {
        probe.glibc_version[0] = '0';
        index = 1U;
    }
    probe.glibc_version[index] = '\0';
}

static bool output_descriptor_is_safe(int fd) {
    struct stat status;
    long flags = syscall(SYS_fcntl, fd, F_GETFL, 0U);
    long descriptor_flags;
    if (flags < 0 || ((int)flags & O_ACCMODE) == O_RDONLY ||
        ((int)flags & O_APPEND) != 0) {
        return false;
    }
    /* Stable active collection writes either to the launcher's private,
     * empty regular file or to the runtime supervisor's private bounded
     * pipe. Sockets and every other descriptor type remain forbidden. */
    if (syscall(SYS_fstat, fd, &status) != 0 ||
        (!S_ISREG(status.st_mode) && !S_ISFIFO(status.st_mode)) ||
        status.st_nlink != 1 || status.st_uid != raw_uid() ||
        (status.st_mode & (mode_t)0777) != (mode_t)0600) {
        return false;
    }
    descriptor_flags = syscall(SYS_fcntl, fd, F_GETFD, 0U);
    if (descriptor_flags < 0 ||
        syscall(SYS_fcntl, fd, F_SETFD, descriptor_flags | FD_CLOEXEC) != 0) {
        return false;
    }
    return true;
}

static void emit_header_unlocked(void) {
    struct probe_builder builder = {0};
    BUILDER_LITERAL(&builder,
                    "{\"schema_version\":\"1.0\",\"record_type\":\"probe_header\","
                    "\"protocol\":\"native_pthread_probe\",\"protocol_version\":\"1.0\","
                    "\"runtime\":\"c_cpp\",\"runtime_version\":\"glibc-");
    builder_safe_version(&builder, probe.glibc_version);
    BUILDER_LITERAL(&builder,
                    "\",\"adapter_id\":\"native-pthread\",\"adapter_version\":\"1\","
                    "\"backend_id\":\"ld-preload\",\"backend_version\":\"1\",\"pid\":");
    builder_u64(&builder, (uint64_t)(uint32_t)probe.pid);
    BUILDER_LITERAL(&builder, ",\"uid\":");
    builder_u64(&builder, (uint64_t)(uint32_t)probe.uid);
    BUILDER_LITERAL(&builder, ",\"target_start_time_ticks\":");
    builder_u64(&builder, probe.target_start_time_ticks);
    BUILDER_LITERAL(&builder, ",\"observed_target_tids\":[");
    builder_u64(&builder, (uint64_t)(uint32_t)probe.pid);
    BUILDER_LITERAL(&builder,
                    "],\"target_kind\":\"host\",\"container_reference\":null,\"semantics\":");
    builder_fixed_string(&builder, probe.exact ? "exact" : "thresholded");
    BUILDER_LITERAL(&builder, ",\"duration_threshold_ns\":");
    if (probe.exact) {
        BUILDER_LITERAL(&builder, "null");
    } else {
        builder_u64(&builder, probe.threshold_ns);
    }
    BUILDER_LITERAL(&builder, ",\"max_events\":");
    builder_u64(&builder, probe.max_events);
    BUILDER_LITERAL(
        &builder,
        ",\"visible_lock_kinds\":[\"condition\",\"mutex\",\"recursive_mutex\","
        "\"rwlock_read\",\"rwlock_write\"],\"fast_path_visibility\":");
    builder_fixed_string(&builder, probe.exact ? "complete" : "partial");
    BUILDER_LITERAL(&builder,
                    ",\"owner_is_source_observed\":false,"
                    "\"hold_time_is_source_observed\":true}");
    if (!write_line_unlocked(&builder)) {
        atomic_store_explicit(&probe.active, false, memory_order_release);
    }
}

static void emit_footer(void) {
    struct probe_builder builder = {0};
    if (!atomic_load_explicit(&probe.active, memory_order_acquire)) {
        return;
    }
    output_lock_acquire();
    /* A wrapper can observe active before the destructor acquires the output lock.
     * Recheck while serialized, then close event publication before writing the
     * footer so no delayed wrapper can append a record after it. */
    if (!atomic_load_explicit(&probe.active, memory_order_acquire)) {
        output_lock_release();
        return;
    }
    atomic_store_explicit(&probe.active, false, memory_order_release);
    ++probe.sequence;
    BUILDER_LITERAL(&builder,
                    "{\"schema_version\":\"1.0\",\"record_type\":\"probe_footer\","
                    "\"protocol\":\"native_pthread_probe\",\"pid\":");
    builder_u64(&builder, (uint64_t)(uint32_t)probe.pid);
    BUILDER_LITERAL(&builder, ",\"sequence\":");
    builder_u64(&builder, probe.sequence);
    BUILDER_LITERAL(&builder, ",\"declared_event_count\":");
    builder_u64(&builder, probe.emitted_events);
    BUILDER_LITERAL(&builder, ",\"lost_event_count\":");
    builder_u64(&builder, probe.lost_events);
    BUILDER_LITERAL(&builder, ",\"truncated\":");
    builder_bool(&builder, atomic_load_explicit(&probe.truncated, memory_order_acquire));
    BUILDER_LITERAL(&builder, "}");
    (void)write_line_unlocked(&builder);
    output_lock_release();
}

static void mark_lost(uint64_t count) {
    if (!atomic_load_explicit(&probe.configured, memory_order_acquire)) {
        return;
    }
    output_lock_acquire();
    probe.lost_events += count;
    atomic_store_explicit(&probe.truncated, true, memory_order_release);
    output_lock_release();
}

static uint64_t emit_event(const char *event_kind, uint64_t timestamp_ns, uint64_t token,
                           enum probe_lock_kind lock_kind, uint64_t related_sequence,
                           bool has_duration, uint64_t duration_ns, bool has_hold_duration,
                           uint64_t hold_duration_ns, const char *result) {
    struct probe_builder builder = {0};
    uint64_t sequence;
    if (!atomic_load_explicit(&probe.active, memory_order_acquire)) {
        return 0U;
    }
    output_lock_acquire();
    /* The destructor may have closed publication after the optimistic check. */
    if (!atomic_load_explicit(&probe.active, memory_order_acquire)) {
        output_lock_release();
        return 0U;
    }
    if (probe.emitted_events >= probe.max_events) {
        ++probe.lost_events;
        atomic_store_explicit(&probe.truncated, true, memory_order_release);
        output_lock_release();
        return 0U;
    }
    sequence = ++probe.sequence;
    BUILDER_LITERAL(&builder,
                    "{\"schema_version\":\"1.0\",\"record_type\":\"probe_event\","
                    "\"sequence\":");
    builder_u64(&builder, sequence);
    BUILDER_LITERAL(&builder, ",\"source_event_id\":\"e");
    builder_u64(&builder, sequence);
    BUILDER_LITERAL(&builder, "\",\"event_kind\":");
    builder_fixed_string(&builder, event_kind);
    BUILDER_LITERAL(&builder, ",\"timestamp_ns\":");
    builder_u64(&builder, timestamp_ns);
    BUILDER_LITERAL(&builder, ",\"pid\":");
    builder_u64(&builder, (uint64_t)(uint32_t)probe.pid);
    BUILDER_LITERAL(&builder, ",\"tid\":");
    builder_u64(&builder, (uint64_t)(uint32_t)raw_tid());
    BUILDER_LITERAL(&builder, ",\"raw_lock_token\":\"");
    builder_hex64(&builder, token);
    BUILDER_LITERAL(&builder, "\",\"lock_kind\":");
    builder_fixed_string(&builder, lock_kind_name(lock_kind));
    BUILDER_LITERAL(&builder, ",\"related_source_event_id\":");
    if (related_sequence == 0U) {
        BUILDER_LITERAL(&builder, "null");
    } else {
        BUILDER_LITERAL(&builder, "\"e");
        builder_u64(&builder, related_sequence);
        BUILDER_LITERAL(&builder, "\"");
    }
    BUILDER_LITERAL(&builder, ",\"duration_ns\":");
    if (has_duration) {
        builder_u64(&builder, duration_ns);
    } else {
        BUILDER_LITERAL(&builder, "null");
    }
    BUILDER_LITERAL(&builder, ",\"hold_duration_ns\":");
    if (has_hold_duration) {
        builder_u64(&builder, hold_duration_ns);
    } else {
        BUILDER_LITERAL(&builder, "null");
    }
    BUILDER_LITERAL(&builder, ",\"result\":");
    builder_fixed_string(&builder, result);
    BUILDER_LITERAL(&builder, ",\"stack_id\":null}");
    if (!write_line_unlocked(&builder)) {
        ++probe.lost_events;
        atomic_store_explicit(&probe.truncated, true, memory_order_release);
        atomic_store_explicit(&probe.active, false, memory_order_release);
        sequence = 0U;
    } else {
        ++probe.emitted_events;
    }
    output_lock_release();
    return sequence;
}

static void resolve_one(void *destination, size_t destination_size, const char *name) {
    void *symbol = dlsym(RTLD_NEXT, name);
    if (destination_size == sizeof(symbol)) {
        __builtin_memcpy(destination, &symbol, sizeof(symbol));
    }
}

#define RESOLVE(member, name) resolve_one(&real_functions.member, sizeof(real_functions.member), (name))

static bool resolve_symbols(void) {
    RESOLVE(mutex_lock, "pthread_mutex_lock");
    RESOLVE(mutex_trylock, "pthread_mutex_trylock");
    RESOLVE(mutex_timedlock, "pthread_mutex_timedlock");
    RESOLVE(mutex_clocklock, "pthread_mutex_clocklock");
    RESOLVE(mutex_unlock, "pthread_mutex_unlock");
    RESOLVE(rwlock_rdlock, "pthread_rwlock_rdlock");
    RESOLVE(rwlock_tryrdlock, "pthread_rwlock_tryrdlock");
    RESOLVE(rwlock_timedrdlock, "pthread_rwlock_timedrdlock");
    RESOLVE(rwlock_clockrdlock, "pthread_rwlock_clockrdlock");
    RESOLVE(rwlock_wrlock, "pthread_rwlock_wrlock");
    RESOLVE(rwlock_trywrlock, "pthread_rwlock_trywrlock");
    RESOLVE(rwlock_timedwrlock, "pthread_rwlock_timedwrlock");
    RESOLVE(rwlock_clockwrlock, "pthread_rwlock_clockwrlock");
    RESOLVE(rwlock_unlock, "pthread_rwlock_unlock");
    RESOLVE(cond_wait, "pthread_cond_wait");
    RESOLVE(cond_timedwait, "pthread_cond_timedwait");
    RESOLVE(cond_clockwait, "pthread_cond_clockwait");
    return real_functions.mutex_lock != NULL && real_functions.mutex_trylock != NULL &&
           real_functions.mutex_timedlock != NULL && real_functions.mutex_unlock != NULL &&
           real_functions.rwlock_rdlock != NULL && real_functions.rwlock_tryrdlock != NULL &&
           real_functions.rwlock_timedrdlock != NULL && real_functions.rwlock_wrlock != NULL &&
           real_functions.rwlock_trywrlock != NULL && real_functions.rwlock_timedwrlock != NULL &&
           real_functions.rwlock_unlock != NULL && real_functions.cond_wait != NULL &&
           real_functions.cond_timedwait != NULL;
}

static bool configure_from_environment(void) {
    const char *fd_text = getenv("PERFLENS_RUNTIME_LOCK_FD");
    const char *mode = getenv("PERFLENS_RUNTIME_LOCK_MODE");
    const char *threshold = getenv("PERFLENS_RUNTIME_LOCK_THRESHOLD_NS");
    const char *maximum_events = getenv("PERFLENS_RUNTIME_LOCK_MAX_EVENTS");
    uint64_t value;
    if (!parse_u64(fd_text, UINT64_C(3), PROBE_MAX_FD, &value)) {
        return false;
    }
    probe.output_fd = (int)value;
    if (!output_descriptor_is_safe(probe.output_fd)) {
        return false;
    }
    if (mode == NULL || mode[0] == '\0' ||
        (mode[0] == 't' && mode[1] == 'h' && mode[2] == 'r' && mode[3] == 'e' &&
         mode[4] == 's' && mode[5] == 'h' && mode[6] == 'o' && mode[7] == 'l' &&
         mode[8] == 'd' && mode[9] == 'e' && mode[10] == 'd' && mode[11] == '\0')) {
        probe.exact = false;
    } else if (mode[0] == 'e' && mode[1] == 'x' && mode[2] == 'a' && mode[3] == 'c' &&
               mode[4] == 't' && mode[5] == '\0') {
        probe.exact = true;
    } else {
        return false;
    }
    if (probe.exact) {
        if (threshold != NULL && threshold[0] != '\0') {
            return false;
        }
        probe.threshold_ns = 0U;
    } else if (threshold == NULL || threshold[0] == '\0') {
        probe.threshold_ns = PROBE_DEFAULT_THRESHOLD_NS;
    } else if (!parse_u64(threshold, UINT64_C(1), UINT64_C(1000000000),
                          &probe.threshold_ns)) {
        return false;
    }
    if (maximum_events == NULL || maximum_events[0] == '\0') {
        probe.max_events = PROBE_HARD_EVENT_LIMIT;
    } else if (!parse_u64(maximum_events, UINT64_C(1), PROBE_HARD_EVENT_LIMIT,
                          &probe.max_events)) {
        return false;
    }
    return true;
}

static void reset_tls(void) {
    probe_recursing = false;
    held_lock_count = 0U;
}

static void atfork_child(void) {
    reset_tls();
    atomic_flag_clear_explicit(&probe.output_lock, memory_order_release);
    atomic_store_explicit(&probe.active, false, memory_order_release);
    atomic_store_explicit(&probe.configured, false, memory_order_release);
    if (probe.output_fd >= 0) {
        (void)syscall(SYS_close, probe.output_fd);
        probe.output_fd = -1;
    }
}

static void ensure_process_identity(void) {
    pid_t current = raw_pid();
    if (current != probe.pid && atomic_load_explicit(&probe.configured, memory_order_acquire)) {
        /* A forked child is outside the launcher's PID-bound authorization. */
        atfork_child();
    }
}

static void probe_initialize(void) PROBE_CONSTRUCTOR;
static void probe_initialize(void) {
    probe_recursing = true;
    if (!resolve_symbols() || !configure_from_environment()) {
        probe_recursing = false;
        return;
    }
    probe.pid = raw_pid();
    probe.uid = raw_uid();
    probe.fork_generation = 1U;
    copy_glibc_version();
    if (!read_start_time_ticks(&probe.target_start_time_ticks) || !randomize_key()) {
        probe_recursing = false;
        return;
    }
    atomic_store_explicit(&probe.configured, true, memory_order_release);
    atomic_store_explicit(&probe.active, true, memory_order_release);
    emit_header_unlocked();
    if (atomic_load_explicit(&probe.active, memory_order_acquire)) {
        (void)pthread_atfork(NULL, NULL, atfork_child);
    }
    probe_recursing = false;
}

static void probe_finalize(void) PROBE_DESTRUCTOR;
static void probe_finalize(void) {
    if (!atomic_load_explicit(&probe.configured, memory_order_acquire)) {
        return;
    }
    probe_recursing = true;
    ensure_process_identity();
    emit_footer();
    probe_recursing = false;
}

static enum probe_lock_kind mutex_lock_kind(const pthread_mutex_t *mutex) {
#if defined(__GLIBC__)
    int kind = mutex->__data.__kind;
    if ((kind & 3) == PTHREAD_MUTEX_RECURSIVE_NP) {
        return PROBE_LOCK_RECURSIVE_MUTEX;
    }
#else
    (void)mutex;
#endif
    return PROBE_LOCK_MUTEX;
}

static bool held_capacity(void) { return held_lock_count < PROBE_HELD_SLOTS; }

static void held_push(uint64_t token, enum probe_lock_kind kind, uint64_t acquire_sequence,
                      uint64_t acquired_ns) {
    if (!held_capacity()) {
        mark_lost(1U);
        return;
    }
    held_locks[held_lock_count] = (struct probe_held_lock){
        .token = token,
        .acquire_sequence = acquire_sequence,
        .acquired_ns = acquired_ns,
        .kind = kind,
    };
    ++held_lock_count;
}

static bool held_take(uint64_t token, struct probe_held_lock *result) {
    size_t index = held_lock_count;
    while (index != 0U) {
        --index;
        if (held_locks[index].token == token) {
            size_t move;
            *result = held_locks[index];
            for (move = index + 1U; move < held_lock_count; ++move) {
                held_locks[move - 1U] = held_locks[move];
            }
            --held_lock_count;
            return true;
        }
    }
    return false;
}

static const char *lock_result(int result) {
    if (result == 0) {
        return "acquired";
    }
    if (result == ETIMEDOUT) {
        return "timed_out";
    }
    return "failed";
}

static uint64_t safe_duration(uint64_t begin, uint64_t end) {
    return end >= begin ? end - begin : 0U;
}

static uint64_t begin_exact_wait(uint64_t timestamp_ns, uint64_t token,
                                 enum probe_lock_kind kind) {
    if (!probe.exact) {
        return 0U;
    }
    return emit_event("wait_begin", timestamp_ns, token, kind, 0U, false, 0U, false, 0U,
                      "unknown");
}

static void record_lock_result(uint64_t token, enum probe_lock_kind kind, uint64_t begin_ns,
                               uint64_t end_ns, int result, uint64_t exact_begin_sequence) {
    uint64_t duration = safe_duration(begin_ns, end_ns);
    uint64_t begin_sequence = exact_begin_sequence;
    uint64_t end_sequence;
    uint64_t acquire_sequence;
    bool observed = probe.exact || duration >= probe.threshold_ns;
    if (!observed) {
        return;
    }
    if (begin_sequence == 0U) {
        begin_sequence = emit_event("wait_begin", begin_ns, token, kind, 0U, false, 0U, false,
                                    0U, "unknown");
    }
    if (begin_sequence == 0U) {
        return;
    }
    end_sequence = emit_event("wait_end", end_ns, token, kind, begin_sequence, true, duration,
                              false, 0U, lock_result(result));
    if (result != 0 || end_sequence == 0U) {
        return;
    }
    if (!held_capacity()) {
        mark_lost(2U);
        return;
    }
    acquire_sequence = emit_event("acquire", end_ns, token, kind, end_sequence, false, 0U, false,
                                  0U, "acquired");
    if (acquire_sequence != 0U) {
        held_push(token, kind, acquire_sequence, end_ns);
    }
}

static bool record_release(uint64_t token, uint64_t timestamp_ns) {
    struct probe_held_lock held;
    if (!held_take(token, &held) || held.acquire_sequence == 0U) {
        return false;
    }
    (void)emit_event("release", timestamp_ns, token, held.kind, held.acquire_sequence, false, 0U,
                     true, safe_duration(held.acquired_ns, timestamp_ns), "released");
    return true;
}

static bool enter_probe(void) {
    if (probe_recursing) {
        return false;
    }
    ensure_process_identity();
    if (!atomic_load_explicit(&probe.active, memory_order_acquire)) {
        return false;
    }
    probe_recursing = true;
    return true;
}

static void leave_probe(void) { probe_recursing = false; }

#define SIMPLE_LOCK_WRAPPER(function_name, real_member, lock_type, kind_expression, arguments, call) \
    PROBE_PUBLIC int function_name arguments {                                                       \
        uint64_t begin_ns;                                                                            \
        uint64_t end_ns;                                                                              \
        uint64_t token;                                                                               \
        uint64_t begin_sequence;                                                                      \
        enum probe_lock_kind kind;                                                                    \
        int result;                                                                                   \
        if (real_functions.real_member == NULL) {                                                     \
            return ENOSYS;                                                                            \
        }                                                                                             \
        if (!enter_probe()) {                                                                         \
            return real_functions.real_member call;                                                   \
        }                                                                                             \
        kind = (kind_expression);                                                                     \
        token = lock_token((const void *)(lock_type), kind);                                          \
        begin_ns = monotonic_ns();                                                                    \
        begin_sequence = begin_exact_wait(begin_ns, token, kind);                                     \
        result = real_functions.real_member call;                                                     \
        end_ns = monotonic_ns();                                                                      \
        record_lock_result(token, kind, begin_ns, end_ns, result, begin_sequence);                    \
        leave_probe();                                                                                \
        return result;                                                                                \
    }

SIMPLE_LOCK_WRAPPER(pthread_mutex_lock, mutex_lock, mutex, mutex_lock_kind(mutex),
                    (pthread_mutex_t *mutex), (mutex))
SIMPLE_LOCK_WRAPPER(pthread_mutex_trylock, mutex_trylock, mutex, mutex_lock_kind(mutex),
                    (pthread_mutex_t *mutex), (mutex))
SIMPLE_LOCK_WRAPPER(pthread_mutex_timedlock, mutex_timedlock, mutex, mutex_lock_kind(mutex),
                    (pthread_mutex_t *mutex, const struct timespec *timeout), (mutex, timeout))
SIMPLE_LOCK_WRAPPER(pthread_mutex_clocklock, mutex_clocklock, mutex, mutex_lock_kind(mutex),
                    (pthread_mutex_t *mutex, clockid_t clock, const struct timespec *timeout),
                    (mutex, clock, timeout))
SIMPLE_LOCK_WRAPPER(pthread_rwlock_rdlock, rwlock_rdlock, rwlock, PROBE_LOCK_RWLOCK_READ,
                    (pthread_rwlock_t *rwlock), (rwlock))
SIMPLE_LOCK_WRAPPER(pthread_rwlock_tryrdlock, rwlock_tryrdlock, rwlock, PROBE_LOCK_RWLOCK_READ,
                    (pthread_rwlock_t *rwlock), (rwlock))
SIMPLE_LOCK_WRAPPER(pthread_rwlock_timedrdlock, rwlock_timedrdlock, rwlock,
                    PROBE_LOCK_RWLOCK_READ,
                    (pthread_rwlock_t *rwlock, const struct timespec *timeout), (rwlock, timeout))
SIMPLE_LOCK_WRAPPER(pthread_rwlock_clockrdlock, rwlock_clockrdlock, rwlock,
                    PROBE_LOCK_RWLOCK_READ,
                    (pthread_rwlock_t *rwlock, clockid_t clock, const struct timespec *timeout),
                    (rwlock, clock, timeout))
SIMPLE_LOCK_WRAPPER(pthread_rwlock_wrlock, rwlock_wrlock, rwlock, PROBE_LOCK_RWLOCK_WRITE,
                    (pthread_rwlock_t *rwlock), (rwlock))
SIMPLE_LOCK_WRAPPER(pthread_rwlock_trywrlock, rwlock_trywrlock, rwlock, PROBE_LOCK_RWLOCK_WRITE,
                    (pthread_rwlock_t *rwlock), (rwlock))
SIMPLE_LOCK_WRAPPER(pthread_rwlock_timedwrlock, rwlock_timedwrlock, rwlock,
                    PROBE_LOCK_RWLOCK_WRITE,
                    (pthread_rwlock_t *rwlock, const struct timespec *timeout), (rwlock, timeout))
SIMPLE_LOCK_WRAPPER(pthread_rwlock_clockwrlock, rwlock_clockwrlock, rwlock,
                    PROBE_LOCK_RWLOCK_WRITE,
                    (pthread_rwlock_t *rwlock, clockid_t clock, const struct timespec *timeout),
                    (rwlock, clock, timeout))

PROBE_PUBLIC int pthread_mutex_unlock(pthread_mutex_t *mutex) {
    int result;
    uint64_t token;
    if (real_functions.mutex_unlock == NULL) {
        return ENOSYS;
    }
    if (!enter_probe()) {
        return real_functions.mutex_unlock(mutex);
    }
    token = lock_token(mutex, mutex_lock_kind(mutex));
    result = real_functions.mutex_unlock(mutex);
    if (result == 0) {
        (void)record_release(token, monotonic_ns());
    }
    leave_probe();
    return result;
}

PROBE_PUBLIC int pthread_rwlock_unlock(pthread_rwlock_t *rwlock) {
    int result;
    uint64_t token;
    if (real_functions.rwlock_unlock == NULL) {
        return ENOSYS;
    }
    if (!enter_probe()) {
        return real_functions.rwlock_unlock(rwlock);
    }
    result = real_functions.rwlock_unlock(rwlock);
    if (result == 0) {
        uint64_t timestamp_ns = monotonic_ns();
        token = lock_token(rwlock, PROBE_LOCK_RWLOCK_READ);
        if (!record_release(token, timestamp_ns)) {
            token = lock_token(rwlock, PROBE_LOCK_RWLOCK_WRITE);
            (void)record_release(token, timestamp_ns);
        }
    }
    leave_probe();
    return result;
}

static void condition_cancel_cleanup(void *unused) {
    (void)unused;
    mark_lost((uint64_t)held_lock_count + UINT64_C(1));
    probe_recursing = false;
    held_lock_count = 0U;
}

static int call_condition_with_cleanup(
    pthread_cond_t *condition, pthread_mutex_t *mutex,
    int (*wait_function)(pthread_cond_t *, pthread_mutex_t *, const void *),
    const void *argument) {
    int result;
    pthread_cleanup_push(condition_cancel_cleanup, NULL);
    result = wait_function(condition, mutex, argument);
    pthread_cleanup_pop(0);
    return result;
}

static int record_condition_wait(pthread_cond_t *condition, pthread_mutex_t *mutex,
                                 int (*wait_function)(pthread_cond_t *, pthread_mutex_t *,
                                                      const void *),
                                 const void *argument) {
    enum probe_lock_kind mutex_kind = mutex_lock_kind(mutex);
    uint64_t condition_token = lock_token(condition, PROBE_LOCK_CONDITION);
    uint64_t mutex_token = lock_token(mutex, mutex_kind);
    uint64_t begin_ns = monotonic_ns();
    uint64_t begin_sequence = begin_exact_wait(begin_ns, condition_token, PROBE_LOCK_CONDITION);
    uint64_t end_ns;
    uint64_t duration;
    uint64_t end_sequence = 0U;
    uint64_t mutex_acquire_sequence = 0U;
    struct probe_held_lock released_mutex;
    bool had_mutex = held_take(mutex_token, &released_mutex);
    bool observed;
    int result;
    if (had_mutex && released_mutex.acquire_sequence != 0U) {
        (void)emit_event("release", begin_ns, mutex_token, released_mutex.kind,
                         released_mutex.acquire_sequence, false, 0U, true,
                         safe_duration(released_mutex.acquired_ns, begin_ns), "released");
    }
    result = call_condition_with_cleanup(condition, mutex, wait_function, argument);
    end_ns = monotonic_ns();
    duration = safe_duration(begin_ns, end_ns);
    observed = probe.exact || duration >= probe.threshold_ns;
    if (observed) {
        if (begin_sequence == 0U) {
            begin_sequence = emit_event("wait_begin", begin_ns, condition_token,
                                        PROBE_LOCK_CONDITION, 0U, false, 0U, false, 0U,
                                        "unknown");
        }
        if (begin_sequence != 0U) {
            const char *outcome = result == 0 ? "notified" : lock_result(result);
            end_sequence = emit_event("wait_end", end_ns, condition_token,
                                      PROBE_LOCK_CONDITION, begin_sequence, true, duration, false,
                                      0U, outcome);
        }
    }
    if (result == 0 || result == ETIMEDOUT) {
        if (observed && end_sequence != 0U && held_capacity()) {
            mutex_acquire_sequence = emit_event("acquire", end_ns, mutex_token, mutex_kind, 0U,
                                                false, 0U, false, 0U, "acquired");
        }
        held_push(mutex_token, mutex_kind, mutex_acquire_sequence, end_ns);
    }
    return result;
}

static int cond_wait_adapter(pthread_cond_t *condition, pthread_mutex_t *mutex,
                             const void *argument PROBE_UNUSED) {
    return real_functions.cond_wait(condition, mutex);
}

struct timed_condition_arguments {
    const struct timespec *timeout;
};

static int cond_timedwait_adapter(pthread_cond_t *condition, pthread_mutex_t *mutex,
                                  const void *argument) {
    const struct timed_condition_arguments *timed =
        (const struct timed_condition_arguments *)argument;
    return real_functions.cond_timedwait(condition, mutex, timed->timeout);
}

struct clock_condition_arguments {
    clockid_t clock;
    const struct timespec *timeout;
};

static int cond_clockwait_adapter(pthread_cond_t *condition, pthread_mutex_t *mutex,
                                  const void *argument) {
    const struct clock_condition_arguments *timed =
        (const struct clock_condition_arguments *)argument;
    return real_functions.cond_clockwait(condition, mutex, timed->clock, timed->timeout);
}

PROBE_PUBLIC int pthread_cond_wait(pthread_cond_t *condition, pthread_mutex_t *mutex) {
    int result;
    if (real_functions.cond_wait == NULL) {
        return ENOSYS;
    }
    if (!enter_probe()) {
        return real_functions.cond_wait(condition, mutex);
    }
    result = record_condition_wait(condition, mutex, cond_wait_adapter, NULL);
    leave_probe();
    return result;
}

PROBE_PUBLIC int pthread_cond_timedwait(pthread_cond_t *condition, pthread_mutex_t *mutex,
                                        const struct timespec *timeout) {
    struct timed_condition_arguments argument = {.timeout = timeout};
    int result;
    if (real_functions.cond_timedwait == NULL) {
        return ENOSYS;
    }
    if (!enter_probe()) {
        return real_functions.cond_timedwait(condition, mutex, timeout);
    }
    result = record_condition_wait(condition, mutex, cond_timedwait_adapter, &argument);
    leave_probe();
    return result;
}

PROBE_PUBLIC int pthread_cond_clockwait(pthread_cond_t *condition, pthread_mutex_t *mutex,
                                        clockid_t clock, const struct timespec *timeout) {
    struct clock_condition_arguments argument = {.clock = clock, .timeout = timeout};
    int result;
    if (real_functions.cond_clockwait == NULL) {
        return ENOSYS;
    }
    if (!enter_probe()) {
        return real_functions.cond_clockwait(condition, mutex, clock, timeout);
    }
    result = record_condition_wait(condition, mutex, cond_clockwait_adapter, &argument);
    leave_probe();
    return result;
}
