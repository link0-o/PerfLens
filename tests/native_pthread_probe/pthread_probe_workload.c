#define _GNU_SOURCE 1

#include <errno.h>
#include <pthread.h>
#include <sched.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static pthread_mutex_t contested_mutex = PTHREAD_MUTEX_INITIALIZER;
static atomic_bool holder_ready;

static void sleep_ns(long nanoseconds) {
    struct timespec delay = {.tv_sec = 0, .tv_nsec = nanoseconds};
    while (nanosleep(&delay, &delay) != 0 && errno == EINTR) {
    }
}

static void *hold_contested_mutex(void *unused) {
    (void)unused;
    if (pthread_mutex_lock(&contested_mutex) != 0) {
        return (void *)(uintptr_t)1U;
    }
    atomic_store_explicit(&holder_ready, true, memory_order_release);
    sleep_ns(3000000L);
    if (pthread_mutex_unlock(&contested_mutex) != 0) {
        return (void *)(uintptr_t)1U;
    }
    return NULL;
}

static int exercise_contended_mutex(void) {
    pthread_t holder;
    void *thread_result = NULL;
    atomic_store_explicit(&holder_ready, false, memory_order_release);
    if (pthread_create(&holder, NULL, hold_contested_mutex, NULL) != 0) {
        return 1;
    }
    while (!atomic_load_explicit(&holder_ready, memory_order_acquire)) {
        sched_yield();
    }
    if (pthread_mutex_lock(&contested_mutex) != 0 ||
        pthread_mutex_unlock(&contested_mutex) != 0 ||
        pthread_join(holder, &thread_result) != 0 || thread_result != NULL) {
        return 1;
    }
    return 0;
}

static int exercise_recursive_mutex(void) {
    pthread_mutexattr_t attributes;
    pthread_mutex_t recursive;
    int failed = 0;
    if (pthread_mutexattr_init(&attributes) != 0 ||
        pthread_mutexattr_settype(&attributes, PTHREAD_MUTEX_RECURSIVE) != 0 ||
        pthread_mutex_init(&recursive, &attributes) != 0) {
        return 1;
    }
    if (pthread_mutex_lock(&recursive) != 0 || pthread_mutex_lock(&recursive) != 0 ||
        pthread_mutex_unlock(&recursive) != 0 || pthread_mutex_unlock(&recursive) != 0) {
        failed = 1;
    }
    if (pthread_mutex_destroy(&recursive) != 0 || pthread_mutexattr_destroy(&attributes) != 0) {
        failed = 1;
    }
    return failed;
}

static int exercise_rwlock(void) {
    pthread_rwlock_t rwlock = PTHREAD_RWLOCK_INITIALIZER;
    int failed = 0;
    if (pthread_rwlock_rdlock(&rwlock) != 0 || pthread_rwlock_unlock(&rwlock) != 0 ||
        pthread_rwlock_wrlock(&rwlock) != 0 || pthread_rwlock_unlock(&rwlock) != 0) {
        failed = 1;
    }
    if (pthread_rwlock_destroy(&rwlock) != 0) {
        failed = 1;
    }
    return failed;
}

static int exercise_condition_timeout(void) {
    pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
    pthread_cond_t condition = PTHREAD_COND_INITIALIZER;
    struct timespec timeout;
    int result;
    int failed = 0;
    if (clock_gettime(CLOCK_REALTIME, &timeout) != 0) {
        return 1;
    }
    timeout.tv_nsec += 1000000L;
    if (timeout.tv_nsec >= 1000000000L) {
        ++timeout.tv_sec;
        timeout.tv_nsec -= 1000000000L;
    }
    if (pthread_mutex_lock(&mutex) != 0) {
        return 1;
    }
    result = pthread_cond_timedwait(&condition, &mutex, &timeout);
    if (result != ETIMEDOUT || pthread_mutex_unlock(&mutex) != 0) {
        failed = 1;
    }
    if (pthread_cond_destroy(&condition) != 0 || pthread_mutex_destroy(&mutex) != 0) {
        failed = 1;
    }
    return failed;
}

static int exercise_fork_isolation(void) {
    pid_t child = fork();
    int status;
    if (child < 0) {
        return 1;
    }
    if (child == 0) {
        pthread_mutex_t child_mutex = PTHREAD_MUTEX_INITIALIZER;
        int failed = pthread_mutex_lock(&child_mutex) != 0 ||
                     pthread_mutex_unlock(&child_mutex) != 0;
        exit(failed ? 2 : 0);
    }
    if (waitpid(child, &status, 0) != child || !WIFEXITED(status) || WEXITSTATUS(status) != 0) {
        return 1;
    }
    return 0;
}

int main(void) {
    if (exercise_contended_mutex() != 0 || exercise_recursive_mutex() != 0 ||
        exercise_rwlock() != 0 || exercise_condition_timeout() != 0 ||
        exercise_fork_isolation() != 0) {
        return 1;
    }
    return 0;
}
