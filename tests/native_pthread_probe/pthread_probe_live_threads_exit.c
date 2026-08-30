#include <pthread.h>
#include <stdbool.h>
#include <stdatomic.h>
#include <stdint.h>
#include <time.h>

static pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
static atomic_bool started = false;

static void *worker(void *argument) {
    (void)argument;
    atomic_store_explicit(&started, true, memory_order_release);
    for (;;) {
        (void)pthread_mutex_lock(&mutex);
        (void)pthread_mutex_unlock(&mutex);
    }
    return NULL;
}

int main(void) {
    pthread_t thread;
    struct timespec pause = {.tv_sec = 0, .tv_nsec = 1000000L};
    if (pthread_create(&thread, NULL, worker, NULL) != 0) {
        return 2;
    }
    while (!atomic_load_explicit(&started, memory_order_acquire)) {
        (void)nanosleep(&pause, NULL);
    }
    (void)nanosleep(&pause, NULL);
    return 0;
}
