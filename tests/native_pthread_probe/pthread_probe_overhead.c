#define _GNU_SOURCE 1

#include <pthread.h>
#include <stdint.h>

static pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
static volatile uint64_t sink;

int main(void) {
    uint64_t iteration;
    for (iteration = 0; iteration < UINT64_C(25000); ++iteration) {
        uint64_t work;
        if (pthread_mutex_lock(&mutex) != 0) {
            return 1;
        }
        for (work = 0; work < UINT64_C(8000); ++work) {
            sink = sink * UINT64_C(6364136223846793005) + work + iteration;
        }
        if (pthread_mutex_unlock(&mutex) != 0) {
            return 1;
        }
    }
    return sink == UINT64_MAX ? 2 : 0;
}
