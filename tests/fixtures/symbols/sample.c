#include <stddef.h>

__attribute__((noinline)) int perflens_hot_function(int value) {
    return value * 3 + 1;
}

int main(void) {
    return perflens_hot_function(7) == 22 ? 0 : 1;
}
