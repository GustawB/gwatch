#include <iostream>
#include <unistd.h>

int32_t xd_unused;
int32_t xd4;
int64_t xd8;

int main(int argc, char *argv[]) {
    if (argc < 2) {
        return 1;
    }
    for (int i = 0; i < 10; ++i) {
        xd4 += 1;
        xd8 += 1;
    }

    return 0;
}