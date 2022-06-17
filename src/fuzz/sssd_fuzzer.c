#include <stddef.h>
#include "util/sss_utf8.h"

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    sss_utf8_check(Data, Size);

    return 0;
}
