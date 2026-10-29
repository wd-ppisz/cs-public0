/* Standalone syscall fault fixtures for the exact header used by the engine. */
#include <assert.h>
#include <stddef.h>
#include <sys/socket.h>
#include <stdint.h>

static int set_error, get_error, short_length, actual, calls;
static int fixture_set(int fd, int level, int option, const void *value, socklen_t len)
{
    assert(fd == 7 && level == SOL_SOCKET && option == SO_RCVBUF);
    assert(len == sizeof(int) && *(const int *)value == 16777216);
    calls++;
    return set_error;
}
static int fixture_get(int fd, int level, int option, void *value, socklen_t *len)
{
    assert(fd == 7 && level == SOL_SOCKET && option == SO_RCVBUF);
    *(int *)value = actual;
    *len = short_length ? 1 : sizeof(int);
    calls++;
    return get_error;
}
#define setsockopt fixture_set
#define getsockopt fixture_get
#include "../patches/source-nfq-rcvbuf.h"

int main(void)
{
    uint32_t parsed;
    assert(NFQRcvbufParse("16777216", &parsed) == 0 && parsed == 16777216);
    assert(NFQRcvbufParse("1048576", &parsed) == 0);
    assert(NFQRcvbufParse("67108864", &parsed) == 0);
    const char *bad[] = {NULL, "", "0", "-1", "+16777216", "016777216", "1mb",
        "16777216 ", " 16777216", "1048575", "67108865", "4294967296",
        "999999999999999999999999999999999999999999"};
    for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++)
        assert(NFQRcvbufParse(bad[i], &parsed) == -1);
    int effective = 0;
    actual = 33554432;
    assert(NFQRcvbufSet(7, 16777216, &effective) == 0 && effective == actual && calls == 2);
    actual = 1536000; /* kernel clamp */
    assert(NFQRcvbufSet(7, 16777216, &effective) == -1);
    actual = 33554432; short_length = 1;
    assert(NFQRcvbufSet(7, 16777216, &effective) == -1);
    short_length = 0; get_error = -1;
    assert(NFQRcvbufSet(7, 16777216, &effective) == -1);
    get_error = 0; set_error = -1; calls = 0;
    assert(NFQRcvbufSet(7, 16777216, &effective) == -1 && calls == 1);
    calls = 0;
    assert(NFQRcvbufSet(7, 0, &effective) == -1 && calls == 0);
    assert(NFQRcvbufSet(7, UINT32_MAX, &effective) == -1 && calls == 0);
    return 0;
}
