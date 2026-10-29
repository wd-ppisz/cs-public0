/* SPDX-License-Identifier: GPL-2.0-only
 * Explicit NFQUEUE socket capacity, independent of packet queue depth.
 * Linux reports twice the SO_RCVBUF request, including bookkeeping space.
 */
#ifndef CS_PUBLIC0_NFQ_RCVBUF_H
#define CS_PUBLIC0_NFQ_RCVBUF_H
#include <stddef.h>
#include <stdint.h>
#include <sys/socket.h>

#define NFQ_RCVBUF_MIN (1024U * 1024U)
#define NFQ_RCVBUF_MAX (64U * 1024U * 1024U)

static inline int NFQRcvbufParse(const char *text, uint32_t *result)
{
    uint32_t value = 0;
    if (text == NULL || text[0] < '1' || text[0] > '9')
        return -1;
    for (const char *p = text; *p != '\0'; p++) {
        if (*p < '0' || *p > '9' || value > NFQ_RCVBUF_MAX / 10U)
            return -1;
        value = value * 10U + (uint32_t)(*p - '0');
        if (value > NFQ_RCVBUF_MAX)
            return -1;
    }
    if (value < NFQ_RCVBUF_MIN)
        return -1;
    *result = value;
    return 0;
}

static inline int NFQRcvbufSet(int fd, uint32_t requested, int *effective)
{
    int value = (int)requested;
    socklen_t length = sizeof(*effective);
    if (requested < NFQ_RCVBUF_MIN || requested > NFQ_RCVBUF_MAX)
        return -1;
    /* Do not use SO_RCVBUFFORCE: a host policy limit must remain effective. */
    if (setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &value, sizeof(value)) != 0 ||
            getsockopt(fd, SOL_SOCKET, SO_RCVBUF, effective, &length) != 0 ||
            length != sizeof(*effective) || *effective != (int)(requested * 2U))
        return -1;
    return 0;
}
#endif
