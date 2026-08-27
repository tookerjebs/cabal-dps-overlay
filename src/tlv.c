#include "tlv.h"

#include <string.h>

static uint32_t
len24(const uint8_t *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16);
}

static void
walk_tlv(const uint8_t *inner, size_t n, pw_field23_fn cb, void *ctx)
{
    size_t i = 0;
    while (i + 3 <= n) {
        uint8_t tag = inner[i];
        uint8_t fid = inner[i + 1];
        if (tag == 5) {
            uint8_t ln = inner[i + 2];
            if (i + 3 + ln > n) {
                break;
            }
            if (fid == 0x23) {
                cb(inner + i + 3, ln, ctx);
            }
            i += 3u + ln;
            continue;
        }
        if (tag == 9) {
            if (fid == 0x23 && i + 4 <= n) {
                cb(inner + i + 4, n - (i + 4), ctx);
            }
            break;
        }
        break;
    }
}

void
pw_each_field23(const uint8_t *stream, size_t len, pw_field23_fn cb, void *ctx)
{
    size_t i = 0;
    if (stream == NULL || cb == NULL) {
        return;
    }
    while (i + 4 <= len) {
        uint32_t ln;
        if (stream[i] != 1) {
            const uint8_t *nxt = (const uint8_t *)memchr(stream + i + 1, 1, len - i - 1);
            if (nxt == NULL) {
                break;
            }
            i = (size_t)(nxt - stream);
            continue;
        }
        ln = len24(stream + i + 1);
        if (ln < 1 || ln > 0x20000u || i + 4 + ln > len) {
            i += 1;
            continue;
        }
        walk_tlv(stream + i + 4, ln, cb, ctx);
        i += 4 + ln;
    }
}
