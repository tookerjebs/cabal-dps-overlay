#include "ostara.h"

#include <string.h>

uint32_t
pw_load_u32(const uint8_t *p)
{
    uint32_t v;
    memcpy(&v, p, 4);
    return v;
}

static void
pw_store_u32(uint8_t *p, uint32_t v)
{
    memcpy(p, &v, 4);
}

int
pw_packet_size(const uint8_t *packet, size_t len, const uint8_t *table)
{
    uint32_t first;
    uint32_t header;
    uint32_t magic;
    uint32_t t;
    uint32_t key;
    uint32_t xh0;
    uint32_t xh1;
    uint64_t xheader;

    if (len < 4 || table == NULL) {
        return 0;
    }
    first = pw_load_u32(packet);
    header = first ^ PW_HEADER_XOR;
    magic = header & 0xFFFFu;
    if (magic == PW_MAGIC_CHECKSUM) {
        if (len < 8) {
            return 0;
        }
        t = (first & 0x3FFFu) * 4u;
        key = pw_load_u32(table + t);
        xh0 = first ^ PW_HEADER_XOR;
        xh1 = pw_load_u32(packet + 4) ^ key;
        xheader = (((uint64_t)xh1 << 32) | xh0) >> 16;
        return (int)(xheader & 0xFFFFFFFFu);
    }
    if (magic != PW_MAGIC_NORMAL) {
        return 0;
    }
    return (int)(header >> 16);
}

size_t
pw_decrypt(const uint8_t *packet, size_t len, const uint8_t *table, uint8_t *out, size_t out_cap)
{
    int size;
    uint32_t first;
    uint32_t key;
    uint32_t t1;
    int remain;
    int aligned;
    int i;
    uint16_t magic;

    if (packet == NULL || table == NULL || out == NULL || len < 4) {
        return 0;
    }
    size = pw_packet_size(packet, len, table);
    if (size < 4 || (size_t)size > len || (size_t)size > out_cap || size > 0x4D000) {
        return 0;
    }
    memcpy(out, packet, (size_t)size);
    first = pw_load_u32(out);
    key = pw_load_u32(table + (first & 0x3FFFu) * 4u);
    pw_store_u32(out, first ^ PW_HEADER_XOR);
    remain = (size - 4) & 3;
    aligned = size - remain;
    i = 4;
    while (i < aligned) {
        t1 = pw_load_u32(out + i);
        key ^= t1;
        pw_store_u32(out + i, key);
        t1 &= 0x3FFFu;
        key = pw_load_u32(table + t1 * 4u);
        i += 4;
    }
    if (remain) {
        uint32_t raw = 0;
        uint32_t mask;
        uint32_t xored;
        memcpy(&raw, out + i, (size_t)remain);
        mask = 0xFFFFFFFFu >> (8 * (4 - remain));
        xored = (raw ^ (key & mask)) & mask;
        memcpy(out + i, &xored, (size_t)remain);
    }
    memcpy(&magic, out, 2);
    if (magic != PW_MAGIC_NORMAL && magic != PW_MAGIC_CHECKSUM) {
        return 0;
    }
    return (size_t)size;
}
