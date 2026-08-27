#ifndef PLAYCABAL_WIRE_OSTARA_H
#define PLAYCABAL_WIRE_OSTARA_H

#include <stddef.h>
#include <stdint.h>

#define PW_HEADER_XOR 0xD15FA427u
#define PW_TABLE_BYTES 0x10000u
#define PW_TABLE_DWORDS 0x4000u
#define PW_MAGIC_NORMAL 0xB7E2u
#define PW_MAGIC_CHECKSUM 0xC8F3u

uint32_t pw_load_u32(const uint8_t *p);
int pw_packet_size(const uint8_t *packet, size_t len, const uint8_t *table);
/* Decrypt in place into out. Returns plaintext length, or 0 on failure. */
size_t pw_decrypt(const uint8_t *packet, size_t len, const uint8_t *table, uint8_t *out, size_t out_cap);

#endif
