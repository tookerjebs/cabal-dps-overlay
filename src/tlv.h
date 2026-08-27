#ifndef PLAYCABAL_WIRE_TLV_H
#define PLAYCABAL_WIRE_TLV_H

#include <stddef.h>
#include <stdint.h>

typedef void (*pw_field23_fn)(const uint8_t *payload, size_t len, void *ctx);

void pw_each_field23(const uint8_t *stream, size_t len, pw_field23_fn cb, void *ctx);

#endif
