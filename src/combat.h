#ifndef PLAYCABAL_WIRE_COMBAT_H
#define PLAYCABAL_WIRE_COMBAT_H

#include <stddef.h>
#include <stdint.h>

#define PW_AE_SIZE 137
#define PW_AE_CMD 0xAEu
#define PW_AE_SKILL 0x06u
#define PW_AE_CASTER 0x08u
#define PW_AE_HITCOUNT 0x61u
#define PW_AE_HIT_OFF 0x62u
#define PW_AE_HIT_STRIDE 0x27u
#define PW_AE_HIT_CAP 16u
#define PW_AE_HIT_DMG 0x06u
#define PW_AE_HIT_COPY 0x0Au
#define PW_AE_HIT_HP 0x12u
#define PW_AE_DAMAGE 0x68u
#define PW_AE_DAMAGE_COPY 0x6Cu
#define PW_AE_HP 0x74u

typedef struct {
    uint16_t skill;
    uint32_t caster;
    uint16_t pkt_size;
    uint8_t hit_count;
    unsigned n_hits;
    int32_t damage;
    int32_t damage_copy;
    int32_t hp;
    int32_t parts[PW_AE_HIT_CAP];
    uint32_t targets[PW_AE_HIT_CAP];
} PwAeHit;

int pw_parse_ae(const uint8_t *plain, size_t len, PwAeHit *out);

#endif
