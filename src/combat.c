#include "combat.h"
#include "ostara.h"

#include <string.h>

static uint16_t
load_u16(const uint8_t *p)
{
    uint16_t v;
    memcpy(&v, p, 2);
    return v;
}

static uint32_t
load_u32(const uint8_t *p)
{
    uint32_t v;
    memcpy(&v, p, 4);
    return v;
}

static int32_t
load_i32(const uint8_t *p)
{
    int32_t v;
    memcpy(&v, p, 4);
    return v;
}

int
pw_parse_ae(const uint8_t *plain, size_t len, PwAeHit *out)
{
    uint16_t magic;
    uint16_t size;
    uint16_t cmd;
    unsigned wanted;
    unsigned fit;
    unsigned n;
    unsigned i;
    uint64_t sum = 0;
    PwAeHit hit;

    if (plain == NULL || out == NULL || len < 6) {
        return 0;
    }
    magic = load_u16(plain);
    size = load_u16(plain + 2);
    cmd = load_u16(plain + 4);
    if (magic != PW_MAGIC_NORMAL || cmd != PW_AE_CMD || size < PW_AE_SIZE ||
        size > len) {
        return 0;
    }
    memset(&hit, 0, sizeof(hit));
    hit.skill = load_u16(plain + PW_AE_SKILL);
    hit.caster = load_u32(plain + PW_AE_CASTER);
    hit.pkt_size = size;
    hit.hit_count = (size > PW_AE_HITCOUNT) ? plain[PW_AE_HITCOUNT] : 1;
    wanted = hit.hit_count ? hit.hit_count : 1u;
    if (wanted > PW_AE_HIT_CAP) {
        wanted = PW_AE_HIT_CAP;
    }
    fit = (unsigned)((size - PW_AE_HIT_OFF) / PW_AE_HIT_STRIDE);
    if (fit < 1) {
        return 0;
    }
    n = wanted < fit ? wanted : fit;
    for (i = 0; i < n; i++) {
        const uint8_t *rec = plain + PW_AE_HIT_OFF + i * PW_AE_HIT_STRIDE;
        int32_t dmg;
        int32_t copy;
        if ((size_t)((rec + PW_AE_HIT_COPY + 4) - plain) > size) {
            break;
        }
        hit.targets[i] = load_u32(rec);
        dmg = load_i32(rec + PW_AE_HIT_DMG);
        copy = load_i32(rec + PW_AE_HIT_COPY);
        if (dmg <= 0 && copy > 0) {
            dmg = copy;
        }
        hit.parts[i] = dmg;
        if (i == 0) {
            hit.damage_copy = copy;
            if ((size_t)((rec + PW_AE_HIT_HP + 4) - plain) <= size) {
                hit.hp = load_i32(rec + PW_AE_HIT_HP);
            }
        }
        if (dmg > 0) {
            sum += (uint64_t)(uint32_t)dmg;
        }
        hit.n_hits = i + 1;
    }
    if (!hit.n_hits || !sum || sum > 0x7FFFFFFFull) {
        return 0;
    }
    hit.damage = (int32_t)sum;
    *out = hit;
    return 1;
}
