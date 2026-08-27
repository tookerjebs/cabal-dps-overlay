#ifndef PLAYCABAL_WIRE_INGEST_H
#define PLAYCABAL_WIRE_INGEST_H

#include <stdint.h>

#define PW_GRAPH_SECS 30u
#define PW_SKILL_UI 6u

#define PW_NOTICE_NONE 0
#define PW_NOTICE_NPCAP 1
#define PW_NOTICE_KEYCHAIN 2
#define PW_NOTICE_CAPTURE 3
#define PW_NOTICE_STALE 4

typedef struct {
    uint32_t id;
    uint64_t dmg;
    unsigned casts;
    unsigned avg_ms;
} PwSkillRow;

typedef struct {
    uint64_t session_total;
    uint64_t last_skill_total;
    uint64_t skill_total;
    uint32_t skill_id;
    unsigned skill_hits;
    int have_last_skill;
    int skill_open;
    int in_combat;
    int capture_ok;
    int notice;
    unsigned last_parts_n;
    uint64_t last_parts[4];
    double dps;
    double peak_dps;
    unsigned ae_ok;
    unsigned ae_dup;
    unsigned ifaces;
    unsigned decrypted;
    uint64_t graph[PW_GRAPH_SECS];
    unsigned skill_n;
    PwSkillRow skills[PW_SKILL_UI];
    char status[96];
} PwMeterSnap;

int pw_ingest_start(const char *table_path, char *err, int errlen);
void pw_ingest_stop(void);
void pw_ingest_reset(void);
void pw_ingest_snap(PwMeterSnap *out);

#endif
