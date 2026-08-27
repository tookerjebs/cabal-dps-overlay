#include "ingest.h"
#include "combat.h"
#include "ostara.h"
#include "pcap_dyn.h"
#include "tlv.h"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <winsock2.h>
#include <windows.h>
#include <iphlpapi.h>
#include <tlhelp32.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>

#define FLOW_CAP 16
#define FLOW_BUF 65536
#define HASH_CAP 48
#define SKILL_CAP 32
#define GRAPH_SECS PW_GRAPH_SECS
#define DUP_MS 50ull
#define COMBAT_IDLE_MS 4000ull
#define GAP_ALERT_MS 800ull
#define PORT_CAP 32
#define PORT_REFRESH_MS 500ull
/* ExitLag world TCP ports move per session/PoP. Do not hardcode 15258/36904/50166.
 * Follow CabalMain sockets; still accept ExitLag/Ostara-shaped payloads if the
 * table is a moment behind a reconnect. BPF only drops HTTPS/web noise. */
#define FILTER "tcp and not port 443 and not port 80"
#define PCAP_CAP 8

typedef struct {
    uint32_t sip, dip;
    uint16_t sport, dport;
    unsigned used;
    uint8_t buf[FLOW_BUF];
} PwFlow;

typedef struct {
    CRITICAL_SECTION lock;
    HANDLE threads[PCAP_CAP];
    unsigned nthreads;
    volatile LONG run;
    uint8_t table[PW_TABLE_BYTES];
    int have_table;
    PwFlow flows[FLOW_CAP];
    unsigned nflows;
    uint64_t hashes[HASH_CAP];
    uint64_t hash_at[HASH_CAP];
    unsigned hash_i;
    unsigned hash_n;
    uint64_t session_total;
    uint64_t first_ms;
    uint64_t last_ms;
    double peak_dps;
    uint32_t skill_id;
    uint64_t skill_total;
    unsigned skill_hits;
    int skill_open;
    int have_last_skill;
    uint64_t last_skill_total;
    unsigned last_parts_n;
    uint64_t last_parts[4];
    uint64_t graph_dmg[GRAPH_SECS];
    uint64_t graph_sec[GRAPH_SECS];
    uint64_t last_graph_sec;
    uint32_t skill_ids[SKILL_CAP];
    uint64_t skill_dmg[SKILL_CAP];
    unsigned skill_casts[SKILL_CAP];
    uint64_t skill_last_ms[SKILL_CAP];
    uint64_t skill_gap_sum[SKILL_CAP];
    unsigned skill_gaps[SKILL_CAP];
    unsigned nskills;
    unsigned ae_ok;
    unsigned ae_dup;
    unsigned decrypted;
    unsigned decrypt_fail;
    unsigned ae_shaped_fail;
    int notice;
    unsigned ifaces;
    char status[96];
    pw_pcap_t *pcaps[PCAP_CAP];
    int dlts[PCAP_CAP];
    unsigned npcap;
    int lock_inited;
    FILE *log;
    uint64_t log_first_ms;
    uint16_t cabal_ports[PORT_CAP];
    unsigned n_cabal_ports;
    uint64_t ports_at;
    uint16_t log_sport;
} PwIngest;

static PwIngest g_ing;

static void
log_ae(const PwAeHit *hit, uint64_t t, const uint8_t *plain)
{
    uint64_t rel;
    uint64_t dt;
    if (!g_ing.log || !hit) {
        return;
    }
    if (!g_ing.log_first_ms) {
        g_ing.log_first_ms = t;
    }
    rel = t - g_ing.log_first_ms;
    dt = (g_ing.last_ms && g_ing.ae_ok) ? (t - g_ing.last_ms) : 0;
    fprintf(g_ing.log,
            "t=%llu dt=%llu sport=%u skill=%u hits=%u dmg=%d copy=%d hp=%d caster=%u  hex60=",
            (unsigned long long)rel,
            (unsigned long long)dt,
            (unsigned)g_ing.log_sport,
            hit->skill,
            (unsigned)hit->hit_count,
            hit->damage,
            hit->damage_copy,
            hit->hp,
            hit->caster);
    if (plain && hit->pkt_size > 0x60) {
        unsigned i;
        unsigned end = hit->pkt_size;
        if (end > 0xB0) {
            end = 0xB0;
        }
        for (i = 0x60; i < end; i++) {
            fprintf(g_ing.log, "%02X", plain[i]);
        }
    }
    if (dt >= GAP_ALERT_MS) {
        fprintf(g_ing.log, "  *** GAP ae=%u dup=%u", g_ing.ae_ok, g_ing.ae_dup);
    }
    fputc('\n', g_ing.log);
    fflush(g_ing.log);
}

static uint16_t
be16(const uint8_t *p)
{
    return (uint16_t)((p[0] << 8) | p[1]);
}

static uint64_t
now_ms(void)
{
    return GetTickCount64();
}

static uint64_t
fnv(const uint8_t *p, size_t n)
{
    uint64_t h = 1469598103934665603ull;
    size_t i;
    for (i = 0; i < n; i++) {
        h ^= p[i];
        h *= 1099511628211ull;
    }
    return h;
}

static int
hash_seen(uint64_t h, uint64_t t)
{
    unsigned i;
    for (i = 0; i < g_ing.hash_n && i < HASH_CAP; i++) {
        if (g_ing.hashes[i] == h) {
            if (t >= g_ing.hash_at[i] && t - g_ing.hash_at[i] <= DUP_MS) {
                return 1;
            }
            g_ing.hash_at[i] = t;
            return 0;
        }
    }
    i = g_ing.hash_i % HASH_CAP;
    g_ing.hashes[i] = h;
    g_ing.hash_at[i] = t;
    g_ing.hash_i++;
    if (g_ing.hash_n < HASH_CAP) {
        g_ing.hash_n++;
    }
    return 0;
}

static void
maybe_close_graph(uint64_t sec_now)
{
    unsigned old;
    uint64_t v;
    if (!g_ing.last_graph_sec || sec_now <= g_ing.last_graph_sec) {
        return;
    }
    old = (unsigned)(g_ing.last_graph_sec % GRAPH_SECS);
    if (g_ing.graph_sec[old] == g_ing.last_graph_sec) {
        v = g_ing.graph_dmg[old];
        if ((double)v > g_ing.peak_dps) {
            g_ing.peak_dps = (double)v;
        }
    }
}

static void
note_graph(uint64_t t, uint64_t dmg)
{
    uint64_t sec = t / 1000ull;
    unsigned slot = (unsigned)(sec % GRAPH_SECS);
    maybe_close_graph(sec);
    g_ing.last_graph_sec = sec;
    if (g_ing.graph_sec[slot] != sec) {
        g_ing.graph_sec[slot] = sec;
        g_ing.graph_dmg[slot] = 0;
    }
    g_ing.graph_dmg[slot] += dmg;
}

static void
note_skill(uint32_t id, uint64_t dmg, uint64_t t)
{
    unsigned i;
    for (i = 0; i < g_ing.nskills; i++) {
        if (g_ing.skill_ids[i] == id) {
            if (g_ing.skill_last_ms[i] && t > g_ing.skill_last_ms[i]) {
                uint64_t dt = t - g_ing.skill_last_ms[i];
                if (dt <= COMBAT_IDLE_MS) {
                    g_ing.skill_gap_sum[i] += dt;
                    g_ing.skill_gaps[i]++;
                }
            }
            g_ing.skill_last_ms[i] = t;
            g_ing.skill_dmg[i] += dmg;
            g_ing.skill_casts[i]++;
            return;
        }
    }
    if (g_ing.nskills >= SKILL_CAP) {
        return;
    }
    i = g_ing.nskills++;
    g_ing.skill_ids[i] = id;
    g_ing.skill_dmg[i] = dmg;
    g_ing.skill_casts[i] = 1;
    g_ing.skill_last_ms[i] = t;
    g_ing.skill_gap_sum[i] = 0;
    g_ing.skill_gaps[i] = 0;
}

static int
skill_rank_cmp(const void *a, const void *b)
{
    const unsigned *ia = (const unsigned *)a;
    const unsigned *ib = (const unsigned *)b;
    if (g_ing.skill_dmg[*ib] > g_ing.skill_dmg[*ia]) {
        return 1;
    }
    if (g_ing.skill_dmg[*ib] < g_ing.skill_dmg[*ia]) {
        return -1;
    }
    return 0;
}

static void
on_ae(const uint8_t *plain, size_t n)
{
    PwAeHit hit;
    uint64_t t = now_ms();
    uint64_t h;
    uint64_t dmg;

    if (!pw_parse_ae(plain, n, &hit) || hit.damage <= 0) {
        return;
    }
    h = fnv(plain, hit.pkt_size && hit.pkt_size <= n ? hit.pkt_size : n);
    if (hash_seen(h, t)) {
        g_ing.ae_dup++;
        return;
    }
    dmg = (uint64_t)(uint32_t)hit.damage;
    g_ing.skill_id = hit.skill;
    g_ing.skill_total = dmg;
    g_ing.last_skill_total = dmg;
    g_ing.skill_hits = hit.n_hits;
    g_ing.last_parts_n = hit.n_hits;
    {
        unsigned i;
        unsigned cap = hit.n_hits < 4u ? hit.n_hits : 4u;
        for (i = 0; i < 4; i++) {
            g_ing.last_parts[i] = 0;
        }
        for (i = 0; i < cap; i++) {
            if (hit.parts[i] > 0) {
                g_ing.last_parts[i] = (uint64_t)(uint32_t)hit.parts[i];
            }
        }
    }
    g_ing.skill_open = 1;
    g_ing.have_last_skill = 1;
    g_ing.session_total += dmg;
    note_graph(t, dmg);
    note_skill(hit.skill, dmg, t);
    if (!g_ing.first_ms) {
        g_ing.first_ms = t;
    }
    log_ae(&hit, t, plain);
    g_ing.last_ms = t;
    g_ing.ae_ok++;
}

static void
try_plain(const uint8_t *cipher, size_t len)
{
    uint8_t plain[2048];
    size_t n;

    if (len > sizeof(plain)) {
        len = sizeof(plain);
    }
    n = pw_decrypt(cipher, len, g_ing.table, plain, sizeof(plain));
    if (!n) {
        g_ing.decrypt_fail++;
        return;
    }
    g_ing.decrypted++;
    {
        unsigned before = g_ing.ae_ok;
        uint16_t cmd = 0;
        on_ae(plain, n);
        if (n >= 6) {
            memcpy(&cmd, plain + 4, 2);
        }
        if (cmd == PW_AE_CMD && g_ing.ae_ok == before) {
            g_ing.ae_shaped_fail++;
        }
    }
}

static void
on_field23(const uint8_t *payload, size_t len, void *ctx)
{
    (void)ctx;
    try_plain(payload, len);
}

static void
drain_flow(PwFlow *f)
{
    unsigned guard = 0;
    while (f->used >= 4 && guard++ < 256) {
        if (f->buf[0] == 1) {
            uint32_t ln = (uint32_t)f->buf[1] | ((uint32_t)f->buf[2] << 8) |
                          ((uint32_t)f->buf[3] << 16);
            if (ln < 1 || ln > 0x20000) {
                memmove(f->buf, f->buf + 1, f->used - 1);
                f->used--;
                continue;
            }
            if (4 + ln > f->used) {
                break;
            }
            pw_each_field23(f->buf, 4 + ln, on_field23, NULL);
            memmove(f->buf, f->buf + 4 + ln, f->used - (4 + ln));
            f->used -= 4 + ln;
            continue;
        }
        {
            int sz = pw_packet_size(f->buf, f->used, g_ing.table);
            if (sz < 4 || sz > 0x10000) {
                memmove(f->buf, f->buf + 1, f->used - 1);
                f->used--;
                continue;
            }
            if ((unsigned)sz > f->used) {
                break;
            }
            try_plain(f->buf, (unsigned)sz);
            memmove(f->buf, f->buf + (unsigned)sz, f->used - (unsigned)sz);
            f->used -= (unsigned)sz;
        }
    }
}

static PwFlow *
flow_get(uint32_t sip, uint32_t dip, uint16_t sport, uint16_t dport)
{
    unsigned i;
    PwFlow *f;
    for (i = 0; i < g_ing.nflows; i++) {
        f = &g_ing.flows[i];
        if (f->sip == sip && f->dip == dip && f->sport == sport && f->dport == dport) {
            return f;
        }
    }
    if (g_ing.nflows < FLOW_CAP) {
        i = g_ing.nflows++;
    } else {
        i = 0;
    }
    f = &g_ing.flows[i];
    memset(f, 0, sizeof(*f));
    f->sip = sip;
    f->dip = dip;
    f->sport = sport;
    f->dport = dport;
    return f;
}

static int
port_boring(uint16_t p)
{
    return p == 0 || p == 80 || p == 443 || p == 53 || p == 853;
}

static int
port_in_list(const uint16_t *ports, unsigned n, uint16_t p)
{
    unsigned i;
    for (i = 0; i < n; i++) {
        if (ports[i] == p) {
            return 1;
        }
    }
    return 0;
}

static void
add_port(uint16_t *ports, unsigned *n, uint16_t p)
{
    if (port_boring(p) || *n >= PORT_CAP || port_in_list(ports, *n, p)) {
        return;
    }
    ports[(*n)++] = p;
}

static DWORD
find_cabal_pid(void)
{
    HANDLE snap;
    PROCESSENTRY32W pe;
    DWORD pid = 0;

    snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) {
        return 0;
    }
    pe.dwSize = sizeof(pe);
    if (Process32FirstW(snap, &pe)) {
        do {
            if (_wcsicmp(pe.szExeFile, L"CabalMain.exe") == 0) {
                pid = pe.th32ProcessID;
                break;
            }
        } while (Process32NextW(snap, &pe));
    }
    CloseHandle(snap);
    return pid;
}

static void
log_cabal_ports(DWORD pid, const uint16_t *ports, unsigned n)
{
    unsigned i;
    if (!g_ing.log) {
        return;
    }
    fprintf(g_ing.log, "cabal pid=%lu ports=", (unsigned long)pid);
    for (i = 0; i < n; i++) {
        fprintf(g_ing.log, "%s%u", i ? "," : "", (unsigned)ports[i]);
    }
    fputc('\n', g_ing.log);
    fflush(g_ing.log);
}

static void
refresh_cabal_ports(void)
{
    uint16_t found[PORT_CAP];
    unsigned nfound = 0;
    uint64_t t = now_ms();
    DWORD pid;
    DWORD sz = 0;
    DWORD err;
    MIB_TCPTABLE_OWNER_PID *tbl = NULL;
    DWORD i;
    int changed;
    int ok = 0;

    EnterCriticalSection(&g_ing.lock);
    if (g_ing.ports_at && t - g_ing.ports_at < PORT_REFRESH_MS) {
        LeaveCriticalSection(&g_ing.lock);
        return;
    }
    g_ing.ports_at = t;
    LeaveCriticalSection(&g_ing.lock);

    pid = find_cabal_pid();
    if (!pid) {
        ok = 1;
    } else {
        err = GetExtendedTcpTable(NULL, &sz, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
        if (err == ERROR_INSUFFICIENT_BUFFER && sz) {
            tbl = (MIB_TCPTABLE_OWNER_PID *)malloc(sz);
            if (tbl) {
                err = GetExtendedTcpTable(tbl, &sz, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
                if (err == NO_ERROR) {
                    ok = 1;
                    for (i = 0; i < tbl->dwNumEntries; i++) {
                        if (tbl->table[i].dwOwningPid != pid) {
                            continue;
                        }
                        add_port(found, &nfound, ntohs((u_short)tbl->table[i].dwLocalPort));
                        add_port(found, &nfound, ntohs((u_short)tbl->table[i].dwRemotePort));
                    }
                }
                free(tbl);
            }
        }
    }
    if (!ok) {
        return;
    }

    EnterCriticalSection(&g_ing.lock);
    changed = nfound != g_ing.n_cabal_ports ||
              memcmp(found, g_ing.cabal_ports, nfound * sizeof(uint16_t)) != 0;
    g_ing.n_cabal_ports = nfound;
    if (nfound) {
        memcpy(g_ing.cabal_ports, found, nfound * sizeof(uint16_t));
    }
    if (changed) {
        g_ing.decrypt_fail = 0;
        g_ing.ae_shaped_fail = 0;
    }
    LeaveCriticalSection(&g_ing.lock);
    if (changed) {
        log_cabal_ports(pid, found, nfound);
    }
}

static unsigned
copy_cabal_ports(uint16_t *out)
{
    unsigned n;
    EnterCriticalSection(&g_ing.lock);
    n = g_ing.n_cabal_ports;
    if (n > PORT_CAP) {
        n = PORT_CAP;
    }
    if (n) {
        memcpy(out, g_ing.cabal_ports, n * sizeof(uint16_t));
    }
    LeaveCriticalSection(&g_ing.lock);
    return n;
}

static int
want_payload(uint16_t sport, uint16_t dport, const uint8_t *payload, unsigned n)
{
    uint16_t copy[PORT_CAP];
    unsigned np;
    int sz;

    refresh_cabal_ports();
    if (port_boring(sport)) {
        return 0;
    }
    np = copy_cabal_ports(copy);
    if (port_in_list(copy, np, sport) || port_in_list(copy, np, dport)) {
        return 1;
    }
    if (!payload || n < 4 || !g_ing.have_table) {
        return 0;
    }
    if (payload[0] == 1) {
        return 1;
    }
    sz = pw_packet_size(payload, n, g_ing.table);
    return sz >= 4 && sz <= 0x10000;
}

static void
accept_payload(uint32_t sip, uint32_t dip, uint16_t sport, uint16_t dport,
               const uint8_t *payload, unsigned n)
{
    PwFlow *f;
    unsigned room;
    if (!n || !g_ing.have_table || !want_payload(sport, dport, payload, n)) {
        return;
    }
    g_ing.log_sport = sport;
    f = flow_get(sip, dip, sport, dport);
    if (n >= FLOW_BUF) {
        n = FLOW_BUF - 1;
    }
    if (f->used + n > FLOW_BUF) {
        f->used = 0;
    }
    room = FLOW_BUF - f->used;
    if (n > room) {
        n = room;
    }
    memcpy(f->buf + f->used, payload, n);
    f->used += n;
    drain_flow(f);
}

static const uint8_t *
skip_l2(const uint8_t *pkt, unsigned cap, int dlt, unsigned *left)
{
    unsigned off = 0;
    if (dlt == PW_DLT_EN10MB) {
        if (cap < 14) {
            return NULL;
        }
        if (be16(pkt + 12) == 0x8100) {
            off = 18;
        } else {
            off = 14;
        }
    } else if (dlt == PW_DLT_NULL || dlt == PW_DLT_LOOP) {
        off = 4;
    } else if (dlt == PW_DLT_RAW || dlt == PW_DLT_IPV4) {
        off = 0;
    } else {
        if (cap > 14 && be16(pkt + 12) == 0x0800) {
            off = 14;
        } else {
            off = 0;
        }
    }
    if (off >= cap) {
        return NULL;
    }
    *left = cap - off;
    return pkt + off;
}

static void
handle_ip(const uint8_t *ip, unsigned n)
{
    unsigned ihl;
    unsigned tot;
    unsigned doff;
    const uint8_t *tcp;
    unsigned payload_off;
    unsigned payload_n;
    uint16_t sport, dport;

    if (n < 20 || (ip[0] >> 4) != 4 || ip[9] != 6) {
        return;
    }
    ihl = (ip[0] & 0x0Fu) * 4u;
    tot = be16(ip + 2);
    if (ihl < 20 || tot < ihl + 20 || tot > n) {
        tot = n;
    }
    tcp = ip + ihl;
    if ((unsigned)(tcp - ip) + 20 > tot) {
        return;
    }
    doff = ((tcp[12] >> 4) & 0x0Fu) * 4u;
    if (doff < 20) {
        return;
    }
    payload_off = ihl + doff;
    if (payload_off >= tot) {
        return;
    }
    payload_n = tot - payload_off;
    sport = be16(tcp);
    dport = be16(tcp + 2);
    accept_payload(pw_load_u32(ip + 12), pw_load_u32(ip + 16), sport, dport,
                   ip + payload_off, payload_n);
}

typedef struct {
    int dlt;
} PktUser;

static void
on_pkt(unsigned char *user, const pw_pcap_pkthdr *hdr, const unsigned char *pkt)
{
    PktUser *u = (PktUser *)user;
    unsigned left = 0;
    const uint8_t *ip;
    if (!hdr || !pkt || hdr->caplen < 20) {
        return;
    }
    ip = skip_l2(pkt, hdr->caplen, u->dlt, &left);
    if (!ip) {
        return;
    }
    EnterCriticalSection(&g_ing.lock);
    handle_ip(ip, left);
    LeaveCriticalSection(&g_ing.lock);
}

static DWORD WINAPI
capture_one(LPVOID arg)
{
    unsigned idx = (unsigned)(uintptr_t)arg;
    PktUser u;

    u.dlt = g_ing.dlts[idx];
    while (InterlockedCompareExchange(&g_ing.run, 1, 1) == 1) {
        int n = pw_pcap_dispatch(g_ing.pcaps[idx], 32, on_pkt, (unsigned char *)&u);
        if (n <= 0) {
            Sleep(1);
        }
    }
    return 0;
}

static int
iface_rank(const pw_pcap_if *it)
{
    char buf[512];

    buf[0] = 0;
    if (it && it->name) {
        lstrcpynA(buf, it->name, 256);
    }
    if (it && it->description) {
        size_t n = strlen(buf);
        if (n + 2 < sizeof(buf)) {
            buf[n] = ' ';
            lstrcpynA(buf + n + 1, it->description, (int)(sizeof(buf) - n - 2));
        }
    }
    CharLowerA(buf);
    if (strstr(buf, "bluetooth") || strstr(buf, "wsl") || strstr(buf, "hyper-v") ||
        strstr(buf, "etw")) {
        return -1;
    }
    if (strstr(buf, "loopback")) {
        return 0;
    }
    if (strstr(buf, "ethernet") || strstr(buf, "wi-fi") || strstr(buf, "wifi") ||
        strstr(buf, "wlan")) {
        return 1;
    }
    return 2;
}

static int
open_iface(pw_pcap_if *it, char *perr)
{
    pw_pcap_t *p;
    if (!it || !it->name) {
        return 0;
    }
    p = pw_pcap_open_live(it->name, 65535, 0, 1, perr);
    if (!p) {
        return 0;
    }
    if (pw_pcap_setfilter(p, FILTER) < 0) {
        pw_pcap_close(p);
        return 0;
    }
    g_ing.dlts[g_ing.npcap] = pw_pcap_datalink(p);
    g_ing.pcaps[g_ing.npcap++] = p;
    if (g_ing.log) {
        fprintf(g_ing.log, "open %s (%s)\n", it->name ? it->name : "?",
                it->description ? it->description : "");
        fflush(g_ing.log);
    }
    return 1;
}

static int
load_table(const char *path)
{
    FILE *f = fopen(path, "rb");
    size_t n;
    if (!f) {
        return 0;
    }
    n = fread(g_ing.table, 1, PW_TABLE_BYTES, f);
    fclose(f);
    g_ing.have_table = n == PW_TABLE_BYTES;
    return g_ing.have_table;
}

static void
open_log(void)
{
    wchar_t exe[MAX_PATH];
    wchar_t path[MAX_PATH];
    wchar_t *slash;
    char utf[MAX_PATH];

    if (!GetModuleFileNameW(NULL, exe, MAX_PATH)) {
        return;
    }
    slash = wcsrchr(exe, L'\\');
    if (!slash) {
        return;
    }
    slash[1] = 0;
    lstrcpyW(path, exe);
    lstrcatW(path, L"cabal-dps.log");
    WideCharToMultiByte(CP_ACP, 0, path, -1, utf, MAX_PATH, NULL, NULL);
    g_ing.log = fopen(utf, "a");
    if (g_ing.log) {
        fprintf(g_ing.log, "---- start ----\n");
        fflush(g_ing.log);
    }
}

int
pw_ingest_start(const char *table_path, char *err, int errlen)
{
    char perr[PW_PCAP_ERRBUF];
    pw_pcap_if *all = NULL;
    pw_pcap_if *it;
    unsigned i;
    int pass;
    wchar_t exe[MAX_PATH];
    wchar_t alt[MAX_PATH];
    char table_try[MAX_PATH];

    memset(&g_ing, 0, sizeof(g_ing));
    InitializeCriticalSection(&g_ing.lock);
    g_ing.lock_inited = 1;
    open_log();
    lstrcpynA(g_ing.status, "starting", 96);

    if (table_path && load_table(table_path)) {
        /* ok */
    } else if (GetModuleFileNameW(NULL, exe, MAX_PATH)) {
        wchar_t *slash = wcsrchr(exe, L'\\');
        if (slash) {
            slash[1] = 0;
            lstrcpyW(alt, exe);
            lstrcatW(alt, L"keychain.bin");
            WideCharToMultiByte(CP_ACP, 0, alt, -1, table_try, MAX_PATH, NULL, NULL);
            load_table(table_try);
        }
    }
    if (!g_ing.have_table) {
        load_table("data\\keychain.bin");
    }
    if (!g_ing.have_table) {
        load_table("playcabal-wire\\data\\keychain.bin");
    }
    if (!g_ing.have_table) {
        if (err && errlen) {
            lstrcpynA(err, "missing keychain.bin", errlen);
        }
        lstrcpynA(g_ing.status, "no keychain.bin", 96);
        g_ing.notice = PW_NOTICE_KEYCHAIN;
        return 0;
    }

    if (!pw_pcap_load(perr, sizeof(perr))) {
        if (err && errlen) {
            lstrcpynA(err, perr, errlen);
        }
        lstrcpynA(g_ing.status, perr, 96);
        g_ing.notice = PW_NOTICE_NPCAP;
        return 0;
    }
    if (pw_pcap_findalldevs(&all, perr) < 0 || !all) {
        if (err && errlen) {
            lstrcpynA(err, perr[0] ? perr : "pcap_findalldevs failed", errlen);
        }
        lstrcpynA(g_ing.status, "no capture devices", 96);
        g_ing.notice = PW_NOTICE_NPCAP;
        return 0;
    }
    for (pass = 0; pass <= 2 && g_ing.npcap < PCAP_CAP; pass++) {
        for (it = all; it && g_ing.npcap < PCAP_CAP; it = it->next) {
            if (iface_rank(it) == pass) {
                open_iface(it, perr);
            }
        }
    }
    pw_pcap_freealldevs(all);
    g_ing.ifaces = g_ing.npcap;
    if (!g_ing.npcap) {
        lstrcpynA(g_ing.status, "no iface accepted filter", 96);
        if (err && errlen) {
            lstrcpynA(err, g_ing.status, errlen);
        }
        g_ing.notice = PW_NOTICE_CAPTURE;
        return 0;
    }
    sprintf_s(g_ing.status, 96, "npcap %u iface", g_ing.ifaces);
    refresh_cabal_ports();
    InterlockedExchange(&g_ing.run, 1);
    for (i = 0; i < g_ing.npcap; i++) {
        g_ing.threads[i] = CreateThread(NULL, 0, capture_one, (LPVOID)(uintptr_t)i, 0, NULL);
        if (g_ing.threads[i]) {
            g_ing.nthreads++;
        }
    }
    if (!g_ing.nthreads) {
        lstrcpynA(g_ing.status, "capture thread failed", 96);
        if (err && errlen) {
            lstrcpynA(err, g_ing.status, errlen);
        }
        g_ing.notice = PW_NOTICE_CAPTURE;
        return 0;
    }
    return 1;
}

void
pw_ingest_stop(void)
{
    unsigned i;
    InterlockedExchange(&g_ing.run, 0);
    for (i = 0; i < g_ing.npcap; i++) {
        pw_pcap_breakloop(g_ing.pcaps[i]);
    }
    for (i = 0; i < g_ing.npcap; i++) {
        if (g_ing.threads[i]) {
            WaitForSingleObject(g_ing.threads[i], 2000);
            CloseHandle(g_ing.threads[i]);
            g_ing.threads[i] = NULL;
        }
    }
    g_ing.nthreads = 0;
    for (i = 0; i < g_ing.npcap; i++) {
        pw_pcap_close(g_ing.pcaps[i]);
        g_ing.pcaps[i] = NULL;
    }
    g_ing.npcap = 0;
    if (g_ing.log) {
        fprintf(g_ing.log, "---- stop ----\n");
        fclose(g_ing.log);
        g_ing.log = NULL;
    }
    if (g_ing.lock_inited) {
        DeleteCriticalSection(&g_ing.lock);
        g_ing.lock_inited = 0;
    }
}

void
pw_ingest_reset(void)
{
    if (!g_ing.lock_inited) {
        return;
    }
    EnterCriticalSection(&g_ing.lock);
    g_ing.session_total = 0;
    g_ing.first_ms = 0;
    g_ing.last_ms = 0;
    g_ing.peak_dps = 0;
    g_ing.skill_id = 0;
    g_ing.skill_total = 0;
    g_ing.skill_hits = 0;
    g_ing.skill_open = 0;
    g_ing.have_last_skill = 0;
    g_ing.last_skill_total = 0;
    g_ing.last_parts_n = 0;
    memset(g_ing.last_parts, 0, sizeof(g_ing.last_parts));
    memset(g_ing.graph_dmg, 0, sizeof(g_ing.graph_dmg));
    memset(g_ing.graph_sec, 0, sizeof(g_ing.graph_sec));
    g_ing.last_graph_sec = 0;
    memset(g_ing.skill_ids, 0, sizeof(g_ing.skill_ids));
    memset(g_ing.skill_dmg, 0, sizeof(g_ing.skill_dmg));
    memset(g_ing.skill_casts, 0, sizeof(g_ing.skill_casts));
    memset(g_ing.skill_last_ms, 0, sizeof(g_ing.skill_last_ms));
    memset(g_ing.skill_gap_sum, 0, sizeof(g_ing.skill_gap_sum));
    memset(g_ing.skill_gaps, 0, sizeof(g_ing.skill_gaps));
    g_ing.nskills = 0;
    g_ing.hash_i = 0;
    g_ing.hash_n = 0;
    g_ing.ae_ok = 0;
    g_ing.ae_dup = 0;
    g_ing.decrypt_fail = 0;
    g_ing.ae_shaped_fail = 0;
    LeaveCriticalSection(&g_ing.lock);
}

void
pw_ingest_snap(PwMeterSnap *out)
{
    uint64_t t = now_ms();
    if (!out) {
        return;
    }
    if (!g_ing.lock_inited) {
        memset(out, 0, sizeof(*out));
        lstrcpynA(out->status, "ingest not started", 96);
        return;
    }
    EnterCriticalSection(&g_ing.lock);
    if (g_ing.skill_open && g_ing.last_ms && t - g_ing.last_ms > COMBAT_IDLE_MS) {
        g_ing.skill_open = 0;
    }
    out->session_total = g_ing.session_total;
    out->last_skill_total = g_ing.last_skill_total;
    out->skill_total = g_ing.skill_total;
    out->skill_id = g_ing.skill_id;
    out->skill_hits = g_ing.skill_hits;
    out->have_last_skill = g_ing.have_last_skill;
    out->skill_open = g_ing.skill_open;
    out->last_parts_n = g_ing.last_parts_n;
    memcpy(out->last_parts, g_ing.last_parts, sizeof(out->last_parts));
    out->capture_ok = g_ing.nthreads && g_ing.have_table && g_ing.ifaces;
    out->ae_ok = g_ing.ae_ok;
    out->ae_dup = g_ing.ae_dup;
    out->ifaces = g_ing.ifaces;
    out->decrypted = g_ing.decrypted;
    out->in_combat = g_ing.skill_open ||
                     (g_ing.last_ms && t - g_ing.last_ms < COMBAT_IDLE_MS);
    lstrcpynA(out->status, g_ing.status, 96);
    if (g_ing.first_ms && t > g_ing.first_ms) {
        out->dps = (double)g_ing.session_total * 1000.0 / (double)(t - g_ing.first_ms);
    } else {
        out->dps = 0;
    }
    maybe_close_graph(t / 1000ull);
    out->peak_dps = g_ing.peak_dps;
    out->notice = g_ing.notice;
    if (!out->notice && !g_ing.ae_ok && g_ing.ae_shaped_fail >= 32u) {
        out->notice = PW_NOTICE_STALE;
    }
    {
        unsigned i;
        unsigned order[SKILL_CAP];
        uint64_t sec = t / 1000ull;
        unsigned n;
        for (i = 0; i < PW_GRAPH_SECS; i++) {
            uint64_t want = sec + (uint64_t)i + 1ull - (uint64_t)PW_GRAPH_SECS;
            unsigned slot = (unsigned)(want % GRAPH_SECS);
            out->graph[i] = (g_ing.graph_sec[slot] == want) ? g_ing.graph_dmg[slot] : 0;
        }
        n = g_ing.nskills;
        if (n > SKILL_CAP) {
            n = SKILL_CAP;
        }
        for (i = 0; i < n; i++) {
            order[i] = i;
        }
        if (n > 1) {
            qsort(order, n, sizeof(order[0]), skill_rank_cmp);
        }
        out->skill_n = n < PW_SKILL_UI ? n : PW_SKILL_UI;
        for (i = 0; i < out->skill_n; i++) {
            unsigned s = order[i];
            out->skills[i].id = g_ing.skill_ids[s];
            out->skills[i].dmg = g_ing.skill_dmg[s];
            out->skills[i].casts = g_ing.skill_casts[s];
            if (g_ing.skill_gaps[s]) {
                out->skills[i].avg_ms = (unsigned)((g_ing.skill_gap_sum[s] +
                                                    (g_ing.skill_gaps[s] / 2u)) /
                                                   g_ing.skill_gaps[s]);
            } else {
                out->skills[i].avg_ms = 0;
            }
        }
        for (; i < PW_SKILL_UI; i++) {
            out->skills[i].id = 0;
            out->skills[i].dmg = 0;
            out->skills[i].casts = 0;
            out->skills[i].avg_ms = 0;
        }
    }
    LeaveCriticalSection(&g_ing.lock);
}
