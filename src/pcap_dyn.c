#include "pcap_dyn.h"

#include <windows.h>
#include <string.h>

typedef struct pcap pcap_t;
typedef struct pcap_if pcap_if_t;
struct bpf_program {
    unsigned int bf_len;
    void *bf_insns;
};
struct pcap_pkthdr_native {
    long tv_sec;
    long tv_usec;
    unsigned int caplen;
    unsigned int len;
};

typedef void (*pcap_handler_n)(unsigned char *, const struct pcap_pkthdr_native *, const unsigned char *);

static pcap_t *(*p_open_live)(const char *, int, int, int, char *);
static pcap_t *(*p_create)(const char *, char *);
static int (*p_set_snaplen)(pcap_t *, int);
static int (*p_set_timeout)(pcap_t *, int);
static int (*p_set_immediate_mode)(pcap_t *, int);
static int (*p_activate)(pcap_t *);
static int (*p_setnonblock)(pcap_t *, int, char *);
static void (*p_close)(pcap_t *);
static int (*p_findalldevs)(pcap_if_t **, char *);
static void (*p_freealldevs)(pcap_if_t *);
static int (*p_compile)(pcap_t *, struct bpf_program *, const char *, int, unsigned int);
static int (*p_setfilter)(pcap_t *, struct bpf_program *);
static void (*p_freecode)(struct bpf_program *);
static int (*p_datalink)(pcap_t *);
static int (*p_dispatch)(pcap_t *, int, pcap_handler_n, unsigned char *);
static void (*p_breakloop)(pcap_t *);

static HMODULE g_wpcap;

int
pw_pcap_load(char *err, int errlen)
{
    wchar_t npcap[] = L"C:\\Windows\\System32\\Npcap";
    FARPROC fp;

    if (g_wpcap) {
        return 1;
    }
    SetDllDirectoryW(npcap);
    g_wpcap = LoadLibraryW(L"wpcap.dll");
    SetDllDirectoryW(NULL);
    if (!g_wpcap) {
        g_wpcap = LoadLibraryW(L"wpcap.dll");
    }
    if (!g_wpcap) {
        if (err && errlen) {
            lstrcpynA(err, "wpcap.dll not found (install Npcap)", errlen);
        }
        return 0;
    }
#define BIND(name, var) \
    fp = GetProcAddress(g_wpcap, name); \
    if (!fp) { \
        if (err && errlen) lstrcpynA(err, "wpcap missing " name, errlen); \
        return 0; \
    } \
    *(FARPROC *)&(var) = fp
#define BIND_OPT(name, var) \
    fp = GetProcAddress(g_wpcap, name); \
    *(FARPROC *)&(var) = fp
    BIND("pcap_open_live", p_open_live);
    BIND("pcap_close", p_close);
    BIND("pcap_findalldevs", p_findalldevs);
    BIND("pcap_freealldevs", p_freealldevs);
    BIND("pcap_compile", p_compile);
    BIND("pcap_setfilter", p_setfilter);
    BIND("pcap_freecode", p_freecode);
    BIND("pcap_datalink", p_datalink);
    BIND("pcap_dispatch", p_dispatch);
    BIND("pcap_breakloop", p_breakloop);
    BIND_OPT("pcap_create", p_create);
    BIND_OPT("pcap_set_snaplen", p_set_snaplen);
    BIND_OPT("pcap_set_timeout", p_set_timeout);
    BIND_OPT("pcap_set_immediate_mode", p_set_immediate_mode);
    BIND_OPT("pcap_activate", p_activate);
    BIND_OPT("pcap_setnonblock", p_setnonblock);
#undef BIND
#undef BIND_OPT
    return 1;
}

int
pw_pcap_findalldevs(pw_pcap_if **all, char *err)
{
    return p_findalldevs((pcap_if_t **)all, err);
}

void
pw_pcap_freealldevs(pw_pcap_if *all)
{
    p_freealldevs((pcap_if_t *)all);
}

pw_pcap_t *
pw_pcap_open_live(const char *dev, int snaplen, int promisc, int to_ms, char *err)
{
    char nberr[PW_PCAP_ERRBUF];
    pcap_t *p = NULL;
    int immediate = 0;

    (void)promisc;
    if (to_ms < 1) {
        to_ms = 1;
    }
    nberr[0] = 0;
    if (p_create && p_activate) {
        p = p_create(dev, err);
        if (p) {
            if (p_set_snaplen) {
                p_set_snaplen(p, snaplen);
            }
            if (p_set_timeout) {
                p_set_timeout(p, to_ms);
            }
            if (p_set_immediate_mode && p_set_immediate_mode(p, 1) == 0) {
                immediate = 1;
            }
            if (p_activate(p) >= 0) {
                if (!immediate && p_setnonblock) {
                    p_setnonblock(p, 1, nberr);
                }
                return (pw_pcap_t *)p;
            }
            p_close(p);
            p = NULL;
        }
    }
    p = p_open_live(dev, snaplen, 0, to_ms, err);
    if (p && p_setnonblock) {
        p_setnonblock(p, 1, nberr);
    }
    return (pw_pcap_t *)p;
}

void
pw_pcap_close(pw_pcap_t *p)
{
    if (p) {
        p_close((pcap_t *)p);
    }
}

int
pw_pcap_setfilter(pw_pcap_t *p, const char *filter)
{
    struct bpf_program fp;
    int rc;

    memset(&fp, 0, sizeof(fp));
    if (p_compile((pcap_t *)p, &fp, filter, 1, 0) < 0) {
        return -1;
    }
    rc = p_setfilter((pcap_t *)p, &fp);
    p_freecode(&fp);
    return rc;
}

int
pw_pcap_datalink(pw_pcap_t *p)
{
    return p_datalink((pcap_t *)p);
}

struct disp_wrap {
    pw_pcap_handler cb;
    unsigned char *user;
};

static void
disp_adapt(unsigned char *user, const struct pcap_pkthdr_native *h, const unsigned char *pkt)
{
    struct disp_wrap *w = (struct disp_wrap *)user;
    pw_pcap_pkthdr hdr;

    hdr.ts_sec = (uint32_t)h->tv_sec;
    hdr.ts_usec = (uint32_t)h->tv_usec;
    hdr.caplen = h->caplen;
    hdr.len = h->len;
    w->cb(w->user, &hdr, pkt);
}

int
pw_pcap_dispatch(pw_pcap_t *p, int cnt, pw_pcap_handler cb, unsigned char *user)
{
    struct disp_wrap w;
    w.cb = cb;
    w.user = user;
    return p_dispatch((pcap_t *)p, cnt, disp_adapt, (unsigned char *)&w);
}

void
pw_pcap_breakloop(pw_pcap_t *p)
{
    if (p && p_breakloop) {
        p_breakloop((pcap_t *)p);
    }
}
