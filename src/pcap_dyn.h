#ifndef PLAYCABAL_WIRE_PCAP_DYN_H
#define PLAYCABAL_WIRE_PCAP_DYN_H

#include <stdint.h>

#define PW_PCAP_ERRBUF 256
#define PW_DLT_NULL 0
#define PW_DLT_EN10MB 1
#define PW_DLT_RAW 12
#define PW_DLT_LOOP 108
#define PW_DLT_IPV4 228

typedef struct pw_pcap pw_pcap_t;

typedef struct pw_pcap_pkthdr {
    uint32_t ts_sec;
    uint32_t ts_usec;
    uint32_t caplen;
    uint32_t len;
} pw_pcap_pkthdr;

typedef struct pw_pcap_if {
    struct pw_pcap_if *next;
    char *name;
    char *description;
} pw_pcap_if;

typedef void (*pw_pcap_handler)(unsigned char *user, const pw_pcap_pkthdr *hdr, const unsigned char *pkt);

int pw_pcap_load(char *err, int errlen);
int pw_pcap_findalldevs(pw_pcap_if **all, char *err);
void pw_pcap_freealldevs(pw_pcap_if *all);
pw_pcap_t *pw_pcap_open_live(const char *dev, int snaplen, int promisc, int to_ms, char *err);
void pw_pcap_close(pw_pcap_t *p);
int pw_pcap_setfilter(pw_pcap_t *p, const char *filter);
int pw_pcap_datalink(pw_pcap_t *p);
int pw_pcap_dispatch(pw_pcap_t *p, int cnt, pw_pcap_handler cb, unsigned char *user);
void pw_pcap_breakloop(pw_pcap_t *p);

#endif
