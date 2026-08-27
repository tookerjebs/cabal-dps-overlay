#include "combat.h"
#include "ostara.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static uint8_t *
read_all(const char *path, size_t *out_len)
{
    FILE *f = fopen(path, "rb");
    uint8_t *buf;
    long sz;
    if (!f) {
        return NULL;
    }
    if (fseek(f, 0, SEEK_END) != 0) {
        fclose(f);
        return NULL;
    }
    sz = ftell(f);
    if (sz < 0) {
        fclose(f);
        return NULL;
    }
    rewind(f);
    buf = (uint8_t *)malloc((size_t)sz);
    if (!buf) {
        fclose(f);
        return NULL;
    }
    if (fread(buf, 1, (size_t)sz, f) != (size_t)sz) {
        free(buf);
        fclose(f);
        return NULL;
    }
    fclose(f);
    *out_len = (size_t)sz;
    return buf;
}

int
main(int argc, char **argv)
{
    const char *table_path = "data\\keychain.bin";
    const char *in_path;
    uint8_t *table;
    uint8_t *blob;
    uint8_t *plain;
    size_t table_len = 0;
    size_t blob_len = 0;
    size_t n;
    PwAeHit hit;
    int i;

    i = 1;
    if (argc >= 3 && strcmp(argv[1], "--table") == 0) {
        table_path = argv[2];
        i = 3;
    }
    if (i >= argc) {
        fprintf(stderr, "usage: pw-decrypt [--table keychain.bin] payload.bin\n");
        return 2;
    }
    in_path = argv[i];
    table = read_all(table_path, &table_len);
    if (!table || table_len < PW_TABLE_BYTES) {
        fprintf(stderr, "cannot read table %s\n", table_path);
        free(table);
        return 1;
    }
    blob = read_all(in_path, &blob_len);
    if (!blob) {
        fprintf(stderr, "cannot read %s\n", in_path);
        free(table);
        return 1;
    }
    plain = (uint8_t *)malloc(blob_len + 8);
    if (!plain) {
        free(table);
        free(blob);
        return 1;
    }
    n = pw_decrypt(blob, blob_len, table, plain, blob_len + 8);
    if (!n) {
        fprintf(stderr, "decrypt failed\n");
        free(table);
        free(blob);
        free(plain);
        return 1;
    }
    printf("plain_len=%zu magic=0x%04X size=%u cmd=0x%04X\n",
        n,
        (unsigned)(plain[0] | (plain[1] << 8)),
        (unsigned)(plain[2] | (plain[3] << 8)),
        n >= 6 ? (unsigned)(plain[4] | (plain[5] << 8)) : 0);
    if (pw_parse_ae(plain, n, &hit)) {
        printf("AE skill=%u hits=%u sum=%d hp0=%d\n",
            hit.skill, hit.n_hits, hit.damage, hit.hp);
        if (hit.n_hits > 1) {
            unsigned k;
            for (k = 0; k < hit.n_hits && k < PW_AE_HIT_CAP; k++) {
                printf("  hit%u tid=%u dmg=%d\n", k, hit.targets[k], hit.parts[k]);
            }
        }
    }
    free(table);
    free(blob);
    free(plain);
    return 0;
}
