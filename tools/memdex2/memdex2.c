// memdex2.c：整段扫 dex 魔数 + 诊断
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>

int main(int argc, char **argv) {
    if (argc < 2) { fprintf(stderr, "usage: %s <pid>\n", argv[0]); return 1; }
    int pid = atoi(argv[1]);
    char mapsPath[64], memPath[64];
    snprintf(mapsPath, sizeof(mapsPath), "/proc/%d/maps", pid);
    snprintf(memPath, sizeof(memPath), "/proc/%d/mem", pid);

    FILE *maps = fopen(mapsPath, "r");
    if (!maps) { perror("maps"); return 1; }
    int mem = open(memPath, O_RDONLY);
    if (mem < 0) { perror("mem"); return 1; }

    char line[512];
    int hits = 0, read_ok = 0, total = 0, lines = 0, sfail = 0, noread = 0;
    while (fgets(line, sizeof(line), maps)) {
        unsigned long lo, hi;
        char perms[5];
        lines++;
        if (sscanf(line, "%lx-%lx %4s", &lo, &hi, perms) != 3) { sfail++; if (sfail <= 3) printf("SSCANF-FAIL: %s", line); continue; }
        if (perms[0] != 'r') { noread++; continue; }
        total++;
        size_t size = hi - lo;
        if (size < 0x1000) continue;
        size_t readSz = size > 0x800000 ? 0x800000 : size;
        unsigned char *rbuf = malloc(readSz);
        if (!rbuf) continue;
        ssize_t n = pread(mem, rbuf, readSz, (off_t)lo);
        if (n < 8) { free(rbuf); continue; }
        read_ok++;
        long hitOff = -1;
        for (long i = 0; i + 7 < n; i++) {
            if (memcmp(rbuf + i, "dex\n035", 7) == 0) { hitOff = i; break; }
        }
        free(rbuf);
        if (hitOff < 0) continue;

        unsigned long dexAddr = lo + hitOff;
        unsigned char hdr[0x70];
        ssize_t hn = pread(mem, hdr, 0x70, (off_t)dexAddr);
        unsigned int fsize = 0;
        if (hn >= 0x24) fsize = *(unsigned int *)(hdr + 0x20);
        printf("HIT %#lx dex_size=%u\n", dexAddr, fsize);
        fflush(stdout);
        hits++;
        if (fsize > 0 && fsize < 0x4000000) {
            char out[64];
            snprintf(out, sizeof(out), "/data/local/tmp/dex_%lx.bin", dexAddr);
            int ofd = open(out, O_WRONLY | O_CREAT | O_TRUNC, 0644);
            if (ofd >= 0) {
                unsigned char *buf = malloc(fsize);
                ssize_t got = pread(mem, buf, fsize, (off_t)dexAddr);
                if (got > 0) write(ofd, buf, got);
                free(buf);
                close(ofd);
                printf("  saved %s (%zd bytes)\n", out, got);
            }
        }
    }
    fclose(maps);
    close(mem);
    printf("total dex hits: %d (read %d/%d regions)\n", hits, read_ok, total);
    return 0;
}
