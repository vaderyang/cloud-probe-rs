/*
 * libpcap parity oracle for the pure-Rust BPF subset.
 *
 * Usage: c_bpf <exprs_file> <pkts_file>
 *
 * Reads filter expressions (one per line) and a packet corpus (one hex frame per
 * line), compiles each expression with libpcap for DLT_EN10MB and prints one
 * line per expression:
 *
 *   OK <bits>    where bit i is '1' iff packet i matches
 *   ERR <msg>    if libpcap could not compile the expression
 *
 * The Rust side (`cpworker --bin bpf_eval`) prints the same format; the two are
 * diffed by parity/verify_bpf.sh.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <pcap/pcap.h>

#define MAXLINE (1 << 16)
#define MAXPKT (MAXLINE / 2)

static int hex2bin(const char *hex, u_char *out, int maxlen)
{
    int n = 0;
    while (hex[0] && hex[1] && n < maxlen) {
        unsigned int b;
        if (sscanf(hex, "%2x", &b) != 1)
            break;
        out[n++] = (u_char)b;
        hex += 2;
    }
    return n;
}

int main(int argc, char **argv)
{
    if (argc != 3) {
        fprintf(stderr, "usage: %s <exprs_file> <pkts_file>\n", argv[0]);
        return 2;
    }
    FILE *fe = fopen(argv[1], "r");
    FILE *fp = fopen(argv[2], "r");
    if (!fe || !fp) {
        perror("open");
        return 2;
    }

    int cap = 1024, np = 0;
    u_char **pkts = malloc((size_t)cap * sizeof(*pkts));
    int *lens = malloc((size_t)cap * sizeof(*lens));
    char line[MAXLINE];
    while (fgets(line, sizeof line, fp)) {
        char *nl = strchr(line, '\n');
        if (nl)
            *nl = 0;
        if (line[0] == 0 || line[0] == '#')
            continue;
        if (np == cap) {
            cap *= 2;
            pkts = realloc(pkts, (size_t)cap * sizeof(*pkts));
            lens = realloc(lens, (size_t)cap * sizeof(*lens));
        }
        u_char *buf = malloc(MAXPKT);
        int n = hex2bin(line, buf, MAXPKT);
        pkts[np] = buf;
        lens[np] = n;
        np++;
    }

    pcap_t *dead = pcap_open_dead(DLT_EN10MB, 262144);
    if (!dead) {
        fprintf(stderr, "pcap_open_dead failed\n");
        return 2;
    }

    while (fgets(line, sizeof line, fe)) {
        char *nl = strchr(line, '\n');
        if (nl)
            *nl = 0;
        if (line[0] == 0 || line[0] == '#')
            continue;

        struct bpf_program prog;
        if (pcap_compile(dead, &prog, line, 0, 0) != 0) {
            printf("ERR %s\n", pcap_geterr(dead));
            continue;
        }
        printf("OK ");
        for (int i = 0; i < np; i++) {
            struct pcap_pkthdr h;
            h.ts.tv_sec = 0;
            h.ts.tv_usec = 0;
            h.caplen = (bpf_u_int32)lens[i];
            h.len = (bpf_u_int32)lens[i];
            putchar(pcap_offline_filter(&prog, &h, pkts[i]) ? '1' : '0');
        }
        putchar('\n');
        pcap_freecode(&prog);
    }
    return 0;
}
