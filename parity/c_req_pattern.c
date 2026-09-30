/*
 * Differential harness for the C req_pattern custom matcher.
 *
 * Default mode:
 *   Input lines:  <pattern>\t<ip>\t<port>
 *   Output:       0 | 1 | INIT_FAIL | BAD_IP
 *
 * Judge mode (--judge), exercising the full packet-feeding entry point
 * `req_pattern_judge_pkt_direction` instead of the matcher alone:
 *   Input lines:  <pattern>\t<frame_hex>
 *   Output:       -1 (UNKNOWN) | 1 (INCOMING) | 2 (OUTGOING) | INIT_FAIL | BAD_HEX
 *
 * `--sentinel` appends `@@END@@` after every answer (difffuzz.sh framing);
 * it can be combined with `--judge`.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>

#include "req_pattern.h"
#include "ip.h"

/* Same bound as cpworker's parse_pattern (MAX_PATTERN_LEN): the parser is
 * recursive descent and C's deep-recursion behaviour is UB, so the differential
 * compares only the domain where both are defined. */
#define PATTERN_MAX_LEN 512

static int hexval(int c)
{
    if (c >= '0' && c <= '9')
        return c - '0';
    if (c >= 'a' && c <= 'f')
        return c - 'a' + 10;
    if (c >= 'A' && c <= 'F')
        return c - 'A' + 10;
    return -1;
}

/* Decode an even-length hex string into `buf`; returns the byte count, or -1
 * when malformed or larger than `cap`. */
static int hex_decode(const char *hex, uint8_t *buf, size_t cap)
{
    size_t n = strlen(hex);
    if (n % 2 != 0 || n / 2 > cap)
        return -1;
    for (size_t i = 0; i < n; i += 2)
    {
        int hi = hexval((unsigned char)hex[i]);
        int lo = hexval((unsigned char)hex[i + 1]);
        if (hi < 0 || lo < 0)
            return -1;
        buf[i / 2] = (uint8_t)((hi << 4) | lo);
    }
    return (int)(n / 2);
}

static void emit(const char *fmt, int sentinel)
{
    printf("%s\n", fmt);
    if (sentinel)
        printf("@@END@@\n");
    fflush(stdout);
}

static void run_judge(char *line, int sentinel)
{
    char *tab = strchr(line, '\t');
    if (!tab)
        return;
    *tab = 0;
    const char *pattern = line;
    const char *hex = tab + 1;

    req_pattern_t rp;
    memset(&rp, 0, sizeof(rp));
    rp.type = REQ_PATTERN_TYPE_CUSTOM;
    if (strlen(pattern) > PATTERN_MAX_LEN ||
        req_pattern_custom_matcher_init(&rp.matcher.custom, pattern, get_if_ip_addr) != 0)
    {
        emit("INIT_FAIL", sentinel);
        return;
    }

    static uint8_t frame[65536];
    int len = hex_decode(hex, frame, sizeof(frame));
    if (len < 0)
    {
        emit("BAD_HEX", sentinel);
        req_pattern_custom_matcher_destroy(&rp.matcher.custom);
        return;
    }

    struct pcap_pkthdr hdr;
    memset(&hdr, 0, sizeof(hdr));
    hdr.caplen = (bpf_u_int32)len;
    hdr.len = (bpf_u_int32)len;

    char out[32];
    snprintf(out, sizeof(out), "%d", req_pattern_judge_pkt_direction(&rp, &hdr, frame));
    emit(out, sentinel);
    req_pattern_custom_matcher_destroy(&rp.matcher.custom);
}

static void run_match(char *line, int sentinel)
{
    char *tab1 = strchr(line, '\t');
    if (!tab1)
        return;
    *tab1 = 0;
    char *tab2 = strchr(tab1 + 1, '\t');
    if (!tab2)
        return;
    *tab2 = 0;

    const char *pattern = line;
    if (strlen(pattern) > PATTERN_MAX_LEN)
    {
        emit("INIT_FAIL", sentinel);
        return;
    }
    const char *ip_str = tab1 + 1;
    int port = atoi(tab2 + 1);

    req_pattern_custom_matcher_t m;
    memset(&m, 0, sizeof(m));
    if (req_pattern_custom_matcher_init(&m, pattern, get_if_ip_addr) != 0)
    {
        emit("INIT_FAIL", sentinel);
        return;
    }

    ip_addr_t ip;
    memset(&ip, 0, sizeof(ip));
    if (inet_pton(AF_INET, ip_str, &ip.data.v4) == 1)
        ip.type = IP_TYPE_IPv4;
    else if (inet_pton(AF_INET6, ip_str, &ip.data.v6) == 1)
        ip.type = IP_TYPE_IPv6;
    else
    {
        emit("BAD_IP", sentinel);
        req_pattern_custom_matcher_destroy(&m);
        return;
    }

    printf("%d\n", req_pattern_custom_match_by_ipport(&m, &ip, (uint16_t)port) ? 1 : 0);
    req_pattern_custom_matcher_destroy(&m);
    if (sentinel)
        printf("@@END@@\n");
    fflush(stdout);
}

int main(int argc, char **argv)
{
    int sentinel = 0;
    int judge = 0;
    for (int i = 1; i < argc; i++)
    {
        if (strcmp(argv[i], "--sentinel") == 0)
            sentinel = 1;
        else if (strcmp(argv[i], "--judge") == 0)
            judge = 1;
    }

    static char line[8192];
    while (fgets(line, sizeof(line), stdin))
    {
        size_t len = strlen(line);
        while (len && (line[len - 1] == '\n' || line[len - 1] == '\r'))
            line[--len] = 0;
        if (len == 0)
            continue;

        if (judge)
            run_judge(line, sentinel);
        else
            run_match(line, sentinel);
    }
    return 0;
}
