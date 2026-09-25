/*
 * Differential-test harness for the C packet_split implementation.
 *
 * Reads lines of the form:  <max_payload_size> <recalc 0|1> <packet_hex>
 * For each line writes:
 *   FAIL                     -- parse_packet failed
 *   <n>                      -- fragment count
 *   <fragment_hex>           -- one line per fragment
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "packet_split.h"

static uint8_t pkt[70000];
static uint8_t out[70000];

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

static size_t from_hex(const char *s, uint8_t *buf, size_t max)
{
    size_t n = 0;
    while (s[0] && s[1] && n < max)
    {
        int hi = hexval(s[0]);
        int lo = hexval(s[1]);
        if (hi < 0 || lo < 0)
            break;
        buf[n++] = (uint8_t)((hi << 4) | lo);
        s += 2;
    }
    return n;
}

int main(void)
{
    static char line[400000];
    while (fgets(line, sizeof(line), stdin))
    {
        int maxp = 0, recalc = 0;
        char hex[390000];
        if (sscanf(line, "%d %d %s", &maxp, &recalc, hex) != 3)
            continue;

        size_t n = from_hex(hex, pkt, sizeof(pkt));
        packet_parse_result_t r;
        if (!parse_packet(pkt, (uint32_t)n, &r))
        {
            printf("FAIL\n");
            fflush(stdout);
            continue;
        }

        int cnt = calculate_fragment_count(&r, maxp);
        printf("%d\n", cnt);
        for (int i = 0; i < cnt; i++)
        {
            int len = build_fragment(&r, pkt, i, maxp, recalc ? true : false, out);
            if (len < 0)
            {
                printf("ERR\n");
                continue;
            }
            for (int j = 0; j < len; j++)
                printf("%02x", out[j]);
            printf("\n");
        }
        fflush(stdout);
    }
    return 0;
}
