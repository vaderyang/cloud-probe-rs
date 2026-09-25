/*
 * Differential harness for the C req_pattern custom matcher.
 * Input lines:  <pattern>\t<ip>\t<port>
 * Output:       0 | 1 | INIT_FAIL | BAD_IP
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>

#include "req_pattern.h"
#include "ip.h"

int main(void)
{
    static char line[8192];
    while (fgets(line, sizeof(line), stdin))
    {
        size_t len = strlen(line);
        while (len && (line[len - 1] == '\n' || line[len - 1] == '\r'))
            line[--len] = 0;
        if (len == 0)
            continue;

        char *tab1 = strchr(line, '\t');
        if (!tab1)
            continue;
        *tab1 = 0;
        char *tab2 = strchr(tab1 + 1, '\t');
        if (!tab2)
            continue;
        *tab2 = 0;

        const char *pattern = line;
        const char *ip_str = tab1 + 1;
        int port = atoi(tab2 + 1);

        req_pattern_custom_matcher_t m;
        memset(&m, 0, sizeof(m));
        if (req_pattern_custom_matcher_init(&m, pattern, get_if_ip_addr) != 0)
        {
            printf("INIT_FAIL\n");
            fflush(stdout);
            continue;
        }

        ip_addr_t ip;
        memset(&ip, 0, sizeof(ip));
        if (inet_pton(AF_INET, ip_str, &ip.data.v4) == 1)
            ip.type = IP_TYPE_IPv4;
        else if (inet_pton(AF_INET6, ip_str, &ip.data.v6) == 1)
            ip.type = IP_TYPE_IPv6;
        else
        {
            printf("BAD_IP\n");
            req_pattern_custom_matcher_destroy(&m);
            fflush(stdout);
            continue;
        }

        printf("%d\n", req_pattern_custom_match_by_ipport(&m, &ip, (uint16_t)port) ? 1 : 0);
        req_pattern_custom_matcher_destroy(&m);
        fflush(stdout);
    }
    return 0;
}
