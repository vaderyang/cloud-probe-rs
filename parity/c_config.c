/*
 * Differential harness for the C config parser.
 * Reads one compact JSON config per line; prints a canonical description.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "config.h"
#include "errorf.h"
#include "cJSON/cJSON.h"

static void print_output(OutputConfig *o)
{
    const char *host = "";
    if (strcmp(o->type, OUTPUT_TYPE_VXLAN) == 0)
        host = o->config.vxlan.host;
    else if (strcmp(o->type, OUTPUT_TYPE_GRE) == 0)
        host = o->config.gre.host;
    else if (strcmp(o->type, OUTPUT_TYPE_ZMQ) == 0)
        host = o->config.zmq.host;
    printf("  output type=%s rate=%llu slice=%d host=%s\n", o->type,
           (unsigned long long)o->rate_limit_mbps, o->slice, host);
}

int main(int argc, char **argv)
{
    int sentinel = (argc > 1 && strcmp(argv[1], "--sentinel") == 0);
    static char line[65536];
    while (fgets(line, sizeof(line), stdin))
    {
        size_t len = strlen(line);
        while (len && (line[len - 1] == '\n' || line[len - 1] == '\r'))
            line[--len] = 0;
        if (len == 0)
            continue;

        cJSONParseError err;
        memset(&err, 0, sizeof(err));
        Config *c = parse_config_data(line, &err);
        if (!c)
        {
            printf("PARSE_FAIL: %s\n", err.message);
            printf("---\n");
            if (sentinel)
                printf("@@END@@\n");
            fflush(stdout);
            continue;
        }

        printf("log_level=%d\n", c->log_level);
        printf("exec_model=%s\n", c->execution_model == EXECUTION_MODEL_PIPELINE ? "pipeline" : "rtc");
        printf("cpu=%s\n", c->cpu_affinity ? c->cpu_affinity : "");
        printf("pipeline_mb=%d\n", c->pipeline.buffer_size_mb);
        if (c->control)
            printf("control type=%s path=%s\n", c->control->type,
                   strcmp(c->control->type, CONTROL_TYPE_UNIX) == 0 ? c->control->config.unix_socket.path : "");
        else
            printf("control none\n");

        int n = c->tasks_cfg->num_tasks;
        printf("tasks=%d\n", n);
        for (int i = 0; i < n; i++)
        {
            TaskConfig *t = c->tasks_cfg->tasks[i];
            const char *bpf = "";
            if (strcmp(t->capturer.type, CAPTURER_TYPE_LIBPCAP) == 0)
                bpf = t->capturer.config.libpcap.bpf_filter;
            else if (strcmp(t->capturer.type, CAPTURER_TYPE_PCAP_FILE) == 0)
                bpf = t->capturer.config.pcap_file.bpf_filter;
            printf(" task idx=%d fp=%s req=%s capturer=%s snaplen=%d bpf=%s\n", i,
                   t->fingerprint ? t->fingerprint : "", t->req_pattern.type, t->capturer.type,
                   task_capturer_snaplen(t), bpf);
            for (int j = 0; j < t->num_outputs; j++)
                print_output(t->outputs[j]);
        }

        char errbuf[ERROR_BUFFER_SIZE];
        errbuf[0] = 0;
        const char *base_bpf = "";
        if (n > 0 && strcmp(c->tasks_cfg->tasks[0]->capturer.type, CAPTURER_TYPE_LIBPCAP) == 0)
            base_bpf = c->tasks_cfg->tasks[0]->capturer.config.libpcap.bpf_filter;
        char *bpf = bpf_filter_exclude_task_output_hosts(base_bpf, c->tasks_cfg, errbuf);
        printf("exclude_bpf=%s\n", bpf ? bpf : "NULL");
        free(bpf);

        free_config(c);
        printf("---\n");
        if (sentinel)
            printf("@@END@@\n");
        fflush(stdout);
    }
    return 0;
}
