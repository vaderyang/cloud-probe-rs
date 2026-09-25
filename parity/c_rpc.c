// C side of the Unix JSON-RPC protocol parity harness: runs the REAL
// unix-manager.c + unix_rpc_basic.c command set on a unix socket.
//
// Usage: c_rpc <socket-path>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>

#include "unix-manager.h"
#include "unix_rpc_basic.h"

void log_log(int level, const char *file, int line, const char *fmt, ...)
{
    (void)level;
    (void)file;
    (void)line;
    (void)fmt;
}

int main(int argc, char **argv)
{
    if (argc < 2)
    {
        fprintf(stderr, "usage: %s <socket-path>\n", argv[0]);
        return 2;
    }
    const char *sock = argv[1];

    unix_rpc_basic_set_started_at(time(NULL));
    unix_rpc_basic_set_config_path("/tmp/config.json");
    unix_rpc_basic_set_working_dir("/tmp");

    if (unix_manager_init(sock) != 0)
        return 1;
    if (unix_manager_register_command("ping", unix_rpc_ping_command, NULL) != 0)
        return 1;
    if (unix_manager_register_command("info", unix_rpc_info_command, NULL) != 0)
        return 1;
    if (unix_manager_thread_spawn() != 0)
        return 1;

    printf("READY\n");
    fflush(stdout);
    for (;;)
        pause();
    return 0;
}
