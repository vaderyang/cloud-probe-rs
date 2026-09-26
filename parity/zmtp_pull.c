// ZMTP interop harness: a real libzmq PULL endpoint.
//
// Binds a PULL socket to an ephemeral TCP port, prints the endpoint on the
// first stdout line, waits for exactly one message, then prints its payload as
// hex on the second line. Used by parity/verify_zmtp.sh to check that the pure
// Rust ZMTP client is wire-compatible with libzmq.
//
// Build: gcc zmtp_pull.c -lzmq -o zmtp_pull

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <zmq.h>

int main(void)
{
    void *ctx = zmq_ctx_new();
    void *sock = zmq_socket(ctx, ZMQ_PULL);
    if (!sock)
    {
        fprintf(stderr, "zmq_socket failed\n");
        return 2;
    }
    if (zmq_bind(sock, "tcp://127.0.0.1:*") != 0)
    {
        fprintf(stderr, "zmq_bind failed\n");
        return 2;
    }

    char endpoint[256];
    size_t len = sizeof(endpoint);
    if (zmq_getsockopt(sock, ZMQ_LAST_ENDPOINT, endpoint, &len) != 0)
    {
        fprintf(stderr, "ZMQ_LAST_ENDPOINT failed\n");
        return 2;
    }
    printf("%s\n", endpoint);
    fflush(stdout);

    zmq_pollitem_t item = {sock, 0, ZMQ_POLLIN, 0};
    int rc = zmq_poll(&item, 1, 8000);
    if (rc <= 0)
    {
        printf("TIMEOUT\n");
        fflush(stdout);
        return 3;
    }

    zmq_msg_t msg;
    zmq_msg_init(&msg);
    if (zmq_msg_recv(&msg, sock, 0) < 0)
    {
        fprintf(stderr, "zmq_msg_recv failed\n");
        return 2;
    }
    size_t n = zmq_msg_size(&msg);
    const unsigned char *d = (const unsigned char *)zmq_msg_data(&msg);
    for (size_t i = 0; i < n; i++)
        printf("%02x", d[i]);
    printf("\n");
    fflush(stdout);

    zmq_msg_close(&msg);
    zmq_close(sock);
    zmq_ctx_term(ctx);
    return 0;
}
