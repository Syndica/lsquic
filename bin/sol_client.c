/* Copyright (c) 2017 - 2022 LiteSpeed Technologies Inc.  See LICENSE. */
/*
 * echo_client.c -- This is really a "line client:" it connects to QUIC server
 * and sends it stuff, line by line.  It works in tandem with echo_server.
 */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/queue.h>

#include <event2/event.h>

#include "lsquic.h"
#include "test_common.h"

#include "../src/liblsquic/lsquic_logger.h"

#define STDIN_FILENO 0

#define MAX_ADDRESS_LEN 256 // Maximum address length
#define MAX_BYTES_SIZE 1232 // Maximum byte array size
#define BUFFER_SIZE 2048    // Buffer size for incoming data

struct prog {
    struct lsquic_engine *engine;
};

// Sol Transaction
typedef struct st_txn_t
{
    char            address[MAX_ADDRESS_LEN];
    int             bytes_size;
    unsigned char   bytes[MAX_BYTES_SIZE];
} sol_txn_t;

// Print transaction data
void sol_print_txn(const sol_txn_t *data)
{
    printf("Transaction: address=%s bytes_size=%d bytes={", data->address, data->bytes_size);
    for (int i = 0; i < data->bytes_size; i++)
    {
        printf("%s%d", i == 0 ? "" : ", ", data->bytes[i]);
    }
    printf("}\n");
}

// Safe parsing function for "cin: address=... bytes_size=... bytes={...}"
int sol_parse_txn(const char *input, sol_txn_t *data)
{
    // Initialize the struct to zero
    memset(data, 0, sizeof(sol_txn_t));

    // Find the position of `bytes_size` and `bytes`
    char *address_start = strstr(input, "address=");
    char *bytes_size_start = strstr(input, "bytes_size=");
    char *bytes_start = strstr(input, "bytes={");

    if (!address_start || !bytes_size_start || !bytes_start)
    {
        printf("Error: Invalid input format.\n");
        return -1; // Input string format is incorrect
    }

    // Parse the address (use a length limit to avoid overflow)
    if (sscanf(address_start, "address=%255s", data->address) != 1)
    {
        printf("Error: Failed to parse the address.\n");
        return -1; // Failed to parse the address
    }

    // Parse the bytes size
    if (sscanf(bytes_size_start, "bytes_size=%d", &data->bytes_size) != 1)
    {
        printf("Error: Failed to parse bytes size.\n");
        return -1; // Failed to parse bytes size
    }

    if (data->bytes_size > MAX_BYTES_SIZE || data->bytes_size < 0)
    {
        printf("Error: Bytes size out of range.\n");
        return -1; // Bytes size is out of valid range
    }

    // Parse the bytes array (comma-separated list inside curly braces)
    bytes_start += strlen("bytes={");
    char *bytes_end = strchr(bytes_start, '}');
    if (!bytes_end)
    {
        printf("Error: Missing closing brace in bytes array.\n");
        return -1; // Malformed input, missing closing brace
    }

    // Create a copy of the bytes string to tokenize safely
    char bytes_str[BUFFER_SIZE];
    strncpy(bytes_str, bytes_start, bytes_end - bytes_start);
    bytes_str[bytes_end - bytes_start] = '\0'; // Null terminate the copied string

    // Now parse the comma-separated bytes
    int byte_count = 0;
    char *byte_token = strtok(bytes_str, ", ");
    while (byte_token && byte_count < data->bytes_size)
    {
        int byte_value;
        if (sscanf(byte_token, "%d", &byte_value) != 1 || byte_value < 0 || byte_value > 255)
        {
            printf("Error: Invalid byte value.\n");
            return -1; // Invalid byte value
        }
        data->bytes[byte_count++] = (unsigned char)byte_value;
        byte_token = strtok(NULL, ", ");
    }

    if (byte_count != data->bytes_size)
    {
        printf("Error: Parsed byte count %d does not match bytes_size %d.\n", byte_count, data->bytes_size);
        return -1; // Parsed byte count does not match bytes_size
    }

    return 0; // Success
}

// Parse the input string and populate the sol_txn_t struct
// Return the number of bytes read, or 0 if no data is available
int sol_read_next_txn_from_stdin(sol_txn_t *data)
{
    char buffer[BUFFER_SIZE]; // Buffer to hold each line of input
    fd_set readfds;           // File descriptor set
    struct timeval tv;        // Timeout structure

    // Set up the timeout value (0 for immediate return)
    tv.tv_sec = 0;
    tv.tv_usec = 0;

    // Clear the file descriptor set
    FD_ZERO(&readfds);

    // Add stdin (file descriptor 0) to the set
    FD_SET(STDIN_FILENO, &readfds);

    // Use select to check if there is input available on stdin
    int result = select(STDIN_FILENO + 1, &readfds, NULL, NULL, &tv);

    if (result > 0 && FD_ISSET(STDIN_FILENO, &readfds))
    {
        // Data is available on stdin, read it
        if (fgets(buffer, sizeof(buffer), stdin) != NULL)
        {
            // Remove the newline character, if any
            buffer[strcspn(buffer, "\n")] = '\0';

            // Attempt to parse the input
            if (sol_parse_txn(buffer, data) == 0)
            {
                return data->bytes_size;
            }
            else
            {
                exit(EXIT_FAILURE);
            }
        }
    }

    // No data available
    return 0;
}

typedef struct st_sol_packets_out_ctx {
} sol_packets_out_ctx_t;

typedef struct st_sol_stream_ctx {
    lsquic_stream_t *stream;
    sol_txn_t txn;
} sol_stream_ctx_t;

int sol_packets_out(
    void                          *ctx,
    const struct lsquic_out_spec  *specs,
    unsigned                       n_specs
) {
    struct msghdr msg;
    int sockfd;
    unsigned n;

    memset(&msg, 0, sizeof(msg));
    sockfd = (int) (uintptr_t) ctx;

    for (n = 0; n < n_specs; ++n)
    {
        msg.msg_name       = (void *) specs[n].dest_sa;
        msg.msg_namelen    = sizeof(struct sockaddr_in);
        msg.msg_iov        = specs[n].iov;
        msg.msg_iovlen     = specs[n].iovlen;
        if (sendmsg(sockfd, &msg, 0) < 0)
            break;
    }

    return (int) n;
}


lsquic_conn_ctx_t * sol_client_on_new_conn(void *stream_ctx, lsquic_conn_t *conn) {
    LSQ_INFO("sol_client_on_new_conn");
    lsquic_conn_make_stream(conn);
    return NULL; // OK to return NULL
}


void sol_client_on_conn_closed(lsquic_conn_t *c) {
    LSQ_INFO("sol_client_on_conn_closed");
}


lsquic_stream_ctx_t * sol_client_on_new_stream(void *stream_ctx, lsquic_stream_t *stream) {
    LSQ_INFO("sol_client_on_new_stream");
    sol_stream_ctx_t *sol_stream_ctx = (sol_stream_ctx_t *)stream_ctx;
    sol_stream_ctx->stream = stream;
    lsquic_stream_wantwrite(stream, 1);
    return (void *)sol_stream_ctx;
}


void sol_client_on_read(lsquic_stream_t *stream, lsquic_stream_ctx_t *stream_ctx) {
    LSQ_INFO("sol_client_on_read");
}


void sol_client_on_write(lsquic_stream_t *stream, lsquic_stream_ctx_t *stream_ctx) {
    LSQ_INFO("sol_client_on_write");
    sol_stream_ctx_t *sol_stream_ctx = (sol_stream_ctx_t *)stream_ctx;
    if (sol_stream_ctx->txn.bytes_size == lsquic_stream_write(stream, sol_stream_ctx->txn.bytes, sol_stream_ctx->txn.bytes_size)) {
        lsquic_stream_close(stream);
    }

}


void sol_client_on_close(lsquic_stream_t *stream, lsquic_stream_ctx_t *stream_ctx) {
    LSQ_INFO("sol_client_on_close");
    sol_stream_ctx_t *sol_stream_ctx = (sol_stream_ctx_t *)stream_ctx;
    free(sol_stream_ctx);
}

int
main(int argc, char **argv)
{

    if (0 != lsquic_global_init(LSQUIC_GLOBAL_CLIENT))
    {
        LSQ_ERROR("global initialization failed");
        exit(EXIT_FAILURE);
    }

    sol_stream_ctx_t sol_stream_ctx = {0};

    struct lsquic_stream_if sol_stream_if = {
        .on_new_conn    = sol_client_on_new_conn,
        .on_conn_closed = sol_client_on_conn_closed,
        .on_new_stream  = sol_client_on_new_stream,
        .on_read        = sol_client_on_read,
        .on_write       = sol_client_on_write,
        .on_close       = sol_client_on_close,
    };

    struct lsquic_engine_api engine_api = {
        .ea_packets_out     = sol_packets_out,
        .ea_packets_out_ctx = NULL,
        .ea_stream_if       = &sol_stream_if,
        .ea_stream_if_ctx   = &sol_stream_ctx,
        .ea_alpn            = "solana-tpu",
    };

    lsquic_engine_t *engine = lsquic_engine_new(0, &engine_api);

    while (1)
    {
        sol_txn_t txn = {0};
        if (0 < sol_read_next_txn_from_stdin(&txn))
        {
            sol_print_txn(&txn);
        }
    }

    lsquic_global_cleanup();
}

