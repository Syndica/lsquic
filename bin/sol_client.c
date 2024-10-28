/* Copyright (c) 2017 - 2022 LiteSpeed Technologies Inc.  See LICENSE. */
/*
 * echo_client.c -- This is really a "line client:" it connects to QUIC server
 * and sends it stuff, line by line.  It works in tandem with echo_server.
 */

#include <unistd.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/queue.h>
#include <arpa/inet.h>

#include <event2/event.h>

#include "lsquic.h"
#include "test_common.h"
#include "../src/liblsquic/lsquic_logger.h"

#include <openssl/ssl.h>
#include <openssl/curve25519.h>
#include <openssl/x509.h>
#include <openssl/bio.h>

#define STDIN_FILENO 0

#define MAX_CONNECTIONS 100                 // Maximum number of connections
#define MAX_PENDING_TXNS_PER_CONNECTION 100 // Max number of pending transactions per connection
#define MAX_ADDRESS_LEN 256                 // Maximum address length
#define MAX_BYTES_SIZE 1232                 // Maximum byte array size
#define BUFFER_SIZE 2048                    // Buffer size for incoming data

#define SSL_EXIT_SUCCESS 1
#define SSL_EXIT_FAILURE 0


typedef struct st_squic_socket {
    int                             fd;
    struct sockaddr_storage         sas;
} squic_socket_t;


typedef struct st_squic_txn
{
    char            address[MAX_ADDRESS_LEN];
    int             bytes_size;
    unsigned char   bytes[MAX_BYTES_SIZE];
} squic_txn_t;


typedef struct st_squic {
    struct lsquic_engine_settings   engine_settings;
    struct lsquic_engine_api        engine_api;
    struct lsquic_engine           *engine;

    struct event_base              *event_base;
    struct event                   *tick_event,
                                   *read_pkts_event,
                                   *read_stdin_event;
    struct timeval                  tick_event_timeout;

    SSL_CTX                        *ssl_ctx;

    lsquic_conn_ctx_t              *conns[MAX_CONNECTIONS];
    int                             n_conns;

    squic_socket_t                 *socket;
} squic_t;


struct lsquic_conn_ctx {
    squic_t             *sqc;
    lsquic_conn_t       *conn;
    int                  is_connected;                              // 0 -> not connected
    char                 address[MAX_ADDRESS_LEN];                  // ip address of peer
    squic_txn_t          txns[MAX_PENDING_TXNS_PER_CONNECTION];     // pending transactions
    int                  n_txns;                                    // number of transactions
    int                  n_stms;                                    // number of streams
};


struct lsquic_stream_ctx {
    lsquic_stream_t     *stream;                
    lsquic_conn_ctx_t   *conn_ctx;              
    squic_txn_t          txn;
};


///////////////////////////////////////////////////////////////////////////////
// Squic Helpers
///////////////////////////////////////////////////////////////////////////////


void
squic_print_txn(const squic_txn_t *data)
{
    printf("Transaction: address=%s bytes_size=%d bytes={", data->address, data->bytes_size);
    for (int i = 0; i < data->bytes_size; i++)
    {
        printf("%s%d", i == 0 ? "" : ", ", data->bytes[i]);
    }
    printf("}\n");
}


int
squic_parse_txn(const char *input, squic_txn_t *data)
{
    // Initialize the struct to zero
    memset(data, 0, sizeof(squic_txn_t));

    // Find the position of `bytes_size` and `bytes`
    char *address_start = strstr(input, "address=");
    char *bytes_size_start = strstr(input, "bytes_size=");
    char *bytes_start = strstr(input, "bytes={");

    if (!address_start || !bytes_size_start || !bytes_start)
    {
        printf("Error: Invalid input format.\n");
        return EXIT_FAILURE; // Input string format is incorrect
    }

    // Parse the address (use a length limit to avoid overflow)
    if (sscanf(address_start, "address=%255s", data->address) != 1)
    {
        printf("Error: Failed to parse the address.\n");
        return EXIT_FAILURE; // Failed to parse the address
    }

    // Parse the bytes size
    if (sscanf(bytes_size_start, "bytes_size=%d", &data->bytes_size) != 1)
    {
        printf("Error: Failed to parse bytes size.\n");
        return EXIT_FAILURE; // Failed to parse bytes size
    }

    if (data->bytes_size > MAX_BYTES_SIZE || data->bytes_size < 0)
    {
        printf("Error: Bytes size out of range.\n");
        return EXIT_FAILURE; // Bytes size is out of valid range
    }

    // Parse the bytes array (comma-separated list inside curly braces)
    bytes_start += strlen("bytes={");
    char *bytes_end = strchr(bytes_start, '}');
    if (!bytes_end)
    {
        printf("Error: Missing closing brace in bytes array.\n");
        return EXIT_FAILURE; // Malformed input, missing closing brace
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
            return EXIT_FAILURE; // Invalid byte value
        }
        data->bytes[byte_count++] = (unsigned char)byte_value;
        byte_token = strtok(NULL, ", ");
    }

    if (byte_count != data->bytes_size)
    {
        printf("Error: Parsed byte count %d does not match bytes_size %d.\n", byte_count, data->bytes_size);
        return EXIT_FAILURE; // Parsed byte count does not match bytes_size
    }

    return EXIT_SUCCESS; // Success
}


struct sockaddr_storage
squic_create_sockaddr_storage(const char *address)
{
    char ip[INET_ADDRSTRLEN];
    int port;
    struct sockaddr_storage ss;

    // Zero out the structure
    memset(&ss, 0, sizeof(struct sockaddr_storage));

    // Cast to sockaddr_in since we are working with IPv4
    struct sockaddr_in *sa_in = (struct sockaddr_in *)&ss;

    // Set the family to AF_INET (IPv4)
    sa_in->sin_family = AF_INET;

    // Split the string into IP and port
    sscanf(address, "%[^:]:%d", ip, &port);

    // Set the port in network byte order
    sa_in->sin_port = htons(port);

    // Convert the IP address from text to binary form
    if (inet_pton(AF_INET, ip, &sa_in->sin_addr) <= 0)
    {
        perror("inet_pton failed");
        exit(EXIT_FAILURE);
    }

    // Return the sockaddr_storage structure
    return ss;
}


int
squic_read_line(int fd, char *buffer, size_t max_len)
{
    size_t i = 0;
    ssize_t bytes_read;
    char ch;

    while (i < max_len - 1) {
        bytes_read = read(fd, &ch, 1);

        if (bytes_read == -1) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                continue;
            } else {
                return EXIT_FAILURE;
            }
        }
        if (bytes_read == 0) {
            break;
        }

        buffer[i++] = ch;

        if (ch == '\n') {
            break;
        }
    }

    buffer[i] = '\0';
    return EXIT_SUCCESS;
}


lsquic_conn_ctx_t * 
squic_get_connection_context(squic_t *sqc, const char *address)
{
    // Check if we already have a connection for the transaction address
    for (int i = 0; i < sqc->n_conns; i++) {
        if (strcmp(sqc->conns[i]->address, address) == 0) {
            return sqc->conns[i];
        }
    }

    // Create new connection context
    lsquic_conn_ctx_t *conn_ctx = (lsquic_conn_ctx_t *)calloc(1, sizeof(lsquic_conn_ctx_t));
    if (NULL == conn_ctx) {
        printf("Error allocating memory for connection context\n");
        exit(EXIT_FAILURE);
    }
    conn_ctx->sqc = sqc;
    conn_ctx->conn = NULL;
    strncpy(conn_ctx->address, address, MAX_ADDRESS_LEN);

    // Initiate connection 
    struct sockaddr_storage peer_sas = squic_create_sockaddr_storage(address);
    if (NULL == lsquic_engine_connect(
        sqc->engine,                                 // engine
        N_LSQVER,                                   // version
        (struct sockaddr *)&sqc->socket->sas,            // local_sa
        (struct sockaddr *)&peer_sas,               // peer_sa
        sqc->ssl_ctx,                                // peer_ctx
        conn_ctx,                                   // conn_ctx
        NULL,                                       // hostname
        0,                                          // base_plpmtu
        NULL,                                       // sess_resume
        0,                                          // sess_resume_len
        NULL,                                       // token
        0                                           // token_len
    ))
    {
        printf("Error connecting to server\n");
        exit(EXIT_FAILURE);
    }

    // Return context pointer
    return conn_ctx;
}


///////////////////////////////////////////////////////////////////////////////
// Send Packets
///////////////////////////////////////////////////////////////////////////////


int
squic_packets_out(
    void                          *ctx,
    const struct lsquic_out_spec  *specs,
    unsigned                       n_specs
)
{
    unsigned n;
    struct msghdr msg;
    memset(&msg, 0, sizeof(msg));

    squic_socket_t *socket = (squic_socket_t *)ctx;
    if (NULL == socket) {
        printf("packets out context is null!\n");
        exit(EXIT_FAILURE);
    }

    for (n = 0; n < n_specs; ++n)
    {
        msg.msg_name       = (void *) specs[n].dest_sa;
        msg.msg_namelen    = sizeof(struct sockaddr_in);
        msg.msg_iov        = specs[n].iov;
        msg.msg_iovlen     = specs[n].iovlen;
        ssize_t bytes_sent = sendmsg(socket->fd, &msg, 0);
        printf("Sent %ld bytes\n", bytes_sent);
        if (bytes_sent < 0) {
            perror("sendmsg");
            return -1;
        }
    }

    return (int) n;
}


///////////////////////////////////////////////////////////////////////////////
// Callbacks
///////////////////////////////////////////////////////////////////////////////


lsquic_conn_ctx_t * 
squic_stream_on_new_conn(void *_, lsquic_conn_t *conn)
{
    printf("squic_stream_on_new_conn\n");

    // Get the connection context from connection
    lsquic_conn_ctx_t *conn_ctx = lsquic_conn_get_ctx(conn);
    if (MAX_CONNECTIONS == conn_ctx->sqc->n_conns) {
        printf("reached max connections");
        exit(EXIT_FAILURE);
    }

    // Set the connection in the context
    conn_ctx->conn = conn;

    // Add the connection context to squic
    conn_ctx->sqc->conns[conn_ctx->sqc->n_conns++] = conn_ctx;

    // Return connection context pointer
    return conn_ctx;
}


void
squic_stream_on_hsk_done(lsquic_conn_t *conn, enum lsquic_hsk_status hsk_status) {
    printf("squic_stream_on_new_conn\n");
    // TODO: Implement
}


void 
squic_stream_on_conn_closed(lsquic_conn_t *conn)
{
    printf("squic_stream_on_conn_closed\n");

    // Get connection context from connection
    lsquic_conn_ctx_t *conn_ctx = lsquic_conn_get_ctx(conn);

    // Remove connection from squic connections
    for (int i = 0; i < conn_ctx->sqc->n_conns; i++) {
        if (conn_ctx->sqc->conns[i] == conn_ctx) {
            conn_ctx->sqc->conns[i] = conn_ctx->sqc->conns[conn_ctx->sqc->n_conns - 1];
            conn_ctx->sqc->n_conns--;
            break;
        }
    }

    // Set the conns connection context to NULL to prevent use after free
    lsquic_conn_set_ctx(conn, NULL);

    // Free connection context
    free(conn_ctx);
}


lsquic_stream_ctx_t * 
squic_stream_on_new_stream(void *_, lsquic_stream_t *stream)
{
    printf("squic_stream_on_new_stream\n");

    // Get the connection and its context
    lsquic_conn_t *conn = lsquic_stream_conn(stream);
    lsquic_conn_ctx_t *conn_ctx = lsquic_conn_get_ctx(conn);

    // Create stream context
    lsquic_stream_ctx_t *stm_ctx = (lsquic_stream_ctx_t *)calloc(1, sizeof(*stm_ctx));
    stm_ctx->stream = stream;
    stm_ctx->conn_ctx = conn_ctx;
    stm_ctx->txn = conn_ctx->txns[conn_ctx->n_txns--];

    // Signal that we want to write
    lsquic_stream_wantwrite(stream, 1);

    // Return stream context pointer
    return stm_ctx;
}


void 
squic_stream_on_read(lsquic_stream_t *stream, lsquic_stream_ctx_t *stream_ctx)
{
    printf("squic_stream_on_read\n");
    // TODO: Implement
}


void 
squic_stream_on_write(lsquic_stream_t *stream, lsquic_stream_ctx_t *stream_ctx)
{
    printf("squic_stream_on_write\n");

    // Write transaction bytes to stream and exit if not all bytes were written
    int bytes_written = lsquic_stream_write(stream, stream_ctx->txn.bytes, stream_ctx->txn.bytes_size);
    if (bytes_written != stream_ctx->txn.bytes_size) {
        printf("only printed portion of txn bytes!!");
        exit(1);
    }

    // Flush and close the stream
    lsquic_stream_flush(stream);
    lsquic_stream_wantwrite(stream, 0);
    lsquic_stream_close(stream);
}


void 
squic_stream_on_close(lsquic_stream_t *stream, lsquic_stream_ctx_t *stream_ctx)
{
    printf("squic_stream_on_close\n");
    // TODO: Implement
}


struct ssl_ctx_st *
squic_get_ssl_ctx(void *peer_ctx, const struct sockaddr *local)
{
    return (struct ssl_ctx_st *)peer_ctx;
}


///////////////////////////////////////////////////////////////////////////////
// Event Handlers
///////////////////////////////////////////////////////////////////////////////

static void 
squic_tick_event_handler(int fd, short what, void *ctx)
{
    printf("squic_tick_event_handler\n");
    squic_t *sqc = (squic_t *)ctx;
    lsquic_engine_process_conns(sqc->engine);
    event_add(sqc->tick_event, &sqc->tick_event_timeout);
}

// evutil_socket_t
static void 
squic_read_packets_event_handler(int fd, short what, void *ctx)
{
    printf("squic_read_packets_event_handler\n");
}

static void
squic_read_stdin_event_handler (int fd, short what, void *arg)
{
    // Event book keeping
    squic_t *squic = (squic_t *)arg;
    if (squic->read_stdin_event) {
        event_del(squic->read_stdin_event);
        event_free(squic->read_stdin_event);
    }
    squic->read_stdin_event = event_new(squic->event_base, STDIN_FILENO, EV_READ, squic_read_stdin_event_handler, squic);
    event_add(squic->read_stdin_event, NULL);

    // Read a line of input from stdin
    char buffer[BUFFER_SIZE];
    if (EXIT_FAILURE == squic_read_line(STDIN_FILENO, buffer, BUFFER_SIZE)) {
        printf("Error reading from stdin\n");
        exit(EXIT_FAILURE);
    }

    // Parse the transaction data
    squic_txn_t txn = {0};
    if (squic_parse_txn(buffer, &txn)) {
        printf("Error parsing transaction data\n");
        exit(EXIT_FAILURE);
    }

    // Get a connection context (connection may not be established yet)
    lsquic_conn_ctx_t *conn_ctx = squic_get_connection_context(squic, txn.address);
    if (NULL == conn_ctx) {
        printf("failed to get connection context");
        exit(EXIT_FAILURE);
    }

    // Add the txn to the connections context
    if (MAX_PENDING_TXNS_PER_CONNECTION == conn_ctx->n_txns) {
        printf("exceeded max pending transactions, skipping transaction");
        return;
    }
    conn_ctx->txns[conn_ctx->n_txns++] = txn;

    // If the connection is active, make a stream for all txns
    if (conn_ctx->is_connected) {
        while (conn_ctx->n_stms < conn_ctx->n_txns) {
            lsquic_conn_make_stream(conn_ctx->conn);
            conn_ctx->n_stms++;
        }
    }

    // Process connections
    lsquic_engine_process_conns(squic->engine);
}


///////////////////////////////////////////////////////////////////////////////
// Squic Initialization
///////////////////////////////////////////////////////////////////////////////

int 
squic_init_dummy_x509_cert(X509 **cert, EVP_PKEY **pkey)
{
    uint8_t public_key[32];
    uint8_t private_key[64];

    ED25519_keypair(public_key, private_key);

    uint8_t pkcs8_prefix[16] = { 0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20, };
    uint8_t key_pkcs8_der[48];

    memcpy(key_pkcs8_der, pkcs8_prefix, 16);
    memcpy(key_pkcs8_der + 16, private_key, 32);

    uint8_t cert_prefix[100] = {
        0x30, 0x81, 0xf6, 0x30, 0x81, 0xa9, 0xa0, 0x03, 0x02, 0x01, 0x02, 0x02, 0x08, 0x01, 0x01,
        0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x30, 0x16,
        0x31, 0x14, 0x30, 0x12, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x0b, 0x53, 0x6f, 0x6c, 0x61,
        0x6e, 0x61, 0x20, 0x6e, 0x6f, 0x64, 0x65, 0x30, 0x20, 0x17, 0x0d, 0x37, 0x30, 0x30, 0x31,
        0x30, 0x31, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x5a, 0x18, 0x0f, 0x34, 0x30, 0x39, 0x36,
        0x30, 0x31, 0x30, 0x31, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x5a, 0x30, 0x00, 0x30, 0x2a,
        0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
    };

    uint8_t cert_suffix[117] = {
        0xa3, 0x29, 0x30, 0x27, 0x30, 0x17, 0x06, 0x03, 0x55, 0x1d, 0x11, 0x01, 0x01, 0xff, 0x04,
        0x0d, 0x30, 0x0b, 0x82, 0x09, 0x6c, 0x6f, 0x63, 0x61, 0x6c, 0x68, 0x6f, 0x73, 0x74, 0x30,
        0x0c, 0x06, 0x03, 0x55, 0x1d, 0x13, 0x01, 0x01, 0xff, 0x04, 0x02, 0x30, 0x00, 0x30, 0x05,
        0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x41, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    };

    uint8_t cert_der[249];

    memcpy(cert_der, cert_prefix, sizeof(cert_prefix));
    memcpy(cert_der + sizeof(cert_prefix), public_key, 32);
    memcpy(cert_der + sizeof(cert_prefix) + 32, cert_suffix, sizeof(cert_suffix));

    *pkey = EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, NULL, private_key, 32);
    if (NULL == *pkey) {
        printf("EVP_PKEY_new_raw_private_key failed\n");
        return EXIT_FAILURE;
    }

    BIO *bio = BIO_new_mem_buf(cert_der, sizeof(cert_der));
    *cert = d2i_X509_bio(bio, NULL);
    BIO_free(bio);

    if (NULL == *cert) {
        printf("d2i_X509_bio failed\n");
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}


int 
squic_init_ssl_ctx(squic_t *squic)
{
    squic->ssl_ctx = SSL_CTX_new(TLS_method());
    if (NULL == squic->ssl_ctx) {
        printf("SSL_CTX_new failed\n");
        return EXIT_FAILURE;
    }

    if (SSL_EXIT_FAILURE == SSL_CTX_set_min_proto_version(squic->ssl_ctx, TLS1_3_VERSION)) {
        printf("SSL_CTX_set_min_proto_version failed\n");
        return EXIT_FAILURE;
    }

    if (SSL_EXIT_FAILURE == SSL_CTX_set_max_proto_version(squic->ssl_ctx, TLS1_3_VERSION)) {
        printf("SSL_CTX_set_max_proto_version failed\n");
        return EXIT_FAILURE;
    }

    const uint16_t sigalg = SSL_SIGN_ED25519;
    if (SSL_EXIT_FAILURE == SSL_CTX_set_verify_algorithm_prefs(squic->ssl_ctx, &sigalg, 1)) {
        printf("SSL_CTX_set_verify_algorithm_prefs failed\n");
        return EXIT_FAILURE;
    }

    // Not working here for some reason - not required but would be nice to know why
    // if (SSL_EXIT_FAILURE == SSL_CTX_set_strict_cipher_list(squic->ssl_ctx, "TLS_AES_128_GCM_SHA256:TLS_CHACHA20_POLY1305_SHA256")) {
    //     printf("SSL_CTX_set_strict_cipher_list failed\n");
    //     return EXIT_FAILURE;
    // }

    EVP_PKEY    *pkey;
    X509        *cert;
    if (EXIT_FAILURE == squic_init_dummy_x509_cert(&cert, &pkey)) {
        printf("squic_init_dummy_x509_cert failed\n");
        return EXIT_FAILURE;
    }

    if (SSL_EXIT_FAILURE == SSL_CTX_use_PrivateKey(squic->ssl_ctx, pkey)) {
        printf("SSL_CTX_use_PrivateKey failed\n");
        return EXIT_FAILURE;
    }

    if (SSL_EXIT_FAILURE == SSL_CTX_use_certificate(squic->ssl_ctx, cert)) {
        printf("SSL_CTX_use_certificate failed\n");
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}


int 
squic_init(squic_t *sqc, squic_socket_t *sqc_socket, struct lsquic_stream_if *stream_if)
{
    // Initialize the squic struct to zero
    memset(sqc, 0, sizeof(*sqc));

    // Initialize the engine settings to defaults
    lsquic_engine_init_settings(&sqc->engine_settings, 0);
    
    // Initialize the engine API
    sqc->engine_api.ea_alpn = "solana-tpu";
    sqc->engine_api.ea_settings = &sqc->engine_settings;
    sqc->engine_api.ea_stream_if = stream_if;
    sqc->engine_api.ea_stream_if_ctx = sqc;
    sqc->engine_api.ea_packets_out = squic_packets_out;
    sqc->engine_api.ea_packets_out_ctx = (void *)sqc_socket;
    sqc->engine_api.ea_get_ssl_ctx = squic_get_ssl_ctx;

    // Create the engine
    sqc->engine = lsquic_engine_new(0, &sqc->engine_api);
    if (NULL == sqc->engine) {
        printf("lsquic_engine_new failed\n");
        return EXIT_FAILURE;
    }

    // Check the engine settings
    char err_buf[100];
    if (EXIT_FAILURE == lsquic_engine_check_settings(sqc->engine_api.ea_settings, 0, err_buf, sizeof(err_buf))) {
        printf("lsquic_engine_check_settings failed: %s\n", err_buf);
        return EXIT_FAILURE;
    }

    // Initialize the SSL context
    if (EXIT_FAILURE == squic_init_ssl_ctx(sqc)) {
        printf("squic_init_ssl_ctx failed\n");
        return EXIT_FAILURE;
    }

    // Create event base and events
    sqc->event_base = event_base_new();
    if (NULL == sqc->event_base) {
        printf("event_base_new failed\n");
        return EXIT_FAILURE;
    }

    sqc->tick_event = event_new(sqc->event_base, -1, 0, squic_tick_event_handler, sqc);
    sqc->tick_event_timeout.tv_sec = 0;
    sqc->tick_event_timeout.tv_usec = 1000000; // 1000ms
    if (NULL == sqc->tick_event) {
        printf("event_new failed\n");
        return EXIT_FAILURE;
    }

    sqc->read_pkts_event = event_new(sqc->event_base, sqc_socket->fd, EV_READ|EV_PERSIST, squic_read_packets_event_handler, sqc);
    if (NULL == sqc->read_pkts_event) {
        printf("event_new failed\n");
        return EXIT_FAILURE;
    }

    sqc->read_stdin_event = event_new(sqc->event_base, STDIN_FILENO, EV_READ, squic_read_stdin_event_handler, sqc);
    if (NULL == sqc->read_stdin_event) {
        printf("event_new failed\n");
        return EXIT_FAILURE;
    }

    // Initialize the socket
    sqc->socket = sqc_socket;
    sqc->socket->fd = socket(AF_INET, SOCK_DGRAM, 0);
    sqc->socket->sas = squic_create_sockaddr_storage("127.0.0.1:4444");
    if (-1 == sqc->socket->fd) {
        printf("socket failed\n");
        return EXIT_FAILURE;
    }
    if (0 != bind(sqc->socket->fd, (struct sockaddr *)&sqc->socket->sas, sizeof(struct sockaddr_in))) {
        printf("bind failed\n");
        return EXIT_FAILURE;
    }

    // Success
    return EXIT_SUCCESS;
}


int
main(int argc, char **argv)
{
    squic_t sqc;
    squic_socket_t sqc_socket;
    struct lsquic_stream_if squic_stream_if = {
        .on_new_conn    = squic_stream_on_new_conn,
        .on_hsk_done    = squic_stream_on_hsk_done,
        .on_conn_closed = squic_stream_on_conn_closed,
        .on_new_stream  = squic_stream_on_new_stream,
        .on_read        = squic_stream_on_read,
        .on_write       = squic_stream_on_write,
        .on_close       = squic_stream_on_close,
    };

    if (EXIT_FAILURE == lsquic_global_init(LSQUIC_GLOBAL_CLIENT)) {
        printf("lsquic_global_init failed\n");
        return EXIT_FAILURE;
    }
    
    if (EXIT_FAILURE == squic_init(&sqc, &sqc_socket, &squic_stream_if)) {
        printf("squic_init failed\n");
        return EXIT_FAILURE;
    }

    event_add(sqc.read_pkts_event, NULL);
    event_add(sqc.read_stdin_event, NULL);
    event_add(sqc.tick_event, &sqc.tick_event_timeout);

    int result = event_base_loop((&sqc)->event_base, 0);
    if (-1 == result) {
        printf("squic_run failed\n");
    } else if (0 == result) {
        printf("squic_run completed successfully\n");
    } else {
        printf("squic_run exited with no more events\n");
    }
}
