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

#include <event2/event.h>

#include "lsquic.h"
#include "test_common.h"

#include "../src/liblsquic/lsquic_logger.h"

#include <openssl/ssl.h>
#include <openssl/curve25519.h>
#include <openssl/x509.h>
#include <openssl/bio.h>

#define STDIN_FILENO 0

#define MAX_ADDRESS_LEN 256 // Maximum address length
#define MAX_BYTES_SIZE 1232 // Maximum byte array size
#define BUFFER_SIZE 2048    // Buffer size for incoming data

#define SSL_EXIT_SUCCESS 1
#define SSL_EXIT_FAILURE 0

struct event;
struct event_base;

typedef struct st_squic {
    struct lsquic_engine_settings   engine_settings;
    struct lsquic_engine_api        engine_api;
    struct lsquic_engine           *engine;

    struct event_base              *event_base;
    struct event                   *read_stdin_event,
                                   *usr1_event;

    SSL_CTX                        *ssl_ctx;

} squic_t;


typedef struct st_squic_stream_ctx {
    struct lsquic_conn_ctx  *conn_h;
    squic_t                 *squic;
} squic_stream_ctx_t;


// Sol Transaction
typedef struct st_squic_txn
{
    char            address[MAX_ADDRESS_LEN];
    int             bytes_size;
    unsigned char   bytes[MAX_BYTES_SIZE];
} squic_txn_t;


// Print transaction data
void squic_print_txn(const squic_txn_t *data)
{
    printf("Transaction: address=%s bytes_size=%d bytes={", data->address, data->bytes_size);
    for (int i = 0; i < data->bytes_size; i++)
    {
        printf("%s%d", i == 0 ? "" : ", ", data->bytes[i]);
    }
    printf("}\n");
}


// Safe parsing function for "cin: address=... bytes_size=... bytes={...}"
int squic_parse_txn(const char *input, squic_txn_t *data)
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

// Read a line of input from a file descriptor
// Blocks until line received or error occurs
int squic_read_line(int fd, char *buffer, size_t max_len) {
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

int squic_packets_out(
    void                          *ctx,
    const struct lsquic_out_spec  *specs,
    unsigned                       n_specs
) {
    printf("squic_packets_out\n");
    (void)ctx;
    (void)specs;
    return n_specs;
}


///////////////////////////////////////////////////////////////////////////////
// Stream Callbacks
///////////////////////////////////////////////////////////////////////////////

lsquic_conn_ctx_t * squic_stream_on_new_conn(void *stream_ctx, lsquic_conn_t *conn) {
    printf("squic_stream_on_new_conn\n");
    return NULL;
}


void squic_stream_on_conn_closed(lsquic_conn_t *c) {
    printf("squic_stream_on_conn_closed\n");
}


lsquic_stream_ctx_t * squic_stream_on_new_stream(void *stream_ctx, lsquic_stream_t *stream) {
    printf("squic_stream_on_new_stream\n");
    return NULL;
}


void squic_stream_on_read(lsquic_stream_t *stream, lsquic_stream_ctx_t *stream_ctx) {
    printf("squic_stream_on_read\n");
}


void squic_stream_on_write(lsquic_stream_t *stream, lsquic_stream_ctx_t *stream_ctx) {
    printf("squic_stream_on_write\n");

}


void squic_stream_on_close(lsquic_stream_t *stream, lsquic_stream_ctx_t *stream_ctx) {
    printf("squic_stream_on_close\n");
}


///////////////////////////////////////////////////////////////////////////////
// Event Handlers
///////////////////////////////////////////////////////////////////////////////

static void
squic_read_stdin_event_handler (int fd, short what, void *arg)
{
    // Event book keeping
    squic_t * squic = (squic_t *)arg;
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

    // Print the transaction data
    squic_print_txn(&txn);
}


static void
squic_usr1_event_handler (int fd, short what, void *arg)
{
    printf("Got SIGUSR1, stopping engine\n");
}


///////////////////////////////////////////////////////////////////////////////
// Squic Initialization
///////////////////////////////////////////////////////////////////////////////

int 
squic_init_dummy_x509_cert(X509 **cert, EVP_PKEY **pkey) {
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
squic_init_ssl_ctx(squic_t *squic) {
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
squic_init(squic_t *squic, struct lsquic_stream_if *stream_if, squic_stream_ctx_t *stream_if_ctx) {
    // Initialize the squic struct to zero
    memset(squic, 0, sizeof(*squic));

    // Initialize the engine settings to defaults
    lsquic_engine_init_settings(&squic->engine_settings, 0);
    
    // Initialize the engine API
    squic->engine_api.ea_alpn = "solana-tpu";
    squic->engine_api.ea_settings = &squic->engine_settings;
    squic->engine_api.ea_stream_if = stream_if;
    squic->engine_api.ea_stream_if_ctx = stream_if_ctx;
    squic->engine_api.ea_packets_out = squic_packets_out;
    squic->engine_api.ea_packets_out_ctx = NULL; // When we are actually sending packets, we will need to set this

    // Create the engine
    squic->engine = lsquic_engine_new(0, &squic->engine_api);
    if (NULL == squic->engine) {
        printf("lsquic_engine_new failed\n");
        return EXIT_FAILURE;
    }

    // Check the engine settings
    char err_buf[100];
    if (EXIT_FAILURE == lsquic_engine_check_settings(squic->engine_api.ea_settings, 0, err_buf, sizeof(err_buf))) {
        printf("lsquic_engine_check_settings failed: %s\n", err_buf);
        return EXIT_FAILURE;
    }

    // Create event base and register handlers
    squic->event_base = event_base_new();
    if (NULL == squic->event_base) {
        printf("event_base_new failed\n");
        return EXIT_FAILURE;
    }
    squic->read_stdin_event = event_new(squic->event_base, STDIN_FILENO, EV_READ, squic_read_stdin_event_handler, squic);
    if (NULL == squic->read_stdin_event) {
        printf("event_new failed\n");
        return EXIT_FAILURE;
    }
    event_add(squic->read_stdin_event, NULL);
    squic->usr1_event = evsignal_new(squic->event_base, SIGUSR1, squic_usr1_event_handler, squic);
    evsignal_add(squic->usr1_event, NULL);

    // Initialize the SSL context
    if (EXIT_FAILURE == squic_init_ssl_ctx(squic)) {
        printf("squic_init_ssl_ctx failed\n");
        return EXIT_FAILURE;
    }

    // Success
    return EXIT_SUCCESS;
}


int
main(int argc, char **argv)
{
    squic_t squic;
    squic_stream_ctx_t squic_stream_ctx;
    struct lsquic_stream_if squic_stream_if = {
        .on_new_conn    = squic_stream_on_new_conn,
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
    
    if (EXIT_FAILURE == squic_init(&squic, &squic_stream_if, &squic_stream_ctx)) {
        printf("squic_init failed\n");
        return EXIT_FAILURE;
    }

    int result = event_base_loop((&squic)->event_base, 0);
    if (-1 == result) {
        printf("squic_run failed\n");
    } else if (0 == result) {
        printf("squic_run completed successfully\n");
    } else {
        printf("squic_run exited with no more events\n");
    }
}

// int
// main(int argc, char **argv)
// {

//     if (0 != lsquic_global_init(LSQUIC_GLOBAL_CLIENT))
//     {
//         LSQ_ERROR("global initialization failed");
//         exit(-1);
//     }

//     squic_stream_ctx_t squic_stream_ctx = {0};

//     struct lsquic_stream_if squic_stream_if = {
//         .on_new_conn    = squic_stream_on_new_conn,
//         .on_conn_closed = squic_stream_on_conn_closed,
//         .on_new_stream  = squic_stream_on_new_stream,
//         .on_read        = squic_stream_on_read,
//         .on_write       = squic_stream_on_write,
//         .on_close       = squic_stream_on_close,
//     };

//     struct lsquic_engine_api engine_api = {
//         .ea_packets_out     = squic_packets_out,
//         .ea_packets_out_ctx = NULL,
//         .ea_stream_if       = &squic_stream_if,
//         .ea_stream_if_ctx   = &squic_stream_ctx,
//         .ea_alpn            = "solana-tpu",
//     };

//     lsquic_engine_t *engine = lsquic_engine_new(0, &engine_api);

//     while (1)
//     {
//         squic_txn_t txn = {0};
//         if (0 < squic_read_next_txn_from_stdin(&txn))
//         {
//             squic_print_txn(&txn);
//         }
//     }

//     lsquic_global_cleanup();
// }
