
#pragma once

#include "lsquic_types.h"

#define MAX_ADDRESS_LEN 256                 // Maximum address length
#define MAX_BYTES_SIZE 1232                 // Maximum bytes in a Solana transaction


/// @brief Our transaction context. Used to pass around data between different callbacks.
/// @note You'll need to update the lsquic library to change this in the Zig code.
typedef struct st_squic_txn
{
    char            address[MAX_ADDRESS_LEN];
    int             bytes_size;
    unsigned char   bytes[MAX_BYTES_SIZE];
} squic_txn_t;

struct lsquic_stream_ctx {
    lsquic_stream_t     *stream;                
    lsquic_conn_ctx_t   *conn_ctx;              
    squic_txn_t          txn;
};
