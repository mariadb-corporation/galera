/*
 * Copyright (C) 2019 Codership Oy <info@codership.com>
 */

#ifndef _gcache_test_encryption_hpp_
#define _gcache_test_encryption_hpp_

#include <wsrep_api.h>

extern "C"
int gcache_test_encrypt_cb(
    void*                 app_ctx,
    wsrep_enc_ctx_t*      enc_ctx,
    const wsrep_buf_t*    input,
    void*                 output,
    wsrep_enc_direction_t direction,
    bool                  fin
    );

#endif /* _gcache_test_encryption_hpp_ */
