/*
 * Copyright (C) 2010-2019 Codership Oy <info@codership.com>
 */
/*!
 * @file C-interface to GCache.
 */

#ifndef _gcache_h_
#define _gcache_h_

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#include "gu_config.h"

typedef struct gcache_st gcache_t;

extern gcache_t* gcache_create  (gu_config_t* conf, const char* data_dir);
extern void      gcache_destroy (gcache_t* gc);

/* See description of the corresponding GCache methods */
extern void* gcache_malloc      (gcache_t* gc, int size, void** ptx);
extern void* gcache_realloc     (gcache_t* gc, void* ptr, int size, void** ptx);
extern void  gcache_free        (gcache_t* gc, const void* ptr);

/* use pointer to ciphertext (returned by gcache_malloc()/gcache_realloc())
 * to get/drop corresponding plaintext buffer */
extern const void* gcache_get_ro_plaintext(gcache_t* gc, const void* ptr);
extern       void* gcache_get_rw_plaintext(gcache_t* gc,       void* ptr);
extern       void  gcache_drop_plaintext  (gcache_t* gc, const void* ptr);

extern int64_t gcache_seqno_min (gcache_t* gc);

#ifdef __cplusplus
}
#endif

#endif /* _gcache_h_ */
