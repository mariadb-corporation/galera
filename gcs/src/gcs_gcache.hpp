/*
 * Copyright (C) 2011-2019 Codership Oy <info@codership.com>
 *
 * $Id$
 */

#ifndef _gcs_gcache_h_
#define _gcs_gcache_h_

#ifndef GCS_FOR_GARB
    #include <gcache.h>
#else
    #ifndef gcache_t
        struct gcache_st;
        typedef struct gcache_st gcache_t;
    #endif
#endif

#include <gu_macros.h>

#include <cstdlib>

static inline void*
gcs_gcache_malloc (gcache_t* gcache, size_t size, void** ptx)
{
#ifndef GCS_FOR_GARB
    if (gu_likely(gcache != NULL))
        return gcache_malloc(gcache, size, ptx);
    else
#endif
    {
        *ptx = ::malloc(size);
        return *ptx;
    }
}

static inline void
gcs_gcache_free (gcache_t* gcache, const void* buf)
{
#ifndef GCS_FOR_GARB
    if (gu_likely (gcache != NULL))
        gcache_free (gcache, buf);
    else
#endif
        ::free (const_cast<void*>(buf));
}

static inline const void*
gcs_gcache_get_ro_plaintext (gcache_t* gcache, const void* buf)
{
#ifndef GCS_FOR_GARB
    if (gu_likely (gcache != NULL))
        return gcache_get_ro_plaintext (gcache, buf);
    else
#endif
        return buf;
}

static inline void*
gcs_gcache_get_rw_plaintext (gcache_t* gcache, void* buf)
{
#ifndef GCS_FOR_GARB
    if (gu_likely (gcache != NULL))
        return gcache_get_rw_plaintext (gcache, buf);
    else
#endif
        return buf;
}

static inline void
gcs_gcache_drop_plaintext (gcache_t* gcache, const void* buf)
{
#ifndef GCS_FOR_GARB
    if (gu_likely (gcache != NULL)) gcache_drop_plaintext (gcache, buf);
#endif
}

#endif /* _gcs_gcache_h_ */
