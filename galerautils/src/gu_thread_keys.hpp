//
// Copyright (C) 2019 Codership Oy <info@codership.com>
//

/*
 * Enumerations for threads, mutexes and conds which will be registered
 * into wsrep thread service if defined by the application.
 */

#ifndef GU_THREAD_KEYS_HPP
#define GU_THREAD_KEYS_HPP

#include "wsrep_thread_service.h"

namespace gu
{
    enum ThreadKey
    {
        GU_THREAD_KEY_SERVICE,
        GU_THREAD_KEY_IST,
        GU_THREAD_KEY_ASYNC_SENDER,
        GU_THREAD_KEY_WRITE_SET_CHECK,
        GU_THREAD_KEY_GCS_RECV,
        GU_THREAD_KEY_GCS_GCOMM,
        GU_THREAD_KEY_MAX // must be the last
    };

    const wsrep_thread_key_t* get_thread_key(enum ThreadKey);

    enum MutexKey
    {
        GU_MUTEX_KEY_CERTIFICATION,
        GU_MUTEX_KEY_CERTIFICATION_STATS,
        GU_MUTEX_KEY_PENDING_CERTIFICATION,
        GU_MUTEX_KEY_LOCAL_MONITOR,
        GU_MUTEX_KEY_APPLY_MONITOR,
        GU_MUTEX_KEY_COMMIT_MONITOR,
        GU_MUTEX_KEY_SERVICE_THREAD,
        GU_MUTEX_KEY_IST_RECEIVER,
        GU_MUTEX_KEY_NBO,
        GU_MUTEX_KEY_SST,
        GU_MUTEX_KEY_IST_EVENT_QUEUE,
        GU_MUTEX_KEY_IST_ASYNC_SENDER,
        GU_MUTEX_KEY_TRX_HANDLE,
        GU_MUTEX_KEY_WSDB_TRX,
        GU_MUTEX_KEY_WSDB_CONN,
        GU_MUTEX_KEY_MEMPOOL,
        GU_MUTEX_KEY_PROTOSTACK,
        GU_MUTEX_KEY_GCS_GCOMM_RECV_BUF,
        GU_MUTEX_KEY_GCS_GCOMM_CONN,
        GU_MUTEX_KEY_GCS_FC,
        GU_MUTEX_KEY_GCS_VOTE,
        GU_MUTEX_KEY_GCS_REPL_ACT_WAIT,
        GU_MUTEX_KEY_GCS_JOIN,
        GU_MUTEX_KEY_GCS_SM,
        GU_MUTEX_KEY_GCS_FIFO_LITE,
        GU_MUTEX_KEY_GCS_CORE_SEND,
        GU_MUTEX_KEY_GCS_CORE_CAUSED,
        GU_MUTEX_KEY_SAVED_STATE,
        GU_MUTEX_KEY_GCACHE,
        GU_MUTEX_KEY_GCS_MEMBERSHIP,
        GU_MUTEX_KEY_WRITESET_WAITER_MAP,
        GU_MUTEX_KEY_WRITESET_WAITER,
        GU_MUTEX_KEY_MAX /* This must always be the last */
    };

    const wsrep_mutex_key_t* get_mutex_key(enum MutexKey key);

    enum CondKey
    {
        GU_COND_KEY_LOCAL_MONITOR,
        GU_COND_KEY_APPLY_MONITOR,
        GU_COND_KEY_COMMIT_MONITOR,
        GU_COND_KEY_SERVICE_THREAD,
        GU_COND_KEY_SERVICE_THREAD_FLUSH,
        GU_COND_KEY_IST_RECEIVER,
        GU_COND_KEY_NBO,
        GU_COND_KEY_SST,
        GU_COND_KEY_IST_EVENT_QUEUE,
        GU_COND_KEY_IST_ASYNC_SENDER,
        GU_COND_KEY_GCS_GCOMM_RECV_BUF,
        GU_COND_KEY_GCS_VOTE,
        GU_COND_KEY_GCS_REPL_ACT_WAIT,
        GU_COND_KEY_GCS_SM,
        GU_COND_KEY_GCS_SM_CLOSE,
        GU_COND_KEY_GCS_SET_LAST_APPLIED,
        GU_COND_KEY_GCS_RECV_THREAD,
        GU_COND_KEY_GCS_OPEN,
        GU_COND_KEY_GCS_DESTROY,
        GU_COND_KEY_GCS_SENDV,
        GU_COND_KEY_GCS_FIFO_LITE_PUT,
        GU_COND_KEY_GCS_FIFO_LITE_GET,
        GU_COND_KEY_GCS_CORE_CAUSED,
        GU_COND_KEY_GCACHE,
        GU_COND_KEY_WRITESET_WAITER,
        GU_COND_KEY_MAX /* This must always be the last */
    };

    const wsrep_cond_key_t* get_cond_key(enum CondKey key);

    int init_thread_service_v1(wsrep_thread_service_v1_t*);
    void deinit_thread_service_v1();
}

#endif /* GU_THREAD_KEYS_HPP */
