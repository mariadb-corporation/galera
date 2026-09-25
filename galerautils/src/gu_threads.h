/*
 * Copyright (C) 2017-2020 Codership Oy <info@codership.com>
 */

/**
 * @file Abstracts naitive multithreading API behind POSIX threads-like API
 */

#ifndef _gu_mutex_h_
#define _gu_mutex_h_

#include "gu_types.h" // bool

#if __unix__

#include <pthread.h>
#include <assert.h>

/*
 * Thread, Mutex and Cond instrumentation
 * ======================================
 *
 * Wsrep-API v26 has an extension to allow provider to use thread, mutex
 * and condition variable implementation which is provided by the
 * application. The following types are defined to allow use of system
 * threads library and application defined thread implementation via
 * wsrep thread service.
 *
 * gu_thread_t - Thread type.
 * gu_mutex_t_SYS - Mutex type.
 * gu_cond_t_SYS - Cond type.
 *
 * Mutex and condition variable types are suffixed with _SYS to
 * allow co-existense of system/instrumented and debug mutex/cond
 * implementation. The symbols for types and function calls are
 * defined later on based on which implementation is chosen
 * during build time.
 *
 * In order to use debug mutex/cond implementation, define
 * GU_DEBUG_MUTEX in preprocessor flags.
 *
 * If the key argument to gu_{mutex|cond}_init_SYS() is NULL the
 * system implementation is used. If the key argument is given,
 * and the wsrep_thread_service is initialized by the application,
 * the mutex/cond is created by using wsrep_thread_service callback
 * and all the following operations are directed to application
 * defined implementation.
 *
 * Both mutex and cond contain two pointers worth of extra
 * space for implementation use.
 *
 * In order to introduce a new instrumented thread, mutex or cond, the
 * key for the variable must be added in wsrep_thread_keys.[c|h]pp.
 *
 * Instrumented conds should only be used with instrumented mutexes.
 * Mixing instrumented and non-instrumented mutexes and conds produce
 * undefined behavior.
 */

#include "wsrep_thread_service.h"

typedef struct gu_thread_st
{
    pthread_t sys_thread;      /* System thread. */
    wsrep_thread_t* ts_thread; /* Pointer to service implementation object. */
} gu_thread_t;

#define GU_THREAD_INITIALIZER (gu_thread_t){ 0, NULL }

extern wsrep_thread_service_v1_t* gu_thread_service;

static inline int gu_thread_create(const wsrep_thread_key_t* key,
                                   gu_thread_t* thread,
                                   void* (*fn)(void*), void* args)
{
    thread->ts_thread = NULL;
    if (gu_thread_service && key)
        return gu_thread_service->thread_create_cb(key, &thread->ts_thread, fn,
                                                   args);
    else
        return pthread_create(&thread->sys_thread, NULL, fn, args);
}

static inline int gu_thread_detach(gu_thread_t thread)
{
    if (thread.ts_thread)
        return gu_thread_service->thread_detach_cb(thread.ts_thread);
    else
        return pthread_detach(thread.sys_thread);
}

static inline int gu_thread_equal(gu_thread_t thread_1,
                                  gu_thread_t thread_2)
{
    if (thread_1.ts_thread && thread_2.ts_thread)
        return gu_thread_service->thread_equal_cb(thread_1.ts_thread,
                                                  thread_2.ts_thread);
    else
        return pthread_equal(thread_1.sys_thread, thread_2.sys_thread);
}

static inline  __attribute__((noreturn)) void gu_thread_exit(void* retval)
{
    wsrep_thread_t* thread = NULL;
    if (gu_thread_service)
        thread = gu_thread_service->thread_self_cb();
    if (thread)
        gu_thread_service->thread_exit_cb(thread, retval);
    else
        pthread_exit(retval);
}

static inline int gu_thread_join(gu_thread_t thread, void** retval)
{
    if (thread.ts_thread)
        return gu_thread_service->thread_join_cb(thread.ts_thread, retval);
    else
        return pthread_join(thread.sys_thread, retval);
}

static inline gu_thread_t gu_thread_self()
{
    gu_thread_t ret = {0, 0};
    if (gu_thread_service)
        ret.ts_thread = gu_thread_service->thread_self_cb();
    if (!ret.ts_thread)
        ret.sys_thread = pthread_self();
    return ret;
}

static inline int gu_thread_setschedparam(gu_thread_t thread, int policy,
                                          const struct sched_param* sp)
{
    if (thread.ts_thread)
        return gu_thread_service->thread_setschedparam_cb(thread.ts_thread,
                                                          policy, sp);
    else
        return pthread_setschedparam(thread.sys_thread, policy, sp);
}

static inline int gu_thread_getschedparam(gu_thread_t thread, int* policy,
                                          struct sched_param* sp)
{
    if (thread.ts_thread)
        return gu_thread_service->thread_getschedparam_cb(thread.ts_thread,
                                                          policy, sp);
    else
        return pthread_getschedparam(thread.sys_thread, policy, sp);
}

typedef struct gu_mutex_st_SYS
{
    pthread_mutex_t sys_mutex; /* System mutex. */
    void*           opaque;    /* Reserved space for service implementation. */
    void*           opaque2;   /* Reserved space for service implementation. */
    wsrep_mutex_t*  ts_mutex;  /* Pointer to service implementation object. */
} gu_mutex_t_SYS;

#define GU_MUTEX_INITIALIZER_SYS {PTHREAD_MUTEX_INITIALIZER, NULL, NULL, NULL}

static inline int gu_mutex_init_SYS(const wsrep_mutex_key_t* key,
                                    gu_mutex_t_SYS *mutex)
{
    mutex->ts_mutex = NULL;
    mutex->opaque = NULL;
    mutex->opaque2 = NULL;
    if (gu_thread_service && key)
        return ((mutex->ts_mutex =
                 gu_thread_service->mutex_init_cb(
                     key,
                     mutex,
                     sizeof(gu_mutex_t_SYS) - sizeof(wsrep_mutex_t*))) ? 0 : 1);
    else
        return pthread_mutex_init(&mutex->sys_mutex, NULL);
}

static inline int gu_mutex_destroy_SYS(gu_mutex_t_SYS *mutex)
{
    if (mutex->ts_mutex)
        return gu_thread_service->mutex_destroy_cb(mutex->ts_mutex);
    else
        return pthread_mutex_destroy(&mutex->sys_mutex);
}

static inline int gu_mutex_lock_SYS(gu_mutex_t_SYS* mutex)
{
    if (mutex->ts_mutex)
        return gu_thread_service->mutex_lock_cb(mutex->ts_mutex);
    else
        return pthread_mutex_lock(&mutex->sys_mutex);
}

static inline int gu_mutex_trylock_SYS(gu_mutex_t_SYS* mutex)
{
    if (mutex->ts_mutex)
        return gu_thread_service->mutex_trylock_cb(mutex->ts_mutex);
    else
        return pthread_mutex_trylock(&mutex->sys_mutex);
}

static inline int gu_mutex_unlock_SYS(gu_mutex_t_SYS* mutex)
{
    if (mutex->ts_mutex)
        return gu_thread_service->mutex_unlock_cb(mutex->ts_mutex);
    else
        return pthread_mutex_unlock(&mutex->sys_mutex);
}

typedef struct gu_cond_st_SYS
{
    pthread_cond_t sys_cond; /* System condition variable. */
    void*          opaque;   /* Reserved space for service implementation. */
    void*          opaque2;  /* Reserved space for service implementation. */
    wsrep_cond_t*  ts_cond; /* Pointer to service implementation object. */
} gu_cond_t_SYS;

#define GU_COND_INITIALIZER_SYS {PTHREAD_COND_INITIALIZER, NULL, NULL, NULL}

static inline int gu_cond_init_SYS(const wsrep_cond_key_t* key,
                                   gu_cond_t_SYS* cond)
{
    cond->ts_cond = NULL;
    cond->opaque = NULL;
    cond->opaque2 = NULL;
    if (gu_thread_service && key)
        return ((cond->ts_cond =
                 gu_thread_service->cond_init_cb(
                     key,
                     cond,
                     sizeof(gu_cond_t_SYS) - sizeof(wsrep_cond_t*))) ? 0 : 1);
    else
        return pthread_cond_init(&cond->sys_cond, NULL);
}

static inline int gu_cond_destroy_SYS(gu_cond_t_SYS* cond)
{
    if (cond->ts_cond)
        return gu_thread_service->cond_destroy_cb(cond->ts_cond);
    else
        return pthread_cond_destroy(&cond->sys_cond);
}

static inline int gu_cond_wait_SYS(gu_cond_t_SYS* cond,
                                   gu_mutex_t_SYS* mutex)
{
    assert((cond->ts_cond && mutex->ts_mutex) ||
           (!cond->ts_cond && !mutex->ts_mutex));
    if (cond->ts_cond)
        return gu_thread_service->cond_wait_cb(cond->ts_cond, mutex->ts_mutex);
    else
        return pthread_cond_wait(&cond->sys_cond, &mutex->sys_mutex);
}

static inline int gu_cond_timedwait_SYS(gu_cond_t_SYS* cond,
                                        gu_mutex_t_SYS* mutex,
                                        const struct timespec* ts)
{
    assert((cond->ts_cond && mutex->ts_mutex) ||
           (!cond->ts_cond && !mutex->ts_mutex));
    if (cond->ts_cond)
        return gu_thread_service->cond_timedwait_cb(cond->ts_cond,
                                                    mutex->ts_mutex, ts);
    else
        return pthread_cond_timedwait(&cond->sys_cond, &mutex->sys_mutex, ts);
}

static inline int gu_cond_signal_SYS(gu_cond_t_SYS* cond)
{
    if (cond->ts_cond)
        return gu_thread_service->cond_signal_cb(cond->ts_cond);
    else
        return pthread_cond_signal(&cond->sys_cond);
}

static inline int gu_cond_broadcast_SYS(gu_cond_t_SYS* cond)
{
    if (cond->ts_cond)
        return gu_thread_service->cond_broadcast_cb(cond->ts_cond);
    else
        return pthread_cond_broadcast(&cond->sys_cond);
}

#if defined(__APPLE__) /* emulate barriers missing on MacOS */

#ifdef __cplusplus
extern "C" {
#endif

typedef int gu_barrierattr_t_SYS;
typedef struct
{
    gu_mutex_t_SYS mutex;
    gu_cond_t_SYS  cond;
    int            count;
    int            tripCount;
} gu_barrier_t_SYS;

int gu_barrier_init_SYS   (gu_barrier_t_SYS *barrier,
                           const gu_barrierattr_t_SYS *attr,unsigned int count);
int gu_barrier_destroy_SYS(gu_barrier_t_SYS *barrier);
int gu_barrier_wait_SYS   (gu_barrier_t_SYS *barrier);

#define GU_BARRIER_SERIAL_THREAD_SYS -1

#ifdef __cplusplus
}
#endif

#else  /* native POSIX barriers */

typedef pthread_barrierattr_t  gu_barrierattr_t_SYS;
typedef pthread_barrier_t      gu_barrier_t_SYS;
#define gu_barrier_init_SYS    pthread_barrier_init
#define gu_barrier_destroy_SYS pthread_barrier_destroy
#define gu_barrier_wait_SYS    pthread_barrier_wait

#define GU_BARRIER_SERIAL_THREAD_SYS PTHREAD_BARRIER_SERIAL_THREAD

#endif /* native POSIX barriers */

#endif /* __unix__ */

/**
 *  Depending on compile-time flags application will either use
 *  normal or debug version of the API calls
 */

#ifdef GU_DEBUG_MUTEX
/* GU_DEBUG_MUTEX defined - use custom debug versions of some calls */

typedef struct
{
    gu_mutex_t_SYS  mutex;
    gu_cond_t_SYS   cond;
    gu_thread_t thread;

    /* point in source code, where called from */
    const char *file;
    int         line;
    int         waiter_count;      //!< # of threads waiting for lock
    int         cond_waiter_count; //!< # of threads waiting for some cond
    bool        locked;            //!< must be 0 or 1
}
gu_mutex_t_DBG;

#define GU_MUTEX_INITIALIZER {              \
        GU_MUTEX_INITIALIZER_SYS,           \
        GU_COND_INITIALIZER_SYS,            \
        GU_THREAD_INITIALIZER,              \
        __FILE__,                           \
        __LINE__,                           \
        0, 0, false }

#define GU_COND_INITIALIZER GU_COND_INITIALIZER_SYS

#ifdef __cplusplus
extern "C" {
#endif
/** @name Debug versions of basic mutex calls */
/*@{*/
extern
int gu_mutex_init_DBG    (gu_mutex_t_DBG *mutex,
                          const char *file, unsigned int line);
extern
int gu_mutex_lock_DBG    (gu_mutex_t_DBG *mutex,
                          const char *file, unsigned int line);
extern
int gu_mutex_unlock_DBG  (gu_mutex_t_DBG *mutex,
                          const char *file, unsigned int line);
extern
int gu_mutex_destroy_DBG (gu_mutex_t_DBG *mutex,
                          const char *file, unsigned int line);

extern
int gu_cond_twait_DBG    (gu_cond_t_SYS *cond,
                          gu_mutex_t_DBG *mutex,
                          const struct timespec *abstime,
                          const char *file, unsigned int line);

#ifdef __cplusplus
} // extern "C"
#endif

static inline
int gu_cond_wait_DBG     (gu_cond_t_SYS *cond,
                          gu_mutex_t_DBG *mutex,
                          const char *file, unsigned int line)
{
    return gu_cond_twait_DBG(cond, mutex, NULL, file, line);
}

static inline
bool gu_mutex_locked  (const gu_mutex_t_DBG* m) { return m->locked; }

static inline
bool gu_mutex_owned   (const gu_mutex_t_DBG* m)
{
    return m->locked && gu_thread_equal(gu_thread_self(), m->thread);
}

static inline
void gu_mutex_disown (gu_mutex_t_DBG* m)
{
    memset(&m->thread, 0, sizeof(m->thread));
}

/*@}*/

typedef gu_mutex_t_DBG gu_mutex_t;
#define gu_mutex_init(K,M)       gu_mutex_init_DBG     (M, __FILE__, __LINE__)
#define gu_mutex_lock(M)         gu_mutex_lock_DBG     (M, __FILE__, __LINE__)
#define gu_mutex_unlock(M)       gu_mutex_unlock_DBG   (M, __FILE__, __LINE__)
#define gu_mutex_destroy(M)      gu_mutex_destroy_DBG  (M, __FILE__, __LINE__)

typedef gu_cond_t_SYS gu_cond_t;
#define gu_cond_init(K,S)        gu_cond_init_SYS      (K, S)
#define gu_cond_wait(S,M)        gu_cond_wait_DBG    (S,M, __FILE__, __LINE__)
#define gu_cond_timedwait(S,M,T) gu_cond_twait_DBG (S,M,T, __FILE__, __LINE__)
#define gu_cond_signal(S)        gu_cond_signal_SYS    (S)
#define gu_cond_broadcast(S)     gu_cond_broadcast_SYS (S)
#define gu_cond_destroy(S)       gu_cond_destroy_SYS   (S)

#else /* GU_DEBUG_MUTEX */

/* System/instrumented mutex and condition variables. */

typedef gu_mutex_t_SYS           gu_mutex_t;
#define GU_MUTEX_INITIALIZER     GU_MUTEX_INITIALIZER_SYS
#define gu_mutex_init            gu_mutex_init_SYS
#define gu_mutex_lock            gu_mutex_lock_SYS
#define gu_mutex_unlock          gu_mutex_unlock_SYS
#define gu_mutex_destroy         gu_mutex_destroy_SYS

typedef gu_cond_t_SYS            gu_cond_t;
#define GU_COND_INITIALIZER      GU_COND_INITIALIZER_SYS
#define gu_cond_init             gu_cond_init_SYS
#define gu_cond_wait             gu_cond_wait_SYS
#define gu_cond_timedwait        gu_cond_timedwait_SYS
#define gu_cond_signal           gu_cond_signal_SYS
#define gu_cond_broadcast        gu_cond_broadcast_SYS
#define gu_cond_destroy          gu_cond_destroy_SYS

#endif /* GU_DEBUG_MUTEX */

typedef gu_barrierattr_t_SYS gu_barrierattr_t;
typedef gu_barrier_t_SYS     gu_barrier_t;
#define gu_barrier_init      gu_barrier_init_SYS
#define gu_barrier_destroy   gu_barrier_destroy_SYS
#define gu_barrier_wait      gu_barrier_wait_SYS

#define GU_BARRIER_SERIAL_THREAD GU_BARRIER_SERIAL_THREAD_SYS

#endif /* _gu_mutex_h_ */
