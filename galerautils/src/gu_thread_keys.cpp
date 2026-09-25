//
// Copyright (C) 2019 Codership Oy <info@codership.com>
//

#include "gu_thread_keys.hpp"
#include "gu_logger.hpp"
#include "gu_throw.hpp"

#include "gu_threads.h"

#include <cassert>
#include <mutex>
#include <set>
#include <vector>

std::vector<std::pair<const char*, const wsrep_thread_key_t*>> thread_keys_vec;
std::vector<std::pair<const char*, const wsrep_mutex_key_t*>> mutex_keys_vec;
std::vector<std::pair<const char*, const wsrep_cond_key_t*>> cond_keys_vec;

static struct ThreadKeysVecInitializer
{
    ThreadKeysVecInitializer()
        : name("thread")
        , expected_size(gu::GU_THREAD_KEY_MAX)
    {
        thread_keys_vec.push_back(
            std::make_pair("service", (wsrep_thread_key_t*)(0)));
        thread_keys_vec.push_back(
            std::make_pair("ist", (wsrep_thread_key_t*)(0)));
        thread_keys_vec.push_back(
            std::make_pair("ist_async_sender", (wsrep_thread_key_t*)(0)));
        thread_keys_vec.push_back(
            std::make_pair("write_set_check", (wsrep_thread_key_t*)(0)));
        thread_keys_vec.push_back(
            std::make_pair("gcs_recv", (wsrep_thread_key_t*)(0)));
        thread_keys_vec.push_back(
            std::make_pair("gcs_gcomm", (wsrep_thread_key_t*)(0)));
        assert(thread_keys_vec.size() == gu::GU_THREAD_KEY_MAX);
    }
    const char* name;
    const size_t expected_size;
} thread_keys_vec_initializer;

static struct MutexKeysVecInitializer
{
public:
    MutexKeysVecInitializer()
        : name("mutex")
        , expected_size(gu::GU_MUTEX_KEY_MAX)
    {
        mutex_keys_vec.push_back(
            std::make_pair("certification", (wsrep_mutex_key_t*)(0)));
        mutex_keys_vec.push_back(
            std::make_pair("certification_stats", (wsrep_mutex_key_t*)(0)));
        mutex_keys_vec.push_back(
            std::make_pair("pending_certification", (wsrep_mutex_key_t*)(0)));
        mutex_keys_vec.push_back(
            std::make_pair("local_monitor", (wsrep_mutex_key_t*)(0)));
        mutex_keys_vec.push_back(
            std::make_pair("apply_monitor", (wsrep_mutex_key_t*)(0)));
        mutex_keys_vec.push_back(
            std::make_pair("commit_monitor", (wsrep_mutex_key_t*)(0)));
        mutex_keys_vec.push_back(
            std::make_pair("service_thread", (wsrep_mutex_key_t*)(0)));
        mutex_keys_vec.push_back(
            std::make_pair("ist_receiver", (wsrep_mutex_key_t*)(0)));
        mutex_keys_vec.push_back(
            std::make_pair("nbo", (wsrep_mutex_key_t*)(0)));
        mutex_keys_vec.push_back(
            std::make_pair("sst", (wsrep_mutex_key_t*)(0)));
        mutex_keys_vec.push_back(
            std::make_pair("ist_event_queue", (wsrep_mutex_key_t*)(0)));
        mutex_keys_vec.push_back(
            std::make_pair("ist_async_sender", (wsrep_mutex_key_t*)(0)));
        mutex_keys_vec.push_back(
            std::make_pair("trx_handle", (wsrep_mutex_key_t*)(0)));
        mutex_keys_vec.push_back(
            std::make_pair("wsdb_trx", (wsrep_mutex_key_t*)(0)));
        mutex_keys_vec.push_back(
            std::make_pair("wsdb_conn", (wsrep_mutex_key_t*)(0)));
        mutex_keys_vec.push_back(
            std::make_pair("mempool", (wsrep_mutex_key_t*)(0)));
        mutex_keys_vec.push_back(
            std::make_pair("protostack", (wsrep_mutex_key_t*)(0)));
        mutex_keys_vec.push_back(
            std::make_pair("gcs_gcomm_recv_buf", (wsrep_mutex_key_t*)(0)));
        mutex_keys_vec.push_back(
            std::make_pair("gcs_gcomm_conn", (wsrep_mutex_key_t*)(0)));
        mutex_keys_vec.push_back(
            std::make_pair("gcs_fc", (wsrep_mutex_key_t*)(0)));
        mutex_keys_vec.push_back(
            std::make_pair("gcs_vote", (wsrep_mutex_key_t*)(0)));
        mutex_keys_vec.push_back(
            std::make_pair("gcs_repl_act_wait", (wsrep_mutex_key_t*)(0)));
        mutex_keys_vec.push_back(
            std::make_pair("gcs_join", (wsrep_mutex_key_t*)(0)));
        mutex_keys_vec.push_back(
            std::make_pair("gcs_sm", (wsrep_mutex_key_t*)(0)));
        mutex_keys_vec.push_back(
            std::make_pair("gcs_fifo_lite", (wsrep_mutex_key_t*)(0)));
        mutex_keys_vec.push_back(
            std::make_pair("gcs_core_send", (wsrep_mutex_key_t*)(0)));
        mutex_keys_vec.push_back(
            std::make_pair("gcs_core_caused", (wsrep_mutex_key_t*)(0)));
        mutex_keys_vec.push_back(
            std::make_pair("saved_state", (wsrep_mutex_key_t*)(0)));
        mutex_keys_vec.push_back(
            std::make_pair("gcache", (wsrep_mutex_key_t*)(0)));
        mutex_keys_vec.push_back(
            std::make_pair("gcs_membership", (wsrep_mutex_key_t*)(0)));
        mutex_keys_vec.push_back(
            std::make_pair("writeset_waiter_map", (wsrep_mutex_key_t*)(0)));
        mutex_keys_vec.push_back(
            std::make_pair("writeset_waiter", (wsrep_mutex_key_t*)(0)));
        assert(mutex_keys_vec.size() == gu::GU_MUTEX_KEY_MAX);
    }
    const char* name;
    const size_t expected_size;
} mutex_keys_vec_initializer;

static struct CondKeysVecInitializer
{
    CondKeysVecInitializer()
        : name("cond")
        , expected_size(gu::GU_COND_KEY_MAX)
    {
        cond_keys_vec.push_back(
            std::make_pair("local_monitor", (wsrep_cond_key_t*)(0)));
        cond_keys_vec.push_back(
            std::make_pair("apply_monitor", (wsrep_cond_key_t*)(0)));
        cond_keys_vec.push_back(
            std::make_pair("commit_monitor", (wsrep_cond_key_t*)(0)));
        cond_keys_vec.push_back(
            std::make_pair("service_thread", (wsrep_cond_key_t*)(0)));
        cond_keys_vec.push_back(
            std::make_pair("service_thread_flush", (wsrep_cond_key_t*)(0)));
        cond_keys_vec.push_back(
            std::make_pair("ist_receiver", (wsrep_cond_key_t*)(0)));
        cond_keys_vec.push_back(
            std::make_pair("nbo", (wsrep_cond_key_t*)(0)));
        cond_keys_vec.push_back(
            std::make_pair("sst", (wsrep_cond_key_t*)(0)));
        cond_keys_vec.push_back(
            std::make_pair("ist_event_queue", (wsrep_cond_key_t*)(0)));
        cond_keys_vec.push_back(
            std::make_pair("ist_async_sender", (wsrep_cond_key_t*)(0)));
        cond_keys_vec.push_back(
            std::make_pair("gcs_gcomm_recv_buf", (wsrep_cond_key_t*)(0)));
        cond_keys_vec.push_back(
            std::make_pair("gcs_gcomm_vote", (wsrep_cond_key_t*)(0)));
        cond_keys_vec.push_back(
            std::make_pair("gcs_repl_act_wait", (wsrep_cond_key_t*)(0)));
        cond_keys_vec.push_back(
            std::make_pair("gcs_sm", (wsrep_cond_key_t*)(0)));
        cond_keys_vec.push_back(
            std::make_pair("gcs_sm_close", (wsrep_cond_key_t*)(0)));
        cond_keys_vec.push_back(
            std::make_pair("gcs_set_last_applied", (wsrep_cond_key_t*)(0)));
        cond_keys_vec.push_back(
            std::make_pair("gcs_recv_thread", (wsrep_cond_key_t*)(0)));
        cond_keys_vec.push_back(
            std::make_pair("gcs_open", (wsrep_cond_key_t*)(0)));
        cond_keys_vec.push_back(
            std::make_pair("gcs_destroy", (wsrep_cond_key_t*)(0)));
        cond_keys_vec.push_back(
            std::make_pair("gcs_sendv", (wsrep_cond_key_t*)(0)));
        cond_keys_vec.push_back(
            std::make_pair("gcs_fifo_lite_put", (wsrep_cond_key_t*)(0)));
        cond_keys_vec.push_back(
            std::make_pair("gcs_fifo_lite_get", (wsrep_cond_key_t*)(0)));
        cond_keys_vec.push_back(
            std::make_pair("gcs_core_caused", (wsrep_cond_key_t*)(0)));
        cond_keys_vec.push_back(
            std::make_pair("gcache", (wsrep_cond_key_t*)(0)));
        cond_keys_vec.push_back(
            std::make_pair("write_set_waiter", (wsrep_cond_key_t*)(0)));
        assert(cond_keys_vec.size() == gu::GU_COND_KEY_MAX);
    }
    const char* name;
    const size_t expected_size;
} cond_keys_vec_initializer;

struct ThreadRegisterOp
{
    const wsrep_thread_key_t* operator()(const char* name)
    {
        return gu_thread_service->thread_key_create_cb(name);
    }
};

struct MutexRegisterOp
{
    const wsrep_mutex_key_t* operator()(const char* name)
    {
        return gu_thread_service->mutex_key_create_cb(name);
    }
};

struct CondRegisterOp
{
    const wsrep_cond_key_t* operator()(const char* name)
    {
        return gu_thread_service->cond_key_create_cb(name);
    }
};

template <class I, class IV, class R>
static void register_keys(I& initializer, IV& initializer_vec,
                          R register_op)
{
    assert(gu_thread_service);
    // Create set to validate uniqueness
    std::set<const char*> uniques;
    for (auto i(initializer_vec.begin()); i != initializer_vec.end(); ++i)
    {
        // Check that the key name is non-null and non empty string.
        if (not i->first || *i->first == '\0')
        {
            gu_throw_error(EINVAL) << "Initializer vec NULL value "
                                   << " in " << initializer.name
                                   << " at index "
                                   << std::distance(initializer_vec.begin(), i);
        }
        // Insert to set will return false if the name is not unique.
        if (not uniques.insert(i->first).second)
        {
            gu_throw_error(EINVAL) << "Initializer vec non-unique value "
                                   << i->first
                                   << " in " << initializer.name
                                   << " at index "
                                   << std::distance(initializer_vec.begin(), i);
        }
    }

    // Number of uniques does not match ini
    if (uniques.size() != initializer.expected_size)
    {
        gu_throw_error(EINVAL) << "Initializer vec for " << initializer.name
                               << ": size "
                               << uniques.size()
                               << " not expected "
                               << initializer.expected_size
                               << "";
    }

    for (auto i(initializer_vec.begin()); i != initializer_vec.end(); ++i)
    {
        i->second = register_op(i->first);
    }
}

const wsrep_thread_key_t* gu::get_thread_key(enum gu::ThreadKey key)
{
    if (size_t(key) >= thread_keys_vec.size()) return 0;
    else return thread_keys_vec[key].second;
}

const wsrep_mutex_key_t* gu::get_mutex_key(enum gu::MutexKey key)
{
    if (size_t(key) >= mutex_keys_vec.size()) return 0;
    else return mutex_keys_vec[key].second;
}

const wsrep_cond_key_t* gu::get_cond_key(enum gu::CondKey key)
{
    if (size_t(key) >= cond_keys_vec.size()) return 0;
    else return cond_keys_vec[key].second;
}

// Use system mutex for thread service initialization. Turning
// the service on while having instrumented mutex locked will
// result in undefined behavior.
static std::mutex thread_service_init_mutex;
static size_t gu_thread_service_usage;

int gu::init_thread_service_v1(wsrep_thread_service_v1_t* ts)
{
    std::lock_guard<std::mutex> lock(thread_service_init_mutex);
    if (gu_thread_service)
    {
        ++gu_thread_service_usage;
        return 0;
    }

    try
    {
        gu_thread_service = ts;
        register_keys(thread_keys_vec_initializer,
                      thread_keys_vec, ThreadRegisterOp());
        register_keys(mutex_keys_vec_initializer,
                      mutex_keys_vec, MutexRegisterOp());
        register_keys(cond_keys_vec_initializer,
                      cond_keys_vec, CondRegisterOp());
        ++gu_thread_service_usage;
        return 0;
    }
    catch (const gu::Exception& e)
    {
        log_error << "Error in gu::init_thread_service_v1: " << e.what();
        return 1;
    }
    catch (...)
    {
        log_error << "Caught unknown exception in gu::init_thread_service_v1";
        gu_thread_service = 0;
        return 1;
    }
}

void gu::deinit_thread_service_v1()
{
    std::lock_guard<std::mutex> lock(thread_service_init_mutex);
    assert(gu_thread_service_usage > 0);
    --gu_thread_service_usage;
    if (gu_thread_service_usage == 0) gu_thread_service = 0;
}
