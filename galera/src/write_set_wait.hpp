//
// Copyright (C) 2023 Codership Oy <info@codership.com>
//

#ifndef GALERA_WRITE_SET_WAIT_HPP
#define GALERA_WRITE_SET_WAIT_HPP

#include <map>

class WriteSetWaiter
{
public:
    WriteSetWaiter()
        : signaled_(false)
        , interrupted_(false)
        , mutex_(gu::get_mutex_key(gu::GU_MUTEX_KEY_WRITESET_WAITER))
        , cond_(gu::get_cond_key(gu::GU_COND_KEY_WRITESET_WAITER))
    {
    }

    void signal()
    {
        signal(false);
    }

    void interrupt()
    {
        signal(true);
    }

    bool wait() const
    {
        gu::Lock lock(mutex_);
        while (signaled_ == false)
        {
            lock.wait(cond_);
        }
        return interrupted_;
    }

private:
    void signal(bool interrupt)
    {
        gu::Lock lock(mutex_);
        signaled_ = true;
        interrupted_ = interrupt;
        cond_.broadcast();
    }

    bool signaled_;
    bool interrupted_;
    gu::Mutex mutex_;
    gu::Cond cond_;
};

class WriteSetWaiters
{
public:
    WriteSetWaiters()
        : mutex_(gu::get_mutex_key(gu::GU_MUTEX_KEY_WRITESET_WAITER_MAP))
        , map_{}
    {
    }

    ~WriteSetWaiters()
    {
        assert(map_.empty());
        map_.clear();
    }

    gu::shared_ptr<WriteSetWaiter>::type
    register_waiter(const wsrep_uuid_t& node_id, wsrep_trx_id_t trx_id)
    {
        gu::Lock lock(mutex_);
        auto ret = map_.emplace(std::make_pair(
            WaiterKey{ node_id, trx_id }, gu::make_shared<WriteSetWaiter>()));
        return ret.first->second;
    }

    void unregister_waiter(const wsrep_uuid_t& node_id, wsrep_trx_id_t trx_id)
    {
        gu::Lock lock(mutex_);
        map_.erase({ node_id, trx_id });
    }

    void signal(const wsrep_uuid_t& node_id, wsrep_trx_id_t trx_id)
    {
        gu::Lock lock(mutex_);
        auto iter(map_.find({ node_id, trx_id }));
        if (iter != map_.end())
        {
            auto waiter = iter->second;
            waiter->signal();
        }
    }

    void interrupt_waiters()
    {
        gu::Lock lock(mutex_);
        for (auto& entry : map_)
        {
            entry.second->interrupt();
        }
    }

private:
    struct WaiterKey
    {
        WaiterKey(wsrep_uuid_t node_id, wsrep_trx_id_t trx_id)
            : node_id_(node_id)
            , trx_id_(trx_id)
        {
        }

        bool operator<(const WaiterKey& other) const
        {
            if (trx_id_ == other.trx_id_)
                return (memcmp(node_id_.data, other.node_id_.data,
                               sizeof(node_id_.data))
                        < 0);
            return (trx_id_ < other.trx_id_);
        }

        wsrep_uuid_t node_id_;
        wsrep_trx_id_t trx_id_;
    };

    gu::Mutex mutex_;
    std::map<WaiterKey, gu::shared_ptr<WriteSetWaiter>::type> map_;
};
#endif /* GALERA_WRITE_SET_WAIT_HPP */
