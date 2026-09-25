//
// Copyright (C) 2019 Codership Oy <info@codership.com>
//

#ifndef GALERA_TEST_ENV_HPP
#define GALERA_TEST_ENV_HPP

#include "gu_config.hpp"
#include "GCache.hpp"
#include "gcache_test_encryption.hpp"
#include "replicator_smm.hpp"
#include "galera_gcs.hpp"

#include <boost/filesystem.hpp>

#include <string>

namespace
{
    class TestEnv
    {
    public:

        TestEnv(const std::string& test_name, bool const enc) :
            gcache_name_(test_name + ".cache"),
            conf_   (),
            path_   (test_name + "_test"),
            init_   (conf_, gcache_name_),
            gcache_pcb_
            (galera::ProgressCallback<int64_t>(WSREP_MEMBER_UNDEFINED,
                                               WSREP_MEMBER_UNDEFINED)),
            gcache_ (&gcache_pcb_, conf_, path_.name(),
                     enc ? gcache_test_encrypt_cb : NULL, NULL),
            gcs_    (conf_, gcache_)
        {
            if (enc)
            {
                wsrep_enc_key_t const key =
                    { gcache_name_.c_str(), gcache_name_.length() };
                gcache_.set_enc_key(key);
            }
        }

        ~TestEnv() { ::unlink(gcache_name_.c_str()); }

        gu::Config&         conf()   { return conf_  ; }
        gcache::GCache&     gcache() { return gcache_; }
        galera::DummyGcs&   gcs()    { return gcs_;    }

    private:

        std::string const                 gcache_name_;
        gu::Config                        conf_;

        class Path
        {
            boost::filesystem::path const path_;
            bool const created_;

        public:
            Path(const std::string& name)
                : path_(name),
                  created_(boost::filesystem::create_directories(path_))
            {}

            ~Path()
            {
                if (created_ &&
                    path_ != boost::filesystem::current_path())
                {
                    boost::filesystem::remove_all(path_);
                }
            }

            std::string name() const { return path_.string(); }

        } /* dedicated dir for test files */  path_;

        struct Init
        {
            galera::ReplicatorSMM::InitConfig init_;

            Init(gu::Config& conf, const std::string& gcache_name)
                : init_(conf, NULL, NULL)
            {
                conf.set("gcache.name", gcache_name);
                conf.set("gcache.size", "1M");
                conf.set("gcache.page_size", "16K");
                conf.set("gcache.keep_pages_size", "0");
#ifndef NDEBUG
                conf.set("gcache.debug", "4");
#endif
            }
        }                                 init_;

        galera::ProgressCallback<int64_t> gcache_pcb_;
        gcache::GCache                    gcache_;
        galera::DummyGcs                  gcs_;
    };

} // namespace

#endif /* GALERA_TEST_ENV_HPP */
