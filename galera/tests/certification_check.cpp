//
// Copyright (C) 2015-2024 Codership Oy <info@codership.com>
//

#include "replicator_smm.hpp" // ReplicatorSMM::InitConfig
#include "certification.hpp"
#include "trx_handle.hpp"
#include "key_os.hpp"

#include "galera_test_env.hpp"

#include "gu_inttypes.hpp"
#include "test_key.hpp"

#include <check.h>

namespace
{
    struct WSInfo
    {
        wsrep_uuid_t     uuid;
        wsrep_conn_id_t  conn_id;
        wsrep_trx_id_t   trx_id;
        wsrep_buf_t      key[3];
        size_t           iov_len;
        bool             shared;
        wsrep_seqno_t    local_seqno;
        wsrep_seqno_t    global_seqno;
        wsrep_seqno_t    last_seen_seqno;
        wsrep_seqno_t    expected_depends_seqno;
        int              flags;
        wsrep_key_type_t zero_level; // type of the zero-level key
        galera::Certification::TestResult result;
        const char data_ptr[24];
        size_t data_len;
    };
}

static
void run_wsinfo(const WSInfo* const wsi, size_t const nws, int const version,
                bool const enc)
{
    galera::TrxHandleMaster::Pool mp(
        sizeof(galera::TrxHandleMaster) + sizeof(galera::WriteSetOut),
        16, "certification_mp");
    galera::TrxHandleSlave::Pool sp(
        sizeof(galera::TrxHandleSlave), 16, "certification_sp");
    TestEnv env("cert", enc);

    {   // At least with GCC 5.4.0-6ubuntu1~16.04.10 another scope is needed
        // to guarantee cert object destruction before env destruction.
        galera::Certification cert(env.conf(), env.gcache(), 0);

        cert.assign_initial_position(gu::GTID(), version);
        galera::TrxHandleMaster::Params const trx_params(
            "", version, galera::KeySet::MAX_VERSION);

        mark_point();

        for (size_t i(0); i < nws; ++i)
        {
            log_info << "%%%%%%%% Processing WS: " << i << " ver: " << version
                     << " l: " << wsi[i].local_seqno
                     << " g: " << wsi[i].global_seqno
                     << " s: " << wsi[i].last_seen_seqno
                     << " leaf: " << (wsi[i].shared ?
                                      WSREP_KEY_REFERENCE : WSREP_KEY_EXCLUSIVE)
                     << " base: " << wsi[i].zero_level;

            galera::TrxHandleMasterPtr trx(galera::TrxHandleMaster::New(
                                               mp,
                                               trx_params,
                                               wsi[i].uuid,
                                               wsi[i].conn_id,
                                               wsi[i].trx_id),
                                           galera::TrxHandleMasterDeleter());
            trx->set_flags(wsi[i].flags);
            trx->append_key(
                galera::KeyData(version,
                                wsi[i].key,
                                wsi[i].iov_len,
                                (wsi[i].shared ? galera::KeyData::BRANCH_KEY_TYPE :
                                 WSREP_KEY_EXCLUSIVE),
                                true));

            if (version >= 6) // version from which zero-level keys were introduced
            {
                if (galera::KeyData::BRANCH_KEY_TYPE != wsi[i].zero_level)
                {
                    trx->append_key(galera::KeyData(version, wsi[i].zero_level));
                }

                // this is always added last in ReplicatorSMM::replicate()
                trx->append_key(galera::KeyData(version));
            }

            if (wsi[i].data_len)
            {
                trx->append_data(wsi[i].data_ptr, wsi[i].data_len,
                                 WSREP_DATA_ORDERED, false);
            }

            galera::WriteSetNG::GatherVector out;
            size_t size(trx->write_set_out().gather(trx->source_id(),
                                                    trx->conn_id(),
                                                    trx->trx_id(),
                                                    out));
            trx->finalize(wsi[i].last_seen_seqno);

            // serialize write set into gcache buffer
            void* ptx;
            void* buf(env.gcache().malloc(size, ptx));
            ck_assert(out.serialize(ptx, size) == size);
            env.gcache().drop_plaintext(buf); // like before the slave queue

            gcs_action act = {wsi[i].global_seqno,
                              wsi[i].local_seqno,
                              buf,
                              static_cast<int32_t>(size),
                              GCS_ACT_WRITESET};
            galera::TrxHandleSlavePtr ts(galera::TrxHandleSlave::New(false, sp),
                                         galera::TrxHandleSlaveDeleter());
            /* even though ptx was not flushed to buf yet, unserialize() should
             * pick it from gcache */
            ck_assert(ts->unserialize<true>(env.gcache(), act) == size);

            galera::Certification::TestResult result(cert.append_trx(ts));
            ck_assert_msg(result == wsi[i].result,
                          "g: %" PRId64 " res: %d exp: %d, version: %d",
                          ts->global_seqno(), result, wsi[i].result, version);
            ck_assert_msg(ts->depends_seqno() == wsi[i].expected_depends_seqno,
                          "wsi: %zu g: %" PRId64 " ld: %" PRId64 " eld: %" PRId64
                          ", version: %d",
                          i, ts->global_seqno(), ts->depends_seqno(),
                          wsi[i].expected_depends_seqno, version);
            cert.set_trx_committed(*ts);
            mark_point();

            // so that the buffer can be released later
            env.gcache().seqno_assign(buf, ts->global_seqno(), GCS_ACT_WRITESET,
                                      false);
            mark_point();

            if (ts->nbo_end() && ts->ends_nbo() != WSREP_SEQNO_UNDEFINED)
            {
                cert.erase_nbo_ctx(ts->ends_nbo());
            }
            mark_point();
        }
    }
    mark_point();
    // gcache cleanup like what would result after purge_trxs_upto()
    env.gcache().seqno_release(wsi[nws - 1].global_seqno);
}

static void
certification_trx_v4(bool const enc)
{
    const int version(4);
    using galera::Certification;
    using galera::TrxHandle;
    using galera::void_cast;

    // TRX certification rules:
    // *
    WSInfo wsi[] = {
        // 1 - 4: shared - shared
        // First four cases are shared keys, they should not collide or
        // generate dependency
        // 1: no dependencies
        { { {1, } }, 1, 1,
          { {void_cast("1"), 1}, {void_cast("1"), 1}, {void_cast("1"), 1} }, 3, true,
          1, 1, 0, 0, TrxHandle::F_BEGIN | TrxHandle::F_COMMIT,
          galera::KeyData::BRANCH_KEY_TYPE,
          Certification::TEST_OK, {0}, 0},
        // 2: no dependencies
        { { {1, } }, 1, 2,
          { {void_cast("1"), 1}, {void_cast("1"), 1}, {void_cast("1"), 1} }, 3, true,
          2, 2, 0, 0, TrxHandle::F_BEGIN | TrxHandle::F_COMMIT,
          galera::KeyData::BRANCH_KEY_TYPE,
          Certification::TEST_OK , {0}, 0},
        // 3: no dependencies
        { { {2, } }, 1, 3,
          { {void_cast("1"), 1}, {void_cast("1"), 1}, {void_cast("1"), 1} }, 3, true,
          3, 3, 0, 0, TrxHandle::F_BEGIN | TrxHandle::F_COMMIT,
          galera::KeyData::BRANCH_KEY_TYPE,
          Certification::TEST_OK, {0}, 0},
        // 4: no dependencies
        { { {3, } }, 1, 4,
          { {void_cast("1"), 1}, {void_cast("1"), 1}, {void_cast("1"), 1} }, 3, true,
          4, 4, 0, 0, TrxHandle::F_BEGIN | TrxHandle::F_COMMIT,
          galera::KeyData::BRANCH_KEY_TYPE,
          Certification::TEST_OK, {0}, 0},
        // 5: shared - exclusive
        // 5: depends on 4
        { { {2, } }, 1, 5,
          { {void_cast("1"), 1}, {void_cast("1"), 1}, {void_cast("1"), 1} }, 3, false,
          5, 5, 4, 4, TrxHandle::F_BEGIN | TrxHandle::F_COMMIT,
          galera::KeyData::BRANCH_KEY_TYPE,
          Certification::TEST_OK, {0}, 0},
        // 6 - 8: exclusive - shared
        // 6: collides with 5
        { { {1, } }, 1, 6,
          { {void_cast("1"), 1}, {void_cast("1"), 1}, {void_cast("1"), 1} }, 3, true,
          6, 6, 4, 5, TrxHandle::F_BEGIN | TrxHandle::F_COMMIT,
          galera::KeyData::BRANCH_KEY_TYPE,
          Certification::TEST_FAILED, {0}, 0},
        // 7: depends on 5
        { { {2, } }, 1, 7,
          { {void_cast("1"), 1}, {void_cast("1"), 1}, {void_cast("1"), 1} }, 3, true,
          7, 7, 4, 5, TrxHandle::F_BEGIN | TrxHandle::F_COMMIT,
          galera::KeyData::BRANCH_KEY_TYPE,
          Certification::TEST_OK, {0}, 0},
        // 8: collides with 5
        { { {1, } }, 1, 8,
          { {void_cast("1"), 1}, {void_cast("1"), 1}, {void_cast("1"), 1}}, 3, true,
          8, 8, 4, 5, TrxHandle::F_BEGIN | TrxHandle::F_COMMIT,
          galera::KeyData::BRANCH_KEY_TYPE,
          Certification::TEST_FAILED, {0}, 0},
        // 9 - 10: shared key shadows dependency to 5
        // 9: depends on 5
        { { {2, } }, 1, 9,
          { {void_cast("1"), 1}, {void_cast("1"), 1}, {void_cast("1"), 1} }, 3, true,
          9, 9, 0, 5, TrxHandle::F_BEGIN | TrxHandle::F_COMMIT,
          galera::KeyData::BRANCH_KEY_TYPE,
          Certification::TEST_OK, {0}, 0},
        // 10: depends on 5
        { { {2, } }, 1, 10,
          { {void_cast("1"), 1}, {void_cast("1"), 1}, {void_cast("1"), 1} }, 3, true,
          10, 10, 6, 5, TrxHandle::F_BEGIN | TrxHandle::F_COMMIT,
          galera::KeyData::BRANCH_KEY_TYPE,
          Certification::TEST_OK, {0}, 0},
        // 11 - 13: exclusive - shared - exclusive dependency
        { { {2, } }, 1, 11,
          { {void_cast("1"), 1}, {void_cast("1"), 1}, {void_cast("1"), 1} }, 3, false,
          11, 11, 10, 10, TrxHandle::F_BEGIN | TrxHandle::F_COMMIT,
          galera::KeyData::BRANCH_KEY_TYPE,
          Certification::TEST_OK, {0}, 0},
        { { {2, } }, 1, 12,
          { {void_cast("1"), 1}, {void_cast("1"), 1}, {void_cast("1"), 1} }, 3, true,
          12, 12, 10, 11, TrxHandle::F_BEGIN | TrxHandle::F_COMMIT,
          galera::KeyData::BRANCH_KEY_TYPE,
          Certification::TEST_OK, {0}, 0},
        { { {2, } }, 1, 13,
          { {void_cast("1"), 1}, {void_cast("1"), 1}, {void_cast("1"), 1} }, 3, false,
          13, 13, 10, 12, TrxHandle::F_BEGIN | TrxHandle::F_COMMIT,
          galera::KeyData::BRANCH_KEY_TYPE,
          Certification::TEST_OK, {0}, 0},
        // 14: conflicts with 13
        { { {1, } }, 1, 14,
          { {void_cast("1"), 1}, {void_cast("1"), 1}, {void_cast("1"), 1}}, 3, false,
          14, 14, 12, 13, TrxHandle::F_BEGIN | TrxHandle::F_COMMIT,
          galera::KeyData::BRANCH_KEY_TYPE,
          Certification::TEST_FAILED, {0}, 0}
    };

    size_t nws(sizeof(wsi)/sizeof(wsi[0]));

    run_wsinfo(wsi, nws, version, enc);
}

START_TEST(test_certification_trx_v4)
{
    certification_trx_v4(false);
}
END_TEST

START_TEST(test_certification_trx_v4E)
{
    certification_trx_v4(true);
}
END_TEST


static void
certification_trx_different_level_v3(bool const enc)
{
    const int version(4);
    using galera::Certification;
    using galera::TrxHandle;
    using galera::void_cast;

    //
    // Test the following cases:
    // 1) exclusive (k1, k2, k3) <-> exclusive (k1, k2) -> conflict
    // 2) exclusive (k1, k2) <-> exclusive (k1, k2, k3) -> conflict
    //
    WSInfo wsi[] = {
        // 1)
        { { {1, } }, 1, 1,
          { {void_cast("1"), 1}, {void_cast("1"), 1}, {void_cast("1"), 1} }, 3, false,
          1, 1, 0, 0, TrxHandle::F_BEGIN | TrxHandle::F_COMMIT,
          galera::KeyData::BRANCH_KEY_TYPE,
          Certification::TEST_OK, {0}, 0},
        { { {2, } }, 2, 2,
          { {void_cast("1"), 1}, {void_cast("1"), 1} }, 2, false,
          2, 2, 0, 1, TrxHandle::F_BEGIN | TrxHandle::F_COMMIT,
          galera::KeyData::BRANCH_KEY_TYPE,
          Certification::TEST_FAILED, {0}, 0},
        // 2)
        { { {2, } }, 2, 2,
          { {void_cast("1"), 1}, {void_cast("1"), 1} }, 2, false,
          3, 3, 2, 1, TrxHandle::F_BEGIN | TrxHandle::F_COMMIT,
          galera::KeyData::BRANCH_KEY_TYPE,
          Certification::TEST_OK, {0}, 0},
        { { {1, } }, 1, 1,
          { {void_cast("1"), 1}, {void_cast("1"), 1}, {void_cast("1"), 1} }, 3, false,
          4, 4, 2, 3, TrxHandle::F_BEGIN | TrxHandle::F_COMMIT,
          galera::KeyData::BRANCH_KEY_TYPE,
          Certification::TEST_FAILED, {0}, 0}
    };

    size_t nws(sizeof(wsi)/sizeof(wsi[0]));

    run_wsinfo(wsi, nws, version, enc);
}

START_TEST(test_certification_trx_different_level_v3)
{
    certification_trx_different_level_v3(false);
}
END_TEST

START_TEST(test_certification_trx_different_level_v3E)
{
    certification_trx_different_level_v3(true);
}
END_TEST


static void
certification_toi_v3(bool const enc)
{
    const int version(3);
    using galera::Certification;
    using galera::TrxHandle;
    using galera::void_cast;

    // Note that only exclusive keys are used for TOI.
    // TRX - TOI and TOI - TOI matches:
    // * TOI should always depend on preceding write set
    // TOI - TRX matches:
    // * if coming from the same source, dependency
    // * if coming from different sources, conflict
    // TOI - TOI matches:
    // * always dependency
    WSInfo wsi[] = {
        // TOI
        { { {1, } }, 1, 1,
          { {void_cast("1"), 1}, {void_cast("1"), 1}, }, 2, false,
          1, 1, 0, 0,
          TrxHandle::F_ISOLATION | TrxHandle::F_BEGIN | TrxHandle::F_COMMIT,
          galera::KeyData::BRANCH_KEY_TYPE,
          Certification::TEST_OK, {0}, 0},
        // TOI 2 Depends on TOI 1
        { { {2, } }, 2, 2,
          { {void_cast("1"), 1}, }, 1, false,
          2, 2, 0, 1,
          TrxHandle::F_ISOLATION | TrxHandle::F_BEGIN | TrxHandle::F_COMMIT,
          galera::KeyData::BRANCH_KEY_TYPE,
          Certification::TEST_OK, {0}, 0},
        // Trx 3 from the same source depends on TOI 2
        { { {2, } }, 3, 3,
          { {void_cast("1"), 1}, {void_cast("1"), 1}, {void_cast("1"), 1}}, 3, false,
          3, 3, 2, 2,
          TrxHandle::F_BEGIN | TrxHandle::F_COMMIT,
          galera::KeyData::BRANCH_KEY_TYPE,
          Certification::TEST_OK, {0}, 0},
        // Trx 4 from different source conflicts with 3
        { { {3, } }, 3, 3,
          { {void_cast("1"), 1}, {void_cast("1"), 1}, {void_cast("1"), 1}}, 3, false,
          4, 4, 2, 3,
          TrxHandle::F_BEGIN | TrxHandle::F_COMMIT,
          galera::KeyData::BRANCH_KEY_TYPE,
          Certification::TEST_FAILED, {0}, 0},
        // Non conflicting TOI 5 depends on 4
        { { {1, } }, 2, 2,
          { {void_cast("2"), 1}, }, 1, false,
          5, 5, 0, 4,
          TrxHandle::F_ISOLATION | TrxHandle::F_BEGIN | TrxHandle::F_COMMIT,
          galera::KeyData::BRANCH_KEY_TYPE,
          Certification::TEST_OK, {0}, 0},
        // Trx 6 from different source conflicts with TOI 5
        { { {3, } }, 3, 3,
          { {void_cast("2"), 1}, {void_cast("1"), 1}, {void_cast("1"), 1}}, 3, false,
          6, 6, 4, 5,
          TrxHandle::F_BEGIN | TrxHandle::F_COMMIT,
          galera::KeyData::BRANCH_KEY_TYPE,
          Certification::TEST_FAILED, {0}, 0}
    };

    size_t nws(sizeof(wsi)/sizeof(wsi[0]));

    run_wsinfo(wsi, nws, version, enc);
}

START_TEST(test_certification_toi_v3)
{
    certification_toi_v3(false);
}
END_TEST

START_TEST(test_certification_toi_v3E)
{
    certification_toi_v3(true);
}
END_TEST


static void
certification_nbo(bool const enc)
{
    log_info << "START: test_certification_nbo";
    const int version(galera::WriteSetNG::VER5);
    using galera::Certification;
    using galera::TrxHandle;
    using galera::void_cast;

    // Non blocking operations with respect to TOI
    // NBO - TOI: Always conflict
    // TOI - NBO: Always dependency
    WSInfo wsi[] = {
        // 1 - 2: NBO(1) - TOI(2)
        // 1 - 3: NBO(1) - NBO(3)
        { { {1, } }, 1, 1,
          { {void_cast("1"), 1}, }, 1, false,
          1, 1, 0, 0,
          TrxHandle::F_ISOLATION | TrxHandle::F_BEGIN,
          galera::KeyData::BRANCH_KEY_TYPE,
          Certification::TEST_OK, {0}, 0},
        { { {1, } }, 2, 2,
          { {void_cast("1"), 1}, }, 1, false,
          2, 2, 0, 1,
          TrxHandle::F_ISOLATION | TrxHandle::F_BEGIN | TrxHandle::F_COMMIT,
          galera::KeyData::BRANCH_KEY_TYPE,
          Certification::TEST_FAILED, {0}, 0},
        { { {1, } }, 3, 3,
          { {void_cast("1"), 1}, }, 1, false,
          3, 3, 0, 2,
          TrxHandle::F_ISOLATION | TrxHandle::F_BEGIN,
          galera::KeyData::BRANCH_KEY_TYPE,
          Certification::TEST_FAILED, {0}, 0},
        // 4 - 5 no conflict, different key
        { { {1, } }, 4, 4,
          { {void_cast("2"), 1}, }, 1, false,
          4, 4, 0, 3,
          TrxHandle::F_ISOLATION | TrxHandle::F_BEGIN | TrxHandle::F_COMMIT,
          galera::KeyData::BRANCH_KEY_TYPE,
          Certification::TEST_OK, {0}, 0},
        { { {2, } }, 5, 5,
          { {void_cast("2"), 1}, }, 1, false,
          5, 5, 0, 4,
          TrxHandle::F_ISOLATION | TrxHandle::F_BEGIN,
          galera::KeyData::BRANCH_KEY_TYPE,
          Certification::TEST_OK, {0}, 0},
        // 6 ends the NBO with key 1
        // notice the same uuid, conn_id/trx_id as the first entry
        { { {1, } }, 1, 1,
          { {void_cast("1"), 1}, }, 1, false,
          6, 6, 0, 5,
          TrxHandle::F_ISOLATION | TrxHandle::F_COMMIT,
          galera::KeyData::BRANCH_KEY_TYPE,
          Certification::TEST_OK,
          {1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0},
          24
        },
        // 7 should now succeed
        { { {1, } }, 7, 7,
          { {void_cast("1"), 1}, }, 1, false,
          7, 7, 0, 6,
          TrxHandle::F_ISOLATION | TrxHandle::F_BEGIN | TrxHandle::F_COMMIT,
          galera::KeyData::BRANCH_KEY_TYPE,
          Certification::TEST_OK, {0}, 0},
        // Complete seqno 5 to clean up
        { { {2, } }, 8, 8,
          { {void_cast("2"), 1}, }, 1, false,
          8, 8, 0, 7,
          TrxHandle::F_ISOLATION | TrxHandle::F_COMMIT,
          galera::KeyData::BRANCH_KEY_TYPE,
          Certification::TEST_OK,
          {5, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 5, 0, 0, 0, 0, 0, 0, 0},
          24
        }
    };

    size_t nws(sizeof(wsi)/sizeof(wsi[0]));

    run_wsinfo(wsi, nws, version, enc);

    log_info << "END: test_certification_nbo";
}

START_TEST(test_certification_nbo)
{
    certification_nbo(false);
}
END_TEST

START_TEST(test_certification_nboE)
{
    certification_nbo(true);
}
END_TEST


static void
certification_commit_fragment(bool const enc)
{
    const int version(galera::WriteSetNG::VER5);
    using galera::Certification;
    using galera::TrxHandle;
    using galera::void_cast;

    WSInfo wsi[] = {
        // commit fragment vs commit fragment
        { { {1, } }, 1, 1,
          { {void_cast("1"), 1}, {void_cast("1"), 1} }, 2, true,
          1, 1, 0, 0, TrxHandle::F_BEGIN | TrxHandle::F_COMMIT | TrxHandle::F_PA_UNSAFE,
          galera::KeyData::BRANCH_KEY_TYPE,
          Certification::TEST_OK, {0}, 0},
        { { {2, } }, 2, 2,
          { {void_cast("1"), 1}, {void_cast("1"), 1} }, 2, true,
          2, 2, 0, 1, TrxHandle::F_BEGIN | TrxHandle::F_COMMIT | TrxHandle::F_PA_UNSAFE,
          galera::KeyData::BRANCH_KEY_TYPE,
          Certification::TEST_OK, {0}, 0},

        // TOI vs commit fragment
        { { {2, } }, 2, 2,
          { {void_cast("1"), 1}, {void_cast("1"), 1} }, 2, false,
          3, 3, 2, 2, TrxHandle::F_ISOLATION | TrxHandle::F_BEGIN | TrxHandle::F_COMMIT,
          galera::KeyData::BRANCH_KEY_TYPE,
          Certification::TEST_OK, {0}, 0},
        { { {1, } }, 1, 1,
          { {void_cast("1"), 1}, {void_cast("1"), 1} }, 2, true,
          4, 4, 2, 3, TrxHandle::F_BEGIN | TrxHandle::F_COMMIT | TrxHandle::F_PA_UNSAFE,
          galera::KeyData::BRANCH_KEY_TYPE,
          Certification::TEST_FAILED, {0}, 0},

        // commit fragment vs TOI
        { { {2, } }, 2, 2,
          { {void_cast("1"), 1}, {void_cast("1"), 1} }, 2, true,
          5, 5, 3, 4, TrxHandle::F_BEGIN | TrxHandle::F_COMMIT | TrxHandle::F_PA_UNSAFE,
          galera::KeyData::BRANCH_KEY_TYPE,
          Certification::TEST_OK, {0}, 0},
        { { {1, } }, 1, 1,
          { {void_cast("1"), 1}, {void_cast("1"), 1} }, 2, false,
          6, 6, 4, 5, TrxHandle::F_ISOLATION | TrxHandle::F_BEGIN | TrxHandle::F_COMMIT,
          galera::KeyData::BRANCH_KEY_TYPE,
          Certification::TEST_OK, {0}, 0}

    };

    size_t nws(sizeof(wsi)/sizeof(wsi[0]));

    run_wsinfo(wsi, nws, version, enc);
}

START_TEST(test_certification_commit_fragment)
{
    certification_commit_fragment(false);
}
END_TEST

START_TEST(test_certification_commit_fragmentE)
{
    certification_commit_fragment(true);
}
END_TEST

static void certification_zero_level(bool const enc)
{

    const int version(6);
    using galera::Certification;
    using galera::TrxHandle;
    using galera::void_cast;

    // Interaction of a zero-level non-REFERENCE key with "regular" transactions
    // "Regular" transaction has a zero-level key, so regarless of TOI or
    // non-TOI, shared or exclusive, it shall interact as a REFERENCE key trx:
    // conflict:
    // * REFERENCE,EXCLUSIVE - EXCLUSIVE conflicts with REFERENCE
    // * EXCLUSIVE,REFERENCE - REFERENCE conflicts with EXCLUSIVE
    WSInfo wsi[] = {
        // 1: no dependencies
        { { {1, } }, 1, 1,
          { {void_cast("1"), 1}, {void_cast("1"), 1}, {void_cast("1"), 1} }, 3, true,
          1, 1, 0, 0, TrxHandle::F_BEGIN | TrxHandle::F_COMMIT,
          galera::KeyData::BRANCH_KEY_TYPE,
          Certification::TEST_OK, {0}, 0},
        // 2: exclusive zero-level same source depends on 1
        { { {1, } }, 1, 2,
          {}, 0, true,
          2, 2, 0, 1, TrxHandle::F_BEGIN | TrxHandle::F_COMMIT,
          WSREP_KEY_EXCLUSIVE,
          Certification::TEST_OK, {0}, 0},
        // 3: default zero-level last seen 1 - conflict with 2
        { { {2, } }, 1, 3,
          { {void_cast("1"), 1}, {void_cast("1"), 1}, {void_cast("1"), 1} }, 3, true,
          3, 3, 1, 2, TrxHandle::F_BEGIN | TrxHandle::F_COMMIT,
          galera::KeyData::BRANCH_KEY_TYPE,
          Certification::TEST_FAILED, {0}, 0},
        // 4: depends on 2
        { { {3, } }, 1, 4,
          { {void_cast("1"), 1}, {void_cast("1"), 1}, {void_cast("1"), 1} }, 3, true,
          4, 4, 2, 2, TrxHandle::F_BEGIN | TrxHandle::F_COMMIT,
          galera::KeyData::BRANCH_KEY_TYPE,
          Certification::TEST_OK, {0}, 0},
        // 5: exclusive depends on 4, conflicts with 2
        { { {1, } }, 1, 5,
          { {void_cast("1"), 1}, {void_cast("1"), 1}, {void_cast("1"), 1} }, 3, false,
          5, 5, 0, 4, TrxHandle::F_BEGIN | TrxHandle::F_COMMIT,
          galera::KeyData::BRANCH_KEY_TYPE,
          Certification::TEST_FAILED, {0}, 0},
        // 6: reference depends but does not conflict with 2 because same source
        { { {1, } }, 1, 6,
          { {void_cast("1"), 1}, {void_cast("1"), 1}, {void_cast("1"), 1} }, 3, true,
          6, 6, 1, 2, TrxHandle::F_BEGIN | TrxHandle::F_COMMIT,
          galera::KeyData::BRANCH_KEY_TYPE,
          Certification::TEST_OK, {0}, 0},
        // 7: exclusive, saw 2, conflicts with 6
        { { {2, } }, 1, 7,
          { {void_cast("1"), 1}, {void_cast("1"), 1}, {void_cast("1"), 1} }, 3, false,
          7, 7, 2, 6, TrxHandle::F_BEGIN | TrxHandle::F_COMMIT,
          galera::KeyData::BRANCH_KEY_TYPE,
          Certification::TEST_FAILED, {0}, 0},
        // 8: exclusive zero-level depends on 6 because same source
        { { {1, } }, 1, 8,
          {}, 0, true,
          8, 8, 4, 6, TrxHandle::F_BEGIN | TrxHandle::F_COMMIT,
          WSREP_KEY_EXCLUSIVE,
          Certification::TEST_OK, {0}, 0},
        // 9: exclusive zero-level conflicts with exclusive zero-level 8
        { { {2, } }, 1, 9,
          {}, 0, true,
          9, 9, 6, 8, TrxHandle::F_BEGIN | TrxHandle::F_COMMIT,
          WSREP_KEY_EXCLUSIVE,
          Certification::TEST_FAILED, {0}, 0},
        // TOI 1 depends on zero-level 8
        { { {2, } }, 1, 1,
          { {void_cast("1"), 1}, }, 1, false,
          10, 10, 7, 9,
          TrxHandle::F_ISOLATION | TrxHandle::F_BEGIN | TrxHandle::F_COMMIT,
          galera::KeyData::BRANCH_KEY_TYPE,
          Certification::TEST_OK, {0}, 0},
        // TOI 2 Depends on zero-level 8 (same source)
        { { {1, } }, 2, 2,
          { {void_cast("1"), 1}, }, 1, false,
          11, 11, 3, 10,
          TrxHandle::F_ISOLATION | TrxHandle::F_BEGIN | TrxHandle::F_COMMIT,
          galera::KeyData::BRANCH_KEY_TYPE,
          Certification::TEST_OK, {0}, 0},
        // zero-level 12 from the different source conflicts with TOI 2
        { { {2, } }, 3, 3,
          {}, 0, true,
          12, 12, 10, 11,
          TrxHandle::F_BEGIN | TrxHandle::F_COMMIT,
          WSREP_KEY_EXCLUSIVE,
          Certification::TEST_FAILED, {0}, 0},
    };

    size_t nws(sizeof(wsi)/sizeof(wsi[0]));

    run_wsinfo(wsi, nws, version, enc);

}

START_TEST(test_certification_zero_level)
{
    certification_zero_level(false);
}
END_TEST

START_TEST(test_certification_zero_levelE)
{
    certification_zero_level(true);
}
END_TEST

using CertResult = galera::Certification::TestResult;
struct CertFixture
{
    gu::Config conf{};
    struct InitConf
    {
        galera::ReplicatorSMM::InitConfig init;
        InitConf(gu::Config& conf) : init(conf, NULL, NULL)
        {
            conf.set("gcache.name", "cert_fixture.cache");
            conf.set("gcache.size", "1M");
        }
    } init_conf{conf};

    galera::TrxHandleMaster::Pool mp{ sizeof(galera::TrxHandleMaster)
                                          + sizeof(galera::WriteSetOut),
                                      16, "certification_mp" };
    galera::TrxHandleSlave::Pool sp{ sizeof(galera::TrxHandleSlave), 16,
                                     "certification_sp" };

    galera::ProgressCallback<int64_t> gcache_pcb{WSREP_MEMBER_UNDEFINED,
        WSREP_MEMBER_UNDEFINED};
    gcache::GCache gcache{&gcache_pcb, conf, "."};
    galera::Certification cert{conf, gcache, 0};
    int version = galera::WriteSetNG::MAX_VERSION;
    CertFixture() {
        cert.assign_initial_position(gu::GTID(), version);
    }

    wsrep_uuid_t node1{{1, }};
    wsrep_uuid_t node2{{2, }};

    wsrep_conn_id_t conn1{1};
    wsrep_conn_id_t conn2{2};

    wsrep_trx_id_t cur_trx_id{0};
    wsrep_seqno_t cur_seqno{0};

    struct CfCertResult {
        CertResult result;
        galera::TrxHandleSlavePtr ts;
    };

    CfCertResult append(const wsrep_uuid_t& node, wsrep_conn_id_t conn,
                        wsrep_seqno_t last_seen,
                        const std::vector<const char*>& key,
                        wsrep_key_type_t type, int flags,
                        const gu::byte_t* data_buf, size_t data_buf_len)
    {
        galera::TrxHandleMasterPtr txm{ galera::TrxHandleMaster::New(
                                            mp,
                                            galera::TrxHandleMaster::Params{
                                                "", version,
                                                galera::KeySet::MAX_VERSION },
                                            node, conn, cur_trx_id),
                                        galera::TrxHandleMasterDeleter{} };
        txm->set_flags(flags);
        TestKey tkey{ txm->version(), type, key };
        txm->append_key(tkey());
        if (data_buf)
        {
            txm->append_data(data_buf, data_buf_len, WSREP_DATA_ORDERED, false);
        }
        galera::WriteSetNG::GatherVector out;
        size_t size = txm->write_set_out().gather(
            txm->source_id(), txm->conn_id(), txm->trx_id(), out);
        txm->finalize(last_seen);
        void* ptx;
        gu::byte_t* buf = static_cast<gu::byte_t*>(gcache.malloc(size, ptx));
        ck_assert(out.serialize(ptx, size) == size);
        gcache.drop_plaintext(buf);
        ++cur_seqno;
        gcs_action act = { cur_seqno, cur_seqno, buf,
                           static_cast<int32_t>(size), GCS_ACT_WRITESET };
        galera::TrxHandleSlavePtr ts(galera::TrxHandleSlave::New(false, sp),
                                     galera::TrxHandleSlaveDeleter{});
        ck_assert(ts->unserialize<true>(gcache, act) == size);
        auto result = cert.append_trx(ts);
        /* Mark committed here to avoid doing it in every test case. If the
         * ts is not marked as committed, the certification destructor will
         * assert during cleanup. */
        ts->mark_committed();
        return { result, ts };
    }

    CfCertResult append_trx(const wsrep_uuid_t& node, wsrep_conn_id_t conn,
                            wsrep_seqno_t last_seen,
                            const std::vector<const char*>& key,
                            wsrep_key_type_t type)
    {
        return append(node, conn, last_seen, key, type,
                      galera::TrxHandle::F_BEGIN | galera::TrxHandle::F_COMMIT,
                      nullptr, 0);
    }

    CfCertResult append_toi(const wsrep_uuid_t& node, wsrep_conn_id_t conn,
                            wsrep_seqno_t last_seen,
                            const std::vector<const char*>& key,
                            wsrep_key_type_t type)
    {
        return append(node, conn, last_seen, key, type,
                      galera::TrxHandle::F_BEGIN | galera::TrxHandle::F_COMMIT
                          | galera::TrxHandle::F_ISOLATION,
                      nullptr, 0);
    }

    CfCertResult append_nbo_begin(const wsrep_uuid_t& node,
                                  wsrep_conn_id_t conn, wsrep_seqno_t last_seen,
                                  const std::vector<const char*>& key,
                                  wsrep_key_type_t type)
    {
        return append(node, conn, last_seen, key, type,
                      galera::TrxHandle::F_BEGIN
                          | galera::TrxHandle::F_ISOLATION,
                      nullptr, 0);
    }

    CfCertResult append_nbo_end(const wsrep_uuid_t& node, wsrep_conn_id_t conn,
                                wsrep_seqno_t last_seen,
                                const std::vector<const char*>& key,
                                wsrep_key_type_t type,
                                wsrep_seqno_t begin_seqno)
    {
        gu::byte_t buf[24];
        galera::NBOKey nbo_key(begin_seqno);
        size_t nbo_key_len = nbo_key.serialize(buf, sizeof(buf), 0);
        return append(node, conn, last_seen, key, type,
                      galera::TrxHandle::F_COMMIT
                          | galera::TrxHandle::F_ISOLATION,
                      buf, nbo_key_len);
    }
};

/* This testcase is mainly for checking that the CertFixture works correctly. */
START_TEST(cert_append_trx)
{
    CertFixture f;
    auto res
        = f.append_trx(f.node1, f.conn2, 0, { "b", "l" }, WSREP_KEY_EXCLUSIVE);
    ck_assert(res.ts->certified());
    ck_assert_int_eq(res.result, CertResult::TEST_OK);
    ck_assert_int_eq(res.ts->depends_seqno(), 0);
    ck_assert_int_eq(res.ts->global_seqno(), 1);
}
END_TEST

/*
 * Cert against shared
 */

START_TEST(cert_certify_shared_shared)
{
    CertFixture f;
    auto res = f.append_trx(f.node1, f.conn1, 0, {"b", "l"}, WSREP_KEY_SHARED);
    ck_assert_int_eq(res.result, CertResult::TEST_OK);
    res = f.append_trx(f.node2, f.conn2, 0, {"b", "l"}, WSREP_KEY_SHARED);
    ck_assert_int_eq(res.result, CertResult::TEST_OK);
    ck_assert_int_eq(res.ts->depends_seqno(), 0);
}
END_TEST

START_TEST(cert_certify_shared_reference)
{
    CertFixture f;
    auto res = f.append_trx(f.node1, f.conn1, 0, {"b", "l"}, WSREP_KEY_SHARED);
    ck_assert_int_eq(res.result, CertResult::TEST_OK);
    res = f.append_trx(f.node2, f.conn2, 0, {"b", "l"}, WSREP_KEY_REFERENCE);
    ck_assert_int_eq(res.result, CertResult::TEST_OK);
    ck_assert_int_eq(res.ts->depends_seqno(), 0);
}
END_TEST

START_TEST(cert_certify_shared_update)
{
    CertFixture f;
    auto res = f.append_trx(f.node1, f.conn1, 0, {"b", "l"}, WSREP_KEY_SHARED);
    ck_assert_int_eq(res.result, CertResult::TEST_OK);
    res = f.append_trx(f.node2, f.conn2, 0, {"b", "l"}, WSREP_KEY_UPDATE);
    ck_assert_int_eq(res.result, CertResult::TEST_OK);
    ck_assert_int_eq(res.ts->depends_seqno(), 1);
}
END_TEST

START_TEST(cert_certify_shared_exclusive)
{
    CertFixture f;
    auto res = f.append_trx(f.node1, f.conn1, 0, {"b", "l"}, WSREP_KEY_SHARED);
    ck_assert_int_eq(res.result, CertResult::TEST_OK);
    res = f.append_trx(f.node2, f.conn2, 0, {"b", "l"}, WSREP_KEY_EXCLUSIVE);
    ck_assert_int_eq(res.result, CertResult::TEST_OK);
    ck_assert_int_eq(res.ts->depends_seqno(), 1);
}
END_TEST

/*
 * Cert against reference
 */

START_TEST(cert_certify_reference_shared)
{
    CertFixture f;
    auto res = f.append_trx(f.node1, f.conn1, 0, {"b", "l"}, WSREP_KEY_REFERENCE);
    ck_assert_int_eq(res.result, CertResult::TEST_OK);
    res = f.append_trx(f.node2, f.conn2, 0, {"b", "l"}, WSREP_KEY_SHARED);
    ck_assert_int_eq(res.result, CertResult::TEST_OK);
    ck_assert_int_eq(res.ts->depends_seqno(), 0);
}
END_TEST

START_TEST(cert_certify_reference_reference)
{
    CertFixture f;
    auto res = f.append_trx(f.node1, f.conn1, 0, {"b", "l"}, WSREP_KEY_REFERENCE);
    ck_assert_int_eq(res.result, CertResult::TEST_OK);
    res = f.append_trx(f.node2, f.conn2, 0, {"b", "l"}, WSREP_KEY_REFERENCE);
    ck_assert_int_eq(res.result, CertResult::TEST_OK);
    ck_assert_int_eq(res.ts->depends_seqno(), 0);
}
END_TEST

START_TEST(cert_certify_reference_update)
{
    CertFixture f;
    auto res = f.append_trx(f.node1, f.conn1, 0, {"b", "l"}, WSREP_KEY_REFERENCE);
    ck_assert_int_eq(res.result, CertResult::TEST_OK);
    res = f.append_trx(f.node2, f.conn2, 0, {"b", "l"}, WSREP_KEY_UPDATE);
    ck_assert_int_eq(res.result, CertResult::TEST_OK);
    ck_assert_int_eq(res.ts->depends_seqno(), 1);
}
END_TEST

START_TEST(cert_certify_reference_exclusive)
{
    CertFixture f;
    auto res = f.append_trx(f.node1, f.conn1, 0, {"b", "l"}, WSREP_KEY_REFERENCE);
    ck_assert_int_eq(res.result, CertResult::TEST_OK);
    res = f.append_trx(f.node2, f.conn2, 0, {"b", "l"}, WSREP_KEY_EXCLUSIVE);
    ck_assert_int_eq(res.result, CertResult::TEST_FAILED);
    ck_assert_int_eq(res.ts->depends_seqno(), 1);
}
END_TEST

/*
 * Cert against update
 */

START_TEST(cert_certify_update_shared)
{
    CertFixture f;
    auto res = f.append_trx(f.node1, f.conn1, 0, {"b", "l"}, WSREP_KEY_UPDATE);
    ck_assert_int_eq(res.result, CertResult::TEST_OK);
    res = f.append_trx(f.node2, f.conn2, 0, {"b", "l"}, WSREP_KEY_SHARED);
    ck_assert_int_eq(res.result, CertResult::TEST_OK);
    ck_assert_int_eq(res.ts->depends_seqno(), 1);
}
END_TEST

START_TEST(cert_certify_update_reference)
{
    CertFixture f;
    auto res = f.append_trx(f.node1, f.conn1, 0, {"b", "l"}, WSREP_KEY_UPDATE);
    ck_assert_int_eq(res.result, CertResult::TEST_OK);
    res = f.append_trx(f.node2, f.conn2, 0, {"b", "l"}, WSREP_KEY_REFERENCE);
    ck_assert_int_eq(res.result, CertResult::TEST_OK);
    ck_assert_int_eq(res.ts->depends_seqno(), 1);
}
END_TEST

START_TEST(cert_certify_update_update)
{
    CertFixture f;
    auto res = f.append_trx(f.node1, f.conn1, 0, {"b", "l"}, WSREP_KEY_UPDATE);
    ck_assert_int_eq(res.result, CertResult::TEST_OK);
    res = f.append_trx(f.node2, f.conn2, 0, {"b", "l"}, WSREP_KEY_UPDATE);
    ck_assert_int_eq(res.result, CertResult::TEST_FAILED);
    ck_assert_int_eq(res.ts->depends_seqno(), 1);
}
END_TEST

START_TEST(cert_certify_update_exclusive)
{
    CertFixture f;
    auto res = f.append_trx(f.node1, f.conn1, 0, {"b", "l"}, WSREP_KEY_UPDATE);
    ck_assert_int_eq(res.result, CertResult::TEST_OK);
    res = f.append_trx(f.node2, f.conn2, 0, {"b", "l"}, WSREP_KEY_EXCLUSIVE);
    ck_assert_int_eq(res.result, CertResult::TEST_FAILED);
    ck_assert_int_eq(res.ts->depends_seqno(), 1);
}
END_TEST

/*
 * Cert against exclusive
 */

START_TEST(cert_certify_exclusive_shared)
{
    CertFixture f;
    auto res = f.append_trx(f.node1, f.conn1, 0, {"b", "l"}, WSREP_KEY_EXCLUSIVE);
    ck_assert_int_eq(res.result, CertResult::TEST_OK);
    res = f.append_trx(f.node2, f.conn2, 0, {"b", "l"}, WSREP_KEY_SHARED);
    ck_assert_int_eq(res.result, CertResult::TEST_FAILED);
    ck_assert_int_eq(res.ts->depends_seqno(), 1);
}
END_TEST

START_TEST(cert_certify_exclusive_reference)
{
    CertFixture f;
    auto res = f.append_trx(f.node1, f.conn1, 0, {"b", "l"}, WSREP_KEY_EXCLUSIVE);
    ck_assert_int_eq(res.result, CertResult::TEST_OK);
    res = f.append_trx(f.node2, f.conn2, 0, {"b", "l"}, WSREP_KEY_REFERENCE);
    ck_assert_int_eq(res.result, CertResult::TEST_FAILED);
    ck_assert_int_eq(res.ts->depends_seqno(), 1);
}
END_TEST

START_TEST(cert_certify_exclusive_update)
{
    CertFixture f;
    auto res = f.append_trx(f.node1, f.conn1, 0, {"b", "l"}, WSREP_KEY_EXCLUSIVE);
    ck_assert_int_eq(res.result, CertResult::TEST_OK);
    res = f.append_trx(f.node2, f.conn2, 0, {"b", "l"}, WSREP_KEY_UPDATE);
    ck_assert_int_eq(res.result, CertResult::TEST_FAILED);
    ck_assert_int_eq(res.ts->depends_seqno(), 1);
}
END_TEST

START_TEST(cert_certify_exclusive_exclusive)
{
    CertFixture f;
    auto res = f.append_trx(f.node1, f.conn1, 0, {"b", "l"}, WSREP_KEY_EXCLUSIVE);
    ck_assert_int_eq(res.result, CertResult::TEST_OK);
    res = f.append_trx(f.node2, f.conn2, 0, {"b", "l"}, WSREP_KEY_EXCLUSIVE);
    ck_assert_int_eq(res.result, CertResult::TEST_FAILED);
    ck_assert_int_eq(res.ts->depends_seqno(), 1);
}
END_TEST

/*
 * Certify branch against leaf. In these cases the first write set has 2 key
 * parts, the second 3 so that the second write set branch key certifies against
 * first write set leaf. These are not actually tests for certification,
 * but rather for key appending producing proper branch keys.
 * Also, in these tests the leaf key for the second transaction does not matter.
 */

START_TEST(cert_certify_shared_branch)
{
    CertFixture f;
    auto res
        = f.append_trx(f.node1, f.conn1, 0, { "b", "b" }, WSREP_KEY_SHARED);
    ck_assert_int_eq(res.result, CertResult::TEST_OK);
    res = f.append_trx(f.node2, f.conn2, 0, { "b", "b", "l" },
                       WSREP_KEY_EXCLUSIVE);
    ck_assert_int_eq(res.result, CertResult::TEST_OK);
    ck_assert_int_eq(res.ts->depends_seqno(), 0);
}
END_TEST

START_TEST(cert_certify_reference_branch)
{
    CertFixture f;
    auto res
        = f.append_trx(f.node1, f.conn1, 0, { "b", "b" }, WSREP_KEY_REFERENCE);
    ck_assert_int_eq(res.result, CertResult::TEST_OK);
    res = f.append_trx(f.node2, f.conn2, 0, { "b", "b", "l" },
                       WSREP_KEY_EXCLUSIVE);
    ck_assert_int_eq(res.result, CertResult::TEST_OK);
    ck_assert_int_eq(res.ts->depends_seqno(), 0);
}
END_TEST

START_TEST(cert_certify_update_branch)
{
    CertFixture f;
    auto res
        = f.append_trx(f.node1, f.conn1, 0, { "b", "b" }, WSREP_KEY_UPDATE);
    ck_assert_int_eq(res.result, CertResult::TEST_OK);
    res = f.append_trx(f.node2, f.conn2, 0, { "b", "b", "l" },
                       WSREP_KEY_EXCLUSIVE);
    ck_assert_int_eq(res.result, CertResult::TEST_OK);
    ck_assert_int_eq(res.ts->depends_seqno(), 1);
}
END_TEST

START_TEST(cert_certify_exclusive_branch)
{
    CertFixture f;
    auto res
        = f.append_trx(f.node1, f.conn1, 0, { "b", "b" }, WSREP_KEY_EXCLUSIVE);
    ck_assert_int_eq(res.result, CertResult::TEST_OK);
    res = f.append_trx(f.node2, f.conn2, 0, { "b", "b", "l" },
                       WSREP_KEY_EXCLUSIVE);
    ck_assert_int_eq(res.result, CertResult::TEST_FAILED);
    ck_assert_int_eq(res.ts->depends_seqno(), 1);
}
END_TEST

/* Test certification for branch against other key types. */

START_TEST(cert_certify_branch_shared)
{
    CertFixture f;
    auto res
        = f.append_trx(f.node1, f.conn1, 0, { "b", "b", "l" }, WSREP_KEY_SHARED);
    ck_assert_int_eq(res.result, CertResult::TEST_OK);
    res = f.append_trx(f.node2, f.conn2, 0, { "b", "b" },
                       WSREP_KEY_SHARED);
    ck_assert_int_eq(res.result, CertResult::TEST_OK);
    ck_assert_int_eq(res.ts->depends_seqno(), 0);
}
END_TEST

START_TEST(cert_certify_branch_reference)
{
    CertFixture f;
    auto res
        = f.append_trx(f.node1, f.conn1, 0, { "b", "b", "l" }, WSREP_KEY_SHARED);
    ck_assert_int_eq(res.result, CertResult::TEST_OK);
    res = f.append_trx(f.node2, f.conn2, 0, { "b", "b" },
                       WSREP_KEY_REFERENCE);
    ck_assert_int_eq(res.result, CertResult::TEST_OK);
    ck_assert_int_eq(res.ts->depends_seqno(), 0);
}
END_TEST

START_TEST(cert_certify_branch_update)
{
    CertFixture f;
    auto res
        = f.append_trx(f.node1, f.conn1, 0, { "b", "b", "l" }, WSREP_KEY_SHARED);
    ck_assert_int_eq(res.result, CertResult::TEST_OK);
    res = f.append_trx(f.node2, f.conn2, 0, { "b", "b" },
                       WSREP_KEY_UPDATE);
    ck_assert_int_eq(res.result, CertResult::TEST_OK);
    ck_assert_int_eq(res.ts->depends_seqno(), 1);
}
END_TEST

START_TEST(cert_certify_branch_exclusive)
{
    CertFixture f;
    auto res
        = f.append_trx(f.node1, f.conn1, 0, { "b", "b", "l" }, WSREP_KEY_SHARED);
    ck_assert_int_eq(res.result, CertResult::TEST_OK);
    res = f.append_trx(f.node2, f.conn2, 0, { "b", "b" },
                       WSREP_KEY_EXCLUSIVE);
    ck_assert_int_eq(res.result, CertResult::TEST_FAILED);
    ck_assert_int_eq(res.ts->depends_seqno(), 1);
}
END_TEST

/*
 * TOI shared
 */

START_TEST(cert_certify_toi_shared_shared)
{
    CertFixture f;
    auto res
        = f.append_toi(f.node1, f.conn1, 0, { "b", "l" }, WSREP_KEY_SHARED);
    ck_assert_int_eq(res.result, CertResult::TEST_OK);
    res = f.append_trx(f.node2, f.conn2, 0, { "b", "l" },
                       WSREP_KEY_SHARED);
    ck_assert_int_eq(res.result, CertResult::TEST_OK);
    ck_assert_int_eq(res.ts->depends_seqno(), 0);
}
END_TEST

START_TEST(cert_certify_toi_shared_reference)
{
    CertFixture f;
    auto res
        = f.append_toi(f.node1, f.conn1, 0, { "b", "l" }, WSREP_KEY_SHARED);
    ck_assert_int_eq(res.result, CertResult::TEST_OK);
    res = f.append_trx(f.node2, f.conn2, 0, { "b", "l" },
                       WSREP_KEY_REFERENCE);
    ck_assert_int_eq(res.result, CertResult::TEST_OK);
    ck_assert_int_eq(res.ts->depends_seqno(), 0);
}
END_TEST

START_TEST(cert_certify_toi_shared_update)
{
    CertFixture f;
    auto res
        = f.append_toi(f.node1, f.conn1, 0, { "b", "l" }, WSREP_KEY_SHARED);
    ck_assert_int_eq(res.result, CertResult::TEST_OK);
    res = f.append_trx(f.node2, f.conn2, 0, { "b", "l" },
                       WSREP_KEY_UPDATE);
    ck_assert_int_eq(res.result, CertResult::TEST_OK);
    ck_assert_int_eq(res.ts->depends_seqno(), 1);
}
END_TEST

START_TEST(cert_certify_toi_shared_exclusive)
{
    CertFixture f;
    auto res
        = f.append_toi(f.node1, f.conn1, 0, { "b", "l" }, WSREP_KEY_SHARED);
    ck_assert_int_eq(res.result, CertResult::TEST_OK);
    res = f.append_trx(f.node2, f.conn2, 0, { "b", "l" },
                       WSREP_KEY_EXCLUSIVE);
    ck_assert_int_eq(res.result, CertResult::TEST_OK);
    ck_assert_int_eq(res.ts->depends_seqno(), 1);
}
END_TEST

/*
 * TOI reference
 */

START_TEST(cert_certify_toi_reference_shared)
{
    CertFixture f;
    auto res
        = f.append_toi(f.node1, f.conn1, 0, { "b", "l" }, WSREP_KEY_REFERENCE);
    ck_assert_int_eq(res.result, CertResult::TEST_OK);
    res = f.append_trx(f.node2, f.conn2, 0, { "b", "l" },
                       WSREP_KEY_SHARED);
    ck_assert_int_eq(res.result, CertResult::TEST_OK);
    ck_assert_int_eq(res.ts->depends_seqno(), 0);
}
END_TEST

START_TEST(cert_certify_toi_reference_reference)
{
    CertFixture f;
    auto res
        = f.append_toi(f.node1, f.conn1, 0, { "b", "l" }, WSREP_KEY_REFERENCE);
    ck_assert_int_eq(res.result, CertResult::TEST_OK);
    res = f.append_trx(f.node2, f.conn2, 0, { "b", "l" },
                       WSREP_KEY_REFERENCE);
    ck_assert_int_eq(res.result, CertResult::TEST_OK);
    ck_assert_int_eq(res.ts->depends_seqno(), 0);
}
END_TEST

START_TEST(cert_certify_toi_reference_update)
{
    CertFixture f;
    auto res
        = f.append_toi(f.node1, f.conn1, 0, { "b", "l" }, WSREP_KEY_REFERENCE);
    ck_assert_int_eq(res.result, CertResult::TEST_OK);
    res = f.append_trx(f.node2, f.conn2, 0, { "b", "l" },
                       WSREP_KEY_UPDATE);
    ck_assert_int_eq(res.result, CertResult::TEST_OK);
    ck_assert_int_eq(res.ts->depends_seqno(), 1);
}
END_TEST

START_TEST(cert_certify_toi_reference_exclusive)
{
    CertFixture f;
    auto res
        = f.append_toi(f.node1, f.conn1, 0, { "b", "l" }, WSREP_KEY_REFERENCE);
    ck_assert_int_eq(res.result, CertResult::TEST_OK);
    res = f.append_trx(f.node2, f.conn2, 0, { "b", "l" },
                       WSREP_KEY_EXCLUSIVE);
    ck_assert_int_eq(res.result, CertResult::TEST_FAILED);
    ck_assert_int_eq(res.ts->depends_seqno(), 1);
}
END_TEST

/*
 * TOI update
 */

START_TEST(cert_certify_toi_update_shared)
{
    CertFixture f;
    auto res
        = f.append_toi(f.node1, f.conn1, 0, { "b", "l" }, WSREP_KEY_UPDATE);
    ck_assert_int_eq(res.result, CertResult::TEST_OK);
    res = f.append_trx(f.node2, f.conn2, 0, { "b", "l" },
                       WSREP_KEY_SHARED);
    ck_assert_int_eq(res.result, CertResult::TEST_OK);
    ck_assert_int_eq(res.ts->depends_seqno(), 1);
}
END_TEST

START_TEST(cert_certify_toi_update_reference)
{
    CertFixture f;
    auto res
        = f.append_toi(f.node1, f.conn1, 0, { "b", "l" }, WSREP_KEY_UPDATE);
    ck_assert_int_eq(res.result, CertResult::TEST_OK);
    res = f.append_trx(f.node2, f.conn2, 0, { "b", "l" },
                       WSREP_KEY_REFERENCE);
    ck_assert_int_eq(res.result, CertResult::TEST_OK);
    ck_assert_int_eq(res.ts->depends_seqno(), 1);
}
END_TEST

START_TEST(cert_certify_toi_update_update)
{
    CertFixture f;
    auto res
        = f.append_toi(f.node1, f.conn1, 0, { "b", "l" }, WSREP_KEY_UPDATE);
    ck_assert_int_eq(res.result, CertResult::TEST_OK);
    res = f.append_trx(f.node2, f.conn2, 0, { "b", "l" },
                       WSREP_KEY_UPDATE);
    ck_assert_int_eq(res.result, CertResult::TEST_FAILED);
    ck_assert_int_eq(res.ts->depends_seqno(), 1);
}
END_TEST

START_TEST(cert_certify_toi_update_exclusive)
{
    CertFixture f;
    auto res
        = f.append_toi(f.node1, f.conn1, 0, { "b", "l" }, WSREP_KEY_UPDATE);
    ck_assert_int_eq(res.result, CertResult::TEST_OK);
    res = f.append_trx(f.node2, f.conn2, 0, { "b", "l" },
                       WSREP_KEY_EXCLUSIVE);
    ck_assert_int_eq(res.result, CertResult::TEST_FAILED);
    ck_assert_int_eq(res.ts->depends_seqno(), 1);
}
END_TEST

/*
 * TOI exclusive
 */

START_TEST(cert_certify_toi_exclusive_shared)
{
    CertFixture f;
    auto res
        = f.append_toi(f.node1, f.conn1, 0, { "b", "l" }, WSREP_KEY_EXCLUSIVE);
    ck_assert_int_eq(res.result, CertResult::TEST_OK);
    res = f.append_trx(f.node2, f.conn2, 0, { "b", "l" },
                       WSREP_KEY_SHARED);
    ck_assert_int_eq(res.result, CertResult::TEST_FAILED);
    ck_assert_int_eq(res.ts->depends_seqno(), 1);
}
END_TEST

START_TEST(cert_certify_toi_exclusive_reference)
{
    CertFixture f;
    auto res
        = f.append_toi(f.node1, f.conn1, 0, { "b", "l" }, WSREP_KEY_EXCLUSIVE);
    ck_assert_int_eq(res.result, CertResult::TEST_OK);
    res = f.append_trx(f.node2, f.conn2, 0, { "b", "l" },
                       WSREP_KEY_REFERENCE);
    ck_assert_int_eq(res.result, CertResult::TEST_FAILED);
    ck_assert_int_eq(res.ts->depends_seqno(), 1);
}
END_TEST

START_TEST(cert_certify_toi_exclusive_update)
{
    CertFixture f;
    auto res
        = f.append_toi(f.node1, f.conn1, 0, { "b", "l" }, WSREP_KEY_EXCLUSIVE);
    ck_assert_int_eq(res.result, CertResult::TEST_OK);
    res = f.append_trx(f.node2, f.conn2, 0, { "b", "l" },
                       WSREP_KEY_UPDATE);
    ck_assert_int_eq(res.result, CertResult::TEST_FAILED);
    ck_assert_int_eq(res.ts->depends_seqno(), 1);
}
END_TEST

START_TEST(cert_certify_toi_exclusive_exclusive)
{
    CertFixture f;
    auto res
        = f.append_toi(f.node1, f.conn1, 0, { "b", "l" }, WSREP_KEY_EXCLUSIVE);
    ck_assert_int_eq(res.result, CertResult::TEST_OK);
    res = f.append_trx(f.node2, f.conn2, 0, { "b", "l" },
                       WSREP_KEY_EXCLUSIVE);
    ck_assert_int_eq(res.result, CertResult::TEST_FAILED);
    ck_assert_int_eq(res.ts->depends_seqno(), 1);
}
END_TEST


/* Exclusive - exclusive TOI to demonstrate that TOI never fails
 * in certification. */
START_TEST(cert_certify_exclusive_toi_exclusive)
{
    CertFixture f;
    auto res
        = f.append_trx(f.node1, f.conn1, 0, { "b", "l" }, WSREP_KEY_EXCLUSIVE);
    ck_assert_int_eq(res.result, CertResult::TEST_OK);
    res = f.append_toi(f.node2, f.conn2, 0, { "b", "l" },
                       WSREP_KEY_EXCLUSIVE);
    ck_assert_int_eq(res.result, CertResult::TEST_OK);
    ck_assert_int_eq(res.ts->depends_seqno(), 1);
}
END_TEST

/* Exclusive TOI - Exclusive TOI */
START_TEST(cert_certify_exclusive_toi_exclusive_toi)
{
    CertFixture f;
    auto res
        = f.append_toi(f.node1, f.conn1, 0, { "b", "l" }, WSREP_KEY_EXCLUSIVE);
    ck_assert_int_eq(res.result, CertResult::TEST_OK);
    res = f.append_toi(f.node2, f.conn2, 0, { "b", "l" },
                       WSREP_KEY_EXCLUSIVE);
    ck_assert_int_eq(res.result, CertResult::TEST_OK);
    ck_assert_int_eq(res.ts->depends_seqno(), 1);
}
END_TEST

/* NBO begin - TOI */
START_TEST(cert_certify_exclusive_nbo_exclusive_toi)
{
    CertFixture f;
    auto res = f.append_nbo_begin(f.node1, f.conn1, 0, { "b", "l" },
                                  WSREP_KEY_EXCLUSIVE);
    ck_assert_int_eq(res.result, CertResult::TEST_OK);
    ck_assert_int_eq(res.ts->global_seqno(), 1);
    res = f.append_toi(f.node2, f.conn2, 0, { "b", "l" }, WSREP_KEY_EXCLUSIVE);
    ck_assert_int_eq(res.result, CertResult::TEST_FAILED);
    ck_assert_int_eq(res.ts->depends_seqno(), 1);
    res = f.append_nbo_end(f.node1, f.conn1, 0, { "b", "l" },
                           WSREP_KEY_EXCLUSIVE, 1);
    res = f.append_toi(f.node2, f.conn2, 0, { "b", "l" }, WSREP_KEY_EXCLUSIVE);
    ck_assert_int_eq(res.result, CertResult::TEST_OK);
    ck_assert_int_eq(res.ts->depends_seqno(), 3);
}
END_TEST

/* TOI - NBO begin */
START_TEST(cert_certify_exclusive_toi_exclusive_nbo)
{
    CertFixture f;
    auto res = f.append_toi(f.node1, f.conn1, 0, { "b", "l" },
                                  WSREP_KEY_EXCLUSIVE);
    ck_assert_int_eq(res.result, CertResult::TEST_OK);
    res = f.append_nbo_begin(f.node2, f.conn2, 0, { "b", "l" }, WSREP_KEY_EXCLUSIVE);
    ck_assert_int_eq(res.result, CertResult::TEST_OK);
    ck_assert_int_eq(res.ts->global_seqno(), 2);
    ck_assert_int_eq(res.ts->depends_seqno(), 1);
    res = f.append_nbo_end(f.node1, f.conn1, 0, { "b", "l" },
                           WSREP_KEY_EXCLUSIVE, 2);
    res = f.append_toi(f.node2, f.conn2, 0, { "b", "l" }, WSREP_KEY_EXCLUSIVE);
    ck_assert_int_eq(res.result, CertResult::TEST_OK);
    ck_assert_int_eq(res.ts->depends_seqno(), 3);
}
END_TEST

/* NBO begin - NBO begin*/
START_TEST(cert_certify_exclusive_nbo_exclusive_nbo)
{
    CertFixture f;
    auto res = f.append_nbo_begin(f.node1, f.conn1, 0, { "b", "l" },
                                  WSREP_KEY_EXCLUSIVE);
    ck_assert_int_eq(res.result, CertResult::TEST_OK);
    ck_assert_int_eq(res.ts->global_seqno(), 1);
    res = f.append_nbo_begin(f.node2, f.conn2, 0, { "b", "l" },
                             WSREP_KEY_EXCLUSIVE);
    ck_assert_int_eq(res.result, CertResult::TEST_FAILED);
    ck_assert_int_eq(res.ts->depends_seqno(), 1);
    res = f.append_nbo_end(f.node1, f.conn1, 0, { "b", "l" },
                           WSREP_KEY_EXCLUSIVE, 1);
    res = f.append_nbo_begin(f.node2, f.conn2, 0, { "b", "l" },
                             WSREP_KEY_EXCLUSIVE);
    ck_assert_int_eq(res.result, CertResult::TEST_OK);
    ck_assert_int_eq(res.ts->depends_seqno(), 3);
}
END_TEST

/* Write sets originating from the same node should not conflict even with
 * exclusive key. */
START_TEST(cert_certify_same_node)
{
    CertFixture f;
    auto res
        = f.append_trx(f.node1, f.conn1, 0, { "b", "l" }, WSREP_KEY_EXCLUSIVE);
    ck_assert_int_eq(res.result, CertResult::TEST_OK);
    res = f.append_trx(f.node1, f.conn2, 0, { "b", "l" },
                       WSREP_KEY_EXCLUSIVE);
    ck_assert_int_eq(res.result, CertResult::TEST_OK);
    ck_assert_int_eq(res.ts->depends_seqno(), 1);
}
END_TEST

/* Write set outside certification range must not cause conflict, but dependency.
 */
START_TEST(cert_certify_exclusive_exclusive_outside_cert_range)
{
    CertFixture f;
    auto res = f.append_trx(f.node1, f.conn1, 0, {"b", "l"}, WSREP_KEY_EXCLUSIVE);
    ck_assert_int_eq(res.result, CertResult::TEST_OK);
    res = f.append_trx(f.node2, f.conn2, 1, {"b", "l"}, WSREP_KEY_EXCLUSIVE);
    ck_assert_int_eq(res.result, CertResult::TEST_OK);
    ck_assert_int_eq(res.ts->depends_seqno(), 1);
}
END_TEST

START_TEST(cert_certify_exclusive_exclusive_shadowed_by_shared)
{
    CertFixture f;
    auto res = f.append_trx(f.node1, f.conn1, 0, {"b", "l"}, WSREP_KEY_EXCLUSIVE);
    ck_assert_int_eq(res.result, CertResult::TEST_OK);
    res = f.append_trx(f.node2, f.conn2, 1, {"b", "l"}, WSREP_KEY_SHARED);
    ck_assert_int_eq(res.result, CertResult::TEST_OK);
    ck_assert_int_eq(res.ts->depends_seqno(), 1);

    res = f.append_trx(f.node2, f.conn2, 0, {"b", "l"}, WSREP_KEY_EXCLUSIVE);
    ck_assert_int_eq(res.result, CertResult::TEST_FAILED);
    /* Note that even though the dependency should be to shared key, the
     * certification checks first for exclusive key and because of conflict,
     * the scan stops there and the depends seqno is not updated. This does
     * not matter however, as the test result is failed. */
    ck_assert_int_eq(res.ts->depends_seqno(), 1);
}
END_TEST

/* Even though shared-shared match does not cause conflict or dependency,
 * having PA_UNSAFE flag in write set must create the dependency. */
START_TEST(cert_certify_shared_shared_pa_unsafe)
{
    CertFixture f;
    auto res = f.append_trx(f.node1, f.conn1, 0, {"b", "l"}, WSREP_KEY_SHARED);
    ck_assert_int_eq(res.result, CertResult::TEST_OK);

    res = f.append(f.node2, f.conn2, 0, { "b", "l" }, WSREP_KEY_SHARED,
                   galera::TrxHandle::F_BEGIN | galera::TrxHandle::F_COMMIT
                       | galera::TrxHandle::F_PA_UNSAFE,
                   nullptr, 0);
    ck_assert_int_eq(res.result, CertResult::TEST_OK);
    ck_assert_int_eq(res.ts->depends_seqno(), 1);
}
END_TEST

/* PA unsafe must create dependency even if there is no match. */
START_TEST(cert_certify_no_match_pa_unsafe)
{
    CertFixture f;
    auto res = f.append_trx(f.node1, f.conn1, 0, {"b", "m"}, WSREP_KEY_SHARED);
    ck_assert_int_eq(res.result, CertResult::TEST_OK);

    res = f.append(f.node2, f.conn2, 0, { "b", "l" }, WSREP_KEY_SHARED,
                   galera::TrxHandle::F_BEGIN | galera::TrxHandle::F_COMMIT
                       | galera::TrxHandle::F_PA_UNSAFE,
                   nullptr, 0);
    ck_assert_int_eq(res.result, CertResult::TEST_OK);
    ck_assert_int_eq(res.ts->depends_seqno(), 1);

}
END_TEST

START_TEST(cert_certify_no_match)
{
    CertFixture f;
    auto res
        = f.append_trx(f.node1, f.conn1, 0, { "b", "m" }, WSREP_KEY_EXCLUSIVE);
    ck_assert_int_eq(res.result, CertResult::TEST_OK);
    res = f.append_trx(f.node2, f.conn2, 0, { "b", "l" }, WSREP_KEY_EXCLUSIVE);
    ck_assert_int_eq(res.result, CertResult::TEST_OK);
    ck_assert_int_eq(res.ts->depends_seqno(), 0);
}
END_TEST


Suite* certification_suite()
{
    Suite* s(suite_create("certification"));
    TCase* t;

    t = tcase_create("certification_trx_v4");
    tcase_add_test(t, test_certification_trx_v4);
    tcase_add_test(t, test_certification_trx_v4E);
    suite_add_tcase(s, t);

    t = tcase_create("certification_trx_different_level_v3");
    tcase_add_test(t, test_certification_trx_different_level_v3);
    tcase_add_test(t, test_certification_trx_different_level_v3E);
    suite_add_tcase(s, t);

    t = tcase_create("certification_toi_v3");
    tcase_add_test(t, test_certification_toi_v3);
    tcase_add_test(t, test_certification_toi_v3E);
    suite_add_tcase(s, t);

    t = tcase_create("certification_nbo");
    tcase_add_test(t, test_certification_nbo);
    tcase_add_test(t, test_certification_nboE);
    suite_add_tcase(s, t);

    t = tcase_create("certification_commit_fragment");
    tcase_add_test(t, test_certification_commit_fragment);
    tcase_add_test(t, test_certification_commit_fragmentE);
    suite_add_tcase(s, t);

    t = tcase_create("certification_zero_level");
    tcase_add_test(t, test_certification_zero_level);
    tcase_add_test(t, test_certification_zero_levelE);
    suite_add_tcase(s, t);

    t = tcase_create("certification_rules");
    tcase_add_test(t, cert_append_trx);
    tcase_add_test(t, cert_certify_shared_shared);
    tcase_add_test(t, cert_certify_shared_reference);
    tcase_add_test(t, cert_certify_shared_update);
    tcase_add_test(t, cert_certify_shared_exclusive);
    tcase_add_test(t, cert_certify_reference_shared);
    tcase_add_test(t, cert_certify_reference_reference);
    tcase_add_test(t, cert_certify_reference_update);
    tcase_add_test(t, cert_certify_reference_exclusive);
    tcase_add_test(t, cert_certify_update_shared);
    tcase_add_test(t, cert_certify_update_reference);
    tcase_add_test(t, cert_certify_update_update);
    tcase_add_test(t, cert_certify_update_exclusive);
    tcase_add_test(t, cert_certify_exclusive_shared);
    tcase_add_test(t, cert_certify_exclusive_reference);
    tcase_add_test(t, cert_certify_exclusive_update);
    tcase_add_test(t, cert_certify_exclusive_exclusive);
    tcase_add_test(t, cert_certify_shared_branch);
    tcase_add_test(t, cert_certify_reference_branch);
    tcase_add_test(t, cert_certify_update_branch);
    tcase_add_test(t, cert_certify_exclusive_branch);
    tcase_add_test(t, cert_certify_branch_shared);
    tcase_add_test(t, cert_certify_branch_reference);
    tcase_add_test(t, cert_certify_branch_update);
    tcase_add_test(t, cert_certify_branch_exclusive);
    tcase_add_test(t, cert_certify_toi_shared_shared);
    tcase_add_test(t, cert_certify_toi_shared_reference);
    tcase_add_test(t, cert_certify_toi_shared_update);
    tcase_add_test(t, cert_certify_toi_shared_exclusive);
    tcase_add_test(t, cert_certify_toi_reference_shared);
    tcase_add_test(t, cert_certify_toi_reference_reference);
    tcase_add_test(t, cert_certify_toi_reference_update);
    tcase_add_test(t, cert_certify_toi_reference_exclusive);
    tcase_add_test(t, cert_certify_toi_update_shared);
    tcase_add_test(t, cert_certify_toi_update_reference);
    tcase_add_test(t, cert_certify_toi_update_update);
    tcase_add_test(t, cert_certify_toi_update_exclusive);
    tcase_add_test(t, cert_certify_toi_exclusive_shared);
    tcase_add_test(t, cert_certify_toi_exclusive_reference);
    tcase_add_test(t, cert_certify_toi_exclusive_update);
    tcase_add_test(t, cert_certify_toi_exclusive_exclusive);
    tcase_add_test(t, cert_certify_exclusive_toi_exclusive);
    tcase_add_test(t, cert_certify_exclusive_toi_exclusive_toi);
    tcase_add_test(t, cert_certify_exclusive_nbo_exclusive_toi);
    tcase_add_test(t, cert_certify_exclusive_toi_exclusive_nbo);
    tcase_add_test(t, cert_certify_exclusive_nbo_exclusive_nbo);
    tcase_add_test(t, cert_certify_same_node);
    tcase_add_test(t, cert_certify_exclusive_exclusive_outside_cert_range);
    tcase_add_test(t, cert_certify_exclusive_exclusive_shadowed_by_shared);
    tcase_add_test(t, cert_certify_shared_shared_pa_unsafe);
    tcase_add_test(t, cert_certify_no_match_pa_unsafe);
    tcase_add_test(t, cert_certify_no_match);

    suite_add_tcase(s, t);

    return s;
}
