/*
 * Copyright (C) 2010-2021 Codership Oy <info@codership.com>
 */

#include "../src/galera_service_thd.hpp"

#include "galera_test_env.hpp"

#include "gu_inttypes.hpp"

#include <check.h>
#include <errno.h>


using namespace galera;

static void
thd1(bool const enc)
{
    TestEnv env("service_thd_check", enc);
    ServiceThd* thd = new ServiceThd(env.gcs(), env.gcache());
    ck_assert(thd != 0);
    delete thd;
}

START_TEST(service_thd1)
{
    thd1(false);
}
END_TEST

START_TEST(service_thd1E)
{
    thd1(true);
}
END_TEST

#define TEST_USLEEP 1000 // 1ms
#define WAIT_FOR(cond)                                                  \
    { int count = 1000; while (--count && !(cond)) { usleep (TEST_USLEEP); }}

static void
thd2(bool const enc)
{
    TestEnv env("service_thd_check", enc);
    DummyGcs& conn(env.gcs());
    ServiceThd* thd = new ServiceThd(conn, env.gcache());
    gu::UUID const state_uuid(NULL, 0);
    ck_assert(thd != 0);

    conn.set_last_applied(gu::GTID(state_uuid, 0));

    gcs_seqno_t seqno = 1;
    thd->report_last_committed (seqno);
    thd->flush(state_uuid);
    WAIT_FOR(conn.last_applied() == seqno);
    ck_assert_msg(conn.last_applied() == seqno,
                  "seqno = %" PRId64 ", expected %" PRId64,
                  conn.last_applied(), seqno);

    seqno = 5;
    thd->report_last_committed (seqno);
    thd->flush(state_uuid);
    WAIT_FOR(conn.last_applied() == seqno);
    ck_assert_msg(conn.last_applied() == seqno,
                  "seqno = %" PRId64 ", expected %" PRId64,
                  conn.last_applied(), seqno);

    thd->report_last_committed (3);
    thd->flush(state_uuid);
    WAIT_FOR(conn.last_applied() == seqno);
    ck_assert_msg(conn.last_applied() == seqno,
                  "seqno = %" PRId64 ", expected %" PRId64,
                  conn.last_applied(), seqno);

    thd->reset();

    seqno = 3;
    thd->report_last_committed (seqno);
    thd->flush(state_uuid);
    WAIT_FOR(conn.last_applied() == seqno);
    ck_assert_msg(conn.last_applied() == seqno,
                  "seqno = %" PRId64 ", expected %" PRId64,
                  conn.last_applied(), seqno);

    delete thd;
}

START_TEST(service_thd2)
{
    thd2(false);
}
END_TEST

START_TEST(service_thd2E)
{
    thd2(true);
}
END_TEST

static void
thd3(bool const enc)
{
    TestEnv env("service_thd_check", enc);
    ServiceThd* thd = new ServiceThd(env.gcs(), env.gcache());
    ck_assert(thd != 0);
    // so far for empty GCache the following should be a noop.
    thd->release_seqno(-1);
    thd->release_seqno(2345);
    thd->release_seqno(234645676);
    delete thd;
}

START_TEST(service_thd3)
{
    thd3(false);
}
END_TEST

START_TEST(service_thd3E)
{
    thd3(true);
}
END_TEST

Suite* service_thd_suite()
{
    Suite* s = suite_create ("service_thd");
    TCase* tc;

    tc = tcase_create ("service_thd");
    tcase_add_test  (tc, service_thd1);
    tcase_add_test  (tc, service_thd1E);
    tcase_add_test  (tc, service_thd2);
    tcase_add_test  (tc, service_thd2E);
    tcase_add_test  (tc, service_thd3);
    tcase_add_test  (tc, service_thd3E);
    tcase_set_timeout(tc, 120);
    suite_add_tcase (s, tc);

    return s;
}
