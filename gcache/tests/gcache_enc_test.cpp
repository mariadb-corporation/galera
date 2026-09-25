/*
 * Copyright (C) 2019-2020 Codership Oy <info@codership.com>
 *
 * $Id$
 */

#include "gcache_test_encryption.hpp"
#include "gcache_enc_test.hpp"

#include <cassert>

static wsrep_buf_t const key1 = { "1", 1 };
static wsrep_buf_t const key2 = { "2", 1 };

static wsrep_enc_iv_t const iv1 = { 1, };
static wsrep_enc_iv_t const iv2 = { 2, };

static wsrep_enc_ctx_t ctx11 = { &key1, &iv1, NULL };
static wsrep_enc_ctx_t ctx12 = { &key1, &iv2, NULL };
static wsrep_enc_ctx_t ctx21 = { &key2, &iv1, NULL };

static char source[] = "Nothing is covered up that will not be revealed, "
                       "or hidden that will not be known.";
static_assert(sizeof(source) == 83, "source length is not a prime number");
/* prime number means it is not multiple of any block size */

/* tests empty message encryption */
static void
do_null_test(wsrep_encrypt_cb_t const cb, void* app_ctx,
             size_t const blocksize)
{
    wsrep_buf_t in = { NULL, 0 };
    char out(0);

    int ret(cb(app_ctx, &ctx11, &in, &out, WSREP_ENC, true));
    ck_assert(ret == 0);
    ck_assert(out == 0);
}

START_TEST(null_test)
{
    do_null_test(gcache_test_encrypt_cb, NULL, 16);
}
END_TEST

/* tests atomic message encryption */
static void
do_fin_test(wsrep_encrypt_cb_t const cb, void* app_ctx, size_t const blocksize)
{
    assert(sizeof(source) % blocksize);
    wsrep_buf_t orig = { source, sizeof(source) };
    char cipher11[sizeof(source)];
    char cipher12[sizeof(source)];
    char cipher21[sizeof(source)];

    int ret(cb(app_ctx, &ctx11, &orig, cipher11, WSREP_ENC, true));
    ck_assert(ret == sizeof(source));
    ck_assert(0 != ::memcmp(orig.ptr, cipher11, ret));

    ret = cb(app_ctx, &ctx12, &orig, cipher12, WSREP_ENC, true);
    ck_assert(ret == sizeof(source));
    ck_assert(0 != ::memcmp(orig.ptr, cipher12, ret));
    ck_assert(0 != ::memcmp(cipher11, cipher12, ret));

    ret = cb(app_ctx, &ctx21, &orig, cipher21, WSREP_ENC, true);
    ck_assert(ret == sizeof(source));
    ck_assert(0 != ::memcmp(orig.ptr, cipher21, ret));
    ck_assert(0 != ::memcmp(cipher11, cipher21, ret));

    wsrep_buf_t res = { cipher11, sizeof(cipher11) };
    char plain[sizeof(cipher11)];

    ret = cb(app_ctx, &ctx11, &res, plain, WSREP_DEC, true);
    ck_assert(ret == sizeof(cipher11));
    ck_assert_msg(0 == ::memcmp(orig.ptr, plain, ret),
                  "Expected:\n%s\nGot:\n%s",
                  static_cast<const char*>(orig.ptr), plain);

    ret = cb(app_ctx, &ctx12, &res, plain, WSREP_DEC, true);
    ck_assert(ret == sizeof(cipher11));
    ck_assert(0 != ::memcmp(orig.ptr, plain, ret));

    ret = cb(app_ctx, &ctx21, &res, plain, WSREP_DEC, true);
    ck_assert(ret == sizeof(cipher11));
    ck_assert(0 != ::memcmp(orig.ptr, plain, ret));
}

START_TEST(fin_test)
{
    do_fin_test(gcache_test_encrypt_cb, NULL, 16);
}
END_TEST

/* test stream encryption */
static void
do_stream_test(wsrep_encrypt_cb_t const cb, void* app_ctx,
               size_t const blocksize)
{
    assert(sizeof(source) % blocksize);
    wsrep_enc_ctx_t const comp_ctx = ctx11;

    char cipher1sweep[sizeof(source)]; /* etalon encryption result */
    {
        wsrep_buf_t in = { source, sizeof(source) };
        int ret(cb(app_ctx, &ctx11, &in, cipher1sweep, WSREP_ENC, true));
        ck_assert(ret == sizeof(source));
        ck_assert(0 == ::memcmp(&comp_ctx, &ctx11, sizeof(ctx11)));
    }

    char cipher[sizeof(source)];
    int ret(-1);
    const char* src(source);
    char* out(cipher);
    unsigned int left(sizeof(source));
    while(left > 0)
    {
        wsrep_buf_t in = { src, (ret != 0 ? left/2 : left) };
        ret = cb(app_ctx, &ctx11, &in, out, WSREP_ENC, 0 == ret);

        ck_assert(ret >= 0);
        ck_assert(ret <= int(in.len));
        src += ret;
        out += ret;
        left-= ret;
    }

    ck_assert(left == 0);
    ck_assert(0 != ::memcmp(source, cipher, sizeof(source)));
    ck_assert(0 == ::memcmp(cipher1sweep, cipher, sizeof(cipher)));
    ck_assert(0 == ::memcmp(&comp_ctx, &ctx11, sizeof(ctx11)));

    char plain [sizeof(source)];
    ret = -1;
    src = cipher;
    out = plain;
    left = sizeof(cipher);
    while(left > 0)
    {
        wsrep_buf_t in = { src, (ret != 0 ? left/2 : left) };
        ret = cb(app_ctx, &ctx11, &in, out, WSREP_DEC, 0 == ret);

        ck_assert(ret >= 0);
        ck_assert(ret <= int(in.len));
        src += ret;
        out += ret;
        left-= ret;
    }

    ck_assert(left == 0);
    ck_assert_msg(0 == ::memcmp(source, plain, sizeof(source)),
                  "Expected:\n%s\nGot:\n%s", source, plain);
    ck_assert(0 == ::memcmp(&comp_ctx, &ctx11, sizeof(ctx11)));
}

START_TEST(stream_test)
{
    do_stream_test(gcache_test_encrypt_cb, NULL, 16);
}
END_TEST

Suite* gcache_enc_suite()
{
    Suite* s = suite_create("gcache::test::Encryption");
    TCase* tc;

    tc = tcase_create("test");
    tcase_add_test(tc, null_test);
    tcase_add_test(tc, fin_test);
    tcase_add_test(tc, stream_test);
    suite_add_tcase(s, tc);

    return s;
}
