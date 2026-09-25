/*
 * Copyright (C) 2019 Codership Oy <info@codership.com>
 */

#include "gcache_test_encryption.hpp"

#include <gu_digest.hpp>

#define NAMESPACE_GCACHE_TEST_BEGIN namespace gcache { namespace test {
#define NAMESPACE_GCACHE_TEST_END   } /* test */ } /* gcache */

NAMESPACE_GCACHE_TEST_BEGIN

class Encrypt
{
    static size_t const BLOCKSIZE = 16;
    static_assert(BLOCKSIZE < sizeof(wsrep_enc_iv_t),
                  "blocksize bigger than IV");
    static_assert(0 == BLOCKSIZE % sizeof(size_t),
                  "blocksize is not multiple of size_t size");

    static int const BLOCKLEN = BLOCKSIZE / sizeof(size_t);

    union block {
        char   c[BLOCKSIZE];
        size_t s[BLOCKLEN];
    };
    static_assert(sizeof(block::c) == sizeof(block::s), "size differs");
    static_assert(sizeof(block) == BLOCKSIZE, "something's wrong");

    static inline
    void XOR_block(const block& l, const block& r, block& out)
    {
        for (int i(0); i < BLOCKLEN; ++i) { out.s[i] = l.s[i] ^ r.s[i]; }
    }

    static inline
    void ENC_block(const block& k, const block& in, block& out)
    {
        XOR_block(k, in, out);
    }

public:

    static int
    CFB(
        void*                 const app_ctx,
        wsrep_enc_ctx_t*      const enc_ctx,
        const wsrep_buf_t*    const input,
        void*                 const output,
        wsrep_enc_direction_t const direction,
        bool                  const fin
        )
    {
        typedef unsigned int uint;
        struct op_ctx { block iv; block key; } ctx;

        if (NULL != enc_ctx->ctx)
        {
            ctx = *static_cast<op_ctx*>(enc_ctx->ctx);
        }
        else
        {
            static_assert(sizeof(ctx.iv) <= sizeof(*enc_ctx->iv),
                          "IV block too big");
            ::memcpy(&ctx.iv, enc_ctx->iv, sizeof(ctx.iv));
            gu::MMH3::digest(enc_ctx->key->ptr, enc_ctx->key->len, ctx.key);
            // @todo: what if block size > 16?
        }

        uint rem(input->len);
        const char* in(static_cast<const char*>(input->ptr));
        char* out(static_cast<char*>(output));

        while (rem > sizeof(block) || (fin && rem > 0))
        {
            uint const cpy(rem > sizeof(block) ? sizeof(block) : rem);
            assert(cpy == sizeof(block) || fin);

            block b;

            if (direction == WSREP_ENC)
            {
                ENC_block(ctx.key, ctx.iv, ctx.iv);
                ::memcpy(&b, in, cpy);
                XOR_block(b, ctx.iv, ctx.iv);
                ::memcpy(out, &ctx.iv, cpy);
            }
            else
            {
                ENC_block(ctx.key, ctx.iv, b);
                ::memcpy(&ctx.iv, in, cpy);
                XOR_block(ctx.iv, b, b);
                ::memcpy(out, &b, cpy);
            }

            assert(rem >= cpy);
            rem -= cpy;
            if (rem > 0)
            {
                in  += sizeof(block);
                out += sizeof(block);
            }
        }

        if (!fin)
        {
            if (NULL == enc_ctx->ctx)
                enc_ctx->ctx = ::operator new(sizeof(op_ctx));

            *static_cast<op_ctx*>(enc_ctx->ctx) = ctx;
        }
        else
        {
            ::operator delete(enc_ctx->ctx);
            enc_ctx->ctx = NULL;
        }

        assert(input->len >= rem);
        return (input->len - rem);
    }
}; /* class Encrypt */

NAMESPACE_GCACHE_TEST_END

extern "C"
int gcache_test_encrypt_cb(
    void*                 const app_ctx,
    wsrep_enc_ctx_t*      const enc_ctx,
    const wsrep_buf_t*    const input,
    void*                 const output,
    wsrep_enc_direction_t const direction,
    bool                  const fin
    )
{
    return gcache::test::Encrypt::CFB
        (app_ctx, enc_ctx, input, output, direction, fin);
}
