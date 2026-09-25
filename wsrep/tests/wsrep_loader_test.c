/*
 * Copyright (C) 2020 Codership Oy <info@codership.com>
 */

/*
 * @note This test file does not use any unit test library
 *       framework in order to keep the link time dependencies
 *       minimal.
 */

#include "wsrep_api.h"
#include "wsrep_membership_service.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dlfcn.h>

#define LOG_FILE "wsrep_tests.log"
static FILE* log_file = NULL;
static void log_fn(wsrep_log_level_t level, const char* msg)
{
    FILE* f = (log_file ? log_file : stdout);
    fprintf(f, "%d: %s\n", level, msg);
    fflush(f);
}

static const char* get_provider()
{
    return WSREP_PROVIDER;
}

#define FAIL_UNLESS(x) if (!(x)) abort()

static
int wsrep_load_unload()
{
    wsrep_t* wsrep = 0;
    char expected_version[128] = {0};
    FAIL_UNLESS(wsrep_load(get_provider(), &wsrep, &log_fn) == 0);
    FAIL_UNLESS(wsrep != NULL);
    if (strlen(GALERA_GIT_REVISION) == 0)
    {
        fprintf(stderr, "Galera git revision not given\n");
        abort();
    }
    snprintf(expected_version, sizeof(expected_version) - 1,
             "%s(r%s)", GALERA_VERSION, GALERA_GIT_REVISION);
    if (strcmp(wsrep->provider_version, expected_version))
    {
        fprintf(stderr, "Provider version string '%s' not expected '%s'\n",
                wsrep->provider_version, expected_version);
        abort();
    }
    wsrep_unload(wsrep);
    return 0;
}

static
int wsrep_load_unload_membership_v1()
{
    wsrep_t* wsrep = 0;
    FAIL_UNLESS(wsrep_load(get_provider(), &wsrep, &log_fn) == 0);
    FAIL_UNLESS(wsrep != NULL);

    void* const dlh = wsrep->dlh;
    FAIL_UNLESS(NULL != dlh);
    wsrep_membership_service_v1_init_fn   wms_init   =
        dlsym(dlh, WSREP_MEMBERSHIP_SERVICE_V1_INIT_FN);
    FAIL_UNLESS(NULL != wms_init);
    wsrep_membership_service_v1_deinit_fn wms_deinit =
        dlsym(dlh, WSREP_MEMBERSHIP_SERVICE_V1_DEINIT_FN);
    FAIL_UNLESS(NULL != wms_deinit);
    {
        struct wsrep_membership_service_v1 membership_v1;
        wsrep_status_t ret = (*wms_init)(&membership_v1);
        FAIL_UNLESS(WSREP_OK == ret);
        FAIL_UNLESS(membership_v1.get_membership != NULL);
        {
            wsrep_gtid_t state_id = WSREP_GTID_UNDEFINED;
            struct ctx {} ctx;

            struct wsrep_init_args args =
            {
                .app_ctx       = &ctx,

                .node_name     = "example listener",
                .node_address  = "127.0.0.1",
                .node_incoming = "",
                .data_dir      = ".", // working directory
                .options       = "gcache.size=1K",
                .proto_ver     = 127, // maximum supported

                .state_id      = &state_id,
                .state         = NULL,

                .logger_cb      = log_fn,
                .view_cb        = NULL,
                .sst_request_cb = NULL,
                .encrypt_cb     = NULL,
                .apply_cb       = NULL,
                .unordered_cb   = NULL,
                .sst_donate_cb  = NULL,
                .synced_cb      = NULL
            };

/* Some GCC/ASAN builds hang at throw if called via dlopen():
   https://gcc.gnu.org/bugzilla/show_bug.cgi?id=91325
   Disable test in ASAN builds until the bug is fixed. */
#ifndef GALERA_WITH_ASAN
            ret = wsrep->init(wsrep, &args);
            FAIL_UNLESS(WSREP_OK == ret);

            struct wsrep_membership* memb = NULL;
            ret = membership_v1.get_membership(wsrep, malloc, &memb);
            FAIL_UNLESS(WSREP_OK != ret);
            FAIL_UNLESS(NULL == memb);

            wsrep->free(wsrep);
            unlink("grastate.dat");
            unlink("galera.cache");
#else
            (void)args;
#endif /* GALERA_WITH_ASAN */
        }
        (*wms_deinit)();
    }
    wsrep_unload(wsrep);
    return 0;
}

int main(int argc, char* argv[])
{
    int no_fork = ((argc > 1) && !strcmp(argv[1], "nofork")) ? 1 : 0;
    int failed  = 0;


    if (!no_fork) {
        log_file = fopen (LOG_FILE, "w");
        if (!log_file) return EXIT_FAILURE;
    }

    failed += wsrep_load_unload();
    failed += wsrep_load_unload_membership_v1();

    if (log_file)
    {
        fclose (log_file);
    }

    if (0 == failed && NULL != log_file) unlink(LOG_FILE);

    printf ("Total tests failed: %d\n", failed);
    return (failed == 0 ? EXIT_SUCCESS : EXIT_FAILURE);
}
