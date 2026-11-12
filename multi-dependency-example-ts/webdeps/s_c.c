/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (C) 2026 midair <midair@localhost> */
/** @file
 * @brief Webdeps: smoke test for the C extension (libpycore.so)
 *
 * dlopen()s libpycore.so -- the C host that embeds CPython so the Python
 * ring stage can take part through a C ABI -- and calls its leaf
 * C-ABI function py_weight() once, in a forked child so a crash inside
 * the library is caught as a child exit status rather than taking the
 * test process down with it. Settles no hypothesis.
 *
 * @author midair <midair@localhost>
 */

#define TE_TEST_NAME    "webdeps/s_c"

#include "te_config.h"

#include <arpa/inet.h>
#include <dirent.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <math.h>
#include <netinet/in.h>
#include <poll.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "tapi_test.h"
#include "te_string.h"
#include "te_vector.h"
#include "te_sockaddr.h"
#include "tsapi_mde.h"

#include "webdeps_lib.h"

#define RUN_TO  30  /**< s, grace period for the child. */

typedef double (*py_weight_fn)(void);

/**
 * ring_stage.py -- the Python module libpycore drives -- binds cpp_step
 * and go_weight through ctypes.CDLL(None) at import time, for every call
 * it exports, not just the ones that use them: importing it to reach the
 * leaf py_weight() still needs both symbols already loaded globally, the
 * way they are inside cpp-demo or any other process that carries the
 * whole ring. A standalone harness has to load that much of the ring
 * itself first.
 */
static bool
preload_ring_for_py(const char *dist_lib)
{
    char path[1024];

    /*
     * libcppcore.so first: it exports cpp_weight, which libgocore.so
     * needs resolved at load time (it was linked with unresolved
     * symbols allowed, for the ring's own build-time cycle break, but
     * dlopen(RTLD_NOW) still resolves everything up front).
     */
    snprintf(path, sizeof(path), "%s/libcppcore.so", dist_lib);
    if (dlopen(path, RTLD_NOW | RTLD_GLOBAL) == NULL)
    {
        printf("dlopen libcppcore.so failed: %s\n", dlerror());
        return false;
    }
    snprintf(path, sizeof(path), "%s/libgocore.so", dist_lib);
    if (dlopen(path, RTLD_NOW | RTLD_GLOBAL) == NULL)
    {
        printf("dlopen libgocore.so failed: %s\n", dlerror());
        return false;
    }
    return true;
}

/** The child: dlopen, dlsym, call, print the value, exit 0 or 1. */
static void
child_main(const char *dist_lib, const char *libpath)
{
    void        *h;
    py_weight_fn fn;
    double       v;

    if (!preload_ring_for_py(dist_lib))
    {
        fflush(stdout);
        _exit(1);
    }

    /*
     * RTLD_GLOBAL, not RTLD_LOCAL: libpycore embeds CPython, and the
     * interpreter's own extension modules (ctypes among them) resolve
     * CPython's C API through the global symbol scope, the same flat-
     * namespace pattern python/demo.py documents for the ring's other
     * cross-library calls.
     */
    h = dlopen(libpath, RTLD_NOW | RTLD_GLOBAL);
    if (h == NULL)
    {
        printf("dlopen failed: %s\n", dlerror());
        fflush(stdout);
        _exit(1);
    }
    fn = (py_weight_fn)dlsym(h, "py_weight");
    if (fn == NULL)
    {
        printf("dlsym(py_weight) failed: %s\n", dlerror());
        fflush(stdout);
        _exit(1);
    }
    v = fn();
    printf("py_weight() = %.6f\n", v);
    fflush(stdout);
    _exit(isfinite(v) ? 0 : 1);
}

int
main(int argc, char **argv)
{
    res_t    res = { .kind = R_SETUP };
    char     dist_lib[512];
    char     libpath[512];
    char     out[256] = "";
    char     code[32];
    proc_t  *p;
    pid_t    pid;

    TEST_START;
    wd_init(&res);
    if (res.kind != R_SETUP)
        goto verdict;
    res.kind = R_PASS;

    snprintf(dist_lib, sizeof(dist_lib), "%s/dist/lib", src_root);
    snprintf(libpath, sizeof(libpath), "%s/dist/lib/libpycore.so", src_root);
    if (access(libpath, F_OK) != 0)
    {
        setup_svc = "libpycore.so";
        res_set(&res, R_SETUP, "%s not found; build it first", libpath);
        goto verdict;
    }

    TEST_STEP("Fork a child, dlopen libpycore.so and call py_weight() once");
    if (n_procs >= MAX_PROCS)
    {
        res_set(&res, R_SETUP, "too many processes");
        goto verdict;
    }
    p = &procs[n_procs];
    memset(p, 0, sizeof(*p));
    p->name = "s_c-child";
    snprintf(p->out, sizeof(p->out), "%s/s_c.out", workdir);
    snprintf(p->err, sizeof(p->err), "%s/s_c.err", workdir);

    pid = fork();
    if (pid < 0)
    {
        res_set(&res, R_SETUP, "fork failed: %s", strerror(errno));
        goto verdict;
    }
    if (pid == 0)
    {
        int o = open(p->out, O_WRONLY | O_CREAT | O_TRUNC, 0600);
        int e = open(p->err, O_WRONLY | O_CREAT | O_TRUNC, 0600);

        setpgid(0, 0);
        dup2(o, 1);
        dup2(e, 2);
        setenv("LD_LIBRARY_PATH", dist_lib, 1);
        child_main(dist_lib, libpath);
        _exit(1); /* unreachable: child_main() always _exit()s. */
    }
    p->pid = pid;
    setpgid(pid, pid);
    n_procs++;

    {
        double end = now_s() + RUN_TO;

        while (now_s() < end && !proc_gone(p))
            usleep(100000);
    }
    exit_code_str(p, code, sizeof(code));
    if (!proc_gone(p))
    {
        res_set(&res, R_FAIL, "s_c: the child did not finish within %d s "
                "(exit code %s)", RUN_TO, code);
        goto verdict;
    }

    {
        FILE  *f = fopen(p->out, "r");
        size_t n = 0;

        if (f != NULL)
        {
            n = fread(out, 1, sizeof(out) - 1, f);
            fclose(f);
        }
        out[n] = '\0';
    }
    if (!WIFEXITED(p->status) || WEXITSTATUS(p->status) != 0)
    {
        char last[300];

        last_line(p->err, last, sizeof(last));
        res_set(&res, R_FAIL, "s_c: the child exited with code %s instead "
                "of 0; stdout: [%s]; last stderr line: [%s]", code, out,
                last);
        goto verdict;
    }
    if (file_has(p->err, "Traceback"))
    {
        /*
         * py_weight() falls back to a default value when its Python side
         * fails to load, so a 0 exit code alone is not proof the example
         * ran: a traceback on stderr means it did not.
         */
        char last[300];

        last_line(p->err, last, sizeof(last));
        res_set(&res, R_FAIL, "s_c: the child exited 0 but its Python side "
                "raised (last stderr line: [%s]); stdout: [%s]", last, out);
        goto verdict;
    }
    res_set(&res, R_PASS, "s_c: libpycore.so's py_weight() ran in a child "
            "that exited 0; stdout: [%s]", out);

verdict:
    WD_VERDICT(&res);

cleanup:
    cleanup_all();
    TEST_END;
}
