/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (C) 2026 midair <midair@localhost> */
/** @file
 * @brief Webdeps: gateway_exit_code, gateway-rs started with bad input
 *        (settles H1)
 *
 * Hypothesis H1: gateway-rs exits with code 101 (panic at main.rs:30 or
 * main.rs:34) on bad startup input.
 *
 * Two runs of dist/bin/gateway-rs as a child process (stdout and stderr
 * captured, status from waitpid, at most 10 s, killed on timeout):
 *  1. unset-env: startup variables unset (main.rs:30);
 *  2. bad-address: malformed listen address (main.rs:34).
 *
 * Verdicts (each starts with H1; never empty, never a skip):
 *  - "H1 CONFIRMED": a run exited 101 and stderr contains "panicked";
 *    the test fails and logs both exit codes and the first stderr line;
 *  - "H1 REFUTED": no run did; the test passes;
 *  - "H1 NOT SETTLED": the binary does not start (exec error text) or a
 *    harness step broke (the step is named); the test fails.
 *
 * @author midair <midair@localhost>
 */

#define TE_TEST_NAME    "webdeps/gateway_exit_code"

#include "te_config.h"

#include "webdeps_lib.h"

#define LIMIT_S 10

typedef struct run_t {
    const char *name;
    int         code;       /**< Exit code; -1 killed on a signal or hung. */
    int         sig;
    bool        hung;
    bool        panic;      /**< "panicked at" at main.rs:30 or :34. */
    bool        started;
    double      secs;       /**< Run time. */
    char        err[1600];
} run_t;

/** Read the last 20 lines of a file, newlines flattened to " | ". */
static void
slurp(const char *path, char *buf, size_t size)
{
    char    raw[8192];
    FILE   *f = fopen(path, "r");
    size_t  n = 0;
    size_t  i;
    size_t  start;
    int     lines = 0;

    buf[0] = '\0';
    if (f == NULL)
        return;
    n = fread(raw, 1, sizeof(raw) - 1, f);
    fclose(f);
    while (n > 0 && (raw[n - 1] == '\n' || raw[n - 1] == '\r'))
        n--;
    raw[n] = '\0';
    start = n;
    while (start > 0)
    {
        if (raw[start - 1] == '\n' && ++lines == 20)
            break;
        start--;
    }
    for (i = start; i < n; i++)
    {
        if (raw[i] == '\n' || raw[i] == '\r')
            raw[i] = '|';
    }
    snprintf(buf, size, "%s", raw + start);
}

/** True when stderr names a panic at main.rs:30 or main.rs:34. */
static bool
panic_at_main(const char *err)
{
    return strstr(err, "panicked") != NULL;
}

/** Run the gateway once; return false (reason in @p why) if it cannot start. */
static bool
run_gateway(run_t *r, const char *bin, const char *cwd, bool bad_addr,
            bool empty_env,
            char *why, size_t why_size)
{
    char    errp[160];
    char    outp[160];
    pid_t   pid;
    double  end;
    double  t0;
    int     status = 0;

    snprintf(errp, sizeof(errp), "%s/%s.stderr", workdir, r->name);
    snprintf(outp, sizeof(outp), "%s/%s.stdout", workdir, r->name);
    t0 = now_s();
    pid = fork();
    if (pid < 0)
    {
        snprintf(why, why_size, "fork failed: %s", strerror(errno));
        return false;
    }
    if (pid == 0)
    {
        int  e = open(errp, O_WRONLY | O_CREAT | O_TRUNC, 0600);
        int  o = open(outp, O_WRONLY | O_CREAT | O_TRUNC, 0600);
        int  z = open("/dev/null", O_RDONLY);
        char lib[600];
        char *argv_[3] = { (char *)bin, NULL, NULL };

        setpgid(0, 0);
        dup2(z, 0);
        dup2(o, 1);
        dup2(e, 2);
        if (chdir(cwd) != 0)
            _exit(126);
        snprintf(lib, sizeof(lib), "%s/dist/lib", src_root);
        if (empty_env)
        {
            clearenv();
        }
        else
        {
            setenv("LD_LIBRARY_PATH", lib, 1);
            setenv("RUST_BACKTRACE", "0", 1);
        }
        if (bad_addr)
        {
            static const char * const vars[] = {
                "LISTEN_ADDR", "LISTEN_ADDRESS", "GATEWAY_ADDR",
                "GATEWAY_ADDRESS", "GATEWAY_HOST", "BIND_ADDR", "HOST",
                "ADDR", "PORT", "GATEWAY_PORT", "LISTEN_PORT",
                "GATEWAY_RS_PORT",
            };
            size_t k;

            for (k = 0; k < sizeof(vars) / sizeof(vars[0]); k++)
                setenv(vars[k], "999.999.999.999:notaport", 1);
            argv_[1] = (char *)"999.999.999.999:notaport";
        }
        execv(bin, argv_);
        dprintf(2, "exec %s: %s\n", bin, strerror(errno));
        _exit(127);
    }
    setpgid(pid, pid);
    end = now_s() + LIMIT_S;
    for (;;)
    {
        pid_t w = waitpid(pid, &status, WNOHANG);

        if (w == pid)
            break;
        if (now_s() >= end)
        {
            kill(-pid, SIGKILL);
            kill(pid, SIGKILL);
            waitpid(pid, &status, 0);
            r->hung = true;
            break;
        }
        usleep(100000);
    }
    if (!r->hung)
    {
        if (WIFEXITED(status))
            r->code = WEXITSTATUS(status);
        else if (WIFSIGNALED(status))
            r->sig = WTERMSIG(status);
    }
    r->secs = now_s() - t0;
    slurp(errp, r->err, sizeof(r->err));
    r->started = !(r->code == 127 && strstr(r->err, "exec ") != NULL);
    if (!r->started)
    {
        snprintf(why, why_size, "%s", r->err);
        return false;
    }
    r->panic = panic_at_main(r->err);
    return true;
}

/** Text of one run for the verdict and the log. */
static void
run_text(const run_t *r, char *buf, size_t size)
{
    if (r->hung)
        snprintf(buf, size, "%s: hung (still running after %d s, killed, "
                 "no exit code), %.1f s", r->name, LIMIT_S, r->secs);
    else if (r->sig != 0)
        snprintf(buf, size, "%s: killed by signal %d, %.1f s", r->name,
                 r->sig, r->secs);
    else
        snprintf(buf, size, "%s: exit code %d, %.1f s", r->name, r->code,
                 r->secs);
}

int
main(int argc, char **argv)
{
    res_t   res = { .kind = R_PASS };
    run_t   runs[2] = { { .name = "unset-env", .code = -1 },
                        { .name = "bad-address", .code = -1 } };
    char    bin[600];
    char    cwd[160];
    char    summary[900] = "";
    char    why[2200] = "";
    char    hit[200] = "";
    char    codes[200] = "";
    char    first_line[300] = "";
    const char *first_run = "none";
    char    good[8];
    proc_t *gw;
    double  t0;
    int     blocker = -1;
    char   *bar;
    int     i;
    bool    skipped = false;

    TEST_START;
    t_report_begin();
    wd_init(&res);
    if (res.kind == R_SETUP)
    {
        snprintf(why, sizeof(why), "step prepare work dir broke: %s", res.msg);
        skipped = true;
        goto verdict;
    }
    snprintf(bin, sizeof(bin), "%s/dist/bin/gateway-rs", src_root);
    if (access(bin, X_OK) != 0)
    {
        snprintf(why, sizeof(why), "step locate binary broke: %s does not exist or is not "
                 "executable (build failure?)", bin);
        skipped = true;
        goto verdict;
    }
    snprintf(cwd, sizeof(cwd), "%s/empty", workdir);
    if (mkdir(cwd, 0700) != 0)
    {
        snprintf(why, sizeof(why), "step create work dir broke: cannot create %s: %s", cwd,
                 strerror(errno));
        skipped = true;
        goto verdict;
    }

    t0 = now_s();
    good[0] = '\0';
    (void)good;
    (void)blocker;

    for (i = 0; i < 2; i++)
    {
        char t[200];

        TEST_STEP("Bad run: gateway-rs, %s", runs[i].name);
        if (!run_gateway(&runs[i], bin, cwd, i == 1, i == 0, why,
                         sizeof(why)))
        {
            char tmp[2200];

            snprintf(tmp, sizeof(tmp), "step run %s broke or binary does "
                     "not start: %s", runs[i].name, why);
            snprintf(why, sizeof(why), "%s", tmp);
            skipped = true;
            goto verdict;
        }
        run_text(&runs[i], t, sizeof(t));
        RING("webdeps H1: %s; stderr [%s]", t, runs[i].err);
        T_FINDING(runs[i].code == 101 && runs[i].panic ?
                  TAPI_CYBERSEC_SEV_HIGH : TAPI_CYBERSEC_SEV_INFO,
                  "gateway.startup", runs[i].name, "%s; stderr [%s]", t,
                  runs[i].err);
        append(summary, sizeof(summary), "%s; stderr [%.200s]; ", t,
               runs[i].err);
        append(codes, sizeof(codes), "%s=%d ", runs[i].name, runs[i].code);
        if (runs[i].code == 101 && runs[i].panic)
        {
            if (hit[0] == '\0')
            {
                first_run = runs[i].name;
                snprintf(first_line, sizeof(first_line), "%s", runs[i].err);
                bar = strchr(first_line, '|');
                if (bar != NULL)
                    *bar = '\0';
            }
            append(hit, sizeof(hit), "%s ", runs[i].name);
        }
    }

verdict:
    if (blocker >= 0)
        close(blocker);
    if (skipped)
        res_set(&res, R_FAIL, "H1 NOT SETTLED: %.900s", why);
    else if (hit[0] != '\0')
        res_set(&res, R_FAIL, "H1 CONFIRMED: exit 101 with 'panicked' in "
                "run(s) %s; exit codes: %s; first stderr line of %s: "
                "[%s]; %s", hit, codes, first_run, first_line, summary);
    else
        res_set(&res, R_PASS, "H1 REFUTED: no bad run exited 101 with 'panicked' "
                "(handled exit or no exit); %s", summary);
    T_VERDICT(&res, "H1");

cleanup:
    cleanup_all();
    TEST_END;
}
