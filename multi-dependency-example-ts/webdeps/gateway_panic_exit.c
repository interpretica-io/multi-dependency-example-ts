/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (C) 2026 midair <midair@localhost> */
/** @file
 * @brief Webdeps: gateway_panic_exit, gateway-rs started three ways
 *        (settles H1)
 *
 * Hypothesis H1: gateway-rs panics at main.rs:30 and main.rs:34 on bad
 * start-up input. The test needs nothing from the other tests of the group.
 *
 * Three runs of dist/bin/gateway-rs, each for at most 10 s, then killed
 * ("hung" in the log); the exit code and stderr of each are recorded:
 *  1. no-config: empty work directory, no configuration variables;
 *  2. bad-port: the port setting given as "notaport" in the environment
 *     and on the command line;
 *  3. port-in-use: another listener holds the gateway port.
 *
 * Verdicts (each starts with H1 and names the exit codes):
 *  - "H1 CONFIRMED": a run exited with 101, or its stderr has "panicked at"
 *    with main.rs:30 or main.rs:34;
 *  - "H1 DISPROVED": no run did (clean error exit, or ran until killed);
 *  - "H1 NOT RUN": the binary is missing or cannot be started; the reason
 *    is printed. This fails the test, it is never a pass.
 *
 * @author midair <midair@localhost>
 */

#define TE_TEST_NAME    "webdeps/gateway_panic_exit"

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
    char        err[400];
} run_t;

/** Read the first bytes of a file with newlines flattened. */
static void
slurp(const char *path, char *buf, size_t size)
{
    FILE   *f = fopen(path, "r");
    size_t  n = 0;
    size_t  i;

    buf[0] = '\0';
    if (f == NULL)
        return;
    n = fread(buf, 1, size - 1, f);
    fclose(f);
    buf[n] = '\0';
    for (i = 0; i < n; i++)
    {
        if (buf[i] == '\n' || buf[i] == '\r')
            buf[i] = ' ';
    }
}

/** True when stderr names a panic at main.rs:30 or main.rs:34. */
static bool
panic_at_main(const char *err)
{
    return strstr(err, "panicked at") != NULL &&
           (strstr(err, "main.rs:30") != NULL ||
            strstr(err, "main.rs:34") != NULL);
}

/** Run the gateway once; return false (reason in @p why) if it cannot start. */
static bool
run_gateway(run_t *r, const char *bin, const char *cwd, bool bad_port,
            char *why, size_t why_size)
{
    char    errp[160];
    pid_t   pid;
    double  end;
    int     status = 0;

    snprintf(errp, sizeof(errp), "%s/%s.stderr", workdir, r->name);
    pid = fork();
    if (pid < 0)
    {
        snprintf(why, why_size, "fork failed: %s", strerror(errno));
        return false;
    }
    if (pid == 0)
    {
        int  e = open(errp, O_WRONLY | O_CREAT | O_TRUNC, 0600);
        int  o = open("/dev/null", O_WRONLY);
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
        clearenv();
        setenv("LD_LIBRARY_PATH", lib, 1);
        setenv("PATH", "/usr/bin:/bin", 1);
        setenv("RUST_BACKTRACE", "0", 1);
        if (bad_port)
        {
            setenv("PORT", "notaport", 1);
            setenv("GATEWAY_PORT", "notaport", 1);
            setenv("LISTEN_PORT", "notaport", 1);
            setenv("GATEWAY_RS_PORT", "notaport", 1);
            argv_[1] = (char *)"notaport";
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
                 "no exit code)", r->name, LIMIT_S);
    else if (r->sig != 0)
        snprintf(buf, size, "%s: killed by signal %d", r->name, r->sig);
    else
        snprintf(buf, size, "%s: exit code %d", r->name, r->code);
}

int
main(int argc, char **argv)
{
    res_t   res = { .kind = R_PASS };
    run_t   runs[3] = { { .name = "no-config", .code = -1 },
                        { .name = "bad-port", .code = -1 },
                        { .name = "port-in-use", .code = -1 } };
    char    bin[600];
    char    cwd[160];
    char    summary[900] = "";
    char    why[2200] = "";
    char    hit[200] = "";
    int     blocker = -1;
    int     i;
    bool    not_run = false;

    TEST_START;
    t_report_begin();
    wd_init(&res);
    if (res.kind == R_SETUP)
    {
        snprintf(why, sizeof(why), "%s", res.msg);
        not_run = true;
        goto verdict;
    }
    snprintf(bin, sizeof(bin), "%s/dist/bin/gateway-rs", src_root);
    if (access(bin, X_OK) != 0)
    {
        snprintf(why, sizeof(why), "%s is missing or not executable "
                 "(build failure?)", bin);
        not_run = true;
        goto verdict;
    }
    snprintf(cwd, sizeof(cwd), "%s/empty", workdir);
    if (mkdir(cwd, 0700) != 0)
    {
        snprintf(why, sizeof(why), "cannot create %s: %s", cwd,
                 strerror(errno));
        not_run = true;
        goto verdict;
    }

    for (i = 0; i < 3; i++)
    {
        char t[200];

        TEST_STEP("Run gateway-rs: %s", runs[i].name);
        if (i == 2)
        {
            struct sockaddr_in sa = { .sin_family = AF_INET,
                                      .sin_port = htons(tab_port[GW]) };

            inet_pton(AF_INET, "127.0.0.1", &sa.sin_addr);
            blocker = socket(AF_INET, SOCK_STREAM, 0);
            if (blocker < 0 ||
                bind(blocker, (struct sockaddr *)&sa, sizeof(sa)) != 0 ||
                listen(blocker, 4) != 0)
            {
                snprintf(why, sizeof(why), "cannot hold port %u for the "
                         "port-in-use run: %s", tab_port[GW],
                         strerror(errno));
                not_run = true;
                goto verdict;
            }
        }
        if (!run_gateway(&runs[i], bin, cwd, i == 1, why, sizeof(why)))
        {
            not_run = true;
            goto verdict;
        }
        run_text(&runs[i], t, sizeof(t));
        RING("webdeps H1: %s; stderr [%s]", t, runs[i].err);
        T_FINDING(runs[i].code == 101 || runs[i].panic ?
                  TAPI_CYBERSEC_SEV_HIGH : TAPI_CYBERSEC_SEV_INFO,
                  "gateway.startup", runs[i].name, "%s; stderr [%s]", t,
                  runs[i].err);
        append(summary, sizeof(summary), "%s; ", t);
        if (runs[i].code == 101 || runs[i].panic)
            append(hit, sizeof(hit), "%s ", runs[i].name);
    }

verdict:
    if (blocker >= 0)
        close(blocker);
    if (not_run)
        res_set(&res, R_FAIL, "H1 NOT RUN: gateway-rs did not start at "
                "all, no exit code: %.600s", why);
    else if (hit[0] != '\0')
        res_set(&res, R_FAIL, "H1 CONFIRMED: gateway-rs panicked (exit 101 "
                "or 'panicked at' main.rs:30/34) in run(s) %s; %s", hit,
                summary);
    else
        res_set(&res, R_PASS, "H1 DISPROVED: no run exited with 101 or "
                "printed a panic at main.rs:30/34; %s", summary);
    T_VERDICT(&res, "H1");

cleanup:
    cleanup_all();
    TEST_END;
}
