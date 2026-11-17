/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (C) 2026 midair <midair@localhost> */
/** @file
 * @brief Webdeps: t11_rust_panic, bad input to gateway-rs (settles H1)
 *
 * Hypothesis H1: gateway-rs exits on a malformed request or a dead
 * upstream (panic! at main.rs:30 and main.rs:34).
 *
 * Sends and reads, in this order:
 *  1. gateway-rs is started (its upstream service-go is not running); its
 *     pid is recorded and one valid request must get a reply (HTTP 200).
 *  2. A malformed request line, "GARBAGE\r\n\r\n"; wait 2 s; the pid must
 *     live and a new valid request must get a reply.
 *  3. The other inputs aimed at main.rs:30 and main.rs:34 (another
 *     service, not HTTP, empty body, bad path, short request line,
 *     oversized line and header, a second gateway on the same port), each
 *     followed by a pid check and a valid request.
 *  4. gateway-rs is stopped and started again after the upstream port
 *     (service-go) was checked to be closed; a valid request is sent and
 *     the pid is checked again.
 *  5. gateway-rs built with an unset and with an invalid upstream setting
 *     is run for 5 s.
 *
 * Verdicts (every one starts with H1; each is logged when reached and the
 * last one ends the test):
 *  - "H1 gateway-survives-malformed" (pass): step 2 found the pid alive and
 *    a reply; H1 is false for a malformed request.
 *  - "H1 gateway-exited-code-N" (fail): the process ended after the
 *    malformed request or another input; N is the exit code, or 128 plus
 *    the signal. H1 is true.
 *  - "H1 gateway-survives-dead-upstream" (pass) or
 *    "H1 gateway-exited-dead-upstream-code-N" (fail): step 4.
 *  - "H1 gateway-exited-bad-setting" (fail): step 5 ended the process.
 *  - "H1 setup-<step>-failed: ..." (fail): the step named did not work,
 *    nothing is settled.
 * The test fails on any exit of the gateway and passes only when every
 * step found it alive. All outcomes go to the tapi_cybersec_report.
 *
 * Both panic! calls sit in main() before the accept loop, so a client
 * cannot reach them while the gateway runs; the dead-upstream start and
 * the bad-setting runs do.
 *
 * @author midair <midair@localhost>
 */

#define TE_TEST_NAME    "webdeps/t11_rust_panic"

#include "te_config.h"

#include "webdeps_lib.h"

#define WAIT_S      2
#define BIG_HEADER  (256 * 1024)
#define BIG_LINE    (4 * 1024 * 1024)

enum {
    IN_GARBAGE,                                 /* malformed request line */
    IN_OTHER_SVC, IN_NOT_HTTP, IN_EMPTY,        /* aimed at main.rs:30 */
    IN_BAD_PATH,                                /* 404 path in the handler */
    IN_BAD_REQLINE,                             /* malformed request line */
    IN_BIG_LINE, IN_BIG_HEADER, IN_BIND,        /* aimed at main.rs:34 */
    N_INPUTS
};

static const struct {
    const char *name;
    unsigned    line;       /**< The panic! the input is aimed at. */
} in_info[N_INPUTS] = {
    { "a malformed request line (GARBAGE)", 30 },
    { "a request that names another service", 30 },
    { "bytes that are not HTTP", 30 },
    { "an empty body", 30 },
    { "a bad path", 30 },
    { "a malformed request line", 30 },
    { "an oversized request line", 34 },
    { "an oversized header", 34 },
    { "a second gateway-rs on the same port", 34 },
};

/** Wait up to WAIT_S s for the child to exit; true when it is gone. */
static bool
exited_within(proc_t *gw)
{
    double end = now_s() + WAIT_S;

    do {
        if (proc_gone(gw))
            return true;
        usleep(100000);
    } while (now_s() < end);

    return proc_gone(gw);
}

/** Send one of the inputs; for IN_BIND the second process is reported. */
static void
send_input(unsigned port, int which)
{
    static const char other[] = "GET /service-go/ring?value=1&hops=1 "
                                "HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n";
    static const char badpath[] = "GET /no/such/..%2f..%2fetc/passwd "
                                  "HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n";
    static const char junk[] = "\x00\xff\xfe\x80\r\n\r\n\x01\x02";
    char    head[256];
    char   *big;
    size_t  n;

    switch (which)
    {
        case IN_GARBAGE:
            send_once(port, "GARBAGE\r\n\r\n", 10, false, 500);
            break;

        case IN_OTHER_SVC:
            send_once(port, other, sizeof(other) - 1, false, 500);
            break;

        case IN_NOT_HTTP:
            send_once(port, junk, sizeof(junk) - 1, true, 500);
            break;

        case IN_BAD_PATH:
            send_once(port, badpath, sizeof(badpath) - 1, false, 500);
            break;

        case IN_BAD_REQLINE:
            send_once(port, "GET\r\n\r\n", 7, false, 500);
            break;

        case IN_EMPTY:
            send_once(port, "", 0, true, 500);
            break;

        case IN_BIG_HEADER:
            big = malloc(BIG_HEADER + 512);
            if (big == NULL)
                return;
            n = snprintf(big, 512, "GET /ring?value=1&hops=1 HTTP/1.1\r\n"
                         "Host: 127.0.0.1\r\nX-Big: ");
            memset(big + n, 'A', BIG_HEADER);
            n += BIG_HEADER;
            n += snprintf(big + n, 16, "\r\n\r\n");
            send_once(port, big, n, false, 500);
            free(big);
            break;

        case IN_BIG_LINE:
            big = malloc(BIG_LINE + 64);
            if (big == NULL)
                return;
            n = snprintf(head, sizeof(head), "GET /");
            memcpy(big, head, n);
            memset(big + n, 'B', BIG_LINE);
            n += BIG_LINE;
            send_once(port, big, n, true, 500);
            free(big);
            break;

        default:
            break;
    }
}

/** Start a second gateway-rs: its bind to the busy port is main.rs:34. */
static void
second_gateway(char *note, size_t size)
{
    res_t   r = { .kind = R_PASS };
    char    path[600];
    char   *argv_[] = { path, NULL };
    char    code[48];
    char    tail[300];
    proc_t *p;

    snprintf(path, sizeof(path), "%s/dist/bin/gateway-rs", src_root);
    p = run_once(&r, "gateway-rs-2", path, argv_, 10);
    if (p == NULL)
    {
        snprintf(note, size, "the second gateway-rs did not end: %s", r.msg);
        return;
    }
    p->stopped = true;
    exit_code_str(p, code, sizeof(code));
    file_tail(p->err, tail, sizeof(tail));
    snprintf(note, size, "second gateway-rs ended with exit code %s; "
             "stderr tail [%s]", code, tail);
    RING("webdeps H1: %s", note);
}

/**
 * Variants of gateway-rs whose setting at main.rs:30 is unset (the upstream
 * names no service of the contract) or invalid (a port that is not a
 * number). The table is compiled in, so each variant is built from a copy of
 * web/ with the table changed. Returns true when a variant stayed up.
 */
static bool
bad_setting(res_t *r, char *note, size_t size)
{
    static const struct {
        const char *name;
        const char *sed;
    } variants[] = {
        { "unset upstream", "s/^\\(gateway-rs[ \\t]*[0-9]*[ \\t]*\\)[^ \\t]*/\\1nosuch/" },
        { "invalid port", "s/^\\(gateway-rs[ \\t]*\\)[0-9]*/\\1notaport/" },
    };
    size_t  i;
    bool    survived = false;

    for (i = 0; i < TE_ARRAY_LEN(variants); i++)
    {
        char    cmd[1600];
        char    code[48];
        char    tail[300];
        char    outtail[300];
        proc_t *p;

        TEST_STEP("Start gateway-rs with the setting at main.rs:30 as '%s'",
                  variants[i].name);
        snprintf(cmd, sizeof(cmd),
                 "T=%s/bad-setting-%zu && rm -rf $T && mkdir -p $T/web && "
                 "cp -r web/contract web/gateway-rs $T/web/ && "
                 "ln -s '%s/dist' $T/dist && "
                 "sed -i '%s' $T/web/contract/services.tab && "
                 "CARGO_TARGET_DIR=$T/target cargo build --release --offline "
                 "--manifest-path $T/web/gateway-rs/Cargo.toml >$T/build.log 2>&1 "
                 "|| { tail -5 $T/build.log; echo build-failed; exit 0; }; "
                 "LD_LIBRARY_PATH='%s/dist/lib' timeout 5 "
                 "$T/target/release/gateway-rs; echo \"exit=$?\"",
                 workdir, i, src_root, variants[i].sed, src_root);
        p = run_sh(r, "gateway-rs-bad-setting", cmd, 240);
        if (p == NULL)
            return survived;
        exit_code_str(p, code, sizeof(code));
        file_tail(p->out, outtail, sizeof(outtail));
        file_tail(p->err, tail, sizeof(tail));
        RING("webdeps H1: gateway-rs with %s: shell exit %s; out [%s]; err "
             "[%s]", variants[i].name, code, outtail, tail);
        if (strstr(outtail, "build-failed") != NULL)
        {
            res_set(r, R_SETUP, "the '%s' variant of gateway-rs did not "
                    "build: %s", variants[i].name, outtail);
            return survived;
        }
        if (strstr(outtail, "exit=124") != NULL)
        {
            survived = true;
            append(note, size, "%s: stayed up for 5 s; ", variants[i].name);
        }
        else
        {
            T_FINDING(TAPI_CYBERSEC_SEV_HIGH, "gateway.exited",
                      variants[i].name, "out [%s] err [%s]", outtail, tail);
            append(note, size, "%s: process ended, out [%s] err [%s]; ",
                   variants[i].name, outtail, tail);
        }
    }
    return survived;
}

/** Name of the first failing verdict; empty while nothing failed. */
static char first_fail[200];

/** Log one named verdict when it is reached; remember the first failure. */
static void
named(bool failed, const char *fmt, ...)
{
    char    text[200];
    va_list ap;

    va_start(ap, fmt);
    vsnprintf(text, sizeof(text), fmt, ap);
    va_end(ap);
    RING_VERDICT("%s", text);
    if (failed && first_fail[0] == '\0')
        snprintf(first_fail, sizeof(first_fail), "%s", text);
}

/** Wait until nothing accepts on @p port (a killed gateway frees it). */
static bool
port_free_within(unsigned port, int seconds)
{
    double end = now_s() + seconds;

    while (port_accepts(port))
    {
        if (now_s() > end)
            return false;
        usleep(100000);
    }
    return true;
}

/** Step 4: the upstream port is closed; start gateway-rs, ask, check pid. */
static void
dead_upstream(res_t *res, proc_t *old, char *seen, size_t seen_size)
{
    proc_t *gw;
    hg_res  h;
    char    tail[400];
    int     n;

    TEST_STEP("Check that the upstream port %u (service-go) is closed",
              tab_port[GO]);
    if (port_accepts(tab_port[GO]))
    {
        res_set(res, R_SETUP, "H1 setup-upstream-port-not-closed: "
                "127.0.0.1:%u accepts TCP, the dead-upstream case cannot "
                "be run", tab_port[GO]);
        return;
    }
    if (old != NULL)
        proc_stop(old);
    if (!port_free_within(tab_port[GW], 5))
    {
        res_set(res, R_SETUP, "H1 setup-stop-gateway-failed: "
                "127.0.0.1:%u still accepts after the first gateway-rs was "
                "stopped", tab_port[GW]);
        return;
    }

    TEST_STEP("Start gateway-rs with its upstream port closed");
    gw = svc_start(res, GW);
    if (gw == NULL)
    {
        char orig[900];

        snprintf(orig, sizeof(orig), "%.890s", res->msg);
        res_set(res, R_SETUP, "H1 setup-start-gateway-dead-upstream-failed:"
                " %s", orig);
        return;
    }
    RING("webdeps H1: gateway-rs with the upstream closed: pid %d, port %u",
         (int)gw->pid, gw->port);

    TEST_STEP("Send a valid request and check the pid");
    http_get(gw->port, REQUEST, PROBE_TO, &h);
    exited_within(gw);
    file_tail(gw->err, tail, sizeof(tail));
    if (proc_gone(gw))
    {
        n = exit_n(gw);
        gw->stopped = true;
        named(true, "H1 gateway-exited-dead-upstream-code-%d", n);
        T_FINDING(TAPI_CYBERSEC_SEV_HIGH, "gateway.exited",
                  "dead upstream", "exit code %d; stderr tail [%s]", n,
                  tail);
        res_set(res, R_FAIL, "H1 gateway-exited-dead-upstream-code-%d: "
                "gateway-rs ended after a valid request with the upstream "
                "closed; stderr tail [%s]", n, tail);
        return;
    }
    http_get(gw->port, REQUEST, PROBE_TO, &h);
    if (h.how != HG_OK)
    {
        named(true, "H1 gateway-no-reply-dead-upstream");
        T_FINDING(TAPI_CYBERSEC_SEV_HIGH, "gateway.no-reply",
                  "dead upstream", "pid %d alive, request %s",
                  (int)gw->pid, hg_str(h.how));
        res_set(res, R_FAIL, "H1 gateway-no-reply-dead-upstream: pid %d is "
                "alive but a valid request got no reply (%s)",
                (int)gw->pid, hg_str(h.how));
        return;
    }
    named(false, "H1 gateway-survives-dead-upstream");
    T_FINDING(TAPI_CYBERSEC_SEV_INFO, "gateway.survived", "dead upstream",
              "pid %d alive, valid request HTTP %d", (int)gw->pid, h.status);
    append(seen, seen_size, "dead upstream: alive, HTTP %d; ", h.status);
}

int
main(int argc, char **argv)
{
    res_t    res = { .kind = R_PASS };
    proc_t  *gw;
    hg_res   h;
    char     code[48];
    char     tail[400];
    char     note[500];
    char     seen[900] = "";
    bool     exited = false;
    int      i;

    TEST_START;

    TEST_STEP("Start gateway-rs and wait for its port");
    gw = svc_start_t(&res, "H1", GW);
    if (gw == NULL)
    {
        char orig[sizeof(res.msg)];

        ERROR("gateway-rs did not start: %s", res.msg);
        snprintf(orig, sizeof(orig), "%s", res.msg);
        res_set(&res, R_SETUP, "H1 setup-start-gateway-failed: %.1400s",
                orig);
        goto verdict;
    }

    RING("webdeps H1: gateway-rs started with its upstream service-go not "
         "running: pid %d, port %u (main.rs:33-36); alive after start: %s",
         (int)gw->pid, gw->port, proc_gone(gw) ? "no" : "yes");
    T_FINDING(TAPI_CYBERSEC_SEV_INFO, "gateway.start-unreachable-upstream",
              "gateway-rs", "no panic at start with the upstream "
              "unreachable; pid %d, port %u", (int)gw->pid, gw->port);

    TEST_STEP("A valid request gets a reply");
    http_get(gw->port, REQUEST, PROBE_TO, &h);
    RING("webdeps H1: GET %s -> %s, HTTP %d", REQUEST, hg_str(h.how),
         h.status);
    if (proc_gone(gw) || h.how != HG_OK || h.status != 200)
    {
        exit_code_str(gw, code, sizeof(code));
        file_tail(gw->err, tail, sizeof(tail));
        res_set(&res, R_SETUP, "H1 setup-first-valid-request-failed: "
                "gateway-rs did not answer the valid request with 200 (%s, "
                "HTTP %d, exit status %s; stderr tail [%s]); settles "
                "nothing", hg_str(h.how), h.status, code, tail);
        goto verdict;
    }

    for (i = 0; i < N_INPUTS && !exited; i++)
    {
        bool gone;

        TEST_STEP("Send %s (aimed at main.rs:%u), wait %d s and read the "
                  "exit status", in_info[i].name, in_info[i].line, WAIT_S);
        note[0] = '\0';
        if (i == IN_BIND)
            second_gateway(note, sizeof(note));
        else
            send_input(gw->port, i);
        gone = exited_within(gw);
        exit_code_str(gw, code, sizeof(code));
        file_tail(gw->err, tail, sizeof(tail));
        RING("webdeps H1: after %s: gateway-rs exit status %s; stderr tail "
             "[%s]", in_info[i].name, code, tail);
        if (gone)
        {
            int n = exit_n(gw);

            gw->stopped = true;
            exited = true;
            ERROR("webdeps H1: gateway-rs gone after %s: exit status %s, "
                  "stderr tail [%s]", in_info[i].name, code, tail);
            T_FINDING(TAPI_CYBERSEC_SEV_HIGH, "gateway.exited",
                      in_info[i].name, "exit status %s; stderr tail [%s]",
                      code, tail);
            named(true, "H1 gateway-exited-code-%d", n);
            res_set(&res, R_FAIL, "H1 gateway-exited-code-%d: gateway-rs %s "
                    "after %s (aimed at main.rs:%u): exit status %s; stderr "
                    "tail [%s]", n, WIFSIGNALED(gw->status) ||
                    WEXITSTATUS(gw->status) == 101 ? "panicked" : "exited",
                    in_info[i].name, in_info[i].line, code, tail);
            break;
        }

        TEST_STEP("A valid request after %s", in_info[i].name);
        http_get(gw->port, REQUEST, PROBE_TO, &h);
        RING("webdeps H1: after %s: valid request %s, HTTP %d", in_info[i].name,
             hg_str(h.how), h.status);
        T_FINDING(TAPI_CYBERSEC_SEV_INFO, "gateway.survived", in_info[i].name,
                  "still running (exit status %s); a new valid request %s, "
                  "HTTP %d%s%s", code, hg_str(h.how), h.status,
                  note[0] != '\0' ? "; " : "", note);
        append(seen, sizeof(seen), "%s (main.rs:%u): alive, new request HTTP "
               "%d; ", in_info[i].name, in_info[i].line, h.status);
        if (!port_accepts(gw->port))
            h.how = HG_REFUSED;
        if (proc_gone(gw) || h.how != HG_OK || h.status != 200)
        {
            int n = exit_n(gw);

            exited = true;
            exit_code_str(gw, code, sizeof(code));
            file_tail(gw->err, tail, sizeof(tail));
            ERROR("webdeps H1: after %s: exit status %s, stderr tail [%s]",
                  in_info[i].name, code, tail);
            if (proc_gone(gw))
            {
                gw->stopped = true;
                named(true, "H1 gateway-exited-code-%d", n);
            }
            else
                named(true, "H1 gateway-no-reply-after-input-%d", i);
            res_set(&res, R_FAIL, "%s: after %s (aimed at main.rs:%u) the "
                    "next valid request %s (HTTP %d); exit status %s; "
                    "stderr tail [%s]", first_fail, in_info[i].name,
                    in_info[i].line, hg_str(h.how), h.status, code, tail);
            break;
        }
        if (i == IN_GARBAGE)
            named(false, "H1 gateway-survives-malformed");
    }

    if (res.kind == R_SETUP)
        goto verdict;

    /* Step 4 runs whatever happened above: one crash hides nothing. */
    {
        res_t   dres = { .kind = R_PASS };

        dead_upstream(&dres, gw, seen, sizeof(seen));
        if (dres.kind != R_PASS && res.kind == R_PASS)
            res = dres;
        else if (dres.kind != R_PASS)
            append(res.msg, sizeof(res.msg), "; %s", dres.msg);
    }

    if (res.kind != R_PASS && res.kind != R_FAIL)
        goto verdict;

    TEST_STEP("Start gateway-rs with its setting unset or invalid");
    {
        char bnote[1000] = "";
        res_t bres = { .kind = R_PASS };

        bad_setting(&bres, bnote, sizeof(bnote));
        if (bres.kind == R_SETUP)
        {
            if (res.kind == R_PASS)
            {
                char orig[sizeof(bres.msg)];

                snprintf(orig, sizeof(orig), "%s", bres.msg);
                res_set(&res, R_SETUP, "H1 setup-bad-setting-failed: %.1400s",
                        orig);
            }
        }
        else if (strstr(bnote, "process ended") != NULL)
        {
            named(true, "H1 gateway-exited-bad-setting");
            if (res.kind == R_PASS)
                res_set(&res, R_FAIL, "H1 gateway-exited-bad-setting: "
                        "gateway-rs with the setting at main.rs:30 unset or "
                        "invalid does not stay up (panic! at main.rs:30): "
                        "%s", bnote);
        }
        else if (bnote[0] == '\0' && res.kind == R_PASS)
            res_set(&res, R_INCONCLUSIVE, "no bad-setting run took place");
    }

    if (res.kind == R_PASS)
    {
        file_tail(gw->err, tail, sizeof(tail));
        res_set(&res, R_PASS, "H1 gateway-survives-malformed; H1 "
                "gateway-survives-dead-upstream: gateway-rs (pid %d) stayed "
                "up and answered after each of %d inputs aimed at "
                "main.rs:30 and main.rs:34 and with the upstream closed "
                "(%s); both panic! calls are in main() before the accept "
                "loop, so a running gateway-rs takes no client input to "
                "them; stderr tail [%s]", (int)gw->pid, N_INPUTS, seen,
                tail);
    }

verdict:
    T_VERDICT(&res, "H1");

cleanup:
    cleanup_all();
    TEST_END;
}
