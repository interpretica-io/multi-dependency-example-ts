/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (C) 2026 midair <midair@localhost> */
/** @file
 * @brief Webdeps: t11_rust_panic, bad input to gateway-rs (settles H1)
 *
 * Start gateway-rs and check that a valid request gets 200. Then send
 * input aimed at the panic! of main.rs:30 (the lookup of the upstream in
 * the contract: a request that names another service, a request that is
 * not HTTP and one that has no query) and input aimed at the panic! of
 * main.rs:34 (the bind: an oversized request line and an oversized header,
 * and a second gateway-rs started on the same port, whose own bind fails).
 * After each input the test reads the exit status of the gateway process
 * and sends a valid request again.
 *
 * H1 CONFIRMED if the process exits or the second request fails. H1
 * DISPROVED for that input if the process stays up and answers. A gateway
 * that does not start, or that fails the first valid request, fails the
 * test with the reason "not started" and settles nothing.
 *
 * The setting at main.rs:30-34 is also set to an unset and an invalid
 * value, in builds of gateway-rs made from a copy of the table.
 *
 * Both panic! calls sit in main() before the accept loop, so no client
 * input can reach them while the gateway is running; the verdict says so
 * when it disproves H1.
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
    IN_OTHER_SVC, IN_NOT_HTTP, IN_EMPTY,        /* aimed at main.rs:30 */
    IN_BAD_PATH,                                /* 404 path in the handler */
    IN_BIG_LINE, IN_BIG_HEADER, IN_BIND,        /* aimed at main.rs:34 */
    N_INPUTS
};

static const struct {
    const char *name;
    unsigned    line;       /**< The panic! the input is aimed at. */
} in_info[N_INPUTS] = {
    { "a request that names another service", 30 },
    { "bytes that are not HTTP", 30 },
    { "an empty body", 30 },
    { "a bad path", 30 },
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
        case IN_OTHER_SVC:
            send_once(port, other, sizeof(other) - 1, false, 500);
            break;

        case IN_NOT_HTTP:
            send_once(port, junk, sizeof(junk) - 1, true, 500);
            break;

        case IN_BAD_PATH:
            send_once(port, badpath, sizeof(badpath) - 1, false, 500);
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
    int      i;

    TEST_START;

    TEST_STEP("Start gateway-rs and wait for its port");
    gw = svc_start_t(&res, "H1", GW);
    if (gw == NULL)
    {
        ERROR("gateway-rs did not start: %s", res.msg);
        goto verdict;
    }

    TEST_STEP("A valid request gets 200");
    http_get(gw->port, REQUEST, PROBE_TO, &h);
    RING("webdeps H1: GET %s -> %s, HTTP %d", REQUEST, hg_str(h.how),
         h.status);
    if (proc_gone(gw) || h.how != HG_OK || h.status != 200)
    {
        exit_code_str(gw, code, sizeof(code));
        file_tail(gw->err, tail, sizeof(tail));
        res_set(&res, R_SETUP, "H1 not started: gateway-rs did not answer "
                "the valid request with 200 (%s, HTTP %d, exit status %s; "
                "stderr tail [%s]); settles nothing", hg_str(h.how),
                h.status, code, tail);
        goto verdict;
    }

    for (i = 0; i < N_INPUTS; i++)
    {
        bool gone;

        TEST_STEP("Send %s (aimed at main.rs:%u) and read the exit status",
                  in_info[i].name, in_info[i].line);
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
            gw->stopped = true;
            ERROR("webdeps H1: gateway-rs gone after %s: exit status %s, "
                  "stderr tail [%s]", in_info[i].name, code, tail);
            T_FINDING(TAPI_CYBERSEC_SEV_HIGH, "gateway.exited",
                      in_info[i].name, "exit status %s; stderr tail [%s]",
                      code, tail);
            res_set(&res, R_FAIL, "H1 CONFIRMED: gateway-rs %s after %s "
                    "(aimed at main.rs:%u): exit status %s; stderr tail "
                    "[%s]", WIFSIGNALED(gw->status) ||
                    WEXITSTATUS(gw->status) == 101 ? "panicked" : "exited",
                    in_info[i].name, in_info[i].line, code, tail);
            goto verdict;
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
            exit_code_str(gw, code, sizeof(code));
            file_tail(gw->err, tail, sizeof(tail));
            ERROR("webdeps H1: after %s: exit status %s, stderr tail [%s]",
                  in_info[i].name, code, tail);
            res_set(&res, R_FAIL, "H1 CONFIRMED: after %s (aimed at "
                    "main.rs:%u) the next valid request %s (HTTP %d); exit "
                    "status %s; stderr tail [%s]", in_info[i].name,
                    in_info[i].line, hg_str(h.how), h.status, code, tail);
            goto verdict;
        }
    }

    TEST_STEP("Start gateway-rs with its setting unset or invalid");
    {
        char bnote[1000] = "";

        bad_setting(&res, bnote, sizeof(bnote));
        if (res.kind == R_SETUP)
            goto verdict;
        if (strstr(bnote, "process ended") != NULL)
        {
            res_set(&res, R_FAIL, "H1 CONFIRMED: gateway-rs with the "
                    "setting at main.rs:30 unset or invalid does not stay "
                    "up (panic! at main.rs:30): %s", bnote);
            goto verdict;
        }
    }

    file_tail(gw->err, tail, sizeof(tail));
    res_set(&res, R_PASS, "H1 DISPROVED for these inputs: gateway-rs (pid "
            "%d) stayed up with no exit status and answered 200 after each "
            "of %d inputs aimed at main.rs:30 and main.rs:34 (%s); both "
            "panic! calls are in main() before the accept loop, so a "
            "running gateway-rs takes no client input to them; stderr tail "
            "[%s]", (int)gw->pid, N_INPUTS, seen, tail);

verdict:
    T_VERDICT(&res, "H1");

cleanup:
    cleanup_all();
    TEST_END;
}
