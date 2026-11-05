/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (C) 2026 Maxim Menshikov */
/** @file
 * @brief Webdeps group helpers
 *
 * The tests of the group settle H1, H2 and H3 about the dependencies
 * between gateway-rs, service-go and service-cs. They all work the same
 * way: the binaries are started from the built artifacts as plain
 * processes of the agent (so their pid, exit status and stderr are
 * known), readiness is polled on the TCP ports found in the process
 * listing (the socket inodes of /proc/PID/fd joined with /proc/net/tcp),
 * and peers are replaced with throw-away loopback stubs.
 *
 * The agent side is one shell script and one python stub, both written
 * to /tmp/mde-wd by wd_install(). Static inline only: each test is built
 * from a single .c file.
 *
 * Every test ends with an explicit verdict: WD_PASS() or WD_FAIL(), each
 * naming the hypothesis it settles. A test without a verdict is a harness
 * error, so nothing in the group skips or stops silently.
 *
 * @author Maxim Menshikov <maximmenshchikov@gmail.com>
 */

#ifndef __WEBDEPS_COMMON_H__
#define __WEBDEPS_COMMON_H__

#include <stdarg.h>
#include <stdio.h>
#include <unistd.h>

#include "../web/web_common.h"
#include "../exposure/exposure_common.h"

/** Services of the tier, in contract order. */
enum {
    WD_GW = 0,  /**< gateway-rs. */
    WD_GO,      /**< service-go. */
    WD_CS,      /**< service-cs. */
    WD_N,       /**< Number of services. */
};

/** Peer each service calls (services.tab upstream column). */
static const unsigned int wd_peer[WD_N] = { WD_GO, WD_CS, WD_GW };

/** Service names. */
static const char * const wd_names[WD_N] = {
    "gateway-rs", "service-go", "service-cs",
};

/** Working directory on the agent. */
#define WD_DIR  "/tmp/mde-wd"

/** Agent-side helper script. */
#define WD_SCRIPT \
    "D=" WD_DIR "\n"                                                         \
    "ports() {\n"                                                            \
    "  for f in /proc/$1/fd/*; do\n"                                         \
    "    l=$(readlink \"$f\" 2>/dev/null) || continue\n"                     \
    "    case $l in \"socket:[\"*) i=${l#socket:[}; i=${i%]}\n"              \
    "      awk -v i=\"$i\" '$4==\"0A\" && $10==i {print $2}' "               \
    "/proc/net/tcp /proc/net/tcp6;;\n"                                       \
    "    esac\n"                                                             \
    "  done | while IFS=: read a p; do printf '%s %d\\n' \"$a\" \"0x$p\"; "  \
    "done\n"                                                                 \
    "}\n"                                                                    \
    "case $1 in\n"                                                           \
    "launch)\n"                                                              \
    "  n=$2; mkdir -p \"$D\"\n"                                              \
    "  rm -f \"${D:?}/${n:?}.pid\" \"$D/$n.rc\" \"$D/$n.out\" "              \
    "\"$D/$n.err\"\n"                                                        \
    "  setsid sh -c \"$3 >$D/$n.out 2>$D/$n.err </dev/null & "               \
    "echo \\$! >$D/$n.pid; wait \\$!; echo \\$? >$D/$n.rc\" "               \
    ">/dev/null 2>&1 </dev/null &\n"                                         \
    "  i=0; while [ ! -s \"$D/$n.pid\" ] && [ $i -lt 50 ]; do "              \
    "i=$((i+1)); sleep 0.1; done\n"                                          \
    "  cat \"$D/$n.pid\";;\n"                                                \
    "ports) ports $2;;\n"                                                    \
    "wait)\n"                                                                \
    "  i=0\n"                                                                \
    "  while [ $i -lt $3 ]; do\n"                                            \
    "    kill -0 $2 2>/dev/null || { echo dead; exit 2; }\n"                 \
    "    p=$(ports $2 | head -n 1)\n"                                        \
    "    [ -n \"$p\" ] && { echo \"$p\"; exit 0; }\n"                        \
    "    i=$((i+1)); sleep 0.1\n"                                            \
    "  done\n"                                                               \
    "  echo timeout; exit 1;;\n"                                             \
    "state)\n"                                                               \
    "  pid=$(cat \"$D/$2.pid\" 2>/dev/null)\n"                               \
    "  if [ -n \"$pid\" ] && kill -0 $pid 2>/dev/null && "                   \
    "[ ! -e \"$D/$2.rc\" ]; then echo alive\n"                               \
    "  else sleep 0.2; echo \"dead $(cat \"$D/$2.rc\" 2>/dev/null)\"; "      \
    "fi;;\n"                                                                 \
    "stop)\n"                                                                \
    "  pid=$(cat \"$D/$2.pid\" 2>/dev/null); [ -n \"$pid\" ] || exit 0\n"    \
    "  kill $pid 2>/dev/null; i=0\n"                                         \
    "  while kill -0 $pid 2>/dev/null && [ $i -lt 30 ]; do "                 \
    "i=$((i+1)); sleep 0.1; done\n"                                          \
    "  kill -9 $pid 2>/dev/null; exit 0;;\n"                                 \
    "sockets)\n"                                                             \
    "  shift\n"                                                              \
    "  for pid in \"$@\"; do for f in /proc/$pid/fd/*; do\n"                 \
    "    l=$(readlink \"$f\" 2>/dev/null) || continue\n"                     \
    "    case $l in \"socket:[\"*) i=${l#socket:[}; echo ${i%]};; esac\n"    \
    "  done; done;;\n"                                                       \
    "esac\n"

/**
 * Stub peer: listens on 127.0.0.1:PORT and misbehaves per mode.
 * argv: mode port logfile (a line per accepted connection).
 */
#define WD_STUB_PY \
    "import socket, struct, sys, threading, time\n"                          \
    "mode, port, log = sys.argv[1], int(sys.argv[2]), sys.argv[3]\n"         \
    "srv = socket.socket()\n"                                                \
    "srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)\n"            \
    "srv.bind(('127.0.0.1', port))\n"                                        \
    "srv.listen(16)\n"                                                       \
    "def serve(c):\n"                                                        \
    "    try:\n"                                                             \
    "        open(log, 'a').write('c\\n')\n"                                 \
    "        if mode == 'silent':\n"                                         \
    "            time.sleep(3600)\n"                                         \
    "            return\n"                                                   \
    "        c.settimeout(2)\n"                                              \
    "        try:\n"                                                         \
    "            c.recv(65536)\n"                                            \
    "        except Exception:\n"                                            \
    "            pass\n"                                                     \
    "        if mode == 'reset':\n"                                          \
    "            c.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, "         \
    "struct.pack('ii', 1, 0))\n"                                             \
    "        elif mode == 'empty':\n"                                        \
    "            c.sendall(b'HTTP/1.1 200 OK\\r\\nContent-Length: 0\\r\\n"   \
    "Connection: close\\r\\n\\r\\n')\n"                                      \
    "        elif mode == 'garbage':\n"                                      \
    "            c.sendall(b'HTTP/1.1 200 OK\\r\\nContent-Length: 21\\r\\n"  \
    "Connection: close\\r\\n\\r\\n\\x00\\xff<not json> {{{ \\xfe\\x01 #')\n" \
    "        elif mode == 'http500':\n"                                      \
    "            c.sendall(b'HTTP/1.1 500 Internal Server Error\\r\\n"       \
    "Content-Length: 4\\r\\nConnection: close\\r\\n\\r\\nboom')\n"           \
    "    except Exception:\n"                                                \
    "        pass\n"                                                         \
    "    finally:\n"                                                         \
    "        c.close()\n"                                                    \
    "while True:\n"                                                          \
    "    c, _ = srv.accept()\n"                                              \
    "    threading.Thread(target=serve, args=(c,), daemon=True).start()\n"

/** Session, example, tier and whatever the test started. */
typedef struct wd_ctx {
    tsapi_mde_session session;      /**< Session on the agent. */
    tsapi_mde_dut     dut;          /**< Example. */
    bool              session_up;   /**< Session needs closing. */
    unsigned int      pid[WD_N];    /**< Pids of the services, 0 if none. */
    unsigned int      port[WD_N];   /**< Listening ports found for them. */
    unsigned int      stub_pid[WD_N]; /**< Stub standing in for a service. */
} wd_ctx;

/** Initializer of #wd_ctx. */
#define WD_CTX_INIT { .session = { .ta = NULL }, .dut = { .root = NULL } }

/** Run a command on the agent, @c true if it exited with 0. */
static inline bool
wd_sh(wd_ctx *ctx, int timeout_ms, te_string *out, const char *fmt, ...)
    TE_LIKE_PRINTF(4, 5);

static inline bool
wd_sh(wd_ctx *ctx, int timeout_ms, te_string *out, const char *fmt, ...)
{
    tsapi_mde_sh_result res = TSAPI_MDE_SH_RESULT_INIT;
    te_string           cmd = TE_STRING_INIT;
    va_list             ap;
    bool                ok;

    va_start(ap, fmt);
    te_string_append_va(&cmd, fmt, ap);
    va_end(ap);

    ok = tsapi_mde_sh(&ctx->session, timeout_ms, &res, "%s", cmd.ptr) == 0 &&
         tsapi_mde_sh_ok(&res);
    if (out != NULL)
        te_string_append(out, "%s", te_string_value(&res.out));
    tsapi_mde_sh_result_free(&res);
    te_string_free(&cmd);

    return ok;
}

/** Strip trailing whitespace of a string in place. */
static inline void
wd_chomp(te_string *s)
{
    while (s->len > 0 && (s->ptr[s->len - 1] == '\n' ||
                          s->ptr[s->len - 1] == ' '))
        s->ptr[--s->len] = '\0';
}

/** Write the helper script and the stub to the agent. */
static inline bool
wd_install(wd_ctx *ctx)
{
    return wd_sh(ctx, 20000, NULL, "mkdir -p " WD_DIR " && "
                 "cat > " WD_DIR "/wd.sh <<'WDEOF'\n%sWDEOF\n"
                 "cat > " WD_DIR "/stub.py <<'WDEOF'\n%sWDEOF\n",
                 WD_SCRIPT, WD_STUB_PY);
}

/**
 * Open the session and locate the example. Neither failing nor an
 * unbuilt example skips: the caller turns @c false into a FAIL verdict.
 *
 * @param[in]  ctx      Context.
 * @param[in]  name     RPC server name.
 * @param[out] why      Reason.
 */
static inline bool
wd_open(wd_ctx *ctx, const char *name, te_string *why)
{
    te_errno rc = tsapi_mde_session_init(&ctx->session, name);

    if (rc != 0)
    {
        te_string_append(why, "cannot open a session on the agent: %r", rc);
        return false;
    }
    ctx->session_up = true;

    rc = tsapi_mde_dut_open(&ctx->session, &ctx->dut);
    if (rc != 0)
    {
        te_string_append(why, "the example is not built (%r)", rc);
        return false;
    }
    if (!tsapi_mde_web_built(&ctx->session, &ctx->dut))
    {
        te_string_append(why, "gateway-rs, service-go or service-cs is "
                         "missing from %s", ctx->dut.bin);
        return false;
    }
    if (!tsapi_mde_have(&ctx->session, "curl") ||
        !tsapi_mde_have(&ctx->session, "python3"))
    {
        te_string_append(why, "curl or python3 is not available on the "
                         "agent");
        return false;
    }
    if (!wd_install(ctx))
    {
        te_string_append(why, "cannot write the helpers to " WD_DIR);
        return false;
    }

    return true;
}

/** Agent-side process key of the stub of a service. */
#define WD_STUB_KEY(_i) ((_i) == WD_GW ? "stub-gw" : \
                         (_i) == WD_GO ? "stub-go" : "stub-cs")

/** Start a process of the agent under a key; its pid, 0 on failure. */
static inline unsigned int
wd_launch(wd_ctx *ctx, const char *key, const char *cmd)
{
    te_string    out = TE_STRING_INIT;
    unsigned int pid = 0;

    if (wd_sh(ctx, 20000, &out, "sh " WD_DIR "/wd.sh launch '%s' '%s'", key,
              cmd))
        pid = (unsigned int)strtoul(te_string_value(&out), NULL, 10);
    te_string_free(&out);

    return pid;
}

/**
 * Wait until a process listens, taking the port from the process
 * listing.
 *
 * @param[in]  ctx      Context.
 * @param[in]  pid      Pid.
 * @param[in]  tenths   How long to poll, in 0.1 s.
 * @param[out] port     First listening port.
 * @param[out] why      Reason when it does not (dead / timeout).
 */
static inline bool
wd_wait_port(wd_ctx *ctx, unsigned int pid, unsigned int tenths,
             unsigned int *port, te_string *why)
{
    te_string    out = TE_STRING_INIT;
    char         addr[64] = "";
    unsigned int p = 0;
    bool         ok;

    ok = wd_sh(ctx, tenths * 100 + 20000, &out, "sh " WD_DIR "/wd.sh wait "
               "%u %u", pid, tenths) &&
         sscanf(te_string_value(&out), "%63s %u", addr, &p) == 2;
    if (ok)
    {
        *port = p;
    }
    else
    {
        wd_chomp(&out);
        te_string_append(why, "%s", out.len > 0 ? out.ptr : "no answer");
    }
    te_string_free(&out);

    return ok;
}

/** Process state: alive, or the exit status (128+N for a signal N). */
static inline bool
wd_alive(wd_ctx *ctx, const char *key, int *rc)
{
    te_string out = TE_STRING_INIT;
    bool      alive;

    *rc = -1;
    if (!wd_sh(ctx, 20000, &out, "sh " WD_DIR "/wd.sh state '%s'", key))
    {
        te_string_free(&out);
        return false;
    }
    alive = strncmp(te_string_value(&out), "alive", 5) == 0;
    if (!alive)
        sscanf(te_string_value(&out), "dead %d", rc);
    te_string_free(&out);

    return alive;
}

/** Stop a process by key. */
static inline void
wd_stop(wd_ctx *ctx, const char *key)
{
    (void)wd_sh(ctx, 20000, NULL, "sh " WD_DIR "/wd.sh stop '%s'", key);
}

/** Append the first bytes of stdout or stderr of a process, on one line. */
static inline void
wd_output(wd_ctx *ctx, const char *key, const char *stream, te_string *out)
{
    (void)wd_sh(ctx, 20000, out, "head -c 300 " WD_DIR "/%s.%s | tr '\\n\"' "
                "\"  \"", key, stream);
}

/** Whether the stderr of a process contains a text. */
static inline bool
wd_err_has(wd_ctx *ctx, const char *key, const char *text)
{
    return wd_sh(ctx, 20000, NULL, "grep -q '%s' " WD_DIR "/%s.err", text,
                 key);
}

/**
 * Start one service from the built artifacts and wait until it listens.
 *
 * @param[in]  ctx  Context.
 * @param[in]  idx  Service.
 * @param[out] why  Reason when it does not.
 */
static inline bool
wd_start_svc(wd_ctx *ctx, unsigned int idx, te_string *why)
{
    te_string cmd = TE_STRING_INIT;
    bool      ok = false;

    te_string_append(&cmd, "%s/%s", ctx->dut.bin, wd_names[idx]);
    ctx->pid[idx] = wd_launch(ctx, wd_names[idx], cmd.ptr);
    if (ctx->pid[idx] == 0)
    {
        te_string_append(why, "%s could not be launched", wd_names[idx]);
        goto out;
    }

    if (!wd_wait_port(ctx, ctx->pid[idx], 150, &ctx->port[idx], why))
    {
        te_string_append(why, " - %s is not listening; stderr: ",
                         wd_names[idx]);
        wd_output(ctx, wd_names[idx], "err", why);
        goto out;
    }
    ok = true;

out:
    te_string_free(&cmd);
    return ok;
}

/** Stop one service. */
static inline void
wd_stop_svc(wd_ctx *ctx, unsigned int idx)
{
    if (ctx->pid[idx] != 0)
        wd_stop(ctx, wd_names[idx]);
    ctx->pid[idx] = 0;
}

/**
 * Start the three binaries, and wait for each to listen on a port taken
 * from the process listing.
 */
static inline bool
wd_start_all(wd_ctx *ctx, te_string *why)
{
    unsigned int i;

    for (i = 0; i < WD_N; i++)
    {
        if (!wd_start_svc(ctx, i, why))
            return false;
    }

    return true;
}

/** Stop all services and all stubs. */
static inline void
wd_stop_all(wd_ctx *ctx)
{
    unsigned int i;

    for (i = 0; i < WD_N; i++)
    {
        wd_stop_svc(ctx, i);
        if (ctx->stub_pid[i] != 0)
            wd_stop(ctx, WD_STUB_KEY(i));
        ctx->stub_pid[i] = 0;
    }
}

/**
 * Learn the ports of the tier: start the three binaries, read the
 * listening ports of each from the process listing, stop them again.
 * The ports come from what the processes hold, not from a constant.
 */
static inline bool
wd_learn_ports(wd_ctx *ctx, te_string *why)
{
    bool         ok = wd_start_all(ctx, why);
    unsigned int i;

    for (i = 0; ok && i < WD_N; i++)
        TEST_ARTIFACT("%s pid %u listens on port %u", wd_names[i],
                      ctx->pid[i], ctx->port[i]);
    for (i = 0; i < WD_N; i++)
        wd_stop_svc(ctx, i);

    return ok;
}

/**
 * Put a stub in place of a service: it listens on that service's port.
 *
 * @param[in] idx   Service to replace.
 * @param[in] mode  empty, garbage, reset, silent, http500 or close.
 * @param[in] log   File that gets a line per accepted connection.
 */
static inline bool
wd_stub_start(wd_ctx *ctx, unsigned int idx, const char *mode,
              const char *log)
{
    te_string    cmd = TE_STRING_INIT;
    te_string    why = TE_STRING_INIT;
    unsigned int port = 0;
    bool         ok = false;

    (void)wd_sh(ctx, 10000, NULL, "rm -f '%s'; : > '%s'", log, log);
    te_string_append(&cmd, "python3 " WD_DIR "/stub.py %s %u %s", mode,
                     ctx->port[idx], log);
    ctx->stub_pid[idx] = wd_launch(ctx, WD_STUB_KEY(idx), cmd.ptr);
    if (ctx->stub_pid[idx] != 0)
        ok = wd_wait_port(ctx, ctx->stub_pid[idx], 50, &port, &why) &&
             port == ctx->port[idx];
    te_string_free(&cmd);
    te_string_free(&why);

    return ok;
}

/** Stop the stub of a service. */
static inline void
wd_stub_stop(wd_ctx *ctx, unsigned int idx)
{
    if (ctx->stub_pid[idx] != 0)
        wd_stop(ctx, WD_STUB_KEY(idx));
    ctx->stub_pid[idx] = 0;
}

/** Number of connections a stub has accepted. */
static inline unsigned int
wd_stub_hits(wd_ctx *ctx, const char *log)
{
    te_string    out = TE_STRING_INIT;
    unsigned int n = 0;

    if (wd_sh(ctx, 10000, &out, "wc -l < '%s'", log))
        n = (unsigned int)strtoul(te_string_value(&out), NULL, 10);
    te_string_free(&out);

    return n;
}

/**
 * GET a path on a port of the loopback.
 *
 * @param[in]  port     Port.
 * @param[in]  path     Path with query.
 * @param[in]  secs     curl --max-time.
 * @param[out] reply    Reply; code 0 is a transport error or a timeout.
 */
static inline bool
wd_get(wd_ctx *ctx, unsigned int port, const char *path, int secs,
       web_reply *reply)
{
    te_string url = TE_STRING_INIT;
    bool      ok;

    te_string_append(&url, "http://127.0.0.1:%u%s", port, path);
    ok = web_get(&ctx->session, "", url.ptr, secs, reply) == 0;
    te_string_free(&url);

    return ok;
}

/** Whether a status is 2xx. */
#define WD_IS_2XX(_code) ((_code) >= 200 && (_code) < 300)

/** Whether a reply took (nearly) all of the time allowed. */
#define WD_TIMED_OUT(_reply, _secs) \
    ((_reply)->code == 0 && (_reply)->time_s >= (_secs) - 0.2)

/**
 * Whether a body reports a failure explicitly: an "error" field or an
 * "error" line, not just prose about an upstream.
 */
static inline bool
wd_body_has_error_field(const char *body)
{
    return strstr(body, "\"error\"") != NULL ||
           strncmp(body, "error", 5) == 0 || strstr(body, "\nerror") != NULL;
}

/** Shorten a body for a verdict: its first line, quotes removed. */
static inline void
wd_snippet(const te_string *body, char *buf, size_t len)
{
    size_t i;

    snprintf(buf, len, "%.60s", web_str(body));
    for (i = 0; buf[i] != '\0'; i++)
    {
        if (buf[i] == '\n')
        {
            buf[i] = '\0';
            break;
        }
        if (buf[i] == '"' || buf[i] == '%')
            buf[i] = '\'';
    }
}

/** Release the context. */
static inline void
wd_close(wd_ctx *ctx)
{
    if (ctx->session_up)
        wd_stop_all(ctx);
    tsapi_mde_dut_free(&ctx->dut);
    if (ctx->session_up)
        tsapi_mde_session_fini(&ctx->session);
}

/** Pass: an explicit PASS verdict naming the hypothesis (literals). */
#define WD_PASS(_test, _hyp, _fmt...) \
    RING_VERDICT("PASS " _test " [" _hyp "]: " _fmt)

/** Fail: an explicit FAIL verdict naming the hypothesis; stops the test. */
#define WD_FAIL(_test, _hyp, _fmt...) \
    do {                                                                 \
        ERROR_VERDICT("FAIL " _test " [" _hyp "]: " _fmt);               \
        TEST_STOP;                                                       \
    } while (0)

/** Open the context or fail on the hypothesis the test serves. */
#define WD_OPEN(_ctx, _test, _hyp) \
    do {                                                                 \
        te_string why_ = TE_STRING_INIT;                                 \
                                                                         \
        if (!wd_open(&(_ctx), _test, &why_))                             \
        {                                                                \
            ERROR_VERDICT("FAIL %s [%s]: %s", _test, _hyp, why_.ptr);    \
            te_string_free(&why_);                                       \
            TEST_STOP;                                                   \
        }                                                                \
        te_string_free(&why_);                                           \
    } while (0)

/** Learn the ports from the three binaries or fail on the hypothesis. */
#define WD_LEARN(_ctx, _test, _hyp) \
    do {                                                                 \
        te_string why_ = TE_STRING_INIT;                                 \
                                                                         \
        if (!wd_learn_ports(&(_ctx), &why_))                             \
        {                                                                \
            ERROR_VERDICT("FAIL %s [%s]: a binary failed to start: %s",  \
                          _test, _hyp, why_.ptr);                        \
            te_string_free(&why_);                                       \
            TEST_STOP;                                                   \
        }                                                                \
        te_string_free(&why_);                                           \
    } while (0)

/** Start one service or fail on the hypothesis, with the reason. */
#define WD_START(_ctx, _idx, _test, _hyp) \
    do {                                                                 \
        te_string why_ = TE_STRING_INIT;                                 \
                                                                         \
        if (!wd_start_svc(&(_ctx), _idx, &why_))                         \
        {                                                                \
            ERROR_VERDICT("FAIL %s [%s]: %s failed to start: %s", _test, \
                          _hyp, wd_names[_idx], why_.ptr);               \
            te_string_free(&why_);                                       \
            TEST_STOP;                                                   \
        }                                                                \
        te_string_free(&why_);                                           \
    } while (0)

/** GET or fail on the hypothesis when curl itself cannot be run. */
#define WD_GET(_ctx, _port, _path, _secs, _reply, _test, _hyp) \
    do {                                                                 \
        if (!wd_get(&(_ctx), _port, _path, _secs, &(_reply)))            \
            WD_FAIL(_test, _hyp, "cannot run curl on the agent");        \
    } while (0)

#endif /* !__WEBDEPS_COMMON_H__ */
