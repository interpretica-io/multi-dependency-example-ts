/** @file
 * @brief TLS Group
 *
 * Helpers shared by the tests of the tls group: a long-running process on
 * the agent that announces when it is ready, the TLS front put before
 * gateway-rs, and small certificate facts read with openssl on the agent.
 * Static inline only - every test is one C file.
 *
 * Copyright (C) 2026 Maxim Menshikov
 *
 * @author Maxim Menshikov <maximmenshchikov@gmail.com>
 */

#ifndef __MDE_TLS_COMMON_H__
#define __MDE_TLS_COMMON_H__

#include "te_config.h"

#include <stdlib.h>
#include <string.h>

#include "logger_api.h"
#include "te_defs.h"
#include "te_errno.h"
#include "te_string.h"
#include "tapi_job.h"
#include "tapi_tls.h"
#include "tsapi_mde.h"

/** Timeout of one openssl/curl run on the agent, ms. */
#define MDE_TLS_TIMEOUT_MS  60000

/** Timeout of one s_client attempt in a scan, ms. */
#define MDE_TLS_PROBE_MS    3000

/** A long-running process of a test. */
typedef struct mde_tls_bg {
    tapi_job_t         *job;    /**< The process. */
    tapi_job_channel_t *out[2]; /**< stdout, stderr. */
    tapi_job_channel_t *ready;  /**< Readable filter for the ready line. */
} mde_tls_bg;

/**
 * Start a process and wait until it prints a line matching @p ready_re on
 * stdout or stderr.
 *
 * @param session       Session.
 * @param argv          @c NULL-terminated argv; argv[0] is the program.
 * @param ready_re      Ready line regexp.
 * @param timeout_ms    How long to wait for it.
 * @param bg            Process; stop with mde_tls_bg_stop() whatever this
 *                      returns.
 *
 * @return Status code.
 */
static inline te_errno
mde_tls_bg_start(tsapi_mde_session *session, const char **argv,
                 const char *ready_re, int timeout_ms, mde_tls_bg *bg)
{
    tapi_job_buffer_t buf = TAPI_JOB_BUFFER_INIT;
    te_errno          rc;

    memset(bg, 0, sizeof(*bg));

    rc = tapi_job_create(session->factory, NULL, argv[0], argv, NULL,
                         &bg->job);
    if (rc != 0)
        return rc;

    rc = tapi_job_alloc_output_channels(bg->job, 2, bg->out);
    if (rc == 0)
    {
        rc = tapi_job_attach_filter(TAPI_JOB_CHANNEL_SET(bg->out[0],
                                                         bg->out[1]),
                                    "bg", false, TE_LL_RING, NULL);
    }
    if (rc == 0)
    {
        rc = tapi_job_attach_filter(TAPI_JOB_CHANNEL_SET(bg->out[0],
                                                         bg->out[1]),
                                    "ready", true, 0, &bg->ready);
    }
    if (rc == 0)
        rc = tapi_job_filter_add_regexp(bg->ready, ready_re, 0);
    if (rc == 0)
        rc = tapi_job_start(bg->job);
    if (rc == 0)
    {
        rc = tapi_job_receive(TAPI_JOB_CHANNEL_SET(bg->ready), timeout_ms,
                              &buf);
        if (rc != 0)
        {
            ERROR("'%s' did not become ready: %r", argv[0], rc);
            rc = TE_RC(TE_TAPI, TE_EFAIL);
        }
    }

    te_string_free(&buf.data);

    return rc;
}

/**
 * Stop a process started by mde_tls_bg_start().
 *
 * @param bg    Process.
 */
static inline void
mde_tls_bg_stop(mde_tls_bg *bg)
{
    if (bg->job != NULL)
    {
        tapi_job_destroy(bg->job, -1);
        bg->job = NULL;
    }
}

/**
 * A TLS terminator for gateway-rs: python3 ssl, TLS 1.2 at least,
 * forwarding each connection to the plain HTTP port.
 *
 * argv: port cert key upstream_port.
 */
static inline const char *
mde_tls_front_script(void)
{
    return
"import socket, ssl, sys, threading\n"
"PORT = int(sys.argv[1])\n"
"UP = int(sys.argv[4])\n"
"ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)\n"
"ctx.minimum_version = ssl.TLSVersion.TLSv1_2\n"
"ctx.load_cert_chain(sys.argv[2], sys.argv[3])\n"
"srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)\n"
"srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)\n"
"srv.bind(('127.0.0.1', PORT))\n"
"srv.listen(64)\n"
"print('MDE_TLS_FRONT_READY %d' % PORT, flush=True)\n"
"\n"
"def pump(src, dst):\n"
"    try:\n"
"        while True:\n"
"            data = src.recv(65536)\n"
"            if not data:\n"
"                break\n"
"            dst.sendall(data)\n"
"    except Exception:\n"
"        pass\n"
"    for s in (src, dst):\n"
"        try:\n"
"            s.close()\n"
"        except Exception:\n"
"            pass\n"
"\n"
"def serve(conn):\n"
"    try:\n"
"        tls = ctx.wrap_socket(conn, server_side=True)\n"
"    except Exception as e:\n"
"        print('MDE_TLS_FRONT_REFUSED %s' % e.__class__.__name__,\n"
"              flush=True)\n"
"        conn.close()\n"
"        return\n"
"    try:\n"
"        up = socket.create_connection(('127.0.0.1', UP))\n"
"    except Exception:\n"
"        tls.close()\n"
"        return\n"
"    threading.Thread(target=pump, args=(up, tls), daemon=True).start()\n"
"    pump(tls, up)\n"
"\n"
"while True:\n"
"    conn, _ = srv.accept()\n"
"    threading.Thread(target=serve, args=(conn,), daemon=True).start()\n";
}

/**
 * Seconds from now until a certificate file on the agent expires, read
 * with openssl x509 -enddate and GNU date.
 *
 * @param[in]  session  Session.
 * @param[in]  path     Certificate file on the agent.
 * @param[out] seconds  Seconds left (negative once expired).
 *
 * @return @c true if it could be read.
 */
static inline bool
mde_tls_cert_seconds_left(tsapi_mde_session *session, const char *path,
                          double *seconds)
{
    tsapi_mde_sh_result res = TSAPI_MDE_SH_RESULT_INIT;
    char               *end = NULL;
    const char         *text;
    bool                ok = false;

    if (tsapi_mde_sh(session, MDE_TLS_TIMEOUT_MS, &res,
                     "e=$(openssl x509 -in '%s' -noout -enddate | "
                     "cut -d= -f2) && "
                     "echo $(( $(date -u -d \"$e\" +%%s) - $(date -u +%%s) ))",
                     path) == 0 && tsapi_mde_sh_ok(&res))
    {
        text = te_string_value(&res.out);
        *seconds = strtod(text, &end);
        ok = end != text;
    }
    tsapi_mde_sh_result_free(&res);

    return ok;
}

/**
 * SHA-256 of the DER form of a certificate file on the agent, as lowercase
 * hex without separators.
 *
 * @param[in]  session  Session.
 * @param[in]  path     Certificate file on the agent.
 * @param[out] hex      String to append the digest to.
 *
 * @return @c true if it could be computed.
 */
static inline bool
mde_tls_cert_der_sha256(tsapi_mde_session *session, const char *path,
                        te_string *hex)
{
    tsapi_mde_sh_result res = TSAPI_MDE_SH_RESULT_INIT;
    bool                ok = false;

    if (tsapi_mde_sh(session, MDE_TLS_TIMEOUT_MS, &res,
                     "openssl x509 -in '%s' -outform DER | sha256sum | "
                     "cut -d' ' -f1", path) == 0 && tsapi_mde_sh_ok(&res))
    {
        const char *text = te_string_value(&res.out);
        size_t      len = strspn(text, "0123456789abcdef");

        if (len == 64)
        {
            te_string_append(hex, "%.64s", text);
            ok = true;
        }
    }
    tsapi_mde_sh_result_free(&res);

    return ok;
}

/**
 * Normalise an OpenSSL fingerprint ("AB:CD:...") to lowercase hex without
 * separators.
 *
 * @param fp    Fingerprint as OpenSSL prints it.
 * @param hex   String to append to.
 */
static inline void
mde_tls_fp_normalise(const char *fp, te_string *hex)
{
    for (; fp != NULL && *fp != '\0'; fp++)
    {
        char c = *fp;

        if (c >= 'A' && c <= 'F')
            c = (char)(c - 'A' + 'a');
        if ((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))
            te_string_append(hex, "%c", c);
    }
}

/** Number of versions a scan tries (SSLv3 .. TLSv1.3). */
#define MDE_TLS_N_VERSIONS  5

/**
 * The i-th version a scan tries, oldest first.
 *
 * @param i     Index below #MDE_TLS_N_VERSIONS.
 *
 * @return Version.
 */
static inline tapi_tls_version
mde_tls_version_at(unsigned int i)
{
    return (tapi_tls_version)(TAPI_TLS_VERSION_SSL3 + i);
}

#endif /* !__MDE_TLS_COMMON_H__ */
