/** @file
 * @brief cwmp Group
 *
 * A TR-069 connection request against a tiny digest-authenticating
 * listener on the agent. A small python3 HTTP server is started on the
 * agent; tapi_cwmp_connection_request_code drives curl against it. With
 * the right credentials the CPE answers 200 (accepted); the control is a
 * wrong password, which must be rejected with 401.
 *
 * Copyright (C) 2026 Maxim Menshikov
 *
 * @author Maxim Menshikov <maximmenshchikov@gmail.com>
 */

#define TE_TEST_NAME    "cwmp/connection_request"

#include "te_config.h"
#include <stdlib.h>
#include <string.h>
#include "tapi_test.h"
#include "te_string.h"
#include "te_sleep.h"

#include "tsapi_mde.h"
#include "tsapi_mde_mi.h"

#include "tapi_cfg_base.h"
#include "tapi_file.h"
#include "tapi_job.h"

#include "tapi_cwmp_cr.h"

#define T_MS    30000
#define CR_PORT 18547
#define CR_USER "mde"
#define CR_PASS "mde-cr-pass"

/* A minimal RFC 2617 digest (qop=auth) HTTP listener. */
static const char cr_server_py[] =
"import sys, hashlib\n"
"from http.server import BaseHTTPRequestHandler, HTTPServer\n"
"USER='mde'; PASS='mde-cr-pass'; REALM='cwmp'; NONCE='mde-nonce-0123456789'\n"
"def parse(h):\n"
" d={}\n"
" for part in h[len('Digest '):].split(','):\n"
"  if '=' not in part: continue\n"
"  k,v=part.strip().split('=',1); d[k]=v.strip().strip('\"')\n"
" return d\n"
"def check(method, hdr):\n"
" if not hdr or not hdr.startswith('Digest '): return False\n"
" d=parse(hdr)\n"
" if d.get('username')!=USER: return False\n"
" ha1=hashlib.md5(('%s:%s:%s'%(USER,REALM,PASS)).encode()).hexdigest()\n"
" ha2=hashlib.md5(('%s:%s'%(method,d.get('uri',''))).encode()).hexdigest()\n"
" if d.get('qop'):\n"
"  r=hashlib.md5((':'.join([ha1,d.get('nonce',''),d.get('nc',''),"
"d.get('cnonce',''),d.get('qop'),ha2])).encode()).hexdigest()\n"
" else:\n"
"  r=hashlib.md5((':'.join([ha1,d.get('nonce',''),ha2])).encode())"
".hexdigest()\n"
" return r==d.get('response')\n"
"class H(BaseHTTPRequestHandler):\n"
" def _h(self,m):\n"
"  if check(m, self.headers.get('Authorization')):\n"
"   self.send_response(200)\n"
"  else:\n"
"   self.send_response(401)\n"
"   self.send_header('WWW-Authenticate','Digest realm=\"%s\", qop=\"auth\", "
"nonce=\"%s\"'%(REALM,NONCE))\n"
"  self.send_header('Content-Length','0'); self.end_headers()\n"
" def do_GET(self): self._h('GET')\n"
" def do_POST(self): self._h('POST')\n"
" def log_message(self,*a): pass\n"
"HTTPServer(('127.0.0.1',int(sys.argv[1])),H).serve_forever()\n";

int
main(int argc, char **argv)
{
    tsapi_mde_session   session;
    bool                session_up = false;
    char               *tmp_dir = NULL;
    te_string           script = TE_STRING_INIT;
    te_string           url = TE_STRING_INIT;
    tapi_job_t         *job = NULL;
    const char         *jargv[4];
    char                port_str[8];
    bool                ready = false;
    int                 code = 0;
    unsigned int        attempt;

    TEST_START;

    TEST_STEP("Open a session (the example need not be built)");
    CHECK_RC(tsapi_mde_session_init(&session, "cwmp_cr"));
    session_up = true;

    TEST_STEP("Skip unless python3 and curl are on the agent");
    if (!tsapi_mde_have(&session, "python3"))
        TEST_SKIP("There is no python3 on the agent to host the listener");
    if (!tsapi_mde_have(&session, "curl"))
        TEST_SKIP("There is no curl on the agent to send the request");

    TEST_STEP("Put the digest listener on the agent");
    tmp_dir = tapi_cfg_base_get_ta_dir(session.ta, TAPI_CFG_BASE_TA_DIR_TMP);
    if (tmp_dir == NULL)
        TEST_FAIL("Cannot find the agent's temporary directory");
    te_string_append(&script, "%s/mde-cwmp-cr.py", tmp_dir);
    CHECK_RC(tapi_file_create_ta(session.ta, script.ptr, "%s", cr_server_py));

    TEST_STEP("Start the listener");
    TE_SPRINTF(port_str, "%d", CR_PORT);
    jargv[0] = "python3";
    jargv[1] = script.ptr;
    jargv[2] = port_str;
    jargv[3] = NULL;
    CHECK_RC(tapi_job_create(session.factory, NULL, "python3", jargv, NULL,
                             &job));
    CHECK_RC(tapi_job_start(job));

    TEST_STEP("Wait until it answers with a digest challenge");
    te_string_append(&url, "http://127.0.0.1:%d/cwmp", CR_PORT);
    for (attempt = 0; attempt < 40 && !ready; attempt++)
    {
        tsapi_mde_sh_result sh = TSAPI_MDE_SH_RESULT_INIT;

        if (tsapi_mde_sh(&session, 10000, &sh,
                         "curl -s -o /dev/null -w '%%{http_code}' "
                         "--max-time 5 http://127.0.0.1:%d/cwmp",
                         CR_PORT) == 0 &&
            strncmp(te_string_value(&sh.out), "401", 3) == 0)
        {
            ready = true;
        }
        tsapi_mde_sh_result_free(&sh);
        if (!ready)
            te_msleep(250);
    }
    if (!ready)
        TEST_VERDICT("The connection-request listener never came up");

    TEST_STEP("The right credentials are accepted (200)");
    CHECK_RC(tapi_cwmp_connection_request_code(session.factory, url.ptr,
                                               CR_USER, CR_PASS, &code));
    RING("Connection request with the right password: HTTP %d", code);
    if (code != 200)
        TEST_VERDICT("A valid connection request was answered %d, not 200",
                     code);
    /* And the convenience wrapper agrees it was accepted. */
    CHECK_RC(tapi_cwmp_connection_request(session.factory, url.ptr, CR_USER,
                                          CR_PASS));

    TEST_STEP("A wrong password is rejected (401) - control");
    CHECK_RC(tapi_cwmp_connection_request_code(session.factory, url.ptr,
                                               CR_USER, "wrong-password",
                                               &code));
    RING("Connection request with a wrong password: HTTP %d", code);
    if (code != 401)
        TEST_VERDICT("A wrong password was answered %d, not 401", code);

    TEST_ARTIFACT("cwmp connection_request: right password -> 200, wrong "
                  "password -> 401 against a digest listener");

    TEST_STEP("Chart the two answers");
    {
        static const char *labels[2] = { "right_pw", "wrong_pw" };
        double             codes[2] = { 200.0, 401.0 };

        tsapi_mde_mi_bars("cwmp", "Connection-request HTTP codes",
                          TE_MI_MEAS_UNITLESS_VALUE, "http_code", 2,
                          (const char * const *)labels, codes,
                          TE_MI_MEAS_MULTIPLIER_PLAIN);
    }

    TEST_SUCCESS;

cleanup:

    if (job != NULL)
        tapi_job_destroy(job, -1);
    if (script.ptr != NULL)
        (void)tapi_file_ta_unlink_fmt(session.ta, "%s", script.ptr);
    free(tmp_dir);
    te_string_free(&script);
    te_string_free(&url);
    if (session_up)
        tsapi_mde_session_fini(&session);

    TEST_END;
}
