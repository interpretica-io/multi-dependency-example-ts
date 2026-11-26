/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (C) 2026 midair <midair@localhost> */
/** @file
 * @brief ts_example: run one reference demo alone and keep what it did
 *
 * Every reference (C++, Rust, Python, Go, C#) is started on its own, in its
 * own process group, with stdin closed, stdout and stderr in separate files,
 * and a time limit. A small Python helper records the exit code, the signal
 * that ended it and whether the limit was reached, so that a crash is told
 * apart from an exit code. The helpers here count the stage lines, find the
 * last stage line and the final value, and write the text of a verdict that
 * names the language, the signal and the last stage reached.
 *
 * @author midair <midair@localhost>
 */

#ifndef MDE_TSR_H
#define MDE_TSR_H

#include "tsd.h"

#define TSR_NREF    5
#define TSR_HELPER  "/tmp/ts_refrun.py"

/** The five references: name, file checked in the project, program. */
static const struct {
    const char *name;
    const char *file;
    const char *prog;       /**< program and fixed arguments, from the project */
} tsr_refs[TSR_NREF] = {
    { "cpp-demo",    "dist/bin/cpp-demo",    "./dist/bin/cpp-demo" },
    { "rust-demo",   "dist/bin/rust-demo",   "./dist/bin/rust-demo" },
    { "python-demo", "python/demo.py",       "python3 python/demo.py" },
    { "go-demo",     "dist/bin/go-demo",     "./dist/bin/go-demo" },
    { "cs-demo",     "dist/bin/cs-demo",     "./dist/bin/cs-demo" },
};

/** What one run did. */
struct tsr_res {
    bool ran;               /**< the helper wrote a result */
    int  code;              /**< exit code, -1 when a signal ended it */
    int  sig;               /**< signal number, 0 when none */
    int  timeout;           /**< 1 when the time limit ended it */
    int  stages;            /**< stage lines on stdout */
    char last[220];         /**< the last stage line, or empty */
    char fin[64];           /**< the final value, or empty */
    char tags[96];          /**< "libSystem dlopen wrong-ELF-class" found */
    bool ok;                /**< exit 0, no signal, 4 stages, a final value */
};

/** Write the helper once: runs argv, records exit, signal and time limit. */
static inline void
tsr_install(void)
{
    tsd_put(TSR_HELPER,
        "import os, subprocess, sys\n"
        "tmo = int(sys.argv[1]); out, err, res = sys.argv[2:5]\n"
        "cmd = sys.argv[6:]\n"
        "code, sig, to = 0, 0, 0\n"
        "with open(out, 'wb') as o, open(err, 'wb') as e:\n"
        "    try:\n"
        "        p = subprocess.Popen(cmd, stdin=subprocess.DEVNULL, stdout=o,\n"
        "                             stderr=e, start_new_session=True)\n"
        "    except OSError as x:\n"
        "        e.write(('cannot start: %s\\n' % x).encode())\n"
        "        p = None\n"
        "        code = 127\n"
        "    if p is not None:\n"
        "        try:\n"
        "            rc = p.wait(timeout=tmo)\n"
        "        except subprocess.TimeoutExpired:\n"
        "            os.killpg(p.pid, 9)\n"
        "            p.wait()\n"
        "            rc = -9\n"
        "            to = 1\n"
        "        if rc < 0:\n"
        "            sig, code = -rc, -1\n"
        "        else:\n"
        "            code = rc\n"
        "with open(res, 'w') as r:\n"
        "    r.write('exit=%d signal=%d timeout=%d\\n' % (code, sig, to))\n");
}

/** Name of a signal number. */
static inline const char *
tsr_signame(int s)
{
    switch (s)
    {
        case 0:  return "none";
        case 1:  return "SIGHUP";
        case 2:  return "SIGINT";
        case 3:  return "SIGQUIT";
        case 4:  return "SIGILL";
        case 6:  return "SIGABRT";
        case 7:  return "SIGBUS";
        case 8:  return "SIGFPE";
        case 9:  return "SIGKILL";
        case 11: return "SIGSEGV";
        case 13: return "SIGPIPE";
        case 15: return "SIGTERM";
        default: return "signal";
    }
}

/** Count of lines of @p path that match the extended regex @p re. */
static inline int
tsr_count(const char *path, const char *re)
{
    char cmd[512];
    char buf[32];

    snprintf(cmd, sizeof(cmd), "grep -ciE '%s' '%s' 2>/dev/null; true", re,
             path);
    tsd_sh("/", cmd, 10, "/tmp/ts_ref_cnt.log");
    tsd_head("/tmp/ts_ref_cnt.log", buf, sizeof(buf));
    return atoi(buf);
}

/**
 * Read the facts of the files out and err written by a run tagged @p tag
 * (/tmp/ts_ref_<tag>.{out,err,res}) into @p r. The run needs 4 stage lines,
 * exit 0, no signal and a final value to be ok.
 */
static inline void
tsr_read(const char *tag, struct tsr_res *r)
{
    char cmd[1200];
    char buf[700];
    char *p;
    char out[64];
    char err[64];
    char res[64];

    snprintf(out, sizeof(out), "/tmp/ts_ref_%s.out", tag);
    snprintf(err, sizeof(err), "/tmp/ts_ref_%s.err", tag);
    snprintf(res, sizeof(res), "/tmp/ts_ref_%s.res", tag);
    memset(r, 0, sizeof(*r));
    r->code = -1;
    tsd_head(res, buf, sizeof(buf));
    r->ran = sscanf(buf, "exit=%d signal=%d timeout=%d", &r->code, &r->sig,
                    &r->timeout) == 3;
    snprintf(cmd, sizeof(cmd),
        "n=$(grep -cE '^[[:space:]]*(([A-Za-z0-9_]+-demo): *)?\\[.*\\] +hops=' '%s'); "
        "l=$(grep -E '^[[:space:]]*(([A-Za-z0-9_]+-demo): *)?\\[.*\\] +hops=' '%s' "
        "| tail -n 1 | cut -c1-200); "
        "f=$(grep -E 'result *=' '%s' | tail -n 1 | sed -E 's/.*= *//; "
        "s/[[:space:]]+$//'); printf '%%s\\n%%s\\n%%s\\n' \"$n\" \"$l\" \"$f\"",
        out, out, out);
    tsd_sh("/", cmd, 10, "/tmp/ts_ref_facts.log");
    tsd_head("/tmp/ts_ref_facts.log", buf, sizeof(buf));
    r->stages = atoi(buf);
    p = strchr(buf, '\n');
    if (p != NULL)
    {
        char *q = strchr(p + 1, '\n');

        if (q != NULL)
        {
            snprintf(r->last, sizeof(r->last), "%.*s", (int)(q - p - 1) > 200
                     ? 200 : (int)(q - p - 1), p + 1);
            snprintf(r->fin, sizeof(r->fin), "%.*s", (int)strcspn(q + 1, "\n")
                     > 40 ? 40 : (int)strcspn(q + 1, "\n"), q + 1);
        }
    }
    snprintf(cmd, sizeof(cmd), "cat '%s' '%s' > /tmp/ts_ref_%s.all", out, err,
             tag);
    tsd_sh("/", cmd, 10, "/tmp/ts_ref_cat.log");
    snprintf(cmd, sizeof(cmd), "/tmp/ts_ref_%s.all", tag);
    if (tsr_count(cmd, "libSystem") > 0)
        strncat(r->tags, "libSystem ", sizeof(r->tags) - strlen(r->tags) - 1);
    if (tsr_count(cmd, "dlopen") > 0)
        strncat(r->tags, "dlopen ", sizeof(r->tags) - strlen(r->tags) - 1);
    if (tsr_count(cmd, "wrong ELF class") > 0)
        strncat(r->tags, "wrong-ELF-class ",
                sizeof(r->tags) - strlen(r->tags) - 1);
    r->ok = r->ran && r->code == 0 && r->sig == 0 && r->timeout == 0 &&
            r->stages == 4 && r->fin[0] != '\0';
}

/**
 * Run the program @p prog (with its fixed arguments) and @p args alone, a
 * limit of @p tmo seconds, files tagged @p tag; fill @p r. @p ld is the
 * value of LD_LIBRARY_PATH or NULL to leave it unset. Runs from the project.
 */
static inline void
tsr_run_prog(const char *prog, const char *args, const char *tag, int tmo,
             const char *ld, struct tsr_res *r)
{
    char cmd[900];
    char log[64];

    tsr_install();
    snprintf(cmd, sizeof(cmd), "%s%s python3 -I %s %d /tmp/ts_ref_%s.out "
             "/tmp/ts_ref_%s.err /tmp/ts_ref_%s.res -- %s %s",
             ld != NULL ? "LD_LIBRARY_PATH=" : "", ld != NULL ? ld : "",
             TSR_HELPER, tmo, tag, tag, tag, prog, args);
    snprintf(log, sizeof(log), "/tmp/ts_ref_%s.log", tag);
    tsd_sh(tsd_src(), cmd, tmo + 25, log);
    tsr_read(tag, r);
}

/** Run the reference @p i alone; see tsr_run_prog(). */
static inline void
tsr_run(int i, const char *args, const char *tag, int tmo, const char *ld,
        struct tsr_res *r)
{
    tsr_run_prog(tsr_refs[i].prog, args, tag, tmo, ld, r);
}

/** Text of what happened to a run: language, signal, last stage reached. */
static inline void
tsr_describe(const char *name, const struct tsr_res *r, char *out, size_t size)
{
    char last[80] = "none";

    if (r->last[0] != '\0')
    {
        const char *e = strchr(r->last, ']');

        snprintf(last, sizeof(last), "%.*s", e != NULL ?
                 (int)(e - r->last) + 1 > 60 ? 60 : (int)(e - r->last) + 1 :
                 40, r->last);
    }
    if (!r->ran)
        snprintf(out, size, "%s left no result", name);
    else if (r->timeout)
        snprintf(out, size, "%s hung: killed after the time limit, %d stage "
                 "line(s), last stage %s", name, r->stages, last);
    else if (r->sig != 0)
        snprintf(out, size, "%s crashed with signal %s (%d) after %d stage "
                 "line(s), last stage reached %s", name, tsr_signame(r->sig),
                 r->sig, r->stages, last);
    else if (r->code != 0)
        snprintf(out, size, "%s exit code %d%s%s after %d stage line(s), "
                 "last stage reached %s", name, r->code,
                 r->code > 128 ? " (128 + signal " : "",
                 r->code > 128 ? tsr_signame(r->code - 128) : "", r->stages,
                 last);
    else if (r->stages != 4)
        snprintf(out, size, "%s exit 0 but %d stage line(s), want 4, last "
                 "stage reached %s", name, r->stages, last);
    else if (r->fin[0] == '\0')
        snprintf(out, size, "%s exit 0 and 4 stages but no final value", name);
    else
        snprintf(out, size, "%s exit 0, 4 stages, final value %s", name,
                 r->fin);
    if (r->code > 128 && r->sig == 0)
    {
        size_t l = strlen(out);

        snprintf(out + l, size - l, " (the process itself returned it)");
    }
    if (r->tags[0] != '\0' && !r->ok)
    {
        size_t l = strlen(out);

        snprintf(out + l, size - l, "; output mentions %s", r->tags);
    }
}

/** Log the last @p n lines of @p path, a few per message, truncated. */
static inline void
tsr_tail(const char *what, const char *path, int n)
{
    char cmd[300];
    int   k = 0;
    char  chunk[1300] = "";

    snprintf(cmd, sizeof(cmd), "tail -n %d '%s' | cut -c1-180", n, path);
    tsd_sh("/", cmd, 10, "/tmp/ts_ref_tail.log");
    {
        FILE *f = fopen("/tmp/ts_ref_tail.log", "r");
        char  line[400];

        if (f == NULL)
            return;
        while (fgets(line, sizeof(line), f) != NULL)
        {
            line[strcspn(line, "\n")] = '\0';
            if (strlen(chunk) + strlen(line) + 2 > 1200)
            {
                tsd_say("%s: %s", what, chunk);
                chunk[0] = '\0';
            }
            strncat(chunk, line, sizeof(chunk) - strlen(chunk) - 2);
            strncat(chunk, " | ", sizeof(chunk) - strlen(chunk) - 1);
            k++;
        }
        fclose(f);
    }
    if (chunk[0] != '\0')
        tsd_say("%s: %s", what, chunk);
    else if (k == 0)
        tsd_say("%s: (empty)", what);
}

#endif /* MDE_TSR_H */
