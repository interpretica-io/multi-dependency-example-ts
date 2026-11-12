/** @file
 * @brief Binary Group
 *
 * Hunt for the injected always-true defect at the machine-code level.
 *
 * Each stage of the ring hands the value on with a call to the next
 * stage (cpp_step -> rust_step, rust_step -> go_step, ...). In the
 * shipped sources that call sits behind an always-true early return
 * (@c if (5) return next;), and an optimising compiler drops what can
 * never run: the call is simply not in the machine code any more. So
 * the disassembly of a stage function tells, without running anything,
 * whether the onward edge of the ring survived the build.
 *
 * tapi_objdump disassembles one function at a time; the test counts the
 * instructions, the calls, and the calls or tail jumps that reach the
 * next stage. None of the latter is a @c binary.dead-call finding.
 *
 * A second view, the dynamic symbol table, must agree: a library that
 * never calls the next stage has no reason to import it.
 *
 * Known-bad control: two functions built on the agent from the same
 * shape, one with the defect and one without. The analysis must flag
 * the first and must not flag the second.
 *
 * Copyright (C) 2026 Maxim Menshikov
 *
 * @author Maxim Menshikov <maximmenshchikov@gmail.com>
 */

#define TE_TEST_NAME    "binary/disasm_defect"

#include "te_config.h"
#include "tapi_test.h"
#include "te_string.h"

#include "tapi_objdump.h"

#include "binary_common.h"

/** One onward edge of the ring as the machine code should carry it. */
typedef struct disasm_edge {
    const char *lib;         /**< Library, without the extension. */
    const char *func;        /**< Function to disassemble. */
    const char *callee;      /**< Substring of the symbol it must reach. */
    bool        import_view; /**< The dynamic imports must agree. */
    const char *note;        /**< What the edge is. */
} disasm_edge;

/*
 * The edges that are direct calls in the machine code. The C# stage
 * reaches Python through a dlsym()ed function pointer and the Python
 * stage through the interpreter, so there is no symbol to look for in
 * them; py_step is kept as an edge with no defect in it (it must reach
 * the interpreter), the others are the ring proper. Go's own function
 * is main.go_step, which reaches C through main._Cfunc_cs_step; the cgo
 * C wrapper keeps cs_step imported whatever Go does, so the import view
 * does not apply there.
 */
static const disasm_edge edges[] = {
    { "libcppcore",  "cpp_step",     "rust_step",             true,
      "C++ ring step -> Rust" },
    { "librustcore", "rust_step",    "go_step",               true,
      "Rust ring step -> Go" },
    { "libgocore",   "main.go_step", "cs_step",               false,
      "Go ring step -> C#" },
    { "libpycore",   "py_step",      "PyObject_CallFunction", false,
      "Python host -> interpreter" },
};
#define DISASM_N_EDGES TE_ARRAY_LEN(edges)

/** What the disassembly of one function says. */
typedef struct disasm_stat {
    unsigned int insns;   /**< Instructions. */
    unsigned int calls;   /**< call instructions. */
    unsigned int reaches; /**< Calls or jumps to the callee. */
} disasm_stat;

/**
 * Walk the disassembly of one function and count what matters.
 *
 * An instruction line is "  addr:<TAB>bytes<TAB>mnemonic operands";
 * the symbol an instruction refers to is the last <...> of the line,
 * with @c @plt or @c +off stripped. A tail call is a jmp to another
 * function, so jumps to the callee count as reaching it.
 */
static void
disasm_count(const char *body, const char *func, const char *callee,
             disasm_stat *st)
{
    const char *line = body;

    memset(st, 0, sizeof(*st));

    while (line != NULL && *line != '\0')
    {
        const char *eol = strchr(line, '\n');
        size_t      len = (eol != NULL) ? (size_t)(eol - line) : strlen(line);
        te_string   cur = TE_STRING_INIT;
        const char *tab1;
        const char *tab2;
        const char *insn;

        te_string_append(&cur, "%.*s", (int)len, line);
        line = (eol != NULL) ? eol + 1 : NULL;

        tab1 = strstr(cur.ptr != NULL ? cur.ptr : "", ":\t");
        if (tab1 == NULL)
        {
            te_string_free(&cur);
            continue;
        }
        tab2 = strchr(tab1 + 2, '\t');
        if (tab2 == NULL)
        {
            /* Only bytes, the continuation of a long instruction. */
            te_string_free(&cur);
            continue;
        }
        insn = tab2 + 1;
        st->insns++;

        if (strncmp(insn, "call", 4) == 0)
            st->calls++;

        if (strstr(insn, "call") != NULL || strstr(insn, "jmp") != NULL)
        {
            const char *open = strrchr(insn, '<');
            const char *close = open != NULL ? strchr(open, '>') : NULL;

            if (open != NULL && close != NULL)
            {
                te_string sym = TE_STRING_INIT;
                const char *p;
                const char *end = close;

                for (p = open + 1; p < close; p++)
                {
                    if (*p == '@' || *p == '+')
                    {
                        end = p;
                        break;
                    }
                }
                te_string_append(&sym, "%.*s", (int)(end - open - 1),
                                 open + 1);
                if (strcmp(te_string_value(&sym), func) != 0 &&
                    strstr(te_string_value(&sym), callee) != NULL)
                    st->reaches++;
                te_string_free(&sym);
            }
        }

        te_string_free(&cur);
    }
}

/**
 * Disassemble one function of a binary and count what matters.
 *
 * @param[in]  session  Session.
 * @param[in]  path     Binary on the agent.
 * @param[in]  func     Function.
 * @param[in]  callee   Callee substring.
 * @param[out] st       Counts.
 * @param[out] body     String to append the disassembly to.
 * @param[out] secs     Time objdump took.
 *
 * @return @c true if the function was found.
 */
static bool
disasm_function(tsapi_mde_session *session, const char *path,
                const char *func, const char *callee, disasm_stat *st,
                te_string *body, double *secs)
{
    tapi_objdump_opt    opt = tapi_objdump_default_opt;
    tapi_objdump_app   *app = NULL;
    tapi_devtool_output output;
    double              t0 = tsapi_mde_now();
    bool                found = false;
    te_errno            rc;

    opt.path = path;
    opt.symbol = func;
    /* Go and Rust names are not C++ ones; keep them as they are. */
    opt.demangle = false;

    rc = tapi_objdump_do(session->factory, &opt, TAPI_DEVTOOL_TIMEOUT_MS,
                         &app);
    *secs = tsapi_mde_now() - t0;
    if (rc != 0)
    {
        WARN("objdump of %s in %s failed: %r", func, path, rc);
    }
    else
    {
        tapi_objdump_get_output(app, &output);
        found = tapi_objdump_extract_function(output.out, func, body);
        if (found)
            disasm_count(body->ptr, func, callee, st);
    }

    (void)tapi_objdump_destroy(app);

    return found;
}

/**
 * Whether a binary imports a symbol (an undefined dynamic symbol).
 *
 * @param session   Session.
 * @param path      Binary on the agent.
 * @param symbol    Symbol name.
 *
 * @return @c true if it is imported.
 */
static bool
disasm_imports(tsapi_mde_session *session, const char *path,
               const char *symbol)
{
    tsapi_mde_sh_result res = TSAPI_MDE_SH_RESULT_INIT;
    bool                yes;

    yes = tsapi_mde_sh(session, 60000, &res,
                       "readelf --dyn-syms -W '%s' | awk '$7==\"UND\" "
                       "{n=$8; sub(/@.*/,\"\",n); print n}' | "
                       "grep -qx '%s'", path, symbol) == 0 &&
          tsapi_mde_sh_ok(&res);
    tsapi_mde_sh_result_free(&res);

    return yes;
}

/** Add the dead-call finding. */
static void
disasm_dead_call(tsapi_mde_report *report, const char *subject,
                 const char *callee, const disasm_stat *st)
{
    tapi_cybersec_report_add(&report->cyber, TAPI_CYBERSEC_SEV_MEDIUM,
                             "binary.dead-call", subject,
                             "no call or tail jump to %s is left in the "
                             "machine code (%u instructions, %u calls): the "
                             "onward edge was compiled away", callee,
                             st->insns, st->calls);
}

/** Where the control library is built. */
#define DISASM_CONTROL_SRC  "/tmp/mde-binary-disasm-control.c"
#define DISASM_CONTROL_LIB  "/tmp/mde-binary-disasm-control.so"

/** The ring stage shape, once with the defect and once without. */
#define DISASM_CONTROL_SOURCE \
    "extern double ext_next(double v, int hops);\n"                     \
    "double step_live(double v, int hops)\n"                            \
    "{\n"                                                               \
    "    double next = v * 1.5 + 1.0;\n"                                \
    "    if (hops <= 0)\n"                                              \
    "        return next;\n"                                            \
    "    return ext_next(next, hops - 1);\n"                            \
    "}\n"                                                               \
    "double step_cut(double v, int hops)\n"                             \
    "{\n"                                                               \
    "    double next = v * 1.5 + 1.0;\n"                                \
    "    if (hops <= 0)\n"                                              \
    "        return next;\n"                                            \
    "    if (5)\n"                                                      \
    "        return next;\n"                                            \
    "    return ext_next(next, hops - 1);\n"                            \
    "}"

int
main(int argc, char **argv)
{
    tapi_cybersec_severity  min_sev;
    tsapi_mde_session       session = { .ta = NULL };
    tsapi_mde_dut           dut = { .root = NULL };
    bool                    session_up = false;
    tsapi_mde_report        report;
    bool                    report_up = false;
    bool                    control_built = false;
    bool                    have_readelf;
    const char             *cc;
    te_string               log = TE_STRING_INIT;
    const char             *labels[DISASM_N_EDGES];
    double                  stats[3 * DISASM_N_EDGES];
    double                  secs[DISASM_N_EDGES];
    const char             *stat_lines[] = { "instructions", "calls",
                                             "reaches_next" };
    unsigned int            n = 0;
    unsigned int            n_dead = 0;
    unsigned int            i;

    TEST_START;

    TEST_STEP("Parse test parameters");
    TEST_GET_MDE_SEVERITY(min_sev);

    TEST_STEP("Open a session and locate the example");
    TSAPI_MDE_OPEN_OR_SKIP(session, "binary_disasm", dut, session_up);
    if (!tsapi_mde_have(&session, "objdump"))
        TEST_VERDICT("There is no objdump on the agent");
    have_readelf = tsapi_mde_have(&session, "readelf");

    tsapi_mde_report_init(&report);
    report_up = true;

    TEST_STEP("Known-bad control: the defect planted in a library of our own");
    cc = binary_compiler(&session);
    if (cc == NULL)
    {
        WARN("There is no C compiler on the agent: no control");
    }
    else
    {
        disasm_stat st_live;
        disasm_stat st_cut;
        te_string   body = TE_STRING_INIT;
        double      t;
        bool        found_live;
        bool        found_cut;

        control_built = binary_build_c(&session, cc, DISASM_CONTROL_SRC,
                                       DISASM_CONTROL_LIB,
                                       "-O2 -fPIC -shared",
                                       DISASM_CONTROL_SOURCE, &log);
        if (!control_built)
        {
            RING("Control build output:\n%s", te_string_value(&log));
            TEST_VERDICT("Cannot build the known-bad control library");
        }

        found_live = disasm_function(&session, DISASM_CONTROL_LIB,
                                     "step_live", "ext_next", &st_live,
                                     &body, &t);
        RING("Control step_live:\n%s", te_string_value(&body));
        te_string_reset(&body);
        found_cut = disasm_function(&session, DISASM_CONTROL_LIB,
                                    "step_cut", "ext_next", &st_cut,
                                    &body, &t);
        RING("Control step_cut:\n%s", te_string_value(&body));
        te_string_free(&body);

        if (!found_live || !found_cut)
            TEST_VERDICT("objdump cannot find the functions of the control");

        TEST_ARTIFACT("control: step_live %u insns %u calls %u reach(es); "
                      "step_cut %u insns %u calls %u reach(es)",
                      st_live.insns, st_live.calls, st_live.reaches,
                      st_cut.insns, st_cut.calls, st_cut.reaches);

        if (st_live.reaches == 0)
            disasm_dead_call(&report, BINARY_CONTROL_NAME ":step_live",
                             "ext_next", &st_live);
        if (st_cut.reaches == 0)
            disasm_dead_call(&report, BINARY_CONTROL_NAME ":step_cut",
                             "ext_next", &st_cut);

        tsapi_mde_report_expect(&report, "binary.dead-call",
                                BINARY_CONTROL_NAME ":step_cut");
        if (tsapi_mde_report_has(&report, "binary.dead-call",
                                 BINARY_CONTROL_NAME ":step_live") > 0)
        {
            TEST_VERDICT("The dead-call analysis flags the live call of "
                         "the control");
        }

        if (have_readelf &&
            disasm_imports(&session, DISASM_CONTROL_LIB, "ext_next") !=
                (st_live.reaches > 0))
        {
            WARN("The control's import table does not agree with its "
                 "disassembly");
        }

        tsapi_mde_report_drop_subject(&report,
                                      BINARY_CONTROL_NAME ":step_cut");
        tsapi_mde_report_drop_subject(&report,
                                      BINARY_CONTROL_NAME ":step_live");
    }

    TEST_STEP("Disassemble every stage function of the ring");
    for (i = 0; i < DISASM_N_EDGES; i++)
    {
        const disasm_edge *e = &edges[i];
        te_string          path = TE_STRING_INIT;
        te_string          body = TE_STRING_INIT;
        te_string          subject = TE_STRING_INIT;
        disasm_stat        st;
        double             t = 0;

        TEST_SUBSTEP("%s in %s: %s", e->func, e->lib, e->note);
        tsapi_mde_dut_lib_path(&dut, e->lib, &path);
        te_string_append(&subject, "%s:%s", e->lib, e->func);

        if (!tsapi_mde_exists(&session, path.ptr))
        {
            TEST_ARTIFACT("%s: library not built, skipped", subject.ptr);
            goto next;
        }

        if (!disasm_function(&session, path.ptr, e->func, e->callee, &st,
                             &body, &t))
        {
            TEST_ARTIFACT("%s: symbol not found, skipped", subject.ptr);
            goto next;
        }

        if (body.len < 16384)
            RING("Disassembly of %s:\n%s", subject.ptr, body.ptr);
        else
            RING("Disassembly of %s: %zu bytes, not logged", subject.ptr,
                 body.len);

        TEST_ARTIFACT("%s: %u instructions, %u calls, %u reach(es) of %s",
                      subject.ptr, st.insns, st.calls, st.reaches,
                      e->callee);

        if (st.reaches == 0)
        {
            disasm_dead_call(&report, subject.ptr, e->callee, &st);
            n_dead++;
        }

        if (e->import_view && have_readelf)
        {
            bool imported = disasm_imports(&session, path.ptr, e->callee);

            TEST_ARTIFACT("%s: %s %s imported", subject.ptr, e->callee,
                          imported ? "is" : "is not");
            if (imported != (st.reaches > 0))
            {
                tapi_cybersec_report_add(&report.cyber,
                                         TAPI_CYBERSEC_SEV_MEDIUM,
                                         "binary.view-mismatch",
                                         subject.ptr,
                                         "the disassembly says %s is "
                                         "%sreached, the import table says "
                                         "it is %simported", e->callee,
                                         st.reaches > 0 ? "" : "not ",
                                         imported ? "" : "not ");
            }
        }

        labels[n] = e->func;
        stats[0 * DISASM_N_EDGES + n] = st.insns;
        stats[1 * DISASM_N_EDGES + n] = st.calls;
        stats[2 * DISASM_N_EDGES + n] = st.reaches;
        secs[n] = t;
        n++;

next:
        te_string_free(&path);
        te_string_free(&body);
        te_string_free(&subject);
    }

    if (n == 0)
        TEST_VERDICT("None of the stage functions could be disassembled");

    TEST_STEP("Chart instructions, calls and onward reaches per function");
    for (i = 1; i < 3; i++)
    {
        unsigned int k;

        for (k = 0; k < n; k++)
            stats[i * n + k] = stats[i * DISASM_N_EDGES + k];
    }
    binary_mi_matrix("objdump", "functions",
                     "Stage functions: instructions, calls, reaches of the "
                     "next stage", n, labels, TE_ARRAY_LEN(stat_lines),
                     stat_lines, stats);
    tsapi_mde_mi_bars("objdump", "Time to disassemble each function",
                      TE_MI_MEAS_TIME, "time", n, labels, secs,
                      TE_MI_MEAS_MULTIPLIER_PLAIN);
    TEST_ARTIFACT("%u of %u stage function(s) have their onward call "
                  "compiled away", n_dead, n);

    TEST_STEP("Decide");
    TSAPI_MDE_REPORT_GATE(&report, "binary", min_sev);

    TEST_SUCCESS;

cleanup:

    if (control_built)
        binary_rm(&session, DISASM_CONTROL_SRC " " DISASM_CONTROL_LIB);
    if (report_up)
        tsapi_mde_report_free(&report);
    te_string_free(&log);
    tsapi_mde_dut_free(&dut);
    if (session_up)
        tsapi_mde_session_fini(&session);

    TEST_END;
}
