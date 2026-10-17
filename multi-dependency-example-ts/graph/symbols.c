/** @file
 * @brief Graph Group
 *
 * Every ring library is a C ABI of exactly two functions: <stage>_step and
 * <stage>_weight (cpp/include/ring/ring.h). Check one library exports both
 * - in two views on ELF: nm's export list and readelf's dynamic symbol
 * table (global, defined functions) - and nothing else that belongs to the
 * ring contract of another stage. Anything else it exports (a language
 * runtime's own symbols) is recorded as low-severity noise.
 *
 * Copyright (C) 2026 Maxim Menshikov
 *
 * @author Maxim Menshikov <maximmenshchikov@gmail.com>
 */

#define TE_TEST_NAME    "graph/symbols"

#include "graph_common.h"

/** Mapping of the @c lib parameter. */
#define SYMBOLS_LIB_LIST \
    { "cpp",  TSAPI_MDE_STAGE_CPP  }, \
    { "rust", TSAPI_MDE_STAGE_RUST }, \
    { "go",   TSAPI_MDE_STAGE_GO   }, \
    { "cs",   TSAPI_MDE_STAGE_CS   }, \
    { "py",   TSAPI_MDE_STAGE_PY   }

/**
 * Check one library's export list against the contract; subjects are
 * "<prefix><lib>:<symbol>" and "<prefix><lib>".
 *
 * @return Number of exports outside the ring contract.
 */
static unsigned int
symbols_check(const graph_lib *lib, const char *prefix,
              tapi_cybersec_report *cyber)
{
    te_string    extra = TE_STRING_INIT;
    unsigned int n_extra = 0;
    unsigned int n_contract = 0;
    unsigned int stage;
    unsigned int k;
    const char  *line;
    char         subject[96];
    char         sym[32];

    for (stage = 0; stage < TSAPI_MDE_STAGE_N; stage++)
    {
        for (k = 0; k < 2; k++)
        {
            bool has;

            graph_sym(stage, k == 0, sym, sizeof(sym));
            has = graph_list_has(&lib->exports, sym);
            TE_SPRINTF(subject, "%s%s:%s", prefix, lib->name, sym);

            if (stage == lib->stage && !has)
            {
                tapi_cybersec_report_add(cyber, TAPI_CYBERSEC_SEV_HIGH,
                                         "graph.missing-export", subject,
                                         "the ring contract needs it");
            }
            else if (stage != lib->stage && has)
            {
                tapi_cybersec_report_add(cyber, TAPI_CYBERSEC_SEV_MEDIUM,
                                         "graph.foreign-export", subject,
                                         "exports a symbol of the %s stage",
                                         tsapi_mde_stage2str(stage));
            }
            if (has)
                n_contract++;
        }
    }

    /* Everything outside the ring contract. */
    for (line = graph_str(&lib->exports); *line != '\0'; )
    {
        const char *eol = strchr(line, '\n');
        size_t      len = eol != NULL ? (size_t)(eol - line) : strlen(line);

        if (len > 0 && len < sizeof(sym))
        {
            bool contract = false;

            memcpy(sym, line, len);
            sym[len] = '\0';
            for (stage = 0; stage < TSAPI_MDE_STAGE_N && !contract; stage++)
            {
                char c[32];

                graph_sym(stage, true, c, sizeof(c));
                contract = strcmp(c, sym) == 0;
                graph_sym(stage, false, c, sizeof(c));
                contract = contract || strcmp(c, sym) == 0;
            }
            if (!contract)
            {
                n_extra++;
                if (n_extra <= 10)
                    te_string_append(&extra, "%s%s", n_extra > 1 ? " " : "",
                                     sym);
            }
        }
        else if (len >= sizeof(sym))
        {
            n_extra++;
        }

        if (eol == NULL)
            break;
        line = eol + 1;
    }

    if (n_extra > 0)
    {
        TE_SPRINTF(subject, "%s%s", prefix, lib->name);
        tapi_cybersec_report_add(cyber, TAPI_CYBERSEC_SEV_LOW,
                                 "graph.unexpected-export", subject,
                                 "%u export(s) outside the ring contract, "
                                 "e.g. %s", n_extra, graph_str(&extra));
    }

    RING("%s%s: %u contract export(s), %u other(s)", prefix, lib->name,
         n_contract, n_extra);
    te_string_free(&extra);
    return n_extra;
}

int
main(int argc, char **argv)
{
    tsapi_mde_stage     lib;
    tsapi_mde_session   session;
    bool                session_up = false;
    tsapi_mde_dut       dut = { .root = NULL };
    tsapi_mde_report    report;
    bool                report_up = false;
    graph_libs          libs;
    graph_lib           planted;
    bool                libs_up = false;
    tsapi_mde_sh_result res = TSAPI_MDE_SH_RESULT_INIT;
    double              n_exports[TSAPI_MDE_STAGE_N];
    double              n_other[TSAPI_MDE_STAGE_N];
    const char         *labels[TSAPI_MDE_STAGE_N];
    graph_lib          *self;
    const char         *why;
    unsigned int        i;
    unsigned int        k;

    TEST_START;
    tsapi_mde_report_init(&report);
    report_up = true;
    graph_libs_init(&libs);
    memset(&planted, 0, sizeof(planted));
    planted.exports = (te_string)TE_STRING_INIT;
    planted.needed = (te_string)TE_STRING_INIT;
    planted.undef = (te_string)TE_STRING_INIT;
    libs_up = true;

    TEST_STEP("Parse test parameters");
    TEST_GET_ENUM_PARAM(lib, SYMBOLS_LIB_LIST);

    TEST_STEP("Open a session and locate the example");
    TSAPI_MDE_OPEN_OR_SKIP(session, "symbols", dut, session_up);

    TEST_STEP("Skip unless the binary tools are available");
    why = graph_tools_unavailable(&session,
                                  strcmp(dut.dylib_ext, "dylib") == 0);
    if (why != NULL)
        TEST_SKIP("%s", why);

    TEST_STEP("Read the exports of every ring library");
    CHECK_RC(graph_libs_load(&session, &dut, &libs));
    self = &libs.lib[lib];
    if (!self->present)
        TEST_SKIP("%s is missing - build the example first", self->name);

    TEST_STEP("Known-bad control: a cppcore exporting rust_step and not "
              "cpp_weight must be caught");
    planted.stage = TSAPI_MDE_STAGE_CPP;
    graph_lib_name(planted.stage, planted.name, sizeof(planted.name));
    te_string_append(&planted.exports, "\ncpp_step\nrust_step\n");
    symbols_check(&planted, "control/", &report.cyber);
    tsapi_mde_report_expect(&report, "graph.missing-export",
                            "control/libcppcore:cpp_weight");
    tsapi_mde_report_expect(&report, "graph.foreign-export",
                            "control/libcppcore:rust_step");
    graph_report_drop_prefix(&report, "control/");

    TEST_STEP("Check %s exports exactly its contract", self->name);
    symbols_check(self, "", &report.cyber);

    if (!libs.macho && tsapi_mde_have(&session, "readelf"))
    {
        te_string path = TE_STRING_INIT;

        TEST_STEP("Second view (readelf --dyn-syms): the contract symbols "
                  "are global defined functions");
        tsapi_mde_dut_lib_path(&dut, self->name, &path);
        for (k = 0; k < 2; k++)
        {
            char sym[32];
            char subject[96];

            graph_sym(lib, k == 0, sym, sizeof(sym));
            TE_SPRINTF(subject, "%s:%s", self->name, sym);
            /*
             * readelf prints the version a symbol is bound to after it
             * (NativeAOT's libcscore has "cs_step@@V1.0"), which nm -D
             * folds away; compare the bare names.
             */
            if (tsapi_mde_sh(&session, 20000, &res,
                             "readelf --dyn-syms -W '%s' | "
                             "awk '{ n = $8; sub(/@.*/, \"\", n) } "
                             "n == \"%s\" && $7 != \"UND\" "
                             "{print $4, $5, $8}'", path.ptr, sym) != 0)
                continue;

            RING("readelf %s: '%s'", sym, graph_str(&res.out));
            if (strstr(graph_str(&res.out), "FUNC GLOBAL") == NULL &&
                strstr(graph_str(&res.out), "FUNC WEAK") == NULL)
            {
                tapi_cybersec_report_add(&report.cyber,
                                         TAPI_CYBERSEC_SEV_MEDIUM,
                                         "graph.export-mismatch", subject,
                                         "readelf does not show it as an "
                                         "exported function (nm %s)",
                                         graph_list_has(&self->exports, sym) ?
                                         "does" : "does not either");
            }
        }
        te_string_free(&path);
    }

    TEST_STEP("Chart the exports of every library");
    for (i = 0; i < TSAPI_MDE_STAGE_N; i++)
    {
        unsigned int contract = 0;

        for (k = 0; k < 2; k++)
        {
            char sym[32];

            graph_sym(i, k == 0, sym, sizeof(sym));
            contract += graph_list_has(&libs.lib[i].exports, sym) ? 1 : 0;
        }
        labels[i] = libs.lib[i].name;
        n_exports[i] = libs.lib[i].n_exports;
        n_other[i] = libs.lib[i].n_exports - contract;
        TEST_ARTIFACT("%s: %u export(s), %u of them the ring contract",
                      libs.lib[i].name, libs.lib[i].n_exports, contract);
    }
    tsapi_mde_mi_bars("graph", "Exported symbols per ring library",
                      TE_MI_MEAS_UNITLESS_VALUE, "exported",
                      TSAPI_MDE_STAGE_N, labels, n_exports,
                      TE_MI_MEAS_MULTIPLIER_PLAIN);
    tsapi_mde_mi_bars("graph", "Exports outside the ring contract per "
                      "library", TE_MI_MEAS_UNITLESS_VALUE, "other",
                      TSAPI_MDE_STAGE_N, labels, n_other,
                      TE_MI_MEAS_MULTIPLIER_PLAIN);

    TEST_STEP("Decide on the findings");
    TSAPI_MDE_REPORT_GATE(&report, "graph", TAPI_CYBERSEC_SEV_MEDIUM);

    TEST_SUCCESS;

cleanup:

    tsapi_mde_sh_result_free(&res);
    if (libs_up)
    {
        graph_libs_free(&libs);
        te_string_free(&planted.exports);
        te_string_free(&planted.needed);
        te_string_free(&planted.undef);
    }
    if (report_up)
        tsapi_mde_report_free(&report);
    tsapi_mde_dut_free(&dut);
    if (session_up)
        tsapi_mde_session_fini(&session);

    TEST_END;
}
