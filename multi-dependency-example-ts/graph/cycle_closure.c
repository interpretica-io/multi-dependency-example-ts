/** @file
 * @brief Graph Group
 *
 * Build the dependency graph of the five ring libraries from their binaries
 * and check its shape:
 *
 * - view "needed": load-time edges only (NEEDED / otool -L). They must form
 *   a DAG, and the README build order py, cs, go, rust, cpp must be a
 *   topological order of it - that is what makes a cyclic ring buildable.
 * - view "full": load-time edges, plus undefined symbols resolved against
 *   the other libraries' exports (load-time binding), plus contract symbol
 *   names a library looks up by string (dlsym in C#), plus the calls of
 *   the Python stage's module (ctypes in ring_stage.py, hosted by
 *   libpycore). The ring cycle cpp->rust->go->cs->py->cpp and the five
 *   chords cpp->py, rust->cs, go->cpp, cs->rust, py->go must all be there,
 *   and every library has in- and out-degree 2.
 *
 * The graph is emitted as DOT (log, artifact line, and a file on the agent)
 * and its degrees are charted.
 *
 * Copyright (C) 2026 Maxim Menshikov
 *
 * @author Maxim Menshikov <maximmenshchikov@gmail.com>
 */

#define TE_TEST_NAME    "graph/cycle_closure"

#include "graph_common.h"

/** Kinds of evidence for an edge (bit mask). */
#define EDGE_NEEDED 0x1     /**< Load-time dependency. */
#define EDGE_UNDEF  0x2     /**< Undefined symbol exported by the target. */
#define EDGE_DLSYM  0x4     /**< Target's contract symbol named as a string. */
#define EDGE_SCRIPT 0x8     /**< Called from the Python stage's module. */

typedef enum cc_view {
    CC_VIEW_NEEDED,
    CC_VIEW_FULL,
} cc_view;

#define CC_VIEW_LIST \
    { "needed", CC_VIEW_NEEDED }, \
    { "full",   CC_VIEW_FULL   }

/** Adjacency: edge[from][to] is a mask of EDGE_*. */
typedef struct cc_graph {
    unsigned int edge[TSAPI_MDE_STAGE_N][TSAPI_MDE_STAGE_N];
} cc_graph;

/** Position of each stage in the README build order (py first). */
static unsigned int
cc_build_pos(unsigned int stage)
{
    switch (stage)
    {
        case TSAPI_MDE_STAGE_PY:   return 0;
        case TSAPI_MDE_STAGE_CS:   return 1;
        case TSAPI_MDE_STAGE_GO:   return 2;
        case TSAPI_MDE_STAGE_RUST: return 3;
        default:                   return 4;
    }
}

/** The chord of a stage: whose weight it multiplies by. */
static unsigned int
cc_chord(unsigned int stage)
{
    switch (stage)
    {
        case TSAPI_MDE_STAGE_CPP:  return TSAPI_MDE_STAGE_PY;
        case TSAPI_MDE_STAGE_RUST: return TSAPI_MDE_STAGE_CS;
        case TSAPI_MDE_STAGE_GO:   return TSAPI_MDE_STAGE_CPP;
        case TSAPI_MDE_STAGE_CS:   return TSAPI_MDE_STAGE_RUST;
        default:                   return TSAPI_MDE_STAGE_GO;
    }
}

/** Text of an edge mask. */
static void
cc_kinds(unsigned int mask, char *buf, size_t size)
{
    TE_SNPRINTF(buf, size, "%s%s%s%s",
                (mask & EDGE_NEEDED) ? "needed," : "",
                (mask & EDGE_UNDEF) ? "undef," : "",
                (mask & EDGE_DLSYM) ? "dlsym," : "",
                (mask & EDGE_SCRIPT) ? "script," : "");
    if (buf[0] != '\0')
        buf[strlen(buf) - 1] = '\0';
}

/** Depth-first search for a cycle among edges in @p mask. */
static bool
cc_dfs(const cc_graph *g, unsigned int mask, unsigned int v,
       unsigned int *state)
{
    unsigned int w;

    state[v] = 1;
    for (w = 0; w < TSAPI_MDE_STAGE_N; w++)
    {
        if ((g->edge[v][w] & mask) == 0 || w == v)
            continue;
        if (state[w] == 1)
            return true;
        if (state[w] == 0 && cc_dfs(g, mask, w, state))
            return true;
    }
    state[v] = 2;

    return false;
}

/**
 * The "needed" checks: a DAG whose topological order admits the README
 * build order. Subjects "<prefix>needed-graph", "<prefix><a>-><b>".
 */
static void
cc_check_needed(const cc_graph *g, const char *prefix,
                tapi_cybersec_report *cyber)
{
    unsigned int state[TSAPI_MDE_STAGE_N] = { 0 };
    unsigned int v;
    unsigned int w;
    bool         cycle = false;
    char         subject[96];

    for (v = 0; v < TSAPI_MDE_STAGE_N && !cycle; v++)
    {
        if (state[v] == 0)
            cycle = cc_dfs(g, EDGE_NEEDED, v, state);
    }
    if (cycle)
    {
        TE_SPRINTF(subject, "%sneeded-graph", prefix);
        tapi_cybersec_report_add(cyber, TAPI_CYBERSEC_SEV_CRITICAL,
                                 "graph.needed-cycle", subject,
                                 "the load-time dependencies form a cycle: "
                                 "the ring cannot be linked in any order");
    }

    for (v = 0; v < TSAPI_MDE_STAGE_N; v++)
    {
        for (w = 0; w < TSAPI_MDE_STAGE_N; w++)
        {
            if ((g->edge[v][w] & EDGE_NEEDED) == 0 || v == w)
                continue;
            if (cc_build_pos(w) >= cc_build_pos(v))
            {
                TE_SPRINTF(subject, "%s%s->%s", prefix,
                           tsapi_mde_stage2str(v), tsapi_mde_stage2str(w));
                tapi_cybersec_report_add(cyber, TAPI_CYBERSEC_SEV_HIGH,
                                         "graph.build-order", subject,
                                         "lib%score needs lib%score, which "
                                         "the build makes later",
                                         tsapi_mde_stage2str(v),
                                         tsapi_mde_stage2str(w));
            }
        }
    }
}

/**
 * The "full" checks: the ring cycle, the chords, degree 2 everywhere.
 * Subjects "<prefix><a>-><b>", "<prefix>lib<stage>core".
 */
static void
cc_check_full(const cc_graph *g, const char *prefix,
              tapi_cybersec_report *cyber, unsigned int *in_deg,
              unsigned int *out_deg)
{
    unsigned int v;
    unsigned int w;
    char         subject[96];

    for (v = 0; v < TSAPI_MDE_STAGE_N; v++)
        in_deg[v] = out_deg[v] = 0;

    for (v = 0; v < TSAPI_MDE_STAGE_N; v++)
    {
        unsigned int next = (v + 1) % TSAPI_MDE_STAGE_N;
        unsigned int chord = cc_chord(v);

        for (w = 0; w < TSAPI_MDE_STAGE_N; w++)
        {
            if (w == v || g->edge[v][w] == 0)
                continue;
            out_deg[v]++;
            in_deg[w]++;
            if (w != next && w != chord)
            {
                TE_SPRINTF(subject, "%s%s->%s", prefix,
                           tsapi_mde_stage2str(v), tsapi_mde_stage2str(w));
                tapi_cybersec_report_add(cyber, TAPI_CYBERSEC_SEV_MEDIUM,
                                         "graph.unexpected-edge", subject,
                                         "neither the ring nor a chord");
            }
        }

        TE_SPRINTF(subject, "%s%s->%s", prefix, tsapi_mde_stage2str(v),
                   tsapi_mde_stage2str(next));
        if (g->edge[v][next] == 0)
        {
            tapi_cybersec_report_add(cyber, TAPI_CYBERSEC_SEV_CRITICAL,
                                     "graph.cycle-edge-missing", subject,
                                     "no evidence %s calls %s_step",
                                     tsapi_mde_stage2str(v),
                                     tsapi_mde_stage2str(next));
        }

        TE_SPRINTF(subject, "%s%s->%s", prefix, tsapi_mde_stage2str(v),
                   tsapi_mde_stage2str(chord));
        if (g->edge[v][chord] == 0)
        {
            tapi_cybersec_report_add(cyber, TAPI_CYBERSEC_SEV_HIGH,
                                     "graph.chord-missing", subject,
                                     "no evidence %s calls %s_weight",
                                     tsapi_mde_stage2str(v),
                                     tsapi_mde_stage2str(chord));
        }
    }

    for (v = 0; v < TSAPI_MDE_STAGE_N; v++)
    {
        if (in_deg[v] != 2 || out_deg[v] != 2)
        {
            TE_SPRINTF(subject, "%slib%score", prefix,
                       tsapi_mde_stage2str(v));
            tapi_cybersec_report_add(cyber, TAPI_CYBERSEC_SEV_MEDIUM,
                                     "graph.degree", subject,
                                     "in-degree %u, out-degree %u; the ring "
                                     "has 2 and 2", in_deg[v], out_deg[v]);
        }
    }
}

int
main(int argc, char **argv)
{
    cc_view             view;
    tsapi_mde_session   session;
    bool                session_up = false;
    tsapi_mde_dut       dut = { .root = NULL };
    tsapi_mde_report    report;
    bool                report_up = false;
    graph_libs          libs;
    bool                libs_up = false;
    tsapi_mde_sh_result res = TSAPI_MDE_SH_RESULT_INIT;
    te_string           strs[TSAPI_MDE_STAGE_N];
    te_string           script = TE_STRING_INIT;
    te_string           dot = TE_STRING_INIT;
    te_string           dot_line = TE_STRING_INIT;
    te_string           dot_path = TE_STRING_INIT;
    cc_graph            g;
    cc_graph            planted;
    unsigned int        in_deg[TSAPI_MDE_STAGE_N];
    unsigned int        out_deg[TSAPI_MDE_STAGE_N];
    unsigned int        dummy_in[TSAPI_MDE_STAGE_N];
    unsigned int        dummy_out[TSAPI_MDE_STAGE_N];
    bool                hosts_script = false;
    unsigned int        n_edges = 0;
    const char         *why;
    te_mi_logger       *logger = NULL;
    unsigned int        v;
    unsigned int        w;
    unsigned int        k;

    TEST_START;
    tsapi_mde_report_init(&report);
    report_up = true;
    graph_libs_init(&libs);
    for (v = 0; v < TSAPI_MDE_STAGE_N; v++)
        strs[v] = (te_string)TE_STRING_INIT;
    libs_up = true;
    memset(&g, 0, sizeof(g));
    memset(&planted, 0, sizeof(planted));

    TEST_STEP("Parse test parameters");
    TEST_GET_ENUM_PARAM(view, CC_VIEW_LIST);

    TEST_STEP("Open a session and locate the example");
    TSAPI_MDE_OPEN_OR_SKIP(session, "cycle_closure", dut, session_up);

    TEST_STEP("Skip unless the binary tools are available");
    why = graph_tools_unavailable(&session,
                                  strcmp(dut.dylib_ext, "dylib") == 0);
    if (why != NULL)
        TEST_SKIP("%s", why);
    if (view == CC_VIEW_FULL && !tsapi_mde_have(&session, "strings"))
        TEST_SKIP("strings is not available on the agent");

    TEST_STEP("Read the linkage of every ring library");
    CHECK_RC(graph_libs_load(&session, &dut, &libs));
    for (v = 0; v < TSAPI_MDE_STAGE_N; v++)
    {
        if (!libs.lib[v].present)
            TEST_SKIP("%s is missing - build the example first",
                      libs.lib[v].name);
    }
    graph_chart_counts(&libs);

    TEST_STEP("Load-time edges");
    for (v = 0; v < TSAPI_MDE_STAGE_N; v++)
    {
        for (w = 0; w < TSAPI_MDE_STAGE_N; w++)
        {
            if (v != w && graph_needs(&libs.lib[v], w))
                g.edge[v][w] |= EDGE_NEEDED;
        }
    }

    if (view == CC_VIEW_FULL)
    {
        TEST_STEP("Run-time edges: undefined symbols resolved against "
                  "exports, contract names looked up by string");
        for (v = 0; v < TSAPI_MDE_STAGE_N; v++)
        {
            te_string path = TE_STRING_INIT;

            /* Contract names in the binary, single-byte and UTF-16LE. */
            tsapi_mde_dut_lib_path(&dut, libs.lib[v].name, &path);
            if (tsapi_mde_sh(&session, 60000, &res,
                             "{ strings -a '%s'; strings -a -el '%s'; } | "
                             "grep -E -x '(cpp|rust|go|cs|py)_(step|weight)'"
                             " | sort -u", path.ptr, path.ptr) == 0)
            {
                te_string_append(&strs[v], "\n%s", graph_str(&res.out));
            }
            RING("%s names ring symbols:%s", libs.lib[v].name,
                 graph_str(&strs[v]));
            te_string_free(&path);

            for (w = 0; w < TSAPI_MDE_STAGE_N; w++)
            {
                if (w == v)
                    continue;
                for (k = 0; k < 2; k++)
                {
                    char sym[32];

                    graph_sym(w, k == 0, sym, sizeof(sym));
                    if (graph_list_has(&libs.lib[v].undef, sym))
                    {
                        if (graph_list_has(&libs.lib[w].exports, sym))
                        {
                            g.edge[v][w] |= EDGE_UNDEF;
                        }
                        else
                        {
                            char subject[64];

                            TE_SPRINTF(subject, "%s:%s", libs.lib[v].name,
                                       sym);
                            tapi_cybersec_report_add(
                                &report.cyber, TAPI_CYBERSEC_SEV_HIGH,
                                "graph.unresolved-symbol", subject,
                                "undefined, and lib%score does not export "
                                "it", tsapi_mde_stage2str(w));
                        }
                    }
                    else if (graph_list_has(&strs[v], sym) &&
                             !graph_list_has(&libs.lib[v].exports, sym))
                    {
                        g.edge[v][w] |= EDGE_DLSYM;
                    }
                }
            }
        }

        TEST_STEP("Run-time edges of the Python stage: ring_stage.py, "
                  "hosted by libpycore");
        {
            te_string path = TE_STRING_INIT;

            tsapi_mde_dut_lib_path(&dut, "libpycore", &path);
            if (tsapi_mde_sh(&session, 20000, &res,
                             "strings -a '%s' | grep -c ring_stage",
                             path.ptr) == 0)
                hosts_script = atoi(graph_str(&res.out)) > 0;
            te_string_free(&path);
            TEST_ARTIFACT("libpycore %s ring_stage",
                          hosts_script ? "hosts" : "does not name");

            if (hosts_script &&
                tsapi_mde_sh(&session, 10000, &res, "cat '%s/ring_stage.py'",
                             dut.python) == 0 && tsapi_mde_sh_ok(&res))
            {
                te_string_append(&script, "%s", graph_str(&res.out));
                for (w = 0; w < TSAPI_MDE_STAGE_N; w++)
                {
                    if (w == TSAPI_MDE_STAGE_PY)
                        continue;
                    for (k = 0; k < 2; k++)
                    {
                        char sym[32];

                        graph_sym(w, k == 0, sym, sizeof(sym));
                        if (strstr(script.ptr, sym) != NULL)
                            g.edge[TSAPI_MDE_STAGE_PY][w] |= EDGE_SCRIPT;
                    }
                }
            }
        }
    }

    TEST_STEP("Emit the graph as DOT");
    te_string_append(&dot, "digraph ring {\n");
    te_string_append(&dot_line, "digraph ring {");
    for (v = 0; v < TSAPI_MDE_STAGE_N; v++)
    {
        for (w = 0; w < TSAPI_MDE_STAGE_N; w++)
        {
            char kinds[64];

            if (v == w || g.edge[v][w] == 0)
                continue;
            n_edges++;
            cc_kinds(g.edge[v][w], kinds, sizeof(kinds));
            te_string_append(&dot, "  %s -> %s [label=\"%s\"];\n",
                             tsapi_mde_stage2str(v), tsapi_mde_stage2str(w),
                             kinds);
            te_string_append(&dot_line, " %s->%s[%s];",
                             tsapi_mde_stage2str(v), tsapi_mde_stage2str(w),
                             kinds);
        }
    }
    te_string_append(&dot, "}\n");
    te_string_append(&dot_line, " }");
    RING("Ring dependency graph (%s view):\n%s",
         view == CC_VIEW_FULL ? "full" : "needed", dot.ptr);
    TEST_ARTIFACT("DOT (%s view, %u edge(s)): %s",
                  view == CC_VIEW_FULL ? "full" : "needed", n_edges,
                  dot_line.ptr);

    te_string_append(&dot_path, "/tmp/mde-graph-cycle_closure-%s.dot",
                     view == CC_VIEW_FULL ? "full" : "needed");
    if (tsapi_mde_sh(&session, 10000, &res,
                     "cat > '%s' <<'MDE_DOT_EOF'\n%sMDE_DOT_EOF\n"
                     "wc -c < '%s'; (sha256sum '%s' 2>/dev/null || "
                     "shasum -a 256 '%s') | awk '{print $1}'",
                     dot_path.ptr, dot.ptr, dot_path.ptr, dot_path.ptr,
                     dot_path.ptr) == 0 && tsapi_mde_sh_ok(&res))
    {
        TEST_ARTIFACT("DOT file %s: %s", dot_path.ptr, graph_str(&res.out));
    }

    TEST_STEP("Known-bad control and the shape checks");
    if (view == CC_VIEW_NEEDED)
    {
        /* Plant go -> cpp at load time: the cycle the build must avoid. */
        planted = g;
        planted.edge[TSAPI_MDE_STAGE_GO][TSAPI_MDE_STAGE_CPP] |= EDGE_NEEDED;
        planted.edge[TSAPI_MDE_STAGE_CPP][TSAPI_MDE_STAGE_RUST] |= EDGE_NEEDED;
        planted.edge[TSAPI_MDE_STAGE_RUST][TSAPI_MDE_STAGE_GO] |= EDGE_NEEDED;
        cc_check_needed(&planted, "control/", &report.cyber);
        tsapi_mde_report_expect(&report, "graph.needed-cycle",
                                "control/needed-graph");
        graph_report_drop_prefix(&report, "control/");

        cc_check_needed(&g, "", &report.cyber);
    }
    else
    {
        /* The full ring with cs -> py removed. */
        for (v = 0; v < TSAPI_MDE_STAGE_N; v++)
        {
            planted.edge[v][(v + 1) % TSAPI_MDE_STAGE_N] = EDGE_NEEDED;
            planted.edge[v][cc_chord(v)] = EDGE_NEEDED;
        }
        planted.edge[TSAPI_MDE_STAGE_CS][TSAPI_MDE_STAGE_PY] = 0;
        cc_check_full(&planted, "control/", &report.cyber, dummy_in,
                      dummy_out);
        tsapi_mde_report_expect(&report, "graph.cycle-edge-missing",
                                "control/cs->py");
        graph_report_drop_prefix(&report, "control/");

        cc_check_full(&g, "", &report.cyber, in_deg, out_deg);
    }

    TEST_STEP("Chart in- and out-degree per library");
    if (view == CC_VIEW_NEEDED)
    {
        for (v = 0; v < TSAPI_MDE_STAGE_N; v++)
            in_deg[v] = out_deg[v] = 0;
        for (v = 0; v < TSAPI_MDE_STAGE_N; v++)
        {
            for (w = 0; w < TSAPI_MDE_STAGE_N; w++)
            {
                if (v != w && g.edge[v][w] != 0)
                {
                    out_deg[v]++;
                    in_deg[w]++;
                }
            }
        }
    }
    if (tsapi_mde_mi_create("graph", &logger) == 0)
    {
        te_mi_logger_add_meas_key(logger, NULL, "view", "%s",
                                  view == CC_VIEW_FULL ? "full" : "needed");
        for (v = 0; v < TSAPI_MDE_STAGE_N; v++)
        {
            char key[16];

            TE_SPRINTF(key, "x%u", v);
            te_mi_logger_add_meas_key(logger, NULL, key, "%s",
                                      libs.lib[v].name);
            te_mi_logger_add_meas(logger, NULL, TE_MI_MEAS_UNITLESS_VALUE,
                                  "library", TE_MI_MEAS_AGGR_SINGLE, v,
                                  TE_MI_MEAS_MULTIPLIER_PLAIN);
            te_mi_logger_add_meas(logger, NULL, TE_MI_MEAS_UNITLESS_VALUE,
                                  "in_degree", TE_MI_MEAS_AGGR_SINGLE,
                                  in_deg[v], TE_MI_MEAS_MULTIPLIER_PLAIN);
            te_mi_logger_add_meas(logger, NULL, TE_MI_MEAS_UNITLESS_VALUE,
                                  "out_degree", TE_MI_MEAS_AGGR_SINGLE,
                                  out_deg[v], TE_MI_MEAS_MULTIPLIER_PLAIN);
            TEST_ARTIFACT("%s: in-degree %u, out-degree %u", libs.lib[v].name,
                          in_deg[v], out_deg[v]);
        }
        tsapi_mde_mi_line(logger, "degree", "In- and out-degree per ring "
                          "library", "library", "in_degree", "out_degree",
                          NULL);
        te_mi_logger_destroy(logger);
        logger = NULL;
    }

    TEST_STEP("Decide on the findings");
    TSAPI_MDE_REPORT_GATE(&report, "graph", TAPI_CYBERSEC_SEV_HIGH);

    TEST_SUCCESS;

cleanup:

    if (logger != NULL)
        te_mi_logger_destroy(logger);
    tsapi_mde_sh_result_free(&res);
    if (libs_up)
    {
        graph_libs_free(&libs);
        for (v = 0; v < TSAPI_MDE_STAGE_N; v++)
            te_string_free(&strs[v]);
    }
    te_string_free(&script);
    te_string_free(&dot);
    te_string_free(&dot_line);
    te_string_free(&dot_path);
    if (report_up)
        tsapi_mde_report_free(&report);
    tsapi_mde_dut_free(&dut);
    if (session_up)
        tsapi_mde_session_fini(&session);

    TEST_END;
}
