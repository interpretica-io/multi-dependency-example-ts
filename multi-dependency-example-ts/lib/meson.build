# Copyright (C) 2026 Maxim Menshikov

sources = [
    'tsapi_evo.c',
    'tsapi_mde.c',
    'tsapi_mde_mi.c',
    'tsapi_mde_report.c',
    'tsapi_mde_ring.c',
    'tsapi_mde_web.c',
]

ts_lib = static_library('ts_lib', sources,
                        dependencies: test_deps,
                        include_directories: lib_dir)
