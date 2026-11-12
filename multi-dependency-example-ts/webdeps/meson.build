# Copyright (C) 2026 Maxim Menshikov

# Every test here is a standalone executable sharing webdeps_lib.h. See
# package.xml. The group prologue installs the toolchains and builds the
# example.
tests = [
    'prologue',
    't1_gateway_bad_request',
    't2_slow_connections',
    't3_egress',
    't4_language_builds',
    't5_binscan',
    't6_skip_causes',
    's_rust',
    's_go',
    's_cs',
    's_cpp',
    's_c',
]

foreach test : tests
    test_exe = test
    test_c = test + '.c'
    package_tests_c += [ test_c ]
    executable(test_exe, test_c, install: true, install_dir: package_dir,
               dependencies: test_deps)
endforeach

install_data(['package.xml'], install_dir: package_dir)
