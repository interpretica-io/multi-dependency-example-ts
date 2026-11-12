# Copyright (C) 2026 Maxim Menshikov

# Every test here is a standalone executable sharing webdeps_lib.h. See
# package.xml. The group prologue installs the toolchains and builds the
# example.
tests = [
    'prologue',
    't10_build_rust',
    't10_build_go',
    't10_build_cs',
    't10_build_cpp',
    't10_build_c',
    't10_build_python',
    't4_binscan',
    't11_rust_panic',
    't12_go_idle',
    't13_cs_swallow',
    't5_egress',
    't9_go_contract',
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
