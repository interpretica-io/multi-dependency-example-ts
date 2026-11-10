# Copyright (C) 2026 Maxim Menshikov

# Every test here is a standalone executable sharing webdeps_lib.h. See
# package.xml. No group prologue/epilogue: a setup problem must never fail
# the session.
tests = [
    'h1_gateway_panic',
    'h2_stalled_peer',
    'h3_csharp_bad_input',
    'h4_go_contract',
    'sec_binscan_netexpose_egress',
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
