# Copyright (C) 2026 Maxim Menshikov

# Every test here is a standalone executable sharing webdeps_lib.h. See
# package.xml. No group prologue/epilogue: a setup problem must never fail
# the session.
tests = [
    't_h1_gateway_bad_input',
    't_h2_go_slow_client',
    't_h3_cs_swallowed_error',
    't_h4_binscan_netexpose_egress',
    't_h5_go_contract_limits',
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
