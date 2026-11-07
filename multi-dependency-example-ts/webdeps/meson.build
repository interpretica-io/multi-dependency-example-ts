# Copyright (C) 2026 Maxim Menshikov

# webdeps_hyp is run once per hypothesis case; the t_h* tests are standalone
# (they share webdeps_lib.h). See package.xml.
# No group prologue/epilogue: a setup problem must never fail the session.
tests = [
    'webdeps_hyp',
    't_h1_gateway_bad_input',
    't_h2_go_slow_client',
    't_h3_cs_swallowed_error',
    't_h4_binscan_netexpose_egress',
]

foreach test : tests
    test_exe = test
    test_c = test + '.c'
    package_tests_c += [ test_c ]
    executable(test_exe, test_c, install: true, install_dir: package_dir,
               dependencies: test_deps)
endforeach

install_data(['package.xml'], install_dir: package_dir)
