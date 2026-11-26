# Copyright (C) 2026 midair <midair@localhost>

# The ts_diag, ts_build, ts_h1_listing, ts_h2_build_guess, ts_contract, ts_h3_same_output,
# ts_robust and ts_h4_port_badinput use only tsd.h and tsd_net.h; the others tsx_lib.h.
# See package.xml. The group prologue only checks the tools; they are
# installed by scripts/midair-setup.sh.
tests = [
    'prologue',
    'ts_diag',
    'ts_control_known_bad',
    'ts_build',
    'ts_run_guess',
    'ts_contract',
    'ts_robust',
    'ts_h1_listing',
    'ts_h2_build_guess',
    'ts_h3_same_output',
    'ts_h4_port_badinput',
]

foreach test : tests
    test_exe = test
    test_c = test + '.c'
    package_tests_c += [ test_c ]
    executable(test_exe, test_c, install: true, install_dir: package_dir,
               dependencies: test_deps)
endforeach

install_data(['package.xml'], install_dir: package_dir)
