# Copyright (C) 2026 midair <midair@localhost>

# The ts_*  tests share tsx_lib.h (the ts_h* tests also tsh_lib.h) and the runner of webdeps/ts_lib.h.
# See package.xml. The group prologue only checks the tools; they are
# installed by scripts/midair-setup.sh.
tests = [
    'prologue',
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
