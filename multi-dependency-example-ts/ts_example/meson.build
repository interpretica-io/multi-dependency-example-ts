# Copyright (C) 2026 midair <midair@localhost>

# ts_robust and ts_h4_port_badinput use only tsd.h and tsd_net.h; the others tsx_lib.h.
# See package.xml. The group prologue only checks the tools; they are
# installed by scripts/midair-setup.sh.
tests = [
    'prologue',
    'ts_diag',
    'ts_control_known_bad',
    'ts_build',
    'ts_run_guess',
    'ts_ref_each_alone',
    'ts_bad_input',
    'ts_contract',
    'ts_slow_peer',
    'ts_robust',
    'ts_build_run',
    'ts_service_contract',
    'ts_vs_go_parity',
    'ts_h1_listing',
    'ts_h2_build_guess',
    'ts_h4_port_badinput',
    'ts_guess_default',
    'ts_guess_bad_input',
    'ts_serve_http',
    'service_ts_upstream_errors',
    'ts_demo_runs',
    'ts_env_failfast',
    'ts_ring_format',
    'ts_server_robust',
]

foreach test : tests
    test_exe = test
    test_c = test + '.c'
    package_tests_c += [ test_c ]
    executable(test_exe, test_c, install: true, install_dir: package_dir,
               dependencies: test_deps)
endforeach

install_data(['package.xml'], install_dir: package_dir)
