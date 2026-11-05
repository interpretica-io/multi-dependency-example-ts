# Copyright (C) 2026 Maxim Menshikov

tests = [
    'prologue',
    'epilogue',
    'webdeps_gw_no_backends',
    'webdeps_gw_bad_backend',
    'webdeps_gw_recovery',
    'webdeps_go_stalled_peer',
    'webdeps_cs_stalled_peer',
    'webdeps_masked_error',
    'webdeps_contract_violation',
    'webdeps_listen_surface',
    'webdeps_egress',
    'webdeps_port_conflict',
]

foreach test : tests
    test_exe = test
    test_c = test + '.c'
    package_tests_c += [ test_c ]
    executable(test_exe, test_c, install: true, install_dir: package_dir,
               dependencies: test_deps)
endforeach

install_data(['package.xml'], install_dir: package_dir)
