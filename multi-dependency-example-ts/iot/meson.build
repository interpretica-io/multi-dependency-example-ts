# Copyright (C) 2026 Maxim Menshikov

tests = [
    'prologue',
    'epilogue',
    'frames_802154',
    'frames_lorawan',
    'sdr',
    'can_bus',
    'bluetooth',
]

foreach test : tests
    test_exe = test
    test_c = test + '.c'
    package_tests_c += [ test_c ]
    executable(test_exe, test_c, install: true, install_dir: package_dir,
               dependencies: test_deps)
endforeach

install_data(['package.xml'], install_dir: package_dir)
