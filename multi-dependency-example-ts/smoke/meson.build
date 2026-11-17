# Copyright (C) 2026 midair <midair@localhost>

# One test, no service: it only reports a verdict. See package.xml.
tests = [
    't0_smoke',
]

foreach test : tests
    test_exe = test
    test_c = test + '.c'
    package_tests_c += [ test_c ]
    executable(test_exe, test_c, install: true, install_dir: package_dir,
               dependencies: test_deps)
endforeach

install_data(['package.xml'], install_dir: package_dir)
