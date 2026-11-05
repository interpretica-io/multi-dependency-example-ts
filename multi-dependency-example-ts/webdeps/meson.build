# Copyright (C) 2026 Maxim Menshikov

# One small test, run once per hypothesis case (see package.xml).
# No group prologue/epilogue: a setup problem must never fail the session.
tests = [
    'webdeps_hyp',
]

foreach test : tests
    test_exe = test
    test_c = test + '.c'
    package_tests_c += [ test_c ]
    executable(test_exe, test_c, install: true, install_dir: package_dir,
               dependencies: test_deps)
endforeach

install_data(['package.xml'], install_dir: package_dir)
