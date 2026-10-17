# Copyright (C) 2026 Maxim Menshikov
project('multi-dependency-example-ts', 'c',
    version: '1.0.0',
    default_options: 'werror=true'
)
te_path = get_option('te_path')
te_libdir = get_option('te_libdir')
add_project_arguments(get_option('te_cflags').split(), language: 'c')
add_project_link_arguments(get_option('te_ldflags').split(), language: 'c')

cc = meson.get_compiler('c')

te_tests_info_sh = find_program(join_paths(te_path, 'te_tests_info.sh'))

test_deps = [
    dependency('threads'),
    dependency('openssl'),
    dependency('zlib'),
    cc.find_library('m'),
]

# The tsf-* libraries come first: a dependant has to be named before what
# it depends on, and every one of them builds on tapi_cybersec, tapi_kernel
# and tapi_devtool (or on TE alone).
te_libs = [
    'tapi_playwright',
    'tapi_http',
    'tapi_fuzz',
    'tapi_memmap',
    'tapi_fs',
    'tapi_container',
    'tapi_package',
    'tapi_cybersec',
    'tapi_kernel',
    'tapi_devtool',
    'tapi_env',
    'tapi_job',
    'tapi_rpc',
    'rcfrpc',
    'tapi',
    'confapi',
    'conf_oid',
    'rcfapi',
    'rpcxdr',
    'rpc_types',
    'logger_ten',
    'ipc',
    'tools',
    'tapi_tad',
    'ndn',
    'asn',
    'logger_core',
]

foreach lib : te_libs
    test_deps += cc.find_library(lib, dirs: te_libdir)
endforeach

lib_dir = include_directories('lib')

# The line below would produce empty dependencies on systems
# having no tirpc - it is not a problem.
dep_tirpc = dependency('libtirpc', required: false)

test_deps += [ dep_tirpc ]

subdir('lib')

test_deps += declare_dependency(include_directories: lib_dir,
                                link_with: [ ts_lib ])


tests = [ 'prologue', 'epilogue' ]

package_dir = 'multi-dependency-example-ts'
package_tests_c = []

foreach test : tests
    test_exe = test
    test_c = test + '.c'
    package_tests_c += [ test_c ]
    executable(test_exe, test_c, install: true, install_dir: package_dir,
               dependencies: test_deps)
endforeach

install_data([ 'mainpage.dox', 'package.xml' ],
             install_dir: package_dir)

mydir = package_dir

package_dir = join_paths(mydir, 'ring')
package_tests_c = []
subdir('ring')

package_dir = join_paths(mydir, 'web')
package_tests_c = []
subdir('web')

package_dir = join_paths(mydir, 'graph')
package_tests_c = []
subdir('graph')

package_dir = join_paths(mydir, 'package')
package_tests_c = []
subdir('package')

package_dir = join_paths(mydir, 'devtool')
package_tests_c = []
subdir('devtool')

package_dir = join_paths(mydir, 'fs')
package_tests_c = []
subdir('fs')

package_dir = join_paths(mydir, 'memmap')
package_tests_c = []
subdir('memmap')

package_dir = join_paths(mydir, 'binary')
package_tests_c = []
subdir('binary')

package_dir = join_paths(mydir, 'exposure')
package_tests_c = []
subdir('exposure')

package_dir = join_paths(mydir, 'http')
package_tests_c = []
subdir('http')

package_dir = join_paths(mydir, 'container')
package_tests_c = []
subdir('container')

package_dir = join_paths(mydir, 'fuzz')
package_tests_c = []
subdir('fuzz')

package_dir = join_paths(mydir, 'browser')
package_tests_c = []
subdir('browser')
