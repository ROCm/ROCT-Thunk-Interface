project('libhsakmt', 'c')

subdir('include')
subdir('src')
subdir('tests')

pkg_mod = import('pkgconfig')
pkg_mod.generate(libraries : hsakmtlib,
                 version : '1.0',
                 name : 'libhsakmt',
                 filebase : 'hsakmt',
                 description : 'AMD Thunk Interface Library.')
