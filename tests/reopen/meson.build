cc = meson.get_compiler('c')
libdl = cc.find_library('dl')

e = executable('kmtreopen', 'kmtreopen.c',
		include_directories : inc,
		link_with : hsakmtlib,
		dependencies : [libdl])

test('hsakmt-reopen', e)
