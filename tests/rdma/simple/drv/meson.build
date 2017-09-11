e = executable('kmtdrv', 'amdp2ptest.c',
		include_directories : inc,
		link_with : hsakmtlib,
		link_args : '-ldl')

test('hsakmt-amdp2p', e)
