e = executable('rdma_test', 'rdma_test.cpp',
		include_directories : inc,
		link_with : hsakmtlib,
		link_args : '-ldl')

test('hsakmt-rdma_test', e)
