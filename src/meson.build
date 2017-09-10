# Static map file
mapfile = 'libhsakmt.ver'
vflag = '-Wl,--version-script,@0@/@1@'.format(meson.current_source_dir(), mapfile)

deps = dependency('libpci')

srcs = ['debug.c', 'events.c', 'fmm.c',
  'globals.c', 'libhsakmt.c', 'memory.c',
  'openclose.c', 'perfctr.c', 'pmc_table.c',
  'queues.c', 'time.c', 'topology.c', 'version.c'
]

hsakmtlib = shared_module('hsakmt',
  sources: srcs, link_args : vflag,
  include_directories : inc,
  dependencies : deps,
  install : true)
