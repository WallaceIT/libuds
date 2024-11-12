pkgconfig = import('pkgconfig')

libuds_sources = ['uds.c']
udslib = library('uds',
                 libuds_sources,
                 version: '0.0.1',
                 soversion: 0,
                 include_directories : incdir,
                 install : true)

pkgconfig.generate(udslib)
