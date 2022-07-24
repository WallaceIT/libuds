
project('uds', 'c',
        version : '0.0.1',
        license : 'MIT',
        default_options: ['buildtype=debugoptimized',
                          'default_library=shared',
                          'warning_level=2'])

incdir = include_directories('include')

subdir('include')
subdir('lib')
subdir('example')

doxygen = find_program('doxygen', required : false)
if not doxygen.found()
  warning('Doxygen not found, documentation will not be generated.')
else

doc_cdata = configuration_data()
doc_cdata.set('VERSION', meson.project_version())

if find_program('dot', required : false).found()
  doc_cdata.set('HAVE_DOT', 'YES')
else
  doc_cdata.set('HAVE_DOT', 'NO')
endif

subdir('doc')
endif
