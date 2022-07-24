doc_cdata.set('TOP_SRCDIR', meson.source_root())
doc_cdata.set('TOP_BUILDDIR', meson.build_root())

doxyfile = configure_file(input: 'Doxyfile.in',
                          output: 'Doxyfile',
                          configuration: doc_cdata,
                          install: false)

datadir = join_paths(get_option('datadir'), 'doc', 'uds')

html_target = custom_target('uds-docs',
                            input: doxyfile,
                            output: 'html',
                            command: [doxygen, doxyfile],
                            install: true,
                            install_dir: datadir)
