
conf = configuration_data()
conf.set('UDS_CONFIG_NUM_PERIODIC_SLOTS', get_option('uds_periodic_slots'))
conf.set('UDS_CONFIG_ENABLE_TRACING', get_option('uds_enable_tracing'))

configure_file(input : 'uds_config.h.in',
               output : 'uds_config.h',
               configuration : conf,
               install_dir : get_option('includedir') / 'uds')

install_headers('uds.h', 'uds_context.h', 'uds_scaling.h', 'uds_types.h', subdir: 'uds')
