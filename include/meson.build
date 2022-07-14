install_headers('uds.h')

conf = configuration_data()
conf.set('uds_periodic_slots', get_option('uds_periodic_slots'))

c_file = configure_file(input : 'uds_config.h.in',
                        output : 'uds_config.h',
                        configuration : conf)
