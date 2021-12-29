
set(SOURCES
    main.c
)

add_executable(uds_example ${SOURCES})
target_link_libraries(uds_example uds)
