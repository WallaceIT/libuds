
set(SOURCES
    uds.c
)

add_library(uds SHARED ${SOURCES})
target_include_directories(uds PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
