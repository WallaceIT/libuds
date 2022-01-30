
SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Wextra -Wpedantic")

set(SOURCES
    uds.c
)

add_library(uds SHARED ${SOURCES})
target_include_directories(uds PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
