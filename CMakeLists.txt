cmake_minimum_required (VERSION 3.22)

project(JobberWS)

set (JobberWS_VERSION_MAJOR 0)
set (JobberWS_VERSION_MINOR 1)
set (JobberWS_VERSION_PATCH 0)

LIST(APPEND CMAKE_MODULE_PATH "${PROJECT_SOURCE_DIR}/modules")

configure_file (
  "${PROJECT_SOURCE_DIR}/src/version.h.in"
  "${PROJECT_BINARY_DIR}/version.h"
)

set (MAIN_SOURCES
    "${PROJECT_SOURCE_DIR}/src/http.c"
    "${PROJECT_SOURCE_DIR}/src/crypt_sha256.c"
    "${PROJECT_SOURCE_DIR}/src/base64.c")
source_group ("Source Files\\main" FILES ${MAIN_SOURCES})

include_directories (
    ${PROJECT_BINARY_DIR}
    "${PROJECT_SOURCE_DIR}/src"
)

add_executable(jobberws
	       ${MAIN_SOURCES})

find_package(Lua 5.4 REQUIRED)
include_directories(${LUA_INCLUDE_DIR})
target_link_libraries(jobberws ${LUA_LIBRARY})

find_package(microhttpd REQUIRED)
include_directories(${MICROHTTPD_INCLUDE_DIR})
target_link_libraries(jobberws ${MICROHTTPD_LIBRARY})

find_package(MySQL REQUIRED)
include_directories(${MYSQL_INCLUDE_DIR})
target_link_libraries(jobberws ${MYSQL_LIBRARY})

find_package(JANSSON REQUIRED)
include_directories(${JANSSON_INCLUDE_DIR})
target_link_libraries(jobberws ${JANSSON_LIBRARY})
