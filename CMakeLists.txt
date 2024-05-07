FILE(GLOB_RECURSE app_sources ${CMAKE_CURRENT_SOURCE_DIR}/src/*.*)

idf_component_register(
        SRCS ${app_sources}
        REQUIRES libsodium cbor jsoncons
        INCLUDE_DIRS "include")
