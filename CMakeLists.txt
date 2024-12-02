FILE(GLOB_RECURSE app_sources ${CMAKE_CURRENT_SOURCE_DIR}/src/*.*)

idf_component_register(
        SRCS ${app_sources}
        REQUIRES mbedtls libsodium cbor nvs_flash
        INCLUDE_DIRS ${CMAKE_CURRENT_SOURCE_DIR}/include)
