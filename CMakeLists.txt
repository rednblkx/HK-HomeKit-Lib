FILE(GLOB_RECURSE app_sources ${CMAKE_CURRENT_SOURCE_DIR}/src/*.*)

idf_component_register(
        SRCS ${app_sources}
        REQUIRES nvs_flash
        PRIV_REQUIRES mbedtls libsodium cbor format
        INCLUDE_DIRS ${CMAKE_CURRENT_SOURCE_DIR}/include
        PRIV_INCLUDE_DIRS ${CMAKE_CURRENT_SOURCE_DIR}/priv)
