FILE(GLOB_RECURSE app_sources ${CMAKE_CURRENT_SOURCE_DIR}/src/*.*)
if(ESP_PLATFORM)
idf_component_register(
        SRCS ${app_sources}
        REQUIRES nvs_flash
        PRIV_REQUIRES mbedtls libsodium cbor format
        INCLUDE_DIRS ${CMAKE_CURRENT_SOURCE_DIR}/include
        PRIV_INCLUDE_DIRS ${CMAKE_CURRENT_SOURCE_DIR}/priv)
target_compile_definitions(${COMPONENT_LIB} PUBLIC "-DLOG_LOCAL_LEVEL=ESP_LOG_VERBOSE")
else()
project(HK-HomeKit-Lib)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
include(FetchContent)

# 1. Declare the dependency
FetchContent_Declare(
    tinycbor
    GIT_REPOSITORY https://github.com/intel/tinycbor.git
    GIT_TAG        main
)

# 2. Make it available
FetchContent_MakeAvailable(tinycbor)
add_library(HK-HomeKit-Lib STATIC ${app_sources})
target_include_directories(HK-HomeKit-Lib PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_include_directories(HK-HomeKit-Lib PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/priv)
target_link_libraries(HK-HomeKit-Lib mbedtls mbedcrypto sodium fmt tinycbor)
endif()
