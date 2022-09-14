cmake_minimum_required(VERSION 3.13)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED True)
set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -ggdb3 -O0 -Wall -Werror -Wno-sign-compare -Wno-unused-function -Wno-unused-variable")
set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} -O3 -Wall -Wno-sign-compare -Wno-unused-function -Wno-unused-variable")

project(RutokenTest VERSION 20220910.1)
add_executable(RutokenTest src/RutokenTest.cpp src/gnutls_crypto.cpp)

find_package(GnuTLS REQUIRED)
find_library(PKICORE_LIBRARY NAMES pki-core PATHS rutoken/lib REQUIRED)

target_compile_options(RutokenTest PRIVATE ${GNUTLS_DEFINITIONS})
target_include_directories(RutokenTest PRIVATE include ${GNUTLS_INCLUDE_DIR} src rutoken/include)
target_link_libraries(RutokenTest ${GNUTLS_LIBRARIES} ${PKICORE_LIBRARY} stdc++fs)
set_target_properties(RutokenTest PROPERTIES RUNTIME_OUTPUT_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR})
