cmake_minimum_required(VERSION 3.10)

project(secureP2P LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# ─── Hardened compiler flags ────────────────
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -Wextra -O2")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fstack-protector-strong")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -D_FORTIFY_SOURCE=2")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fPIE")
set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -g -fsanitize=address")

# ─── Hardened linker flags ──────────────────
set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -pie -Wl,-z,relro,-z,now,-z,noexecstack")

include_directories(include)

# Find required packages
find_package(PkgConfig REQUIRED)
find_package(OpenSSL REQUIRED)
pkg_check_modules(LIBOQS REQUIRED liboqs)

# ─── Shared source library (no main) ───────
add_library(secureP2P_lib STATIC
    src/server.cpp
    src/client.cpp
    src/crypto.cpp
    src/network.cpp
)

target_include_directories(secureP2P_lib PUBLIC
    ${CMAKE_SOURCE_DIR}/include
    ${OPENSSL_INCLUDE_DIR}
    ${LIBOQS_INCLUDE_DIRS}
)

target_link_libraries(secureP2P_lib
    ${OPENSSL_LIBRARIES}
    ${LIBOQS_LIBRARIES}
    pthread
)

target_link_directories(secureP2P_lib PUBLIC
    ${LIBOQS_LIBRARY_DIRS}
)

# ─── Main executable ───────────────────────
add_executable(secureP2P src/main.cpp)
target_link_libraries(secureP2P secureP2P_lib)

# ─── Test executable ───────────────────────
add_executable(secureP2P_tests tests/test_main.cpp)
target_link_libraries(secureP2P_tests secureP2P_lib)

enable_testing()
add_test(NAME SecureP2P_Tests COMMAND secureP2P_tests)

if(WIN32)
    target_link_libraries(secureP2P ws2_32)
    target_link_libraries(secureP2P_tests ws2_32)
endif()
