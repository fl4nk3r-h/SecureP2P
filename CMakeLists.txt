cmake_minimum_required(VERSION 3.10)

project(secureP2P LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

include_directories(include)

add_executable(secureP2P
    src/main.cpp
    src/server.cpp
    src/client.cpp
)

if(WIN32)
    target_link_libraries(secureP2P ws2_32)
endif()
