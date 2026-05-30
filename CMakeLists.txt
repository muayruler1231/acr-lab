cmake_minimum_required(VERSION 3.20)

project(lattice LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

if(NOT WIN32)
    message(FATAL_ERROR "Lattice targets Windows and requires the Windows SDK.")
endif()

add_executable(lattice
    src/main.cpp
    src/process_enum.cpp
    src/sysinfo.cpp
)

target_include_directories(lattice PRIVATE include)

# ntdll for the Native API entry points used in sysinfo.cpp
target_link_libraries(lattice PRIVATE ntdll)
