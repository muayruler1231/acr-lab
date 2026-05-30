#pragma once

// Lattice - Windows internals exploration toolkit.
//
// Public surface shared across translation units. Keep this header free of
// implementation detail; it only declares the operations the CLI dispatches to.

namespace lattice {

// Enumerate every process visible to the caller and print a pid / name table.
// Returns 0 on success, non-zero on failure.
int list_processes();

// List the loaded modules for the process identified by `pid`.
// Returns 0 on success, non-zero on failure.
int list_modules(unsigned long pid);

// Print basic system information sourced from the Native API.
// Returns 0 on success, non-zero on failure.
int print_system_info();

}  // namespace lattice
