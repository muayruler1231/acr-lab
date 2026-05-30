// Lattice - process and module enumeration via the ToolHelp snapshot API.
//
// CreateToolhelp32Snapshot gives a consistent point-in-time view of processes
// and the modules loaded into a given process. These are documented Win32 APIs
// and require no special privilege to read the caller's own session.

#include <windows.h>
#include <tlhelp32.h>

#include <cstdio>

#include "lattice.h"

namespace lattice {

int list_processes() {
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
        std::fprintf(stderr, "CreateToolhelp32Snapshot failed: %lu\n",
                     GetLastError());
        return 1;
    }

    PROCESSENTRY32W entry;
    entry.dwSize = sizeof(entry);

    if (!Process32FirstW(snapshot, &entry)) {
        std::fprintf(stderr, "Process32FirstW failed: %lu\n", GetLastError());
        CloseHandle(snapshot);
        return 1;
    }

    std::printf("%-8s %-8s %s\n", "PID", "PPID", "NAME");
    do {
        std::printf("%-8lu %-8lu %ws\n", entry.th32ProcessID,
                    entry.th32ParentProcessID, entry.szExeFile);
    } while (Process32NextW(snapshot, &entry));

    CloseHandle(snapshot);
    return 0;
}

int list_modules(unsigned long pid) {
    HANDLE snapshot =
        CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
    if (snapshot == INVALID_HANDLE_VALUE) {
        std::fprintf(stderr,
                     "CreateToolhelp32Snapshot failed for pid %lu: %lu\n", pid,
                     GetLastError());
        return 1;
    }

    MODULEENTRY32W entry;
    entry.dwSize = sizeof(entry);

    if (!Module32FirstW(snapshot, &entry)) {
        std::fprintf(stderr, "Module32FirstW failed: %lu\n", GetLastError());
        CloseHandle(snapshot);
        return 1;
    }

    std::printf("%-18s %-10s %s\n", "BASE", "SIZE", "MODULE");
    do {
        std::printf("0x%016llx %-10lu %ws\n",
                    reinterpret_cast<unsigned long long>(entry.modBaseAddr),
                    entry.modBaseSize, entry.szModule);
    } while (Module32NextW(snapshot, &entry));

    CloseHandle(snapshot);
    return 0;
}

}  // namespace lattice
