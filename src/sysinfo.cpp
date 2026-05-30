// Lattice - basic system information via the Native API.
//
// Demonstrates a documented use of NtQuerySystemInformation from ntdll. We ask
// for SystemBasicInformation, a stable, well-known class describing the CPU and
// memory layout of the machine. The struct shape below matches the public WDK
// definition.

#include <windows.h>

#include <cstdio>

#include "lattice.h"

namespace {

// SYSTEM_INFORMATION_CLASS value for the basic information block.
constexpr unsigned long kSystemBasicInformation = 0;

// Mirrors SYSTEM_BASIC_INFORMATION from the WDK headers.
struct SystemBasicInformation {
    unsigned long Reserved;
    unsigned long TimerResolution;
    unsigned long PageSize;
    unsigned long NumberOfPhysicalPages;
    unsigned long LowestPhysicalPageNumber;
    unsigned long HighestPhysicalPageNumber;
    unsigned long AllocationGranularity;
    ULONG_PTR MinimumUserModeAddress;
    ULONG_PTR MaximumUserModeAddress;
    ULONG_PTR ActiveProcessorsAffinityMask;
    char NumberOfProcessors;
};

using NtQuerySystemInformationFn = long(__stdcall*)(unsigned long, void*,
                                                    unsigned long,
                                                    unsigned long*);

}  // namespace

namespace lattice {

int print_system_info() {
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    if (ntdll == nullptr) {
        std::fprintf(stderr, "GetModuleHandleW(ntdll) failed: %lu\n",
                     GetLastError());
        return 1;
    }

    auto query = reinterpret_cast<NtQuerySystemInformationFn>(
        GetProcAddress(ntdll, "NtQuerySystemInformation"));
    if (query == nullptr) {
        std::fprintf(stderr, "NtQuerySystemInformation not found\n");
        return 1;
    }

    SystemBasicInformation info{};
    unsigned long returned = 0;
    long status = query(kSystemBasicInformation, &info, sizeof(info), &returned);
    if (status < 0) {
        std::fprintf(stderr, "NtQuerySystemInformation failed: 0x%08lx\n",
                     static_cast<unsigned long>(status));
        return 1;
    }

    std::printf("Processors:            %d\n", info.NumberOfProcessors);
    std::printf("Page size:             %lu bytes\n", info.PageSize);
    std::printf("Allocation granularity: %lu bytes\n",
                info.AllocationGranularity);
    std::printf("Physical pages:        %lu\n", info.NumberOfPhysicalPages);
    std::printf("Min user address:      0x%016llx\n",
                static_cast<unsigned long long>(info.MinimumUserModeAddress));
    std::printf("Max user address:      0x%016llx\n",
                static_cast<unsigned long long>(info.MaximumUserModeAddress));
    return 0;
}

}  // namespace lattice
