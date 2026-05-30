// Lattice - command-line entry point.
//
// Parses the subcommand and dispatches to the matching operation. Keeping the
// dispatch tiny here means each feature lives in its own translation unit.

#include <cstdio>
#include <cstdlib>
#include <cstring>

#include "lattice.h"

namespace {

void print_usage() {
    std::puts(
        "Lattice - Windows internals exploration toolkit\n"
        "\n"
        "Usage:\n"
        "  lattice                 List all running processes.\n"
        "  lattice modules <pid>   List loaded modules for the given PID.\n"
        "  lattice sysinfo         Print basic system information.\n");
}

}  // namespace

int main(int argc, char** argv) {
    if (argc < 2) {
        return lattice::list_processes();
    }

    if (std::strcmp(argv[1], "modules") == 0) {
        if (argc < 3) {
            std::fputs("error: 'modules' requires a <pid>\n", stderr);
            print_usage();
            return 2;
        }
        char* end = nullptr;
        unsigned long pid = std::strtoul(argv[2], &end, 10);
        if (end == argv[2] || *end != '\0') {
            std::fprintf(stderr, "error: invalid pid '%s'\n", argv[2]);
            return 2;
        }
        return lattice::list_modules(pid);
    }

    if (std::strcmp(argv[1], "sysinfo") == 0) {
        return lattice::print_system_info();
    }

    if (std::strcmp(argv[1], "-h") == 0 || std::strcmp(argv[1], "--help") == 0) {
        print_usage();
        return 0;
    }

    std::fprintf(stderr, "error: unknown command '%s'\n", argv[1]);
    print_usage();
    return 2;
}
