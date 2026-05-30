# Lattice

A small Windows internals exploration toolkit. Lattice is a user-mode console
application for inspecting the live state of a Windows system — processes,
threads, loaded modules, and selected pieces of system information exposed by
the Native API. It is meant as a learning/reference project for Windows system
programming.

## What it does

- Enumerates running processes (via the ToolHelp snapshot API).
- Lists loaded modules for a chosen process.
- Demonstrates a documented use of `NtQuerySystemInformation` to read basic
  system and performance information from `ntdll.dll`.

Everything Lattice does relies on standard, documented Windows interfaces and
information the calling user is already entitled to read. It does not modify
other processes, inject code, or touch the kernel.

## Building

Lattice targets Windows and requires the Windows SDK. It does **not** build on
Linux/macOS.

### Visual Studio (CMake)

```powershell
cmake -B build -G "Visual Studio 17 2022" -A x64
cmake --build build --config Release
```

The binary lands in `build\Release\lattice.exe`.

### Command line (MSVC)

```powershell
cl /EHsc /std:c++17 /Iinclude src\*.cpp /Fe:lattice.exe
```

## Usage

```text
lattice                 List all running processes.
lattice modules <pid>   List loaded modules for the given process ID.
lattice sysinfo         Print basic system information via the Native API.
```

## Layout

```
include/   Public headers
src/       Implementation
```

## Status

Early scaffold. See open work in the issue tracker.
