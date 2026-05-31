// beacon.h — CS beacon.h-compatible BOF API.
//
// This header provides the public ABI that Cobalt Strike BOFs expect.
// BOFs compiled against this header will run on Lattice's COFF loader
// without modification. The implementations of these functions are
// provided by coff_loader.c at load time.
//
// Source: Cobalt Strike beacon.h (public, widely redistributed). This is
// the minimal subset needed for community BOF compatibility.

#pragma once

#include <windows.h>
#include <stdarg.h>

// ---------------------------------------------------------------------------
// Output channel constants
// ---------------------------------------------------------------------------

#define CALLBACK_OUTPUT          0x0
#define CALLBACK_OUTPUT_OEM      0x1e
#define CALLBACK_ERROR           0xd
#define CALLBACK_OUTPUT_UTF8     0x20

// ---------------------------------------------------------------------------
// Data parser — used to read BOF arguments from the arg blob
// ---------------------------------------------------------------------------

typedef struct {
    char *original;
    char *buffer;
    int   length;
    int   size;
} datap;

DECLSPEC_IMPORT void   BeaconDataParse(datap *parser, char *buffer, int size);
DECLSPEC_IMPORT int    BeaconDataInt(datap *parser);
DECLSPEC_IMPORT short  BeaconDataShort(datap *parser);
DECLSPEC_IMPORT int    BeaconDataLength(datap *parser);
DECLSPEC_IMPORT char  *BeaconDataExtract(datap *parser, int *size);

// ---------------------------------------------------------------------------
// Format buffer — accumulates BOF output before sending
// ---------------------------------------------------------------------------

typedef struct {
    char *original;
    char *buffer;
    int   length;
    int   size;
} formatp;

DECLSPEC_IMPORT void   BeaconFormatAlloc(formatp *format, int maxsz);
DECLSPEC_IMPORT void   BeaconFormatReset(formatp *format);
DECLSPEC_IMPORT void   BeaconFormatFree(formatp *format);
DECLSPEC_IMPORT void   BeaconFormatAppend(formatp *format, char *text, int len);
DECLSPEC_IMPORT void   BeaconFormatPrintf(formatp *format, char *fmt, ...);
DECLSPEC_IMPORT char  *BeaconFormatToString(formatp *format, int *size);
DECLSPEC_IMPORT void   BeaconFormatInt(formatp *format, int value);

// ---------------------------------------------------------------------------
// Output functions
// ---------------------------------------------------------------------------

DECLSPEC_IMPORT void BeaconOutput(int type, const char *data, int len);
DECLSPEC_IMPORT void BeaconPrintf(int type, const char *fmt, ...);

// ---------------------------------------------------------------------------
// Utility
// ---------------------------------------------------------------------------

DECLSPEC_IMPORT BOOL  BeaconUseToken(HANDLE token);
DECLSPEC_IMPORT void  BeaconRevertToken(void);
DECLSPEC_IMPORT BOOL  BeaconIsAdmin(void);

// ---------------------------------------------------------------------------
// Spawn-to process (post-ex fork-and-run target)
// ---------------------------------------------------------------------------

DECLSPEC_IMPORT void BeaconGetSpawnTo(BOOL x86, char *buffer, int length);
DECLSPEC_IMPORT BOOL BeaconSpawnTemporaryProcess(BOOL x86, BOOL ignoreToken,
                                                 STARTUPINFO *si,
                                                 PROCESS_INFORMATION *pi);

// ---------------------------------------------------------------------------
// Injection helpers
// ---------------------------------------------------------------------------

DECLSPEC_IMPORT void BeaconInjectProcess(HANDLE hProc, int pid, char *payload,
                                         int p_len, int p_offset,
                                         char *arg, int a_len);
DECLSPEC_IMPORT void BeaconInjectTemporaryProcess(PROCESS_INFORMATION *pi,
                                                  char *payload, int p_len,
                                                  int p_offset,
                                                  char *arg, int a_len);
DECLSPEC_IMPORT void BeaconCleanupProcess(PROCESS_INFORMATION *pi);

// ---------------------------------------------------------------------------
// Win32 API wrappers — these go through the call-gate when enabled
// in the opsec_plane profile so that all WinAPI calls from BOFs share
// the same call-stack spoofing as the agent's own calls.
// ---------------------------------------------------------------------------

DECLSPEC_IMPORT BOOL   toWideChar(char *src, wchar_t *dst, int max);
