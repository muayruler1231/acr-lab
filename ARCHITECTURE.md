# Lattice — Architecture

> Lab-only C2 research framework. Every offensive capability documented here
> has a paired detection in `detections/`. The goal is understanding EDR telemetry
> well enough to build one.

---

## Overview

Lattice is a modular C2 framework designed around three principles derived from
reviewing BRC4, Cobalt Strike (2014–2026), Havoc, AdaptixC2, and Crystal Palace:

1. **Separation of planes**: wire format, operational behavior, and OPSEC policy
   are three orthogonal dimensions — not a single monolithic config.
2. **PICO agent**: the implant is position-independent code composed of hook-wired
   modules at link time (Crystal Palace model) rather than a PE that loads plugins.
3. **Detection parity**: for each evasion technique implemented, a Sigma rule or
   ETW query documenting what a well-instrumented EDR would see is committed
   alongside it in `detections/`.

---

## Repository Layout

```
lattice/
├── teamserver/          # Go — gRPC primary, REST/OpenAPI, WebSocket, GraphQL
│   ├── cmd/lattice-server/   main entry point
│   ├── internal/
│   │   ├── api/         gRPC service implementations
│   │   ├── core/        agent lifecycle, task scheduler, session manager
│   │   ├── profile/     3-plane profile parsing and validation
│   │   ├── transport/   transport plugin interface (Go plugin .so)
│   │   └── store/       in-memory + SQLite agent state and task queues
│   └── proto/           Protobuf definitions (lattice.proto)
│
├── agent/               C — Crystal Palace PICO modular implant
│   ├── include/         agent-internal headers
│   └── src/
│       ├── core/        COFF/BOF loader, async task lifecycle, comms loop
│       ├── transport/   transport PICO stub (swappable at link time)
│       └── opsec/       sleep mask, call-gate stub, CFG-friendly trampolines
│
├── bof/                 BOF/COFF modules (CS beacon.h-compatible ABI)
│   └── include/beacon.h public BOF API — CS beacon.h compatible
│
├── profiles/            3-plane JSON profiles
│   └── default.json     reference profile with all planes documented
│
└── detections/          companion EDR documentation
    ├── sigma/           Sigma rules for each Lattice capability
    └── README.md        detection index
```

---

## Team Server

**Language:** Go  
**Primary API:** gRPC + protobuf (bidirectional streaming for beacon check-in)  
**Operator UI API:** REST/OpenAPI (Gin) + GraphQL subscriptions (gqlgen) for live feed  
**Internal bus:** NATS JetStream — decouples transport listeners from core scheduler  
**Plugin system:** Go `plugin` package (`.so`) — each transport is a separate plugin

### Core services (proto/lattice.proto)

```
service AgentService {
  rpc CheckIn(CheckInRequest) returns (CheckInResponse);
  rpc TaskStream(stream TaskResult) returns (stream Task);
}

service OperatorService {
  rpc ListAgents(ListAgentsRequest) returns (stream AgentInfo);
  rpc IssueTask(IssueTaskRequest) returns (Task);
  rpc TaskResultStream(TaskFilter) returns (stream TaskResult);
}

service ProfileService {
  rpc LoadProfile(ProfilePayload) returns (LoadResult);
  rpc ActiveProfile(google.protobuf.Empty) returns (ProfilePayload);
}
```

### Agent lifecycle (internal/core)

```
REGISTERED → ACTIVE → TASKED → RESULT_PENDING → ACTIVE
                ↓
            SLEEPING   (masked, timer pending)
                ↓
            DEAD       (missed N check-ins)
```

---

## Agent (PICO)

**Language:** C11 (no CRT, no PE imports, position-independent)  
**Model:** Crystal Palace — modules are `.pico` units linked with `__attribute__((section))`
  hooks; a linker script wires the execution stack at build time.  
**BOF ABI:** CS `beacon.h` compatible — operators can run existing COFF BOFs unchanged.

### Module execution stack (compile-time wiring)

```
[transport_recv]
      ↓
[parser]         extracts task type + payload
      ↓
[dispatcher]     routes to: bof_loader | builtin | opsec_check
      ↓
[sleep_mask]     RW→RX restore, call-gate, CET-safe return trampoline
      ↓
[transport_send] result egress
```

Each arrow is a weak symbol resolved at link time. Swapping a transport or sleep
mask is a relink, not a source change.

### Async BOF lifecycle (3-state)

Based on Outflank's formal model (2025):

```
SYNC        — runs in agent thread, blocks check-in until complete
BACKGROUND  — spawned thread, agent continues checking in, result queued
AUTONOMOUS  — long-running monitor; calls can_mask() before agent sleeps;
              if returns false, agent stays awake until BOF yields
```

The `can_mask()` predicate is the key addition: it prevents sleep obfuscation
from masking an agent that has an AUTONOMOUS BOF mid-execution.

---

## Profile System (3 planes)

See `profiles/default.json` for a fully annotated example.

### wire_plane
Controls what the traffic looks like on the wire:
- HTTP host header, URI patterns, cookie/header malleable fields
- TLS fingerprint (JA4 target), jitter %, sleep interval
- Beacon strategy: HTTP long-poll vs WebSocket vs DNS vs HTTPS-only

### operational_plane
Controls agent behavior independent of comms:
- fork_and_run vs in-process (BOF) task execution
- Process injection target class (hollowable, signed, sacrificial)
- Memory allocation strategy (direct syscall vs ntdll trampoline)
- BOF execution timeout, max concurrent BACKGROUND BOFs

### opsec_plane
Controls which evasion layers are active and their parameters:
- sleep_mask: type (timer-queue, APC, fiber), encrypt_heap (bool)
- call_gate: enabled, gate_dll (which DLL to proxy through)
- etwti_avoidance: none | indirect_syscall | hardware_breakpoint
- cfg_spoof: none | gadget_chain (list of gadget RVAs)

The three planes are composable: a "noisy lab" profile can use default
wire + aggressive operational + no opsec, while a "production red team"
profile layers all three.

---

## BOF / COFF Loader

Located in `agent/src/core/coff_loader.c`.

- Parses COFF object file in memory (no disk touch)
- Resolves imports via `GetProcAddress` chain with DJB2 hash fallback
- Supports x86_64 relocation types: `IMAGE_REL_AMD64_ADDR64`, `IMAGE_REL_AMD64_REL32`
- Exposes CS `beacon.h` internal functions (`BeaconOutput`, `BeaconPrintf`,
  `BeaconDataParse`, `BeaconGetSpawnTo`, etc.)
- ASYNC BOF wrapper: spawns thread, registers handle in task table, polls
  `can_mask()` before sleep

---

## Detection Parity

Every capability in this table has a Sigma rule in `detections/sigma/`.

| Lattice capability           | Primary telemetry                            | Signal strength |
|------------------------------|----------------------------------------------|-----------------|
| PICO agent (no PE on disk)   | Thread start in MEM_PRIVATE+RX (unbacked)    | High            |
| COFF/BOF loader              | VirtualAlloc RWX in-process                  | High            |
| Sleep mask (RW↔RX flip)      | ETW-TI EtwTi-FluctuationMonitor events       | High            |
| Indirect syscalls            | Call stack: ntdll→[gap]→return address       | Medium          |
| Call-gate (DLL proxying)     | Unusual caller in known-DLL call chain       | Medium          |
| HTTP malleable beacon        | RITA beacon score, JA4 fingerprint           | Medium          |
| DNS transport                | High-entropy TXT queries, NXD ratio          | Medium          |
| Cloud-API transport          | M365 Unified Audit Log graph_api events      | Low–Medium      |
| Async BOF threads            | CreateRemoteThread to unbacked (Sysmon EID8) | High            |

---

## Technology Choices

| Component       | Choice                  | Rationale                                              |
|-----------------|-------------------------|--------------------------------------------------------|
| Server language | Go                      | Native concurrency, strong gRPC support, easy plugins  |
| Agent language  | C11 (no CRT)            | PICO requires no runtime; Crystal Palace model         |
| Primary protocol| gRPC + protobuf         | BRC4 WebSocket+JSON is fast; gRPC adds schema + streaming |
| Message bus     | NATS JetStream          | Havoc uses none; NATS adds at-least-once delivery + replay |
| UI API          | GraphQL (gqlgen)        | Live subscription feed; CS TeamServer uses TCP events  |
| BOF ABI         | CS beacon.h compatible  | Reuse existing open-source BOF ecosystem               |
| Profile format  | JSON (3 planes)         | BRC4 uses JSON, CS uses DSL; JSON is simpler to validate |

---

## Build Requirements

### Team server
- Go 1.22+
- `protoc` + `protoc-gen-go` + `protoc-gen-go-grpc`
- NATS server (Docker or binary)

### Agent
- MSVC or LLVM/Clang cross-compiler targeting `x86_64-pc-windows-msvc`
- Python 3.10+ (Crystal Palace `pic_link.py` linker script)
- CMake 3.20+

### BOFs
- Any C compiler targeting COFF output (`cl /c` or `x86_64-w64-mingw32-gcc -c`)
- Include `bof/include/beacon.h`
