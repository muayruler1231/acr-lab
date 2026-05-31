# Lattice — Detection Companion

Every capability in the Lattice agent has a paired detection here.
The goal is to build the companion EDR that can catch Lattice in action.
If you can detect it, you understand it well enough to talk about it at a conference.

---

## Index

| Sigma rule file                         | Detects                                           | Signal strength | Telemetry source              |
|-----------------------------------------|---------------------------------------------------|-----------------|-------------------------------|
| `sigma/bof_rwx_transition.yml`          | COFF loader RW→RX VirtualProtect                  | High            | ETW-TI / Sysmon               |
| `sigma/thread_start_unbacked.yml`       | Thread started in MEM_PRIVATE+RX (no file backing)| High            | ETW-TI PsCreateThread         |
| `sigma/sleep_mask_rw_flip.yml`          | Timer-queue sleep mask RW↔RX fluctuation          | High            | ETW-TI FluctuationMonitor     |
| `sigma/http_beacon_ja4.yml`             | HTTP beacon JA4 fingerprint anomaly               | Medium          | Network (Zeek/Suricata)       |
| `sigma/rita_beacon_score.yml`           | RITA beacon scoring ≥ 0.7 on internal hosts       | Medium          | Network flow (RITA/Zeek)      |
| `sigma/indirect_syscall_callstack.yml`  | Syscall origin outside ntdll (unbacked gap)       | Medium          | ETW-TI / Elastic call stack   |
| `sigma/amsi_patch_audit.yml`            | AMSI patch attempt via Kernel-Audit-API-Calls     | High            | ETW Kernel-Audit-API-Calls    |
| `sigma/sysmon_eid8_unbacked_thread.yml` | CreateRemoteThread target in unbacked memory      | High            | Sysmon EID 8                  |
| `sigma/process_injection_granted_access.yml` | OpenProcess with PROCESS_VM_WRITE (0x0020)   | Medium          | Sysmon EID 10 GrantedAccess   |

---

## Why this matters

A C2 framework is a probe for EDR telemetry. Each Lattice capability
tests one specific sensor:

- **COFF loader** → tests ETW-TI VirtualAlloc/VirtualProtect telemetry.
- **Sleep mask** → tests FluctuationMonitor and memory-scan heuristics.
- **PICO agent** → tests thread-start-in-unbacked and process-injection telemetry.
- **HTTP transport** → tests JA4 and RITA beacon scoring.
- **Indirect syscalls** → tests call-stack origin analysis (Elastic 8.8+).

When a detection fires, it confirms the EDR sensor is working. When it
doesn't fire, it reveals a sensor gap — which is the actual research finding.

---

## Telemetry sources referenced

| Source | Description |
|--------|-------------|
| `Microsoft-Windows-Threat-Intelligence` | Kernel-mode ETW provider; requires ELAM/PPL. Non-hookable from user-mode. |
| `Kernel-Audit-API-Calls` | ETW provider for AMSI bypass detection (patchless bypass audit). |
| Sysmon EID 8 | CreateRemoteThread with source/target process + target address. |
| Sysmon EID 10 | ProcessAccess with GrantedAccess bitmask (literal, not bitwise-decoded). |
| Sysmon EID 17/18 | Named pipe create/connect — catches default CS pipe names. |
| Elastic call stack | call_stack_contains_unbacked field (Elastic 8.8+, 2023). |
| RITA | Beacon scorer: MADM, skew, duration. 30 s MADM = flagged. Content-independent. |
| JA4+ | FoxIO Sep 2023; sorts extensions before hashing — randomization-resistant. |
