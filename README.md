# Lattice

Security research C2 framework. Lab-only, authorized use.

The thesis: understand how commercial EDRs detect implant activity, implement
each offensive technique, and pair it with the exact telemetry that catches it.
The end goal is a companion EDR design informed by operating the offensive side.

See [`ARCHITECTURE.md`](ARCHITECTURE.md) for the full design.  
See [`detections/`](detections/) for the companion EDR Sigma rules.  
See the research reports for the literature review behind each design decision.

---

## Repository layout

```
teamserver/       Go team server (gRPC + REST + NATS)
agent/            C PICO implant (no CRT, position-independent)
bof/              BOF/COFF modules (CS beacon.h-compatible ABI)
profiles/         3-plane JSON profiles (wire / operational / opsec)
detections/       Sigma rules and ETW queries — companion EDR documentation
src/              Windows internals demos (NtQuerySystemInformation, ToolHelp)
include/          Headers for the demo scaffold
research-report-*.md  Literature review reports
ARCHITECTURE.md   Full system design document
```

---

## Quick start

### Team server (Go 1.22+)

```bash
cd teamserver
go mod download
go run ./cmd/lattice-server -grpc :50051 -rest :8080 -nats nats://127.0.0.1:4222
```

Requires a running NATS server:
```bash
docker run -p 4222:4222 nats:latest
```

### Agent (Windows, MSVC + CMake 3.20+)

```powershell
cd agent
cmake -B build -G "Visual Studio 17 2022" -A x64 `
    -DLATTICE_HOST=L\"192.168.1.100\" -DLATTICE_PORT=443
cmake --build build --config Release
```

### BOFs (CS beacon.h-compatible)

Any C compiler targeting COFF output works:
```bash
# MinGW
x86_64-w64-mingw32-gcc -c my_bof.c -I bof/include -o my_bof.o
# MSVC
cl /c my_bof.c /I bof\include /Fo:my_bof.obj
```

---

## Status

Active research scaffold. See [`ARCHITECTURE.md`](ARCHITECTURE.md) for
what is implemented vs. stubbed.

| Component           | Status        |
|---------------------|---------------|
| Team server skeleton| Scaffolded    |
| gRPC proto          | Defined       |
| Agent comms loop    | Scaffolded    |
| COFF/BOF loader     | Partial (SYNC only) |
| HTTP transport      | Stub          |
| Sleep mask          | Stub (plain)  |
| Sigma detections    | 4 rules       |
| 3-plane profiles    | Defined (JSON)|
