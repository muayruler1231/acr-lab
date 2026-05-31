# Ideas de Arquitectura para Lattice
### Síntesis de innovaciones de Cobalt Strike, Brute Ratel C4 y Havoc + comunidad open source

> **Propósito.** Este documento sintetiza las mejores ideas arquitectónicas de los tres frameworks más importantes (CS, BRC4, Havoc) y la comunidad open source (Mythic, Sliver, AdaptixC2, Crystal Palace/PICO, Outflank), extraídas de investigación pública verificada. El objetivo es informar el diseño de **Lattice** — un C2 de investigación desde cero — y su **companion EDR**. Nivel arquitectura/conceptual; cada idea ofensiva emparejada con su telemetría de detección.

---

## 0. Resumen ejecutivo: qué pionereó cada framework

| Framework | Innovación pionera | Año |
|---|---|---|
| **Cobalt Strike** | Malleable C2 (DSL de wire-format) | 2014 |
| **Cobalt Strike** | BOF/COFF — el agente como runtime linker | 2020 |
| **Cobalt Strike** | UDRL — loader operador-reemplazable | 2021 |
| **Cobalt Strike** | Sleep Mask como BOF (unificación elegante) | 2022 |
| **Cobalt Strike** | BeaconGate — WinAPI proxy universal + call-stack spoofing | 2024 |
| **Cobalt Strike** | UDC2 — BOF como protocolo de transporte | 2026 |
| **Brute Ratel** | DLL load proxying para ETWTI (primer C2 en hacerlo) | 2022 |
| **Brute Ratel** | OTA key burn (clave destruida en primer check-in) | 2022 |
| **Brute Ratel** | `obfsleep` runtime switching sin rebuild | 2022 |
| **Brute Ratel** | Network entropy self-measurement | 2023 |
| **Brute Ratel** | C2 fallback chains con failure counter | 2023 |
| **Brute Ratel** | Compilador propio para control de stack/memoria | 2025 |
| **Mythic** | Microservicios Docker + RabbitMQ (agentes en cualquier lenguaje) | 2021 |
| **Mythic** | Translation containers (wire format ≠ API format) | 2021 |
| **Mythic** | GraphQL subscriptions para UI reactiva | 2023 |
| **Havoc** | Service API — handlers de agentes out-of-process | 2022 |
| **Outflank** | Async BOF lifecycle formal (3 estados) | 2025 |
| **Crystal Palace** | PICO — agente modular PIC sin PE | 2025 |
| **FortiGuard/GraphStrike** | Cloud-API (Graph/SharePoint) como canal C2 | 2024 |

---

## 1. La arquitectura de Lattice (síntesis de lo mejor de los tres)

### 1.1 Team server — lo que CS + Mythic + Sliver enseñan

**Diseño propuesto:** servidor Go, API-first, con tres superficies de acceso:

```
Operadores ──gRPC/mTLS──▶ Team Server ──NATS/gRPC──▶ Plugin handlers (agentes, canales)
                              │
                         REST API (OpenAPI spec) ──▶ automatización / CI-CD / LLM
                              │
                         WebSocket/SSE ──▶ UI React / TUI (eventos en push, sin polling)
```

**Ideas clave por fuente:**

| Idea | Fuente | Por qué |
|---|---|---|
| **gRPC + protobuf** como API primaria del operador | Sliver | API tipada, stubs en cualquier lenguaje, streaming nativo, mTLS per-operador |
| **REST API con OpenAPI spec** para automatización | CS 4.12 | Integración con LLM/AI, CI/CD, herramientas externas sin cliente dedicado |
| **WebSocket/SSE event stream** para output asíncrono | Mythic/Havoc | Operador recibe eventos en push; no polling; output de tareas correlacionado con ID |
| **GraphQL subscriptions** para UI | Mythic 3.0 | UI reactiva sin polling; Jupyter notebooks pueden consultar el DB operacional |
| **Message bus** (NATS o RabbitMQ) para plugins | Mythic | Teamserver sin conocimiento hardcodeado de ningún agente ni canal |
| **Plugin system formal**: Go interfaces in-process + gRPC out-of-process | AdaptixC2 + Havoc | In-process = bajo overhead; out-of-process = lenguaje agnóstico para handlers de terceros |
| **Artifact store content-addressed** con ACLs por operador | CS 4.12 REST | BOFs/módulos compartidos entre operadores; evitar staging redundante |
| **Server-side scripting** (Lua o JS, no Java) | CS Aggressor | Automatización permanente sin cliente conectado; sin dependencia de JVM |

**Mejora nueva para Lattice:** Unificar los dos modelos de scripting de CS (Aggressor client-side + REST server-side) en **un solo event bus**. Todo consumidor de eventos — GUI, REST client, script server-side — escucha el mismo bus. No hay canales privilegiados separados.

---

### 1.2 Agente — lo que CS + BRC4 + Crystal Palace enseñan

**Diseño propuesto: hook-based execution stack con módulos PICO**

```
[Transport BOF / UDC2] → [Framing/Crypto] → [PICO Loader] → [Sleep Mask BOF] → [WinAPI Dispatch / Call-Gate] → [Task Executor]
```

Cada capa es **independientemente reemplazable**, siguiendo el modelo CS (UDRL + Sleep Mask + BeaconGate + UDC2 como extensiones del mismo mecanismo COFF). La novedad: unificar todo bajo **Crystal Palace PICO** como unidad de composición.

#### A. La unidad de composición: PICO (Crystal Palace)

Un agente Lattice = colección de módulos PICO independientes:
- `transport.pico` — implementa el canal C2 (HTTP, DNS, Graph API, SMB...)
- `tasking.pico` — loop principal, despacho de comandos
- `bof_loader.pico` — COFF runtime linker (compatible con el ecosistema BOF de CS)
- `sleep_mask.pico` — estrategia de dormancia, intercambiable
- `callgate.pico` — WinAPI proxy (BeaconGate-style)

La tradecraft (sleep obfuscation, stack spoofing) se **teje en link-time** como AOP — no baked en cada PICO. Actualizar evasión = relinkar, no recompilar capacidades.

El bootstrap PICO desaparece de memoria tras cargar los módulos (BRC4 + Crystal Palace combinados). Solo los PICOs activos permanecen.

*Fuentes: Crystal Palace (tradecraftgarden.org), Maverick (BlackSnufkin/GitHub), Rasta Mouse blog, Stardust/5pider. Conf. media-alta.*

#### B. BOF/COFF runtime linker compatible con el ecosistema CS

El agente Lattice implementa un COFF loader compatible con la `beacon.h` API de CS:
- Hereda el ecosistema de miles de BOFs públicos existentes.
- Extiende con una API tipada propia (argumentos con manifiesto de tipos, no solo binary-packed).
- El `BEACON_INFO` pattern (descriptor de runtime pasado del loader al agente) — adoptar para comunicar contexto de inicialización.

**Mejora nueva:** añadir un segundo tier de módulos **WASM** para capacidades multiplataforma (no Windows-only) sin cambiar el COFF loader.

*Fuentes: CS BOF docs, TrustedSec COFFLoader, beacon.h. Conf. alta.*

#### C. Stack de hooks reemplazables (modelo CS)

```
Loader     → UDRL-equivalent: PICO loader personalizable por el operador
Dormancy   → Sleep Mask PICO: estrategia intercambiable (Ekko/Foliage/custom)
WinAPI     → Call-Gate PICO: proxy por categoría (mem ops, net ops, proc ops)
Transport  → Transport PICO: protocolo arbitrario (UDC2-equivalent)
Post-ex    → Injection PICO: técnica de inyección por tarea (Process Inject Kit-equivalent)
```

El operador compila y sustituye cualquier capa sin tocar el core del agente. El sistema de build embebe el PICO personalizado en el payload blob en build-time.

*Fuentes: CS UDRL/BeaconGate/UDC2/Process Inject Kit. Conf. alta.*

#### D. Async BOF lifecycle con estados formales (Outflank + AdaptixC2)

Tres estados formales de tarea:

| Estado | Comportamiento | Ejemplo |
|---|---|---|
| `sync` | Bloquea el beacon loop hasta completar | Whoami, ipconfig |
| `async-background` | Corre concurrente, reporta via queue | Port scan, screenshot |
| `autonomous-monitor` | Corre indefinidamente, event-driven wakeup | Keylogger, Procmon, Clipmon |

El subsistema de sleep expone un predicado `can_mask(task_id) bool` que cada tarea responde. El sleep mask solo aplica cuando todos los `autonomous-monitor` activos lo permiten o tienen un mensaje en queue.

**Mejora nueva vs Havoc/Outflank:** el estado `autonomous-monitor` implementa un protocolo de "wakeup con mensaje" — cuando detecta el evento, deposita datos en un buffer y señala al beacon loop para despertar antes del sleep programado. El resultado: beaconing irregular (interrumpido por eventos) que es detectable como anomalía temporal desde el EDR companion.

*Fuentes: Outflank Async BOFs (2025), AdaptixC2 async BOF docs. Conf. media-alta.*

---

### 1.3 Sistema de perfiles — lo que BRC4 + CS enseñan

**Diseño propuesto: perfiles como objetos JSON modulares por planos ortogonales**

```json
{
  "wire_plane": {        // qué aspecto tiene el tráfico
    "transport": "http",
    "uri_patterns": [...],
    "headers": {...},
    "body_transform": ["base64", "prepend:user=", "strrep:Bearer "]
  },
  "operational_plane": { // cómo se comporta el beacon
    "sleep_ms": 60000,
    "jitter_pct": 20,
    "fallback_chain": [...],
    "kill_date": "2026-12-31"
  },
  "opsec_plane": {       // estrategia de evasión en memoria
    "sleep_mode": "ekko",     // switchable en runtime
    "stomp_module": "clbcatq.dll",
    "restore_on_sleep": true,
    "entropy_target": 4.0     // nuevo: objetivo de Shannon entropy
  }
}
```

**Ideas clave por fuente:**

| Idea | Fuente | Detalle |
|---|---|---|
| **Wire transform pipeline composable y reversible** | CS Malleable C2 | Operadores de transformación encadenables: `base64 → prepend → strrep`; el servidor aplica la inversa automáticamente |
| **Perfiles por listener** (no global) | CS | Distintos indicadores por operación/objetivo |
| **Planos ortogonales separados** | CS + BRC4 | Wire / Operational / OPSEC independientemente intercambiables |
| **`sleep_mode` runtime-switchable** | BRC4 `obfsleep` | Sin rebuild de payload; el operador escala OPSEC en fases sensibles |
| **`entropy_target`** en el payload generator | BRC4 v1.6 | Mide Shannon entropy del payload antes de deploy; alerta si supera umbral |
| **`fallback_chain` con failure counter** | BRC4 v1.7 | Failover automático entre C2 listeners sin re-infección |
| **`kill_date` pre-ejecución** | BRC4 v1.9 | Validación antes de que el core corra (no post-ejecución) |
| **`restore_on_sleep`** | BRC4 v1.5 | Restaura el `.text` original del módulo stompeado durante sleep; derrota pe-sieve |

---

### 1.4 Transporte — las ideas más nuevas

#### A. Cloud-API como canal de primera clase (Graph/SharePoint)

El Transport PICO maneja OAuth lifecycle + polling/write en cloud storage. Desde el endpoint, todo tráfico va a IPs de Microsoft/Google con TLS válido.

**Patrón de detección que el companion EDR debe implementar:**
- Ingerir M365 Unified Audit Log
- Detectar: cuenta de servicio no-humana leyendo/escribiendo ficheros en SharePoint con contenido binario/cifrado a intervalos regulares
- El naming convention de los ficheros (`{VictimID}pD9-tK*` en el caso de Havoc/FortiGuard) es firma inicial; Lattice usará naming configurable

*Fuentes: FortiGuard Labs (Havoc + Graph API, mar-2025), Red Siege GraphStrike (ene-2024), Hunters.security VEILDrive. Conf. alta.*

#### B. DoH two-phase (A+TXT) — BRC4 v1.0

Primera fase: petición de A records para check-in. Segunda fase: TXT records para el comando cifrado. El canal completo es DNS-over-HTTPS a resolvers legítimos (Cloudflare/Google). CS 4.11 también implementó DoH. Lattice debe incluir esto como Transport PICO built-in.

#### C. SMB named pipe peer-to-peer

Canal de movimiento lateral: un Badger/Demon conecta a otro a través de named pipe. Para Lattice: Transport PICO SMB con nombre de pipe configurable en el perfil OPSEC (evitar nombres por defecto detectados por Sysmon EID 17/18).

---

### 1.5 OPSEC de agente — ideas más importantes

#### A. OTA key burn (BRC4, conf. alta)

Cada payload embebe una clave de registro única. Al primer check-in: servidor valida, emite session token, destruye la clave permanentemente. Sandbox/analista que captura el payload después de la primera ejecución = clave quemada, autenticación imposible.

**Mejora nueva:** el token es HMAC(clave + hardware fingerprint) — también host-locked. Token robado de un host no sirve en otro.

#### B. Network entropy self-measurement (BRC4 v1.6, conf. media)

El generador de payloads mide la Shannon entropy del payload cifrado antes de generar el artefacto final. Si supera el umbral configurado en el `opsec_plane`, alerta al operador y ofrece ajustar la transformación del wire. La entropía alta (~7.4/8) es un flag de EDRs que inspeccionan TLS. BRC4 bajó a ~4/8 estructurando el payload para mimetizar contenido HTTPS normal.

#### C. Module stomp + restauración (BRC4 v1.5, conf. alta)

El agente selecciona un DLL legítimo de tamaño suficiente, escribe el código en su `.text` section, ejecuta desde ahí. Al dormir: restaura el `.text` original. Pe-sieve compara in-memory vs on-disk y no ve diferencia.

**Safety check crítico** (BRC4 documentado): verificar que el DLL target no está en la IAT del agente — stompearlo causaría crash. Implementar este check en el builder.

#### D. Compilador/linker custom (BRC4 v2.3, Crystal Palace, conf. media)

BRC4 construyó su propio compilador en v2.3 para control fino de stack layout y tamaño (reducción 30%). Crystal Palace es el equivalente open-source: linker PIC + script language para COFF → PICO.

Para Lattice: usar Crystal Palace como el linker de PICOs. No requiere compilador propio; sí requiere dominar el `.spec` linker script para control de layout de memoria.

---

## 2. Las 10 ideas más nuevas / no-obvias para Lattice

Estas son las que más diferenciarían a Lattice de los frameworks existentes:

### #1 — PICO modular desde cero con tradecraft aspect-oriented
El agente como conjunto de PICOs compilados independientemente, con tradecraft tejida en link-time. Ningún framework open source ha unificado esto completamente todavía (Crystal Palace + Lattice sería el primero en hacerlo con una API formal). **Fuente:** Crystal Palace/Tradecraft Garden, 2025.

### #2 — BOF-as-transport (UDC2 pattern) desde el día 1
Unificar capacidades y canales bajo el mismo mecanismo COFF. Un solo plugin system para ambos. **Fuente:** CS UDC2 (2026) — tan reciente que ningún framework open source lo tiene aún.

### #3 — Async BOF con 3 estados formales + predicado `can_mask()`
Un API formal para el lifecycle de tareas, no ad-hoc. El `autonomous-monitor` con wakeup event-driven produce beaconing irregular — documentarlo como IoC en el companion EDR. **Fuente:** Outflank + AdaptixC2, síntesis nueva.

### #4 — Entropy-aware payload generator
El builder muestra la Shannon entropy estimada del payload antes de deploy y alerta si supera el umbral del `opsec_plane`. Ningún framework open source lo tiene como feature de primera clase. **Fuente:** BRC4 v1.6, generalizado.

### #5 — OTA key burn + host-locking del token
Clave única destruida en primer check-in + token HMAC(key + hardware fingerprint). Dos capas de protección anti-sandbox. **Fuente:** BRC4 v1.9, mejorado.

### #6 — Cloud-API channel como Transport PICO built-in
Graph API/SharePoint como canal C2 de primera clase, con el companion EDR diseñado para detectarlo via M365 UAL desde el inicio. **Fuente:** FortiGuard/GraphStrike, 2024-2025.

### #7 — Call-Gate configurable por categoría de API
BeaconGate-style pero con política por categoría (mem ops, net ops, proc ops) configuradas en el `opsec_plane`. El operador puede aplicar spoofing solo a operaciones de red (donde el call-stack importa) y no a operaciones locales (overhead innecesario). **Fuente:** CS BeaconGate 4.10, generalizado.

### #8 — Sleep mode runtime-switchable via API
El operador puede cambiar el modo de sleep en un implant vivo (`sync → ekko → foliage`) sin rebuild. La lección de BRC4: el OPSEC debe poder escalarse durante fases sensibles. Ningún framework open source expone esto como API de primera clase. **Fuente:** BRC4 `obfsleep`.

### #9 — Lattice en "modo EDR companion"
El mismo agente de Lattice puede correr en modo **blue-team sensor**: en vez de exfiltrar datos al teamserver atacante, emite telemetría ETW/memoria al EDR companion. Dos modos de operación, un solo codebase. Esto hace que el lab de Lattice sea simultáneamente el banco de pruebas del EDR — cada técnica tiene su dataset de detección. **Fuente:** síntesis nueva basada en los objetivos del proyecto.

### #10 — Per-build identidad única (garble-style) + CS BOF API compatibility shim
Cada implant generado: par de claves asimétrico único, hashes de API únicos por seed por build, identifiers renombrados (garble). Imposible correlación por hash estático. Simultáneamente: shim de compatibilidad con `beacon.h` de CS para heredar el ecosistema de BOFs públicos. **Fuente:** Sliver (garble) + TrustedSec CS2BR (shim pattern).

---

## 3. Matriz completa: técnica → telemetría → detección companion EDR

| Técnica/Diseño | Telemetría generada | Detección en companion EDR |
|---|---|---|
| PICO modular (sin PE) | Memoria private+RWX sin respaldo en disco | Enumerar regiones no-module-backed; YARA en heap ejecutable |
| BOF COFF in-process | RWX region efímera en proceso del agente | Patrón alloc-execute-free en ventana corta; COFF magic bytes en memoria |
| Module stomp + restauración | Hilo con start address en DLL que normalmente no tiene hilos; ventana RX breve en restore | Correlacionar start address de hilos vs. DLLs con threading esperado |
| Sleep mask (Ekko/Foliage) | Timer/APC callbacks con operaciones crypto; fluctuación RW↔RX | ETW-TI `PROTECTVM_LOCAL`; EtwTi-FluctuationMonitor |
| Call-Gate (BeaconGate-style) | Call-stack spoofed; ret address no llega a BaseThreadInitThunk | CET shadow-stack comparison; inspección proactiva de hilos |
| OTA key burn | Payload no ejecutable post-primer-uso | Detección en sandbox: segunda ejecución = auth fail (IoC de design) |
| Async monitor BOF | Hilo persistente en proceso entre beacon intervals | Correlacionar lifetime de hilos vs. cadencia de beacon; hilo vivo >1 ciclo = anomalía |
| Entropy controlada (~4/8) | TLS payload de baja entropía | Detección de entropía ya menos efectiva — desplazar a fingerprinting de stack TLS (JA4) |
| Cloud-API transport | HTTPS a graph.microsoft.com; ficheros SharePoint R/W a intervalos | M365 Unified Audit Log: cuenta de servicio + R/W binario regular + GUID-like filenames |
| DoH two-phase | HTTPS a DoH resolver; sin DNS visible | Timing/volumen de tráfico DoH cifrado a CDN; behavioral analysis del flujo |
| Per-build unique crypto | Sin hash estático compartido | YARA estructural (Go runtime patterns, Crystal Palace PICO bootstrap) |
| C2 fallback chains | Cambio de destino C2 tras N fallos | NDR: nueva dirección C2 post-silencio; correlacionar con failure counter |
| `autonomous-monitor` wakeup | Beaconing irregular (check-in anticipado al evento) | RITA/AC: desviación estadística de interval esperado = evento-driven wakeup |

---

## 4. Stack recomendado para Lattice (decisión)

Con base en toda la investigación, la combinación más alineada con los objetivos (investigación, charla, futuro EDR, OPSEC, Crystal Palace PIC):

| Componente | Stack | Justificación |
|---|---|---|
| **Team server** | **Go** | Concurrencia nativa, gRPC built-in, toda la comunidad C2 moderna lo usa (Sliver, Havoc, AdaptixC2) |
| **Operador API** | **gRPC + protobuf** (primaria) + **REST/OpenAPI** (automatización) | Tipado, versioning, stubs en cualquier lenguaje, streaming |
| **UI de operador** | **Web (React + GraphQL subscriptions)** o **TUI** | Desacoplada del server; sin cliente Java monolítico |
| **Agente** | **C + Crystal Palace PIC linker** (módulos PICO) | PIC puro, sin PE, compatible con COFF/BOF ecosystem de CS, control fino de memoria |
| **COFF loader** | **Compatible con CS `beacon.h`** + extensiones propias | Hereda el ecosistema; diferencia con API propia (typed manifest, async lifecycle) |
| **Scripting server-side** | **Lua** (o TypeScript/Deno) | Sin JVM, ligero, ya usado en tooling de seguridad (Nmap scripts, etc.) |
| **Plugin bus** | **NATS** (o RabbitMQ si ya familiar) | Mensajería ligera, pub/sub, mejor para binarios grandes que RabbitMQ |

---

## 5. Fuentes consolidadas

### Cobalt Strike
- CS Blogs: Malleable C2, BOF (4.1), UDRL (4.4/4.5), Fork&Run (4.5), Sleep Mask (4.5/4.7), BeaconGate (4.10), Async BOFs/DoH (4.11), REST API/UDC2 (4.12): https://www.cobaltstrike.com/blog/
- beacon.h: https://github.com/Cobalt-Strike/bof_template/blob/main/beacon.h
- Malleable C2 reference: https://github.com/threatexpress/malleable-c2/blob/master/MalleableExplained.md
- TrustedSec COFFLoader: https://trustedsec.com/blog/coffloader-building-your-own-in-memory-loader-or-how-to-run-bofs
- TrustedSec BOF landscape: https://trustedsec.com/blog/changes-in-the-beacon-object-file-landscape
- IBM BOFMask: https://www.ibm.com/think/x-force/how-to-hide-beacon-during-bof-execution
- FalconForce syscalls + BOFs: https://medium.com/falconforce/falconfriday-direct-system-calls-and-cobalt-strike-bofs-0xff14-741fa8e1bdd6
- Unit 42 Malleable C2: https://unit42.paloaltonetworks.com/cobalt-strike-malleable-c2-profile/

### Brute Ratel C4
- Vendor release notes: https://bruteratel.com/category/release/
- Unit 42 BRC4: https://unit42.paloaltonetworks.com/brute-ratel-c4-tool/
- MDSec (How I Met Your Beacon Pt.3): https://www.mdsec.co.uk/
- Splunk RE: https://www.splunk.com/en_us/blog/security/deliver-a-strike-by-reversing-a-badger-brute-ratel-detection.html
- NVISO CS2BR: https://blog.nviso.eu/2023/05/15/introducing-cs2br-pt-i-how-we-enabled-brute-ratel-badgers-to-run-cobalt-strike-bofs/
- External C2 spec: https://github.com/paranoidninja/Brute-Ratel-External-C2-Specification
- Community kit: https://github.com/paranoidninja/Brute-Ratel-C4-Community-Kit
- brc4_profile_maker: https://github.com/cyndicatelabs/brc4_profile_maker

### Havoc + comunidad
- Havoc WIKI.MD: https://github.com/HavocFramework/Havoc/blob/main/WIKI.MD
- Havoc Talon (Service API): https://github.com/HavocFramework/Talon
- Zscaler Havoc: https://www.zscaler.com/blogs/security-research/havoc-across-cyberspace
- Mythic docs: https://docs.mythic-c2.net/ · https://pypi.org/project/mythic-container/
- Sliver: https://github.com/bishopfox/sliver · wiki: Armory, BOF & COFF, Multiplayer
- AdaptixC2: https://github.com/Adaptix-Framework/AdaptixC2 · https://deepwiki.com/Adaptix-Framework/AdaptixC2/3-extender-plugin-system
- Outflank Async BOFs: https://www.outflank.nl/blog/2025/07/16/async-bofs-wake-me-up-before-you-go-go/
- Crystal Palace: https://tradecraftgarden.org/crystalpalace.html
- Maverick: https://github.com/BlackSnufkin/Maverick
- Rasta Mouse PICO: https://rastamouse.me/modular-pic-c2-agents/
- FortiGuard Havoc+Graph: https://www.fortinet.com/blog/threat-research/havoc-sharepoint-with-microsoft-graph-api-turns-into-fud-c2
- GraphStrike: https://redsiege.com/blog/2024/01/graphstrike-release/
- VEILDrive: https://www.hunters.security/en/blog/veildrive-microsoft-services-malware-c2
- Darktrace Sliver: https://www.darktrace.com/blog/sliver-c2-how-darktrace-provided-a-sliver-of-hope-in-the-face-of-an-emerging-c2-framework

*Investigación para laboratorio cerrado / charla de seguridad. Toda decisión de diseño ofensiva emparejada con su telemetría de detección para el companion EDR.*
