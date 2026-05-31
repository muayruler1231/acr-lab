# El estado del arte en frameworks C2 (2024–2026)
### Informe de investigación — arquitectura ↔ detección — para charla de seguridad y diseño de un EDR defensivo

> **Propósito y alcance.** Revisión de literatura pública, verificada en múltiples fuentes, orientada a (a) fundamentar una charla sobre cómo funcionan los C2 modernos y (b) sentar las bases para construir un EDR propio. El eje es **ofensa ↔ detección**: cada tendencia ofensiva se documenta junto a su contraparte de telemetría/detección. **No** contiene código armado, payloads, perfiles operativos ni bypasses paso a paso contra productos concretos. Uso previsto: laboratorio cerrado / adversary emulation autorizada.
>
> **Método.** 5 ramas de búsqueda en paralelo → ~80 búsquedas web y ~115 fetches → extracción de *claims falsificables* con cita y nivel de confianza → verificación cruzada. **Nota de fiabilidad del entorno:** muchos sitios de vendor (Elastic, Microsoft Learn, Cobalt Strike, MDSec, Outflank, FoxIO, GitHub) devolvieron HTTP 403 al fetch directo; esos claims se apoyan en extractos de buscador corroborados con ≥2 fuentes y/o mirrors (DeepWiki, PyPI, repos oficiales). Los puntos sensibles van marcados.

---

## 0. Resumen ejecutivo

El panorama 2024–2026 se mueve en cuatro ejes, y los cuatro tienen contraparte defensiva madura:

1. **Servidores API-first.** El cambio arquitectónico de fondo es desacoplar *team server*, lógica C2 y UI de operador detrás de una API estructurada (REST/gRPC/WebSocket+JSON). Es **transversal**: Mythic (GraphQL/Hasura + microservicios Docker) y Brute Ratel (WebSocket+JSON) son los más "API-puros", pero incluso Cobalt Strike añadió REST API y Nighthawk reescribió su backend a .NET con API dedicada. "Rápido" es, en su mayoría, *framing* de marketing (no hay benchmark público); el beneficio real es **scriptabilidad, concurrencia multi-operador y modularidad**.

2. **Implant in-memory y ejecución por objetos (BOF/COFF) in-process.** El patrón "fork-and-run" (proceso sacrificial + inyección por tarea) cede ante la ejecución *in-process* de BOFs/COFFs. Menos telemetría de proceso, a costa de estabilidad (un crash tumba el implant). Es el cambio con **mayor impacto en detección de endpoint**. 2025 trae el *async BOF* para no bloquear el sleep.

3. **Evasión "residente": de no-tocar-disco a esconderse en memoria.** Una vez el código se carga reflexivamente, la exposición residual es el **escaneo de memoria** y la **pila de llamadas** durante el sleep. De ahí: sleep obfuscation (cifrar la propia memoria), call-stack / return-address spoofing, syscalls indirectas.

4. **La detección madura en paralelo.** Por cada técnica hay contraparte pública: en endpoint, **ETW-TI + callbacks de kernel + análisis de call-stack sobre memoria *unbacked*** (no los hooks user-mode, que los BOFs/bypasses patchless derrotan); en red, **JA3→JA4** (JA3 degradado desde la randomización de Chrome en 2023), **JARM** (útil pero genérico-Java y spoofable) y, lo más resistente, **análisis de temporización de beacons (RITA)**, independiente del contenido.

**Tesis para la charla y el EDR:** entender la evasión *es* el plano de la detección. La detección robusta se ancla en **invariantes de comportamiento** (memoria unbacked, periodicidad estadística, origen de call-stack), no en IoCs frágiles (un URI, un hash, un certificado).

---

## 1. Arquitecturas C2 modernas y el giro a las APIs

### 1.1 Qué significa "API-first" y por qué se percibe rápido

El patrón común: **desacoplar transporte/protocolo, núcleo del servidor y UI de operador** tras una API estable.

- **Mythic** es el exponente más puro: microservicios en Docker — servidor Go, PostgreSQL, **RabbitMQ** como bus de mensajes, Nginx, y un **GraphQL (Hasura)** por el que pasan tanto la UI React como el scripting. Agentes y perfiles C2 viven en **contenedores independientes**, instalables por separado (`mythic-cli install github <repo>`), de modo que se actualizan sin tocar el core. Los contenedores de perfil C2 actúan de **traductores**: sacan datos del cable en el protocolo que sea y los convierten a llamadas REST/JSON del servidor → agente y protocolo de cable agnósticos al núcleo. *(Confianza alta; docs oficiales + corroboración.)*
- **Sliver** (Go): protocolo cliente↔servidor en **gRPC + Protobuf**; el gRPC es la interfaz primaria de toda la funcionalidad. Multi-operador ("multiplayer", puerto gRPC por defecto 31337, auth mTLS con config por operador). Modo **daemon** headless. *(Confianza alta.)*
- **Brute Ratel C4**: el *Ratel Server* es API-driven sobre **WebSocket**, con peticiones/respuestas **JSON** desde la GUI Commander o scripts; trae librería Python y scripts de API. En su modelo External C2, el servidor solo recibe la salida (posiblemente cifrada) del Badger y el conector externo maneja el transporte. *(Confianza media — fuente **vendor-only**: notas de release de BRC4.)*
- **Outflank C2** (ex-Stage1): TeamServer Linux entregado como ficheros Docker, operadores por **navegador**, automatización por **API Python + runbooks + Jupyter**. *(Confianza alta, vendor.)*
- **Cobalt Strike**: arquitectura cliente–servidor clásica (Team Server + cliente Aggressor), pero **añadió REST API** para scripting agnóstico de lenguaje y ejecución server-side; el vendor afirma que la REST API pasará a ser componente central. *(Confianza alta para el diseño, pero **single-source/vendor**.)*
- **Nighthawk** (MDSec): la 0.3 **reescribió el backend de Python a .NET Core**, creó APIs JSON, reubicó la lógica C2 en el nuevo servidor API y movió la comunicación UI↔API a **WebSockets**. *(Confianza alta para los hechos, **vendor-only**.)*

**Por qué "rápido":** percepción operativa (scriptabilidad, concurrencia, modularidad sin recompilar el core), **no** rendimiento de red medido. Tratar como racional de diseño, no como dato.

### 1.2 Comparativa arquitectónica

| Framework | Stack servidor | Cliente↔servidor | Modelo de agente | Extensibilidad | Naturaleza |
|---|---|---|---|---|---|
| **Cobalt Strike** | Java (Team Server) | Cliente Java (Aggressor) + **REST API** | Beacon (fork-and-run; BOF in-process) | Aggressor Script (client-side), BOF, Malleable C2, artefactos server-side | Comercial |
| **Sliver** | Go | **gRPC + Protobuf** (multiplayer, daemon) | Sessions (interactivas) y Beacons (async); mTLS/WireGuard/HTTPS/DNS | **Armory** (aliases/extensions), COFF loader | Open source |
| **Mythic** | Go + Docker, **GraphQL/Hasura**, RabbitMQ, PostgreSQL | GraphQL (UI React + scripting `mythic` PyPI) | Agentes en **cualquier lenguaje** (contenedores) | Payload types y perfiles C2 como contenedores; bus RabbitMQ | Open source |
| **Havoc** | Go (teamserver) | Cliente C++/Qt, **API/WebSocket** | Demon (C/ASM), in-memory | Agentes custom (Talon), API Python, BOF | Open source *(repo archivado feb-2026, conf. media)* |
| **Brute Ratel C4** | Ratel Server (**WebSocket+JSON**) | GUI Commander + API Python | Badger, OPSEC-first | Perfiles, BOF, External C2 | Comercial |
| **Nighthawk** | Backend **.NET Core** + API JSON | Cliente + **WebSockets**, API Python | Implant C++, DLL reflexiva → múltiples formatos | Perfiles/módulos | Comercial |

*(Detalles de productos cerrados según vendor/terceros; ver §7 salvedades.)*

### 1.3 Detección a nivel arquitectónico

- **Perfiles por defecto** = causa #1 de detección histórica. Cambiar el perfil reduce, no elimina, la huella.
- **Fingerprinting del servidor**: paneles de Mythic identificables por JARM/JA3S, certificado/branding, título HTML, favicon; Sliver por JARM y *subject/issuer* del cert por defecto (sobre todo el gRPC multiplayer). *(Aplica a despliegues por defecto; conf. alta para Sliver — Corelight + Microsoft.)*
- **El giro a APIs y URLs "legítimas"** (p. ej. rutas tipo `/api/v1/...`) **degrada la detección por firma de red**, empujando hacia detección **conductual/TLS** y **host-side (ETW/memoria)**.

---

## 2. Comunicaciones y beaconing

### 2.1 Canales y perfiles de tráfico
- **HTTP(S)** domina; se modela con perfiles ("malleable" en CS) que reescriben URIs/headers/User-Agent y codifican payloads para imitar servicios legítimos (Microsoft/Google/Amazon). *(Unit 42, conf. alta.)*
- **DNS tunneling**: datos en subdominios largos de alta entropía (cerca del límite de 255 chars), tipos de registro raros/grandes (NULL/TXT > MX/SRV/CNAME/A). Throughput bajo (decenas–cientos de bytes/consulta; iodine ~10 KB/s) → mover MB exige miles de consultas. *(Docs de dnscat2/iodine, conf. alta.)*
- **Domain fronting**: en declive. Google/AWS CloudFront lo deshabilitaron en **abr-2018** (421 si SNI≠Host); **Azure Front Door/CDN** desde **22-ene-2024** (SSLMismatchedSNI → 421); **Fastly** anunció bloqueo ~feb-2024 *pero* hay reportes (mar-2025) de que el fronting aún funcionaba → **enforcement parcial/en disputa, verificar antes de afirmar**. Edgio se retiró ene-2025. El relevo: **redirectors de alta reputación** en cloud/CDN legítimos (sin depender de SNI/Host mismatch). *(Microsoft/Wikipedia conf. alta; estado de Fastly conf. media.)*

### 2.2 Beaconing
- **CS por defecto**: sleep 60 s; jitter 0–99 % que *resta* fracción aleatoria (p. ej. `sleep 300 20` → 240–300 s). *(Vendor, conf. alta.)*
- Aun con jitter, los intervalos **se agrupan en torno a una media** (no Poisson), por lo que son estadísticamente distinguibles del tráfico humano. **SUNBURST** usó jitter largo (~15 min ± ~90 s) para derrotar umbrales fijos. *(Conf. alta el principio; ±90 s aproximado.)*

### 2.3 Detección de red (núcleo)
- **Análisis de temporización (lo más resistente):** **RITA** (Active Countermeasures) ingiere logs Zeek y puntúa cada par src/dst 0–1 combinando *skew* (Bowley), dispersión (**MADM**, umbral ~30 s: `1 − MADM/30`) y duración en tiempo y en tamaño de datos. Score ~0.93–0.996 = beacon muy periódico. **Independiente de contenido y puerto → sobrevive a Malleable C2.** Convergen 3 toolchains independientes (RITA/MADM, Elastic COV+RV+autocorrelación, Splunk SPL time-delta+stdev) → señal central robusta. *(Conf. alta; constantes exactas dependen de versión.)*
- **Fingerprinting TLS:** **JA3/JA3S** (5 campos del ClientHello / 3 del ServerHello, MD5). **JA3 degradado desde ~ene-2023 (Chrome 110 randomiza el orden de extensiones)** → inestable para Chromium. **JA4/JA4+** (FoxIO, sep-2023) **ordena** ciphers/extensiones antes de hashear → resistente a randomización; añade ALPN/QUIC; nativo en Wireshark. *(Conf. alta.)*
- **JARM:** fingerprint **activo** del servidor (10 ClientHellos). Agrupa servidores; el JARM "por defecto de CS" muy citado es realmente un fingerprint **Java/OpenJDK-11** (falsos positivos) y es **spoofable**. *(Conf. alta mecánica/limitaciones; conf. media que el hash citado siga vigente por versión.)*
- **Firmas:** Suricata (`ja3.hash`, JA4 en ≥9.0), Zeek (ssl.log), Sigma (cert por defecto de CS en Zeek). *(Conf. alta capacidad.)*
- **DoH** anula la inspección de contenido → la detección se mueve a **temporización/conducta** del flujo cifrado (Active Countermeasures lo demuestra). Visto en OilRig y ChamelDoH. *(Conf. media-alta.)*

---

## 3. Diseño de implant en Windows (nivel arquitectura)

### 3.1 Modelos de ejecución
- **Fork-and-run**: proceso sacrificial (`spawnto`) + inyección de DLL reflexiva por tarea. Estable y aislado, pero genera **creación de proceso + inyección + artefactos de DLL reflexiva**. *(CS docs, conf. alta.)*
- **BOF/COFF in-process**: un BOF es un **objeto COFF** que el C2 parsea y para el que actúa de **linker/loader** (sin el loader de Windows); código *position-independent* single-thread, corto, recibe punteros a las APIs internas del Beacon. Huella menor (sin process-create/inject), **a costa de estabilidad** (crash = implant caído). Tamaño minúsculo (BOF <3 KB vs DLL reflexiva 100 KB+, ilustrativo) → ideal para canales estrechos (DNS). **Estándar cross-framework**: CS, Sliver (COFF loader vía Armory), Havoc, AdaptixC2. *(Conf. alta.)*
- **Reflective / in-memory loading**: el loader mapea la DLL en memoria, **sin tocar disco**, evitando el image-load del loader de Windows. CS lo hace operador-reemplazable (UDRL). *(Conf. alta.)*
- **Taxonomía moderna** (Sliver): **aliases** (out-of-process: .NET assemblies, sideload, proceso sacrificial) vs **extensions** (in-process nativo/BOF) — mapea directo el tradeoff sigilo↔blast-radius. Distribución por **package manager** (Armory) → capacidades cargadas en memoria bajo demanda. *(Conf. alta.)*

### 3.2 Tendencias 2025 y evasión residente
- **Async BOF** (Outflank, jul-2025): los BOF síncronos bloquean el implant e impiden el *deep sleep* (mantienen un stack de hilo unbacked visible); los async dejan correr la tooling en background mientras el implant sigue sleepmasked. AdaptixC2 también lo documenta. *(Conf. alta.)*
- **Esconderse en memoria**: sleep obfuscation (Ekko/Zilean/FOLIAGE — cifrar la propia memoria al dormir), **return-address/call-stack spoofing**, **syscalls indirectas**. El Demon de Havoc incluye estas tres. *(Conf. alta el inventario; "estándar en todos" conf. media — fuerte en CS/Havoc/Nighthawk, desigual en otros.)*

### 3.3 Técnica ↔ detección (endpoint)
- **Fork-and-run/inyección** → creación de proceso + `VirtualAllocEx/WriteProcessMemory/CreateRemoteThread` vía ETW-TI/callbacks; Sigma maduro.
- **BOF in-process** → *menos* eventos de proceso → la detección se desplaza a **escaneo de memoria** (regiones privadas RX/unbacked) y **anomalías de call-stack**.
- **Reflective loading** → módulo en memoria **sin respaldo en disco** y **sin image-load event** → detectable enumerando regiones ejecutables no respaldadas. *(Elastic, conf. alta.)*
- **Caveat de carrera armamentista:** call-stack spoofing / API proxying derrotan firmas de call-stack (incl. las de Elastic) → señal fuerte, no definitiva.

---

## 4. Telemetría y detección (el corazón del EDR)

### 4.1 Fuentes de telemetría de endpoint
| Sensor | Qué observa | Nota clave |
|---|---|---|
| **ETW** | Eventos kernel/user con timestamp, PID/TID, CPU | Base de todo |
| **ETW-TI** (Microsoft-Windows-Threat-Intelligence) | ALLOC/PROTECT/MAPVIEW VM, QUEUEUSERAPC, SETTHREADCONTEXT, READ/WRITEVM, SUSPEND/RESUME (LOCAL+REMOTE) | **Kernel-sourced → no se silencia parcheando ntdll**. Pero **gated tras PPL/ELAM** (solo AV/EDR con cert ELAM co-firmado) |
| **AMSI** | Scripts/in-memory (PowerShell, .NET, VBA) antes de ejecutar | Bypasses parchean `AmsiScanBuffer` o usan HW breakpoints/VEH; señal = ausencia anómala de scans + eventos `Kernel-Audit-API-Calls` |
| **Callbacks de kernel** | `PsSetCreateProcessNotifyRoutine(Ex)` (proceso), `PsSetCreateThreadNotifyRoutine` (hilo), `PsSetLoadImageNotifyRoutine` (carga imagen; **máx 8 drivers**), `ObRegisterCallbacks` (handles a Process/Thread — p. ej. abrir LSASS, puede bloquear) | Telemetría autoritativa, no-hookable |
| **Minifilter (file)** | I/O por IRP (`IRP_MJ_CREATE`, `IRP_MJ_WRITE`, `IRP_MJ_SET_INFORMATION` = rename masivo ⇒ ransomware) | "Unlinking" del minifilter ciega la telemetría |
| **Escaneo de memoria** | Código ejecutable **unbacked/floating**, transiciones RW→RWX, hilos con start en memoria privada | PE-sieve; señal central de reflective/shellcode |

### 4.2 Técnica → detección (Sysmon/ETW/Sigma)
- **CreateRemoteThread → Sysmon EID 8** (expone StartAddress/Module). *Límite:* solo hookea `CreateRemoteThread`; evaden NtCreateThreadEx/QueueUserAPC/SetThreadContext → correlacionar con EID 7/10.
- **Acceso cross-process/LSASS → Sysmon EID 10 (GrantedAccess)**: inyección = VM_OPERATION+VM_WRITE+CREATE_THREAD (p. ej. 0x0820); dump LSASS = TargetImage `\lsass.exe` con 0x1010/0x1410/0x1438. *Caveat:* Sysmon compara GrantedAccess como **string literal** (no bitwise) y 0x1410 también es legítimo (Task Manager). Complementar con **SACL de LSASS**.
- **Reflective/BOF/inyección in-process → call-stacks de kernel (Elastic 8.8, may-2023; ampliado 8.11)**: compara el call-stack del evento contra la estructura esperada (`ntdll!RtlUserThreadStart`→`kernel32!BaseThreadInitThunk`→primer módulo de usuario); llamada sensible (VirtualAlloc/Protect, MapViewOfFile, WriteProcessMemory, CreateThread) **originada en memoria unbacked** = inyección. Reglas para syscalls directas, threadless injection, module stomping, parcheo AMSI/ETW. *(Conf. alta; **evadible** por call-stack spoofing.)*
- **Named pipes por defecto de CS → Sysmon EID 17/18 + Sigma** (`\MSSE-*-server`, `\postex_*`, `\status_*`, `\msagent_*`). *(Conf. alta.)*

### 4.3 Síntesis para el diseñador de EDR
- **La señal más difícil de manipular** para C2 in-memory = **ETW-TI + callbacks de kernel + análisis de call-stack sobre memoria unbacked**, **no** los hooks user-mode (los BOFs y bypasses patchless los derrotan). ETW-TI exige **PPL/ELAM**.
- **Sysmon EID 8/10 son necesarios pero insuficientes** (matching literal, cobertura solo de ciertas APIs) → correlacionar EID 7/8/10 + SACL + telemetría de kernel con call-stack.
- **Red:** JA3 efectivamente deprecado para navegadores modernos → **JA4 es el estándar**; JARM útil pero genérico-Java y spoofable; **el análisis de temporización (RITA) es lo más resistente** por ser independiente de contenido e IoC.
- **Memoria como verdad de terreno** y **comportamiento > IoC** (subir en la *Pyramid of Pain*).

---

## 5. Tendencias y threat intel (2024–2026)

- **Prevalencia:** Cobalt Strike sigue siendo el C2 más desplegado en intrusiones reales pese a una década de detección; en el reporte de infraestructura de Recorded Future 2024 dominó ~2/3 de servidores OST detectados, y en el 2025 (pub. mar-2026) bajó a ~50 % al ampliarse la cobertura. *(Vendor; **denominadores distintos — no comparar porcentajes como serie**.)*
- **Diversificación:** giro hacia open source modular y multiplataforma — **Sliver (Go), Havoc, Mythic, AdaptixC2** — por menor detección, código modificable y atribución difícil; difumina la línea APT/cibercrimen. *(Red Canary + Recorded Future, conf. alta.)*
- **Brute Ratel:** primer uso malicioso documentado may-2022 (0 detecciones; Unit 42 lo ligó a APT29); creado por Chetan Nayak (ex-Mandiant/CrowdStrike), ~$2,500/usuario/año con verificación manual — **derrotada**: Conti obtuvo licencias vía *shell companies* y luego circuló copia crackeada (sep-2022, "Molecules"). Uso real menor que CS/Sliver. *(SANS/BleepingComputer/Unit 42, conf. alta.)*
- **Havoc abusado en 2025–2026:** cadena ClickFix/SharePoint (FortiGuard, mar-2025) con Demon tunelizando C2 por **Microsoft Graph/SharePoint** para mimetizar tráfico corporativo; campaña Huntress (~feb/mar-2026) de falso soporte IT desplegando Demon customizado. *(Conf. alta/media-alta.)*
- **AdaptixC2:** open source (~ago-2024); Unit 42 lo observó in-the-wild may-2025; ligado a ransomware (Akira, Fog) y crews rusoparlantes vía CountLoader. *(Unit 42, conf. alta.)*
- **Tracking y takedowns:** Microsoft DCU/Fortra/Health-ISAC (2023) → caída **~80 %** de copias crackeadas de CS (**métrica auto-reportada por el vendor**); **Operation MORPHEUS** (Europol, jun-2024) marcó 690 IPs en 27 países, 593 caídas. **Shadowserver** escanea a diario frameworks post-explotación; **Censys** ofrece dataset C2 consultable (`host.services.threats.type="C2_SERVER"`, JA3/JA4/JARM). *(Conf. alta.)*
- **Vetting de C2 comercial:** existe pero imperfecto (cracks de CS y BRC4; licencias vía shell company). La caída del 80 % refleja **enforcement/takedowns** más que vetting.

---

## 6. Matriz ofensa ↔ detección (síntesis para la charla)

| Capa | Técnica ofensiva | Telemetría / detección de referencia | Resistencia de la detección |
|---|---|---|---|
| Servidor | API-first + URLs legítimas (`/api/v1/...`) | JARM/JA4S, cert/favicon/título, conducta | Media (defaults cambian) |
| Red | Malleable C2, jitter | **RITA timing (MADM/skew)**, JA4, Sigma | **Alta** (timing, indep. de contenido) |
| Red | DNS tunneling / DoH | Entropía+longitud+tasa de subdominios; timing en DoH | Alta (claro DNS) / Media (DoH) |
| Endpoint | Fork-and-run / inyección | ETW-TI + EID 8/10 + callbacks | Alta |
| Endpoint | BOF in-process | Escaneo de memoria + call-stack kernel | Media-alta (spoofable) |
| Endpoint | Reflective loading | Memoria unbacked, sin image-load | Alta |
| Endpoint | Sleep obfuscation / call-stack spoof | Escaneo de procesos dormidos; origen de call-stack | Media (carrera armamentista) |
| Endpoint | Parcheo AMSI/ETW | Ausencia anómala de scans; `Kernel-Audit-API-Calls` | Media-alta |
| Cred | Acceso a LSASS | EID 10 (GrantedAccess) + **SACL** + ObRegisterCallbacks | Alta |

---

## 7. Implicaciones para Lattice (C2 de investigación) y el EDR futuro

1. **Arquitectura:** adoptar el patrón moderno verificado — **team server con API** (REST/gRPC) desacoplado de la UI, transportes como módulos, perfiles configurables. Para *investigación* esto es oro: permite instrumentar, medir y **scriptar experimentos** repetibles.
2. **Instrumentación dual desde el día 1:** diseñar Lattice para **emitir y registrar su propia telemetría** en el lab (qué ETW/Sysmon/eventos genera cada acción), generando un **dataset de detección** por técnica. El C2 se vuelve banco de pruebas del EDR.
3. **Emparejar siempre:** por cada *capability*, documentar (a) telemetría generada y (b) detección de referencia (Sigma/ETW/red). Carpeta `detections/` en el repo. Es el eje de la charla y el semillero del EDR.
4. **Apuntar a invariantes, no a IoCs:** tanto para entender evasión como para construir detección resistente, centrarse en **memoria unbacked, periodicidad estadística, origen de call-stack, GrantedAccess sobre LSASS** — lo que el atacante no puede cambiar sin rediseñar.
5. **Para el EDR:** la cobertura fuerte vive en **kernel** (ETW-TI tras PPL/ELAM + callbacks + call-stack), no en hooks user-mode. Diseñar combinando sensores y mapeando puntos ciegos conocidos (límite de 8 drivers en load-image, unlinking de minifilter, comparación literal de Sysmon).

---

## 8. Claims de baja confianza / a verificar antes de publicar

- **"Rápido" de los servidores API** → framing de marketing, sin benchmark público. Presentar como racional de diseño.
- **Internos de productos cerrados** (BRC4 WebSocket+JSON, CS REST API como "core", Nighthawk .NET, "headless Havoc") → **vendor/single-source**; re-verificar contra la URL primaria.
- **Estado real del bloqueo de domain fronting en Fastly** → anuncio firme (feb-2024) pero enforcement **en disputa** (reporte mar-2025 de que aún funcionaba).
- **Constantes de RITA** (MADM 30 s, modo de datos ~65 KB) y **JARM por defecto de CS** → dependientes de versión.
- **SUNBURST ±90 s** y **ritmo 4 s/11 s de Havoc** → aproximados / single-source.
- **Porcentajes de prevalencia** (2/3, ~50 %, 23.7 %) → vendors y denominadores distintos; **no** presentar como serie comparable. Los conteos por escaneo **subestiman** (redirectors, C2 sobre Graph/SharePoint).
- **Fecha de archivado de Havoc (feb-2026)** → secundaria.

---

## 9. Fuentes (deduplicadas)

**Frameworks — docs/repos oficiales**
- Mythic: https://docs.mythic-c2.net/ · https://github.com/its-a-feature/Mythic · https://github.com/MythicMeta/Documentation · https://pypi.org/project/mythic-container/
- Sliver: https://github.com/BishopFox/sliver · wiki (Multiplayer, Armory, Aliases-&-Extensions, BOF-&-COFF, Daemon) · https://deepwiki.com/BishopFox/sliver
- Havoc: https://github.com/HavocFramework/Havoc · https://github.com/HavocFramework/Havoc/blob/main/WIKI.MD
- Cobalt Strike: https://www.cobaltstrike.com/blog/release-out-finally-some-rest · https://hstechdocs.helpsystems.com/manuals/cobaltstrike/current/userguide/ · https://github.com/Cobalt-Strike/bof_template
- Brute Ratel: https://bruteratel.com/ · https://bruteratel.com/release/2025/05/15/Release-Rinnegan/ · https://github.com/paranoidninja/Brute-Ratel-External-C2-Specification
- Outflank C2: https://www.outflank.nl/blog/2024/08/07/introducing-outflank-c2-with-implant-support-for-windows-macos-and-linux/ · https://www.outflank.nl/products/outflank-security-tooling/outflank-c2/
- Nighthawk (MDSec): https://www.mdsec.co.uk/2024/06/nighthawk-0-3-automate-all-the-things/ · https://www.mdsec.co.uk/2021/12/nighthawk-0-1-new-beginnings/

**Implant / OPSEC / BOF**
- Outflank: https://www.outflank.nl/blog/2020/12/26/direct-syscalls-in-beacon-object-files/ · https://www.outflank.nl/blog/2025/07/16/async-bofs-wake-me-up-before-you-go-go/
- AdaptixC2 docs: https://adaptix-framework.gitbook.io/adaptix-framework/adaptix-c2/bof-and-extensions
- IBM X-Force (reflective loader): https://www.ibm.com/think/x-force/defining-cobalt-strike-reflective-loader

**Detección — endpoint**
- Elastic Security Labs: https://www.elastic.co/security-labs/hunting-memory · https://www.elastic.co/security-labs/upping-the-ante-detecting-in-memory-threats-with-kernel-call-stacks · https://www.elastic.co/security-labs/doubling-down-etw-callstacks · https://www.elastic.co/security-labs/detonating-beacons-to-illuminate-detection-gaps · https://github.com/elastic/protections-artifacts
- Microsoft: https://learn.microsoft.com/en-us/windows/win32/etw/about-event-tracing · https://learn.microsoft.com/en-us/defender-endpoint/amsi-on-mdav · https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-pssetloadimagenotifyroutine · https://www.microsoft.com/en-us/security/blog/2017/11/13/detecting-reflective-dll-loading-with-windows-defender-atp/
- ETW-TI: https://github.com/repnz/etw-providers-docs · https://jonny-johnson.medium.com/uncovering-windows-events-b4b9db7eac54 · https://www.bordergate.co.uk/etw-threat-intelligence/ · https://blog.tofile.dev/2020/12/16/elam.html
- Callbacks/minifilter: https://jonny-johnson.medium.com/understanding-telemetry-kernel-callbacks-1a97cfcb8fb3 · https://otterhacker.github.io/Malware/Kernel%20callback.html · https://nostarch.com/download/EvadingEDR_chapter6.pdf · https://fluxsec.red/simple-ransomware-detection-sanctum-minifilter
- AMSI bypass: https://www.crowdstrike.com/en-us/blog/crowdstrike-investigates-threat-of-patchless-amsi-bypass-attacks/ · https://www.trendmicro.com/en_us/research/22/l/detecting-windows-amsi-bypass-techniques.html
- Sysmon/Sigma: https://github.com/trustedsec/SysmonCommunityGuide · https://github.com/SigmaHQ/sigma (rules: lsass_memdump, cobaltstrike named pipes, zeek default CS cert) · https://www.splunk.com/en_us/blog/security/you-bet-your-lsass-hunting-lsass-access.html · https://redcanary.com/threat-detection-report/techniques/lsass-memory/
- Evasión de call-stack: https://offsec.almond.consulting/evading-elastic-callstack-signatures.html

**Detección — red**
- JA3/JARM (Salesforce): https://github.com/salesforce/ja3 · https://engineering.salesforce.com/tls-fingerprinting-with-ja3-and-ja3s-247362855967/ · https://engineering.salesforce.com/easily-identify-malicious-servers-on-the-internet-with-jarm-e095edac525a/ · https://github.com/salesforce/jarm
- JA4 (FoxIO): https://github.com/FoxIO-LLC/ja4 · https://blog.foxio.io/ja4+-network-fingerprinting
- Randomización Chrome: https://www.fastly.com/blog/a-first-look-at-chromes-tls-clienthello-permutation-in-the-wild · https://www.stamus-networks.com/blog/ja3-fingerprints-fade-browsers-embrace-tls-extension-randomization
- RITA/beaconing: https://github.com/activecm/rita · https://www.activecountermeasures.com/malware-of-the-day-understanding-c2-beacons-part-2-of-2/ · https://activecm.github.io/threat-hunting-labs/beacons/ · https://www.elastic.co/security-labs/identifying-beaconing-malware-using-elastic
- DNS/DoH: https://github.com/iagox86/dnscat2 · https://github.com/yarrick/iodine · https://unit42.paloaltonetworks.com/dns-tunneling-in-the-wild/ · https://www.activecountermeasures.com/malware-of-the-day-encrypted-dns-comparison-detecting-c2-when-you-cant-see-the-queries/
- Domain fronting: https://en.wikipedia.org/wiki/Domain_fronting · https://techcommunity.microsoft.com/blog/azurenetworkingblog/prohibiting-domain-fronting-with-azure-front-door-and-azure-cdn-standard-from-mi/4006619 · https://www.risky.biz/fastly-to-block-domain-fronting-in-2024/ · https://blog.compass-security.com/2025/03/bypassing-web-filters-part-3-domain-fronting/
- Suricata/Zeek: https://docs.suricata.io/en/latest/rules/ja-keywords.html · https://packages.zeek.org/packages/view/cebd1c8c-9348-11eb-81e7-0a598146b5c6
- Malleable C2 (Unit 42): https://unit42.paloaltonetworks.com/cobalt-strike-malleable-c2-profile/

**Threat intel / tendencias**
- Recorded Future: https://www.recordedfuture.com/research/2024-malicious-infrastructure-report · https://www.recordedfuture.com/research/2025-year-in-review-malicious-infrastructure
- Red Canary: https://redcanary.com/threat-detection-report/trends/c2-frameworks/
- Microsoft (Sliver): https://www.microsoft.com/en-us/security/blog/2022/08/24/looking-for-the-sliver-lining-hunting-for-emerging-command-and-control-frameworks/
- Unit 42: https://unit42.paloaltonetworks.com/brute-ratel-c4-tool/ · https://unit42.paloaltonetworks.com/adaptixc2-post-exploitation-framework/
- FortiGuard (Havoc/Graph): https://www.fortinet.com/blog/threat-research/havoc-sharepoint-with-microsoft-graph-api-turns-into-fud-c2
- Huntress: https://www.huntress.com/blog/fake-tech-support-havoc-command-control
- SANS/Bushido (BRC4 crack): https://www.sans.org/blog/cracked-brute-ratel-c4-framework-proliferates-across-the-cybercriminal-underground · https://blog.bushidotoken.net/2022/09/brute-ratel-cracked-and-shared-across.html
- Takedowns: https://www.cybersecuritydive.com/news/cobalt-strike-takedown-effort-cuts-cracked-versions-by-80/741906/ · https://www.bleepingcomputer.com/news/security/europol-takes-down-593-cobalt-strike-servers-used-by-cybercriminals/
- Tracking: https://www.shadowserver.org/what-we-do/network-reporting/post-exploitation-framework/ · https://docs.censys.com/docs/platform-threat-hunting-threat-hunting-dataset · https://corelight.com/blog/new-sliver-c2-detection-released-redteam-detected

---

*Revisión de literatura para investigación de seguridad autorizada (lab-only). Toda técnica ofensiva documentada junto a su detección. Verificar los claims marcados de baja confianza contra su fuente primaria antes de publicar en la charla.*
