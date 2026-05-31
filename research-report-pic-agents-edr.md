# Agentes PIC, OPSEC mínima y detección de EDR (2024-2026)
### Insumo de investigación para arquitectura de Lattice y diseño del EDR defensivo

> **Propósito.** Revisión de literatura pública, nivel arquitectura/conceptual. Cada técnica ofensiva está emparejada con su contraparte de detección — porque el objetivo es diseñar un EDR, no un recetario de evasión. Uso previsto: laboratorio cerrado / investigación autorizada.
>
> **Método.** 2 ramas de búsqueda en paralelo (~60 búsquedas web, ~62 fetches) → claims falsificables con cita y confianza → síntesis. Muchos sites de vendor devolvieron HTTP 403; esos claims se apoyan en extractos de buscador + mirrors (GitHub READMEs, secondary coverage) y se marcan con su nivel de confianza.

---

## 0. Resumen ejecutivo

**PIC puro elimina 2 artefactos, pero deja los que importan para el EDR:**

| Lo que elimina | Lo que NO elimina |
|---|---|
| PE en disco | Memoria ejecutable **unbacked/privada** |
| Evento de image-load (reflective) | Thread con start address en memoria unbacked |
| Header/secciones PE en memoria | Return address en call-stack apuntando a región unbacked |

**Iris C2/MANTIS:** existe como producto marketado, pero sin corroboración técnica independiente. Ver §2.

**El descubrimiento más importante para el EDR:** ninguna detección individual es suficiente — cada una tiene un counter documentado. La arquitectura correcta es un **scorer multi-señal** (ETW-TI + CET shadow stack + call-stack + memoria + estado de hilos), no una sola heurística.

---

## 1. Agentes PIC puros — arquitectura y trade-offs

### 1.1 Qué es "pure PIC"

Un agente **100% position-independent** se compila como shellcode ejecutable directamente sin estructura PE ni fase de reflective loader en runtime. Es distinto del patrón mainstream (Cobalt Strike, Sliver, Mythic) donde un *stager* PIC carga reflexivamente una DLL/PE del agente.

**Ventajas arquitectónicas:**
- Sin PE que mapear → sin PE header/secciones fingerprinting en memoria
- Sin reflective loader → sin image-load event del loader de Windows
- Ideal para canales estrechos (DNS): un BOF <3 KB vs DLL reflexiva 100 KB+

**Costes reales:**
- Sin CRT (C runtime)
- Sin datos estáticos/globales de la forma normal
- Resolución manual de APIs (walk del PEB + hashing de exports)
- Desarrollo significativamente más difícil

*(Stardust/5pider blog, conf. alta)*

### 1.2 Stardust — la referencia real (5pider / autor de Havoc)

**Claim:** Stardust es un template 32/64-bit de implant PIC en C++20 moderno; 5pider afirmó que Havoc se reescribiría para usar implants fully-PIC sin reflective loaders. Es un *template*, no un agente C2 completo.

Técnicas documentadas en el código:
- Hashing FNV-1a en compile-time para resolución de módulo/función
- Encriptación de strings en compile-time (`expr::hash_string`, `symbol`)
- Modificación de permisos de `.bss`/`.data` en runtime para soportar variables globales (workaround porque PIC no puede depender del loader para setup de secciones de datos)

*(https://github.com/Cracked5pider/Stardust · https://5pider.net/blog/2024/01/27/modern-shellcode-implant-design/ — conf. alta)*

### 1.3 Proyectos relacionados (nivel conceptual)

| Proyecto | Qué es | Artefacto en runtime |
|---|---|---|
| **Stardust** (5pider) | Template PIC C++20 | Shellcode puro, sin PE |
| **donut** (TheWover) | Genera shellcode PIC que carga .NET/EXE/DLL desde memoria | PE se mapea en memoria (donut es el extremo opuesto: wraps PE en loader PIC) |
| **sRDI** (monoxgas) | Convierte DLL a shellcode añadiendo un reflective loader PIC | PE reflexivamente mapeado en runtime |
| **Crystal Palace** (Tradecraft Garden) | Linker PIC + lenguaje de linker-script para COFFs → ejecutables PIC sin OS-loader | Modular, multi-PICO |
| **NimPlant beacon PIC** (tijme) | PoC: beacon en C puro, sin Donut/sRDI, ~30 KB vs ~800 KB del beacon reflexivo | Shellcode puro |

Crystal Palace es particularmente relevante (2024-2026): proyectos como **Maverick** y **Adaptix-StealthPalace** construyen agentes C2 modulares PIC sobre él. Rasta Mouse publicó un write-up de "Modular PIC C2 Agents" basado en Crystal Palace.

*(https://tradecraftgarden.org/crystalpalace.html · https://rastamouse.me/modular-pic-c2-agents/ · conf. alta)*

---

## 2. Iris C2 — veredicto

### 2.1 Existe como producto marketado

Existe un producto en irisc2.com con cuenta X/Twitter (@C2IRIS) que:
- Llama a su agente Windows **MANTIS** y lo describe explícitamente como "pure position-independent shellcode" sin fase de reflective PE-load
- Llama a su loader **JAVELIN** y lo marketa como "Fully Undetectable (FUD)" para entregar "MANTIS stage zero" en memoria
- Se presenta como herramienta solo para "agencias de inteligencia, comandos militares de ciberoperaciones, aplicación de la ley y prime contractors"

*(irisc2.com — conf. media: site confirma existencia via snippets; fetch directo bloqueado)*

### 2.2 ⚠️ Sin corroboración técnica independiente

**No se encontró ningún análisis independiente y reputado** (ni Elastic Security Labs, ni Mandiant/Google, ni MDSec, ni SpecterOps, ni Unit 42, ni ningún análisis de muestra de malware) que confirme que IRIS C2/MANTIS es un framework real y capaz. Todo el detalle técnico disponible proviene de su propio marketing.

Red flags:
- Branding "FUD" (Fully Undetectable) — tropo de marketing, no propiedad verificable
- Claims masivos no verificables ("150+ países", proxies residenciales, IA, zero-click iOS/Android)
- Exclusividad de cliente no verificable

**Conclusión para la charla y el diseño del EDR:** IRIS C2 puede citarse como **ejemplo del posicionamiento comercial "pure PIC"**, pero no como referencia técnica verificada. La referencia técnica real para PIC puro es **Stardust + Crystal Palace**.

---

## 3. Detección desde el EDR — las señales residuales

### 3.1 Señales de memoria (base)

**C1. Memoria ejecutable unbacked = señal central independiente del formato.**
Código legítimo vive en regiones `MEM_IMAGE` (mapeadas a un fichero en disco). Código inyectado/PIC vive en `MEM_PRIVATE` committed con permiso de ejecución y sin respaldo en fichero ("floating code"). Esta señal es **invariante al formato**: PIC puro elimina el PE pero NO la región privada+ejecutable.

*(Elastic Security Labs — Hunting Memory, conf. alta)*

**C2. Moneta** (Forrest Orr) detecta: memoria privada committed+ejecutable; imagen PEB sin módulo correspondiente en la lista de módulos cargados (NtMapViewOfSection manual en lugar de LdrLoadDll); hilos con start address en memoria privada/unbacked. Usa contexto circundante para reducir falsos positivos.

*(https://github.com/forrest-orr/moneta · CyberArk Part II, conf. alta)*

**C3. PE-sieve** (hasherezade) busca artefactos PE/shellcode dentro de regiones sospechosas — requiere IOCs adicionales con forma de PE antes de alertar, reduciendo FPs vs. "toda región privada+ejecutable".

*(https://github.com/hasherezade/pe-sieve, conf. alta)*

**C4. Escaneo de procesos dormidos** (Hunt-Sleeping-Beacons / thefLink):
- Wait-reason `DelayExecution` (Sleep) = heurística barata que atrapa muchos implants
- Hilo bloqueado con página privada R(W)X en su call-stack
- Timer/APC-based sleep: `ntdll!KiUserApcDispatcher` en el stack de función bloqueante, enumeración de callbacks de timer de thread-pool (`ntdll!NtContinue`)

*(https://github.com/thefLink/Hunt-Sleeping-Beacons, conf. alta)*

**C5. Fluctuación de protección RW↔RX durante sleep** es detectable vía ETW-TI.
`EtwTi-FluctuationMonitor` consume eventos `PROTECTVM_LOCAL` (NtProtectVirtualMemory): región ejecutable que se vuelve no-ejecutable, o región ejecutable no-escribible que se vuelve escribible. Alerta en >1 violación para suprimir FPs de JIT/hooking.

*(https://github.com/jdu2600/EtwTi-FluctuationMonitor, conf. alta)*

**C6. El bitmap CFG = registro forense persistente de "alguna vez ejecutable".**
En procesos con CFG habilitado, el bitmap se actualiza cuando una región se marca ejecutable pero NO se limpia cuando se marca no-ejecutable. Una región marcada en el bitmap pero actualmente no-ejecutable = shellcode que togglea la ejecución durante el sleep (p. ej. Gargoyle).

*(https://github.com/jdu2600/CFG-FindHiddenShellcode, conf. media)*

**⚠️ Límite (C7):** "MemoryBouncing" (cifrar PE, liberar la región durante sleep, re-alocar como RWX antes de reanudar) y "MemoryHopping" (re-alocar en dirección nueva cada ciclo) evadieron EtwTi-FluctuationMonitor, CFG-FindHiddenShellcode, Moneta y PE-sieve simultáneamente. **Ninguna heurística de estado de memoria sola es completa.**

*(Naksyn blog, DEF CON 30 Kyle Avery, conf. media)*

### 3.2 Call-stack de kernel (la señal más difícil de derrotar)

**C8. Forma esperada del call-stack** para una llamada sensible:
`ntdll.dll!RtlUserThreadStart` → `kernel32.dll!BaseThreadInitThunk` → módulos de usuario → API Win32. El frame final que origina la llamada debe estar en un módulo cargado. **Frame que termina en `Unbacked` = anomalía central.**

*(Elastic Security Labs, conf. alta)*

**C9. Reglas de producción de Elastic** usan `process.thread.Ext.call_stack_contains_unbacked == true` y patrones de `call_stack_summary` como `ntdll.dll|kernelbase.dll|Unbacked`, especialmente cuando DLLs de red (`ws2_32.dll`, `wininet.dll`, `winhttp.dll`) están cargadas — "operación de red cuyo call-stack termina en memoria unbacked."

*(https://github.com/elastic/protections-artifacts — rule: network_module_loaded_from_suspicious_unbacked_memory, conf. alta)*

**C10. Get-InjectedThreadEx** extiende la detección de start address a cuatro clases de trampolines (hooks, hijacks, gadgets, funciones existentes) usados para hacer que la start address parezca respaldada por un PE.

*(https://www.elastic.co/security-labs/get-injectedthreadex-detection-thread-creation-trampolines · https://github.com/jdu2600/Get-InjectedThreadEx, conf. alta)*

**C11. Stacks sintéticos/spoofed** se construyen con RUNTIME_FUNCTION/UNWIND_INFO válidos para que se desenrollen limpiamente. La versión simple (sobreescribir primer frame con 0) deja un stack que no llega a `BaseThreadInitThunk` — anomalía. Versiones avanzadas ("desync"/Draugr) generan frames con unwind codes válidos.

*(https://github.com/mgeeky/ThreadStackSpoofer · https://klezvirus.github.io/posts/Byoud/, conf. alta)*

**⚠️ Límite (C12):** Almond insertó un módulo no-signatured arbitrario via call gadgets en DLLs del sistema, rompiendo los patrones esperados de `call_stack_summary` de Elastic. Elastic fue notificado y actualizó reglas. **Las firmas de resumen de call-stack son frágiles ante inserción de gadgets.**

*(https://offsec.almond.consulting/evading-elastic-callstack-signatures.html, conf. media-alta)*

### 3.3 ETW-TI — fuente de verdad no hookeable (desde user-mode)

**C13.** `Microsoft-Windows-Threat-Intelligence` es un proveedor kernel que emite eventos tras completar operaciones de memoria (ALLOCVM, PROTECTVM, MAPVIEW), manipulación de hilos, APCs, etc. Los eventos salen del kernel → los syscalls directos/indirectos y la eliminación de hooks user-mode NO lo silencian.

*(research.meekolab.com · Praetorian, conf. alta)*

**C14. Gated tras PPL/ELAM.** El kernel solo entrega eventos TI a consumidores con `PS_PROTECTED_ANTIMALWARE_LIGHT` + cert ELAM co-firmado por Microsoft. **Implicación de diseño:** el EDR necesita un driver firmado con ELAM y correr su sensor como PPL.

*(conf. alta)*

**⚠️ Límite (C15):** Con primitivas de escritura kernel (BYOVD), adversarios parchean `nt!EtwThreatIntProvRegHandle.ProviderEnableInfo` a 0, silenciando TI. **La ausencia de eventos TI debe tratarse en sí misma como una alerta.**

*(https://github.com/wavestone-cdt/EDRSandblast, conf. media)*

### 3.4 Hardware: CET Shadow Stack

**C16. Intel CET** empuja la return address a un shadow stack en cada CALL; en RET un mismatch lanza #CP. El shadow stack es read-only en user-mode y no se puede falsificar sin privilegios. Requiere ~11ª gen Intel / Ryzen 5000+ con OS Hardware-enforced Stack Protection habilitado.

*(Microsoft Learn, conf. alta)*

**C17. ShadowStackWalk** (Gabriel Landau / Elastic) reimplementa CaptureStackBackTrace sobre el CET shadow stack: recupera frames que stacks NULL-terminados/rotos ocultan y revela frames forjados que engañan a las APIs estándar. **Diseño recomendado:** inspección híbrida (walk tradicional + verificación shadow-stack) para detectar discrepancias.

*(https://www.elastic.co/security-labs/finding-truth-in-the-shadows · https://github.com/gabriellandau/ShadowStackWalk, conf. alta)*

---

## 4. La carrera armamentista — límites que el diseñador del EDR debe conocer

| Detección | Counter documentado | Confianza del counter |
|---|---|---|
| Escaneo de memoria unbacked | Sleep-mask encrypt/free/realloc (MemoryBouncing/Hopping) | Media |
| Heurísticas de start address | Trampolines de creación de hilo | Alta |
| Firmas de call_stack_summary | Inserción de call-gadgets | Media-alta |
| Walk de stack estándar | Return-address spoofing / synthetic frames | Alta |
| CET shadow-stack comparison | (sin counter de user-mode conocido) | Alta |
| ETW-TI | Patching de ProviderEnableInfo (BYOVD / kernel access) | Media |

**Conclusión:** ninguna capa sola es suficiente. Las herramientas de detección ellas mismas lo reconocen: Hunt-Sleeping-Beacons dice explícitamente que "(almost) none of those IOCs can be considered a 100% true positive."

**La arquitectura correcta del EDR** es un **scorer de señales pesadas** que combina:
1. ETW-TI (no-hookable ground truth)
2. CET shadow-stack comparison
3. Validación de call-stack origin/shape
4. Estado de regiones de memoria
5. Estado de hilos dormidos
6. Detección de sus propios gaps de telemetría (silencio de ETW-TI = alerta)

---

## 5. Implicaciones directas para Lattice y el EDR

### Para Lattice (el agente de investigación)
- El patrón **Crystal Palace** (linker PIC + agentes modulares PICO) es el estado del arte en PIC puro para investigación — más maduro y documentado que depender de marketing de vendors cerrados.
- Para el lab: instrumentar el agente para que emita su propia telemetría de detección (qué regiones crea, qué threads lanza) → el agente como banco de pruebas del EDR.

### Para el EDR
- **Sensor 1:** Escaneo periódico de regiones de memoria por proceso — flag MEM_PRIVATE+ejecutable, esp. long-lived RWX.
- **Sensor 2:** Enumeración de hilos dormidos (wait-reason + start address + región de call-stack).
- **Sensor 3:** Colección de call-stacks en operaciones sensibles (Sleep, llamadas de red) vía ETW-TI.
- **Sensor 4:** Verificación de shadow-stack (CET) cuando disponible.
- **Scorer:** pesar señales, no dar veredictos atómicos.
- **Meta-detección:** ausencia anómala de eventos ETW-TI = alerta propia.

---

## 6. Salvedades de confianza

- **Iris C2/MANTIS**: marketing no corroborado. Usar solo como ejemplo de posicionamiento.
- **5pider/Stardust blog** (5pider.net): devolvió HTTP 403 al fetch; claims via snippets + repo GitHub directamente accesible.
- **Constantes de herramientas** (umbrales de Moneta, thresholds de Hunt-Sleeping-Beacons): verificar contra versión específica.
- **MemoryBouncing/Hopping** como counter (C7): reportado en blog/DEF CON; tratar como conf. media hasta reproducción independiente.

---

## 7. Fuentes

**PIC / Stardust / Crystal Palace**
- https://github.com/Cracked5pider/Stardust
- https://5pider.net/blog/2024/01/27/modern-shellcode-implant-design/
- https://tradecraftgarden.org/crystalpalace.html
- https://rastamouse.me/modular-pic-c2-agents/
- https://github.com/BlackSnufkin/Maverick
- https://github.com/tijme/nimplant-beacon-position-independent-c-code
- https://github.com/TheWover/donut
- https://github.com/monoxgas/sRDI · https://www.netspi.com/blog/technical-blog/adversary-simulation/srdi-shellcode-reflective-dll-injection/

**Iris C2** (marketing no verificado)
- https://www.irisc2.com/ · https://www.irisc2.com/blog/mantis-deep-dive · https://x.com/C2IRIS

**Detección — memoria**
- Elastic Security Labs — Hunting Memory: https://www.elastic.co/security-labs/hunting-memory
- https://github.com/forrest-orr/moneta · https://www.cyberark.com/resources/threat-research-blog/masking-malicious-memory-artifacts-part-ii-insights-from-moneta
- https://github.com/hasherezade/pe-sieve
- https://github.com/thefLink/Hunt-Sleeping-Beacons
- https://github.com/jdu2600/EtwTi-FluctuationMonitor
- https://github.com/jdu2600/CFG-FindHiddenShellcode
- https://naksyn.com/cobalt%20strike/2024/07/02/raising-beacons-without-UDRLs-teaching-how-to-sleep.html

**Detección — call-stack**
- Elastic — Upping the Ante: https://www.elastic.co/security-labs/upping-the-ante-detecting-in-memory-threats-with-kernel-call-stacks
- Elastic — Doubling Down: https://www.elastic.co/security-labs/doubling-down-etw-callstacks
- Elastic — Get-InjectedThreadEx: https://www.elastic.co/security-labs/get-injectedthreadex-detection-thread-creation-trampolines
- https://github.com/jdu2600/Get-InjectedThreadEx
- https://github.com/mgeeky/ThreadStackSpoofer
- https://klezvirus.github.io/posts/Byoud/
- https://offsec.almond.consulting/evading-elastic-callstack-signatures.html
- https://github.com/elastic/protections-artifacts

**ETW-TI / ELAM**
- https://research.meekolab.com/introduction-into-microsoft-threat-intelligence-drivers-etw-ti
- https://www.praetorian.com/blog/etw-threat-intelligence-and-hardware-breakpoints/
- https://github.com/adanto/EtwTiViewer
- https://github.com/wavestone-cdt/EDRSandblast

**CET / Shadow Stack**
- https://www.elastic.co/security-labs/finding-truth-in-the-shadows
- https://github.com/gabriellandau/ShadowStackWalk
- https://learn.microsoft.com/en-us/windows-server/security/kernel-mode-hardware-stack-protection
- https://techcommunity.microsoft.com/blog/windowsosplatform/understanding-hardware-enforced-stack-protection/1247815

*Investigación para seguridad autorizada (lab-only). Toda técnica ofensiva emparejada con su detección. Uso previsto: fundamentar la charla de investigación y el diseño del EDR.*
