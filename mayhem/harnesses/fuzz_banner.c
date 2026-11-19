/*
 * fuzz_banner.c — TCP banner parsers, entered exactly as masscan's TCP stack
 * enters them for data received from a scanned server: banner1_parse() on a
 * fresh StreamState (see banner1_selftest() in src/proto-banner1.c).
 *
 * Build variants:
 *   (default)          byte 0 picks the starting app_proto (PROTO_NONE = the
 *                      smack heuristic dispatcher, or one parser directly),
 *                      bytes 1-2 the server port, byte 3 the chunk size.
 *   -DFIXED_PROTO=X    always start in protocol X (PROTO_SMB / PROTO_SSL3);
 *                      byte 0 is the chunk size.
 * The rest is the server's byte stream, fed in chunks so the per-protocol state
 * machines see data split across TCP segments, as they do on the wire.
 *
 * The socket handle has no TCB, so tcpapi_send/recv/close (the parsers' only
 * use of it) return SOCKERR_EBADF instead of transmitting.
 */
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "proto-banner1.h"
#include "proto-banout.h"
#include "masscan-app.h"
#include "stack-tcp-api.h"
#include "proto-x509.h"

static struct Banner1 *g_banner1;

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
    (void)argc; (void)argv;
    x509_init();              /* main() does this at startup: the OID matcher */
    g_banner1 = banner1_create();
    /* Turn on every optional capture, as the --capture options do, so the
     * cert/html/heartbleed paths parse too. Read-only after this point. */
    g_banner1->is_capture_html = 1;
    g_banner1->is_capture_cert = 1;
    g_banner1->is_capture_servername = 1;
    g_banner1->is_capture_heartbleed = 1;
    g_banner1->is_capture_ticketbleed = 1;
    return 0;
}

#ifndef FIXED_PROTO
static const unsigned short protos[] = {
    PROTO_NONE, PROTO_HEUR, PROTO_SSH1, PROTO_SSH2, PROTO_HTTP, PROTO_FTP,
    PROTO_SSL3, PROTO_SMB, PROTO_SMTP, PROTO_POP3, PROTO_IMAP4, PROTO_VNC_RFB,
    PROTO_MEMCACHED, PROTO_SCRIPTING, PROTO_VERSIONING, PROTO_TELNET, PROTO_RDP,
    PROTO_MC,
};
#endif

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    struct StreamState state;
    struct BannerOutput banout[1];
    struct stack_handle_t socket = {0, 0, 0, 0};
    size_t chunk, off;

    memset(&state, 0, sizeof(state));
#ifdef FIXED_PROTO
    if (size < 1)
        return 0;
    state.app_proto = FIXED_PROTO;
    state.port = FIXED_PORT;
    state.is_sent_sslhello = 1;
    chunk = data[0];
    data += 1; size -= 1;
#else
    if (size < 4)
        return 0;
    state.app_proto = protos[data[0] % (sizeof(protos)/sizeof(protos[0]))];
    state.port = (unsigned short)(data[1] << 8 | data[2]);
    state.is_sent_sslhello = (data[0] & 0x80) != 0;
    chunk = data[3];
    data += 4; size -= 4;
#endif
    if (chunk == 0)
        chunk = size ? size : 1;

    banout_init(banout);
    for (off = 0; off < size; off += chunk) {
        size_t n = size - off < chunk ? size - off : chunk;
        banner1_parse(g_banner1, &state, data + off, n, banout, &socket);
    }
    banout_release(banout);
    return 0;
}
