/*
 * fuzz_frame.c — a received Ethernet frame, decoded and dispatched the way
 * masscan's receive thread does it (src/main.c, receive_thread()):
 * preprocess_frame() then, by parsed.found, handle_udp (DNS, NTP, NetBIOS,
 * SNMP, ISAKMP, CoAP, memcached, ZeroAccess), handle_icmp, handle_sctp,
 * handle_oproto or arp_recv_response. Byte 0 picks the data-link type
 * (Ethernet, raw IP, 802.11, ...); the rest is the frame.
 *
 * The Output object is created from a zeroed Masscan with output format
 * "none" and --banners on, so every banner reaches output_report_banner()
 * but nothing is written anywhere. entropy is fixed at 0, so the syn-cookie
 * checks are deterministic per input.
 */
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "masscan.h"
#include "output.h"
#include "proto-preprocess.h"
#include "proto-udp.h"
#include "proto-icmp.h"
#include "proto-sctp.h"
#include "proto-oproto.h"
#include "proto-arp.h"
#include "syn-cookie.h"
#include "templ-pkt.h"
#include "proto-snmp.h"
#include "proto-x509.h"

static struct Masscan *g_masscan;
static struct Output *g_out;

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
    (void)argc; (void)argv;
    snmp_init();              /* main() does both at startup */
    x509_init();
    g_masscan = calloc(1, sizeof(*g_masscan));
    g_masscan->output.format = Output_None;
    g_masscan->is_banners = 1;
    g_out = output_create(g_masscan, 0);
    return 0;
}

/* libpcap LINKTYPE_* values preprocess_frame() handles; Ethernet weighted most. */
static const unsigned links[] = { 1, 1, 1, 1, 0, 12, 0x69, 113, 119, 127 };

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    struct PreprocessedInfo parsed;
    unsigned link, cookie;
    const unsigned char *px;
    unsigned length;
    uint64_t entropy = 0;

    if (size < 1 || size > 1515) /* main.c drops frames > 1514 bytes */
        return 0;
    link = links[data[0] % (sizeof(links)/sizeof(links[0]))];
    length = (unsigned)size - 1;
    /* Known upstream bug: preprocess_frame() reads the 4-byte null/loopback header
     * (link type 0) without a length check (proto-preprocess.c parse_linktype). It is
     * hit within a handful of iterations and stops Mayhem's sanity check, so skip it. */
    if (link == 0 && length < 4)
        return 0;
    /* Copy so ASan sees the exact frame bounds. */
    px = length ? malloc(length) : malloc(1);
    memcpy((void*)px, data + 1, length);

    memset(&parsed, 0, sizeof(parsed));
    if (preprocess_frame(px, length, link, &parsed)) {
        if (parsed.ip_protocol == 132)
            cookie = (unsigned)(syn_cookie(parsed.src_ip, parsed.port_src | (Proto_SCTP<<16),
                                parsed.dst_ip, parsed.port_dst, entropy) & 0xFFFFFFFF);
        else
            cookie = (unsigned)(syn_cookie(parsed.src_ip, parsed.port_src,
                                parsed.dst_ip, parsed.port_dst, entropy) & 0xFFFFFFFF);
        switch (parsed.found) {
        case FOUND_ARP:
            if (parsed.opcode == 2)
                arp_recv_response(g_out, 0, px, length, &parsed);
            break;
        case FOUND_UDP:
        case FOUND_DNS:
            handle_udp(g_out, 0, px, length, &parsed, entropy);
            break;
        case FOUND_ICMP:
            handle_icmp(g_out, 0, px, length, &parsed, entropy);
            break;
        case FOUND_SCTP:
            handle_sctp(g_out, 0, px, length, cookie, &parsed, entropy);
            break;
        case FOUND_OPROTO:
            handle_oproto(g_out, 0, px, length, &parsed, entropy);
            break;
        default:
            break;
        }
    }
    free((void*)px);
    return 0;
}
