/* fuzz_pcap_payloads.c — --pcap-payloads: masscan's own pcap reader
 * (rawsock-pcapfile.c) plus preprocess_frame() on every frame and the UDP /
 * other-protocol payload extraction in payloads_read_pcap(). */
#include "fuzz_file_common.h"
#include "templ-payloads.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    struct PayloadsUDP *u, *o;
    const char *path = write_input(data, size);
    u = payloads_udp_create();
    o = payloads_oproto_create();
    payloads_read_pcap(path, u, o);
    payloads_udp_destroy(u);
    /* payloads_oproto_destroy() is declared but never defined upstream; the
     * oproto table is the same struct PayloadsUDP, so free it the same way. */
    payloads_udp_destroy(o);
    return 0;
}
