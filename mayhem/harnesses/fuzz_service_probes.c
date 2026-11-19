/* fuzz_service_probes.c — --nmap-service-probes: the nmap-service-probes
 * grammar parser, then the printer that re-serializes what it parsed. */
#include "fuzz_file_common.h"
#include "read-service-probes.h"

static FILE *g_null;

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    struct NmapServiceProbeList *list;
    const char *path = write_input(data, size);
    if (!g_null)
        g_null = fopen("/dev/null", "w");
    list = nmapserviceprobes_read_file(path);
    /* Like the CLI (one --nmap-service-probes option): read, then use. The
     * list is not freed: nmapserviceprobes_free() loops on `list->count`
     * instead of `i < list->count` (upstream bug), reached from the CLI only
     * when the option is given twice. Each input leaks its own parsed list. */
    if (list)
        nmapserviceprobes_print(list, g_null);
    return 0;
}
