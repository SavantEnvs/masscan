/* fuzz_ranges.c — -iL / --exclude-file: massip_parse_file() (IPv4/IPv6
 * address, range and CIDR state machine) then massip_optimize(), as
 * main-conf.c does for an include/exclude file. */
#include "fuzz_file_common.h"
#include "massip.h"
#include "massip-parse.h"
#include "massip-rangesv4.h"
#include "massip-rangesv6.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    struct MassIP m;
    const char *path = write_input(data, size);
    memset(&m, 0, sizeof(m));
    massip_parse_file(&m, path);
    massip_optimize(&m);
    rangelist_remove_all(&m.ipv4);
    range6list_remove_all(&m.ipv6);
    return 0;
}
