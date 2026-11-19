/* Shared helper for the file-format harnesses: the loaders under test take a
 * path (the CLI option's argument), so each input is written to one private
 * temp file under $TMPDIR, created once per process and rewritten per input. */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static char g_path[4096];

static const char *write_input(const uint8_t *data, size_t size)
{
    FILE *fp;
    if (!g_path[0]) {
        const char *dir = getenv("TMPDIR");
        int fd;
        snprintf(g_path, sizeof(g_path), "%s/masscan-fuzz-XXXXXX", dir && *dir ? dir : "/tmp");
        fd = mkstemp(g_path);
        if (fd < 0)
            abort();
        close(fd);
    }
    fp = fopen(g_path, "wb");
    if (!fp)
        abort();
    if (size)
        fwrite(data, 1, size, fp);
    fclose(fp);
    return g_path;
}
