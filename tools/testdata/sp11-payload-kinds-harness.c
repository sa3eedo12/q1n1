/* SPDX-License-Identifier: MIT */
/* Test harness for tools/test-q1n1-sp11-payload-chain.py, never installed: reads a Q1N1PLD1 manifest, checks it
 * with the runner's own validator and prints, for each entry, its path and the kind the runner's loader gives that
 * path ("code" for a payload, "data" for anything else). The test compares this with the kinds
 * tools/sp11_payload_manifest.py says it wrote, so that the host tool and the runner cannot drift apart on which
 * files are called. */
#include <stdio.h>
#include <string.h>

#define SNAP_PLATFORM_SP11 1
#define Q1N1_SP11_PAYLOAD 1
#include "sp11-payload.h"

static struct q1n1_preload_manifest manifest;

int main(int argc, char **argv)
{
    if (argc != 2) return 2;
    FILE *file = fopen(argv[1], "rb");
    if (!file) return 2;
    size_t bytes = fread(&manifest, 1, sizeof manifest, file);
    fclose(file);
    if (!q1n1_preload_manifest_valid(&manifest, bytes)) {
        puts("INVALID");
        return 1;
    }
    for (uint64_t i = 0; i < manifest.count; i++)
        printf("%s %s\n", manifest.files[i].path, q1n1_payload_path_is_code(manifest.files[i].path) ? "code" : "data");
    return 0;
}
