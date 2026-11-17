/* SPDX-License-Identifier: MIT */
/* What the compilation units of the host test of the payload "xhci" share (tools/test-q1n1-sp11-payload-xhci.py builds them with the
 * parts of the payload): the constants of the unit, the world a run is set in, the state of the model, and the helpers that read the page
 * of a run. test-q1n1-sp11-payload-xhci.c is the model, the audit and main; test-q1n1-sp11-payload-xhci-cases.c holds the suites that run
 * the payload; test-q1n1-sp11-payload-xhci-gates.c calls its store gates directly with inputs no caller of the payload makes. */
#pragma once
#include <inttypes.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define SNAP_PLATFORM_SP11 1
#define Q1N1_SP11_PAYLOAD 1
#include "sp11-payload.h"

#define CAPLENGTH 0x20
#define DBOFF 0x2000
#define RTSOFF 0x1000

uint64_t payload_entry(const struct q1n1_payload_args *a);
#ifndef XHCI_S1_CONTROLLER
#error "build with -DXHCI_S1_CONTROLLER=0 or 1"
#endif
#define T XHCI_S1_CONTROLLER
#define HZ 19200000u
#define LINE 64u
#define BASE_OF(n) ((n) ? UINT64_C(0x0a800000) : UINT64_C(0x0a600000))
#define SMMU_BASE UINT64_C(0x15000000)
#define CB3 (SMMU_BASE + 0x80000 + 3 * 0x1000)
#define WINDOW 0xfc100u
#define NSEC(n) ((uint64_t)(n) * HZ)
#define COUNTER_BASE NSEC(1000)
#define OP(x) (CAPLENGTH + (x))
#define IR(x) (RTSOFF + 0x20 + (x))
#define FIRST_ARENA (T ? 2u : 1u)
#define ATTEMPTS_ALL (T ? 3u : 4u)
/* The tight builds shrink the payload's line budget (and its load budget) to exercise the cuts: only the generic rules and the fuzz apply. */
#ifndef XHCI_S1_LINE_CAP
#define XHCI_S1_LINE_CAP 40u
#endif
#ifndef XHCI_S1_LOAD_CAP
#define XHCI_S1_LOAD_CAP 3800u
#endif
/* xhc_fault_off holds the faulting offset plus one, so that offset 0 can fault as well */
#define FAULT_ON(offset) ((offset) + 1u)

enum { R_STACK, R_FW, R_LOW, R_HIGH, R_DECOY, REGIONS };
enum { K_SILENT, K_CODE, K_POINTER, K_CYCLE, K_REDIRECT, K_PSC, K_HSE_RUN, K_HCE_RUN, K_COUNT };
#define ALL_ARENAS 0x1eu
enum { VIO_NONE, VIO_STORE_OUTSIDE, VIO_STORE_BITS, VIO_NOT_ARMED, VIO_TOO_EARLY, VIO_RAM_OUTSIDE, VIO_RAM_EARLY, VIO_HCRST_RUNNING, VIO_ERSTBA_ORDER,
       VIO_HIGH_FIRST, VIO_RS_SETUP, VIO_RS_SCRATCH, VIO_WRITE_RUNNING, VIO_ALIGN, VIO_DB, VIO_IMAN, VIO_ERDP, VIO_READ, VIO_STORE_SMMU,
       VIO_BAD_COMMAND, VIO_UNKNOWN_WINDOW, VIO_SYSREG, VIO_UNMAPPED_RAM, VIO_NOT_ARMED_RAM, VIO_RAM_RUNNING, VIO_NO_BARRIER, VIO_DC_OUTSIDE, VIO_COUNT };

struct region { uint64_t base; size_t size; uint8_t *dram, *cpu, *state; };
struct store { uint64_t now; unsigned offset, value; char name[16]; };

/* Everything a scenario can change: set after world_default(), applied by go(). */
struct world {
    uint32_t gsnpsid, hciversion, hcs1, hcc1, dboff_reg, rtsoff_reg, pagesize, init_cmd, init_sts, scratch, caplen_reg;
    int hcrst_stuck, cnr_after_reset, cnr_initial, halt_stuck, run_stuck, readback_wrong;
    uint32_t hcrst_ms, cnr_ms;              /* HCRST (or CNR after it) stays set this long after the reset store, then clears: a slow but working reset */
    uint32_t eint_at_run;                   /* per arena id bit: USBSTS.EINT is already set when the controller starts to run (an event posted that we cannot see) */
    uint32_t knob[K_COUNT];                 /* per knob, a bit per arena id (1 to 4) for which it applies */
    uint32_t code, psc_events, iommu;       /* iommu: a bit per region the SMMU lets the xHC reach */
    int coherent, el, map_missing, fw_not_free, high_not_free, low_missing, stall_at_next, stall_in_watch;
    uint64_t tick, stuck_after;
    uint64_t back_ticks;                    /* the counter is set back by this many ticks once: at its back_after-th read, or at the back_at_next-th read after the first NEXT line */
    unsigned back_after, back_at_next;
    int berr_only;                          /* a DMA the SMMU refuses leaves the SMMU's own fault registers as they were: 1, the DWC3 latches its bus error address and valid bit; 2, only the valid bit */
    int reset_error;                        /* the reset itself ends with USBSTS.HSE (1) or USBSTS.HCE (2) set */
    uint32_t smmu_id0, smmu_id1, gfsr, cb_fsr, smmu_fault_off, smmu_fault_after, xhc_fault_off, xhc_fault_after, other_cap0, no_smr;
    uint64_t cb_far;
    int dwc3_fault;
    struct { unsigned at_s, win, port; uint32_t value; } script[8];
    unsigned scripts;
};

#define LINES_MAX 64
#define STORES_MAX 512

/* The state of the model after a run (xhci model in test-q1n1-sp11-payload-xhci.c). */
extern struct world W;
extern struct region regions[REGIONS];
extern struct q1n1_payload_args args;
extern char lines[LINES_MAX][128];
extern unsigned nlines, loads, ram_stores, bad_lines, dma_faults, dma_outside, nstores;
extern struct store stores[STORES_MAX];
extern uint64_t arena_base, arena_bytes, suite_checks, ret_value;
extern char stores_joined[STORES_MAX * 14];
extern unsigned fail_count, checks_count;

void world_default(void);
void world_apply(void);
/* What the model's audit saw since world_apply(): a bit per VIO_ kind, and the first violation's text. */
unsigned model_violation_mask(void);
const char *model_first_violation(void);
/* Runs the payload in the world as it is set and applies the rules that hold of every run; non-zero if one is broken. */
int go(const char *label);
const char *has_prefix(const char *prefix);
int has(const char *line);
unsigned count_prefix(const char *prefix);
int verdict_is(const char *text);

#define CHECK(x) do { \
        if (!(x)) { fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #x); fail_count++; return 1; } \
        checks_count++; \
    } while (0)

/* a missing line is a failed check, not a crash */
static inline const char *str_in(const char *haystack, const char *needle)
{
    return haystack ? strstr(haystack, needle) : NULL;
}
#define strstr(haystack, needle) str_in(haystack, needle)

#define STORES_ARE(s) (!strcmp(stores_joined, (s)))
#define S_RESET "USBCMD:HCRST;"
#define S_PROG "CONFIG;DCBAAP_LO;DCBAAP_HI;CRCR_LO;CRCR_HI;ERSTSZ;ERDP_LO;ERDP_HI;ERSTBA_LO;ERSTBA_HI;"
#define S_RUN "USBCMD:RS;"
#define S_DB "DB0;"
#define S_HAND "ERDP_LO;ERDP_HI;IMAN;"
#define S_STOP "USBCMD:STOP;"
#define ATT_OK S_RESET S_PROG S_RUN S_DB S_HAND S_STOP
#define ATT_SILENT S_RESET S_PROG S_RUN S_DB S_STOP
#define VERDICT_IS(s) verdict_is(s)

/* The suites of test-q1n1-sp11-payload-xhci-cases.c, and suite_gates of test-q1n1-sp11-payload-xhci-gates.c: 0 if they pass. */
int suite_nominal(void);
int suite_scratch(void);
int suite_refuse(void);
int suite_faults(void);
int suite_fallback(void);
int suite_watch(void);
int suite_edges(void);
int suite_fuzz(void);
int suite_gates(void);
