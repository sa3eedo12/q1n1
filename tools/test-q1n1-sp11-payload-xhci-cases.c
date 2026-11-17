/* SPDX-License-Identifier: MIT */
/* The suites of the host test of the payload "xhci" (payloads/xhci*.c, stage S1 of the Surface Pro 11 stick study): each sets a world,
 * runs the payload in the model of test-q1n1-sp11-payload-xhci.c and checks the page and the stores against an oracle that does not use the
 * payload's formatter. Every case that must refuse or fail has its page and its stores checked as closely as the nominal one. Nothing here
 * runs on hardware. Evidence: EXPERIMENTAL (host model only). */
#include "test-q1n1-sp11-payload-xhci.h"

static char repeated[STORES_MAX * 14];
static const char *times(unsigned n, const char *unit)
{
    repeated[0] = 0;
    for (unsigned i = 0; i < n; i++) strcat(repeated, unit);
    return repeated;
}

static int hex_text(char *dst, size_t cap, const char *fmt, uint64_t v)
{
    return snprintf(dst, cap, fmt, v);
}

/* The unit as far as it is known: the page of a nominal run, line by line, from an oracle that does not use the payload's formatter. */
int suite_nominal(void)
{
    char expect[200];
    unsigned first = FIRST_ARENA;
    uint64_t base = first == 1 ? 0xCF412000ull : 0xCEC91000ull;
    world_default();
    CHECK(!go("nominal"));
    CHECK(ret_value == 0);
    CHECK(VERDICT_IS("NOOP_OK ARENA=") && strstr(has_prefix("PAYLOAD XHCI VERDICT "), first == 1 ? "ARENA=1" : "ARENA=2"));
    snprintf(expect, sizeof expect, "PAYLOAD XHCI U%d ID=0X33313130 CAPL=0X20 VER=0X110 HCS1=0X2000840 HCS2=0X10000000 HCC1=0X110FFC5", T);
    CHECK(has(expect));
    snprintf(expect, sizeof expect, "PAYLOAD XHCI U%d SCRATCH=2 PAGESZ=0X1 AC64=1 CSZ=64 DBOFF=0X2000 RTSOFF=0X1000", T);
    CHECK(has(expect));
    snprintf(expect, sizeof expect, "PAYLOAD XHCI U%d CMD=0X0 STS=%s CRCR=0X0 DCBAAP=0X0 CFG=0X0", T, T ? "0X1:HCH" : "0X11:HCH.PCD");
    CHECK(has(expect));
    snprintf(expect, sizeof expect, "PAYLOAD XHCI SMMU STREAM=%s SMR=%d TRANS CB=3 NCB=0X5F", T ? "0X1460" : "0X1420", T ? 4 : 3);
    CHECK(has(expect));
    CHECK(has("PAYLOAD XHCI SMMU0 GFSR=0X0 FSR=0X400 FAR=0X953FDF7CF7F7 FSYNR0=0X46005D"));
    CHECK(has(T ? "PAYLOAD XHCI ARENAS 2=OK 3=OK 4=OK" : "PAYLOAD XHCI ARENAS 1=OK 2=OK 3=OK 4=OK"));
    CHECK(has("PAYLOAD XHCI WATCH 30 S: CONNECT THE MAC USB-C CABLE TO THE FREE PORT NOW"));
    CHECK(has("PAYLOAD XHCI BASE U0P1=0X20002A0 U0P2=0X20002A0 U1P1=0X20002A0 U1P2=0X20002A0"));
    CHECK(has("PAYLOAD XHCI WATCH 20 S LEFT") && has("PAYLOAD XHCI WATCH 10 S LEFT"));
    CHECK(has("PAYLOAD XHCI WATCH DONE CHANGED=NONE N=0"));
    hex_text(expect, sizeof expect, "PAYLOAD XHCI NEXT ARENA %d", first);
    CHECK(has_prefix(expect));
    snprintf(expect, sizeof expect, "PAYLOAD XHCI NEXT ARENA %u %s 0X%llX PAGES 3 AFTER 8 S", first, first == 1 ? "FW" : "STACK", (unsigned long long)base);
    CHECK(has(expect));
    CHECK(has("PAYLOAD XHCI NEXT RESET AFTER 8 S") && has("PAYLOAD XHCI NEXT PROGRAM AFTER 8 S") && has("PAYLOAD XHCI NEXT RUN AFTER 8 S") &&
          has("PAYLOAD XHCI NEXT NOOP AFTER 8 S"));
    snprintf(expect, sizeof expect, "PAYLOAD XHCI R1 ARENA=%u NOOP_OK STAGE=NOOP CC=1 STS=0X9:HCH.EINT EV=1 SMMU=SAME", first);
    CHECK(has(expect));
    snprintf(expect, sizeof expect, "PAYLOAD XHCI VERDICT NOOP_OK ARENA=%u", first);
    CHECK(has(expect));
    snprintf(expect, sizeof expect, "PAYLOAD XHCI END HALTED=YES WRITES=17 LOADS=%u", loads);
    CHECK(has(expect));
    CHECK(STORES_ARE(ATT_OK));
    CHECK(nlines == 19);
    /* the order of the page: the announcements stand before their results */
    for (unsigned i = 0, seen = 0; i < nlines; i++) {
        if (!strncmp(lines[i], "PAYLOAD XHCI NEXT ARENA", 23)) seen |= 1;
        if (!strncmp(lines[i], "PAYLOAD XHCI NEXT NOOP", 22)) seen |= 2;
        if (!strncmp(lines[i], "PAYLOAD XHCI R1 ", 16)) CHECK(seen == 3);
    }
    /* a coherent machine gives the same page: the maintenance is harmless there */
    world_default();
    W.coherent = 1;
    CHECK(!go("nominal-coherent"));
    CHECK(VERDICT_IS("NOOP_OK ARENA=") && STORES_ARE(ATT_OK));
    return 0;
}

static unsigned expected_first_arena(unsigned scratch)
{
    unsigned pages = 1 + scratch;
    if (!T && pages <= 4) return 1;
    return pages <= 9 ? 2 : 3;
}

int suite_scratch(void)
{
    static const unsigned counts[] = {0, 1, 2, 3, 4, 8, 9, 16, 31, 32};
    char expect[120];
    for (unsigned i = 0; i < sizeof counts / sizeof counts[0]; i++) {
        unsigned n = counts[i], arena = expected_first_arena(n);
        world_default();
        W.scratch = n;
        CHECK(!go("scratch"));
        snprintf(expect, sizeof expect, "PAYLOAD XHCI VERDICT NOOP_OK ARENA=%u", arena);
        CHECK(has(expect));
        snprintf(expect, sizeof expect, "PAYLOAD XHCI NEXT ARENA %u ", arena);
        CHECK(has_prefix(expect));
        snprintf(expect, sizeof expect, " PAGES %u AFTER 8 S", 1 + n);
        CHECK(strstr(has_prefix("PAYLOAD XHCI NEXT ARENA"), expect));
        CHECK(STORES_ARE(ATT_OK));
        CHECK(count_prefix("PAYLOAD XHCI NEXT ARENA") == 1);
    }
    world_default();
    W.scratch = 33;
    CHECK(!go("scratch-33"));
    CHECK(has("PAYLOAD XHCI VERDICT REFUSED=SCRATCHPADS VALUE=0X21") && !nstores && !ram_stores);
    /* the count is HCSPARAMS2's high and low fields together */
    world_default();
    W.scratch = 0x23;
    CHECK(!go("scratch-0x23"));
    CHECK(has("PAYLOAD XHCI VERDICT REFUSED=SCRATCHPADS VALUE=0X23") && !nstores);
    return 0;
}

static int refused(const char *name, const char *rest)
{
    char expect[160];
    snprintf(expect, sizeof expect, "PAYLOAD XHCI VERDICT REFUSED=%s%s%s", name, rest[0] ? " " : "", rest);
    if (!has(expect)) fprintf(stderr, "wanted %s; the page has %s\n", expect, has_prefix("PAYLOAD XHCI VERDICT") ? has_prefix("PAYLOAD XHCI VERDICT") : "none");
    return has(expect) && !nstores && !ram_stores ? 0 : 1;
}

int suite_refuse(void)
{
    world_default(); W.gsnpsid = 0x33313131; CHECK(!go("id")); CHECK(!refused("DWC3_ID", "VALUE=0X33313131"));
    world_default(); W.caplen_reg = 0x30; CHECK(!go("caplength")); CHECK(!refused("CAPLENGTH", "VALUE=0X30"));
    world_default(); W.hciversion = 0x0100; CHECK(!go("version")); CHECK(!refused("HCIVERSION", "VALUE=0X100"));
    world_default(); W.hcs1 = 0; CHECK(!go("no-ports")); CHECK(!refused("NOT_XHCI", ""));
    world_default(); W.hcs1 = (2u << 24) | (8u << 8) | 72u; CHECK(!go("slots")); CHECK(!refused("NOT_XHCI", ""));
    world_default(); W.dboff_reg = 0x200000; CHECK(!go("dboff")); CHECK(!refused("OFFSET", "VALUE=0X200000"));
    world_default(); W.rtsoff_reg = 0x10; CHECK(!go("rtsoff")); CHECK(!refused("OFFSET", "VALUE=0X10"));
    /* DBOFF and RTSOFF are the controller's word and are used as printed: reserved low bits refuse, and so does any register of the record that would lie
     * at or above the DWC3 global registers (0xc100), where a doorbell write would land in the core's own control register. */
    world_default(); W.dboff_reg = 0xc110; CHECK(!go("dboff-dwc3")); CHECK(!refused("OFFSET", "VALUE=0XC110"));
    world_default(); W.dboff_reg = 0xc100; CHECK(!go("dboff-limit")); CHECK(!refused("OFFSET", "VALUE=0XC100"));
    world_default(); W.dboff_reg = 0x2002; CHECK(!go("dboff-unaligned")); CHECK(!refused("OFFSET", "VALUE=0X2002"));
    world_default(); W.dboff_reg = 0x2001; CHECK(!go("dboff-unaligned-1")); CHECK(!refused("OFFSET", "VALUE=0X2001"));
    world_default(); W.rtsoff_reg = 0x1004; CHECK(!go("rtsoff-unaligned")); CHECK(!refused("OFFSET", "VALUE=0X1004"));
    world_default(); W.rtsoff_reg = 0x1010; CHECK(!go("rtsoff-half")); CHECK(!refused("OFFSET", "VALUE=0X1010"));
    world_default(); W.rtsoff_reg = 0xc0e0; CHECK(!go("rtsoff-dwc3")); CHECK(!refused("OFFSET", "VALUE=0XC108"));
    world_default(); W.init_sts |= 1u << 12; CHECK(!go("hce")); CHECK(has_prefix("PAYLOAD XHCI VERDICT REFUSED=HCE STS=") && !nstores);
    world_default(); W.init_sts |= 1u << 2; CHECK(!go("hse")); CHECK(has_prefix("PAYLOAD XHCI VERDICT REFUSED=HSE STS=") && !nstores);
    world_default(); W.cnr_initial = 1; CHECK(!go("cnr")); CHECK(has_prefix("PAYLOAD XHCI VERDICT REFUSED=CNR STS=") && !nstores && !ram_stores);
    world_default(); W.init_cmd = 1; W.init_sts = 0; CHECK(!go("running")); CHECK(!refused("RUNNING", "CMD=0X1"));
    world_default(); W.init_sts = 0; CHECK(!go("not-halted")); CHECK(has_prefix("PAYLOAD XHCI VERDICT REFUSED=RUNNING"));
    world_default(); W.pagesize = 0; CHECK(!go("pagesize")); CHECK(!refused("PAGESIZE", "VALUE=0X0"));
    world_default(); W.smmu_fault_off = 0x20; CHECK(!go("smmu-id0")); CHECK(!refused("SMMU_UNREADABLE", "AT=SMMU_ID0"));
    world_default(); W.smmu_fault_off = 0x24; CHECK(!go("smmu-id1")); CHECK(!refused("SMMU_UNREADABLE", "AT=SMMU_ID1"));
    world_default(); W.smmu_fault_off = 0x48; CHECK(!go("smmu-gfsr")); CHECK(!refused("SMMU_UNREADABLE", "AT=SMMU_GFSR"));
    world_default(); W.smmu_fault_off = 0x800 + 4 * 2; CHECK(!go("smmu-smr")); CHECK(!refused("SMMU_UNREADABLE", "AT=SMMU_SMR"));
    world_default(); W.smmu_fault_off = (uint32_t)(CB3 - SMMU_BASE + 0x58); CHECK(!go("smmu-fsr")); CHECK(!refused("SMMU_UNREADABLE", "AT=CB_FSR"));
    world_default(); W.smmu_id0 = 0; CHECK(!go("smmu-zero")); CHECK(!refused("SMMU_UNREADABLE", ""));
    world_default(); W.smmu_id1 = 0xffffffffu; CHECK(!go("smmu-ones")); CHECK(!refused("SMMU_UNREADABLE", ""));
    world_default(); W.dwc3_fault = 1; CHECK(!go("dwc3")); CHECK(!refused("READ_FAULT", "AT=GSNPSID"));
    world_default(); W.xhc_fault_off = FAULT_ON(0x400 + CAPLENGTH); W.xhc_fault_after = 1; CHECK(!go("portsc")); CHECK(!refused("READ_FAULT", "AT=PORTSC"));
    world_default(); W.xhc_fault_off = FAULT_ON(0); W.xhc_fault_after = 1; CHECK(!go("cap0")); CHECK(!refused("READ_FAULT", "AT=CAP0"));
    world_default(); W.el = 1; CHECK(!go("el1")); CHECK(nlines == 1 && has("PAYLOAD XHCI SKIPPED_NOT_AT_EL2") && !loads && !nstores);
    world_default(); W.tick = 0; CHECK(!go("counter-stuck")); CHECK(!refused("COUNTER_STUCK", ""));
    world_default(); W.iommu = 0; W.map_missing = 1; W.low_missing = 1; W.high_not_free = 1; W.fw_not_free = 1; CHECK(!go("no-arena"));
    CHECK(has_prefix("PAYLOAD XHCI VERDICT NOOP_") || has_prefix("PAYLOAD XHCI VERDICT REFUSED"));
    world_default(); W.hcc1 &= ~1u; W.map_missing = 1; CHECK(!go("no-map-no-ac64"));
    CHECK(has(T ? "PAYLOAD XHCI ARENAS 2=OK 3=NO_MAP 4=NO_AC64" : "PAYLOAD XHCI ARENAS 1=NO_MAP 2=OK 3=NO_MAP 4=NO_AC64"));
    /* the target's window is not touched when the arguments are bad */
    world_default(); world_apply(); args.magic = 0; CHECK(payload_entry(&args) == 1 && !nlines && !loads);
    return 0;
}

static int check_failed_attempts(unsigned n, const char *unit, const char *verdict_text)
{
    CHECK(count_prefix("PAYLOAD XHCI NEXT ARENA") == n);
    CHECK(STORES_ARE(times(n, unit)));
    CHECK(has_prefix(verdict_text));
    return 0;
}

int suite_faults(void)
{
    const unsigned n = ATTEMPTS_ALL;
    char expect[200];
    /* A No Op that never completes: every arena is tried, each ends halted, the verdict is the last one's, and every attempt announces each of its groups. */
    world_default(); W.knob[K_SILENT] = ALL_ARENAS; CHECK(!go("silent"));
    CHECK(!check_failed_attempts(n, ATT_SILENT, "PAYLOAD XHCI VERDICT NOOP_TIMEOUT STAGE=NOOP WHY=EVENT"));
    CHECK(strstr(has_prefix("PAYLOAD XHCI END"), "HALTED=YES") && count_prefix("PAYLOAD XHCI R") == n);
    CHECK(count_prefix("PAYLOAD XHCI NEXT RESET") == n && count_prefix("PAYLOAD XHCI NEXT PROGRAM") == n && count_prefix("PAYLOAD XHCI NEXT RUN") == n &&
          count_prefix("PAYLOAD XHCI NEXT NOOP") == n);
    /* A completion that is not a success, not ours, or with the wrong cycle bit is a bad completion: the run ends there, after one attempt, and the controller
     * is halted. A controller that answers wrongly is not given a fresh DMA into another arena in the same boot. */
    world_default(); W.knob[K_CODE] = ALL_ARENAS; CHECK(!go("code"));
    CHECK(!check_failed_attempts(1, ATT_OK, "PAYLOAD XHCI VERDICT NOOP_BAD_COMPLETION STAGE=NOOP WHY=CODE"));
    snprintf(expect, sizeof expect, "PAYLOAD XHCI R1 ARENA=%u NOOP_BAD_COMPLETION STAGE=NOOP WHY=CODE CC=13", FIRST_ARENA);
    CHECK(has(expect) && has("PAYLOAD XHCI R1 STS=0X9:HCH.EINT EV=1 SMMU=SAME"));
    CHECK(strstr(has_prefix("PAYLOAD XHCI END"), "HALTED=YES") && count_prefix("PAYLOAD XHCI R") == 2);
    world_default(); W.knob[K_POINTER] = ALL_ARENAS; CHECK(!go("pointer"));
    CHECK(!check_failed_attempts(1, ATT_OK, "PAYLOAD XHCI VERDICT NOOP_BAD_COMPLETION STAGE=NOOP WHY=POINTER"));
    CHECK(strstr(has_prefix("PAYLOAD XHCI END"), "HALTED=YES"));
    world_default(); W.knob[K_CYCLE] = ALL_ARENAS; CHECK(!go("cycle"));
    CHECK(!check_failed_attempts(1, ATT_SILENT, "PAYLOAD XHCI VERDICT NOOP_BAD_COMPLETION STAGE=NOOP WHY=CYCLE"));
    CHECK(strstr(has_prefix("PAYLOAD XHCI END"), "HALTED=YES"));
    /* An event the controller says it posted (USBSTS.EINT, clear before the doorbell) that is not in the ring: it was written somewhere else, and the DMA went
     * astray: a bad completion, and no further attempt. */
    world_default(); W.knob[K_REDIRECT] = ALL_ARENAS; CHECK(!go("redirect"));
    CHECK(!check_failed_attempts(1, ATT_SILENT, "PAYLOAD XHCI VERDICT NOOP_BAD_COMPLETION STAGE=NOOP WHY=REDIRECT"));
    CHECK(dma_outside >= 1 && strstr(has_prefix("PAYLOAD XHCI END"), "HALTED=YES"));
    snprintf(expect, sizeof expect, "PAYLOAD XHCI R1 ARENA=%u NOOP_BAD_COMPLETION STAGE=NOOP WHY=REDIRECT STS=0X9:HCH.EINT EV=0 SMMU=SAME", FIRST_ARENA);
    CHECK(has(expect));
    /* A silence first and a bad completion after it: the second attempt ends the run (the first one's arena is not retried, the third is not tried). */
    world_default(); W.knob[K_SILENT] = 1u << FIRST_ARENA; W.knob[K_CODE] = 2u << FIRST_ARENA; CHECK(!go("silent-then-code"));
    CHECK(count_prefix("PAYLOAD XHCI NEXT ARENA") == 2 && STORES_ARE(ATT_SILENT ATT_OK) && has_prefix("PAYLOAD XHCI VERDICT NOOP_BAD_COMPLETION STAGE=NOOP WHY=CODE"));
    CHECK(strstr(has_prefix("PAYLOAD XHCI R1 ARENA="), " NOOP_TIMEOUT ") && strstr(has_prefix("PAYLOAD XHCI R2 ARENA="), " NOOP_BAD_COMPLETION "));
    world_default(); W.knob[K_SILENT] = 1u << FIRST_ARENA; W.knob[K_REDIRECT] = 2u << FIRST_ARENA; CHECK(!go("silent-then-redirect"));
    CHECK(count_prefix("PAYLOAD XHCI NEXT ARENA") == 2 && STORES_ARE(ATT_SILENT ATT_SILENT) && has_prefix("PAYLOAD XHCI VERDICT NOOP_BAD_COMPLETION STAGE=NOOP WHY=REDIRECT"));
    /* An event that may be pending already (USBSTS.EINT set before the doorbell, nothing of ours in the ring) cannot be told from a silence: a timeout, and the
     * next arena. */
    world_default(); W.eint_at_run = ALL_ARENAS; W.knob[K_SILENT] = ALL_ARENAS; CHECK(!go("eint-before-and-silent"));
    CHECK(!check_failed_attempts(n, ATT_SILENT, "PAYLOAD XHCI VERDICT NOOP_TIMEOUT STAGE=NOOP WHY=EVENT"));
    /* An event that is in the ring is not a redirect, whatever else the controller posted. */
    world_default(); W.psc_events = 2; W.knob[K_PSC] = ALL_ARENAS; W.knob[K_SILENT] = ALL_ARENAS; CHECK(!go("psc-and-silent"));
    CHECK(!check_failed_attempts(n, ATT_SILENT, "PAYLOAD XHCI VERDICT NOOP_TIMEOUT STAGE=NOOP WHY=EVENT"));
    /* A completion after port status changes: they are skipped, the completion is found, the ring is handed back past all of them. */
    world_default(); W.psc_events = 3; W.knob[K_PSC] = ALL_ARENAS; CHECK(!go("psc"));
    CHECK(VERDICT_IS("NOOP_OK ARENA=") && STORES_ARE(ATT_OK));
    snprintf(expect, sizeof expect, "PAYLOAD XHCI R1 ARENA=%u NOOP_OK STAGE=NOOP CC=1 STS=0X9:HCH.EINT EV=4 PSC=3 SMMU=SAME", FIRST_ARENA);
    CHECK(has(expect));
    /* A bus error: the SMMU refuses every arena. */
    world_default(); W.iommu = 0; CHECK(!go("hse"));
    CHECK(!check_failed_attempts(n, ATT_SILENT, "PAYLOAD XHCI VERDICT NOOP_HSE STAGE=NOOP WHY=HSE"));
    CHECK(dma_faults >= n && has_prefix("PAYLOAD XHCI R1 ARENA=") && strstr(has_prefix("PAYLOAD XHCI R1 ARENA="), "SMMU=CHANGED"));
    CHECK(strstr(has_prefix("PAYLOAD XHCI SMMU1 R1 "), " FSR=0X402 FAR=0X") && strstr(has_prefix("PAYLOAD XHCI SMMU1 R1 "), " BERR=0X"));
    CHECK(count_prefix("PAYLOAD XHCI SMMU0 ") == 1 && count_prefix("PAYLOAD XHCI SMMU1 R1 ") == 1);
    /* HSE and HCE right after R/S. */
    world_default(); W.knob[K_HSE_RUN] = ALL_ARENAS; CHECK(!go("hse-run"));
    CHECK(has_prefix("PAYLOAD XHCI VERDICT NOOP_HSE STAGE=RUN WHY=HSE") && STORES_ARE(times(n, S_RESET S_PROG S_RUN S_STOP)));
    world_default(); W.knob[K_HCE_RUN] = ALL_ARENAS; CHECK(!go("hce-run"));
    CHECK(has_prefix("PAYLOAD XHCI VERDICT NOOP_HSE STAGE=RUN WHY=HCE") && STORES_ARE(times(n, S_RESET S_PROG S_RUN S_STOP)));
    /* HSE or HCE that the reset itself ends with is the controller's answer and not the arena's: the run ends at that attempt, with no other arena tried. */
    world_default(); W.reset_error = 1; CHECK(!go("hse-reset"));
    CHECK(has_prefix("PAYLOAD XHCI VERDICT NOOP_HSE STAGE=RESET WHY=HSE") && STORES_ARE(S_RESET) && count_prefix("PAYLOAD XHCI NEXT ARENA") == 1 && count_prefix("PAYLOAD XHCI NEXT PROGRAM") == 0);
    world_default(); W.reset_error = 2; CHECK(!go("hce-reset"));
    CHECK(has_prefix("PAYLOAD XHCI VERDICT NOOP_HSE STAGE=RESET WHY=HCE") && STORES_ARE(S_RESET) && count_prefix("PAYLOAD XHCI NEXT ARENA") == 1 && count_prefix("PAYLOAD XHCI NEXT PROGRAM") == 0);
    /* The controller itself: nothing after the stage reached. */
    world_default(); W.hcrst_stuck = 1; CHECK(!go("hcrst"));
    CHECK(has_prefix("PAYLOAD XHCI VERDICT NOOP_TIMEOUT STAGE=RESET WHY=HCRST") && STORES_ARE(S_RESET) && count_prefix("PAYLOAD XHCI NEXT PROGRAM") == 0);
    world_default(); W.cnr_after_reset = 1; CHECK(!go("cnr-after"));
    CHECK(has_prefix("PAYLOAD XHCI VERDICT NOOP_TIMEOUT STAGE=RESET WHY=CNR") && STORES_ARE(S_RESET) && count_prefix("PAYLOAD XHCI NEXT PROGRAM") == 0);
    world_default(); W.readback_wrong = 1; CHECK(!go("not-held"));
    CHECK(has_prefix("PAYLOAD XHCI VERDICT NOOP_TIMEOUT STAGE=PROGRAM WHY=NOT_HELD") && count_prefix("PAYLOAD XHCI NEXT RUN") == 0);
    CHECK(strstr(stores_joined, "ERSTBA_HI;") && !strstr(stores_joined, "USBCMD:RS"));
    world_default(); W.run_stuck = 1; CHECK(!go("run-stuck"));
    CHECK(has_prefix("PAYLOAD XHCI VERDICT NOOP_TIMEOUT STAGE=RUN WHY=HCH") && count_prefix("PAYLOAD XHCI NEXT NOOP") == 0);
    CHECK(!strstr(stores_joined, "DB0"));
    /* A halt that never completes: the controller is not known to be halted, the arena is not zeroed, nothing more is tried. */
    world_default(); W.halt_stuck = 1; W.knob[K_SILENT] = ALL_ARENAS; CHECK(!go("halt-stuck"));
    CHECK(strstr(has_prefix("PAYLOAD XHCI END "), "HALTED=NO") && count_prefix("PAYLOAD XHCI NEXT ARENA") == 1);
    CHECK(STORES_ARE(S_RESET S_PROG S_RUN S_DB S_STOP));
    /* A counter that stops after the first announcement: no write at all. */
    world_default(); W.stall_at_next = 1; CHECK(!go("counter-stall"));
    CHECK(nstores == 0 && has_prefix("PAYLOAD XHCI VERDICT NOOP_TIMEOUT STAGE=ARENA WHY=CLOCK"));
    /* A register that stops answering after the writes began: the load budget and the page stay bounded. */
    world_default(); W.xhc_fault_off = FAULT_ON(CAPLENGTH + 4); W.xhc_fault_after = 400; CHECK(!go("read-fault-later"));
    CHECK(has_prefix("PAYLOAD XHCI VERDICT NOOP_TIMEOUT STAGE=") && loads < Q1N1_PAYLOAD_LOADS_MAX);
    /* The SMMU stops answering after the pre-flight: the page says UNREAD, the attempt's own verdict stands, nothing else changes. */
    world_default(); W.smmu_fault_off = 0x48; W.smmu_fault_after = 100; CHECK(!go("smmu-unread"));
    CHECK(strstr(has_prefix("PAYLOAD XHCI R1 ARENA="), "SMMU=UNREAD") && VERDICT_IS("NOOP_OK ARENA=") && STORES_ARE(ATT_OK));
    return 0;
}

int suite_fallback(void)
{
    char expect[160];
    /* The arena the SMMU does not reach fails, the next completes; each attempt announces all its groups, and the second one's SMMU line compares with the end of
     * the first, not with the start of the run: attempt 1 faulted, attempt 2 changed nothing. */
    world_default(); W.iommu = ~(1u << R_STACK) & ((1u << REGIONS) - 1); CHECK(!go("stack-refused"));
    CHECK(VERDICT_IS(T ? "NOOP_OK ARENA=3" : "NOOP_OK ARENA=1"));
    if (T) {
        CHECK(STORES_ARE(ATT_SILENT ATT_OK) && count_prefix("PAYLOAD XHCI NEXT RESET") == 2 && count_prefix("PAYLOAD XHCI NEXT ARENA") == 2);
        CHECK(strstr(has_prefix("PAYLOAD XHCI R1 ARENA=2 "), " NOOP_HSE ") && strstr(has_prefix("PAYLOAD XHCI R1 ARENA=2 "), " SMMU=CHANGED"));
        CHECK(strstr(has_prefix("PAYLOAD XHCI R2 ARENA=3 "), " NOOP_OK ") && strstr(has_prefix("PAYLOAD XHCI R2 ARENA=3 "), " SMMU=SAME"));
        CHECK(count_prefix("PAYLOAD XHCI SMMU1 R1 ") == 1 && count_prefix("PAYLOAD XHCI SMMU1 R2") == 0);
    }
    if (!T) {
        world_default(); W.iommu = ~(1u << R_FW) & ((1u << REGIONS) - 1); CHECK(!go("fw-refused"));
        CHECK(VERDICT_IS("NOOP_OK ARENA=2") && STORES_ARE(ATT_SILENT ATT_OK) && count_prefix("PAYLOAD XHCI NEXT RESET") == 2);
        CHECK(has_prefix("PAYLOAD XHCI R1 ARENA=1 NOOP_HSE STAGE=NOOP WHY=HSE") && has_prefix("PAYLOAD XHCI R2 ARENA=2 NOOP_OK"));
        CHECK(strstr(has_prefix("PAYLOAD XHCI R1 ARENA=1 "), " SMMU=CHANGED") && strstr(has_prefix("PAYLOAD XHCI R2 ARENA=2 "), " SMMU=SAME"));
        CHECK(count_prefix("PAYLOAD XHCI SMMU1 R1 ") == 1 && count_prefix("PAYLOAD XHCI SMMU1 R2") == 0);
        world_default(); W.iommu = 1u << R_HIGH; CHECK(!go("only-high"));
        CHECK(VERDICT_IS("NOOP_OK ARENA=4") && count_prefix("PAYLOAD XHCI NEXT ARENA") == 4);
    }
    world_default(); W.iommu = 1u << R_HIGH; CHECK(!go("only-high-t"));
    CHECK(VERDICT_IS("NOOP_OK ARENA=4") && count_prefix("PAYLOAD XHCI NEXT ARENA") == (T ? 3u : 4u));
    CHECK(count_prefix("PAYLOAD XHCI NEXT RESET") == (T ? 3u : 4u) && count_prefix("PAYLOAD XHCI NEXT PROGRAM") == (T ? 3u : 4u));
    /* Every attempt that fails with a fault says so against the one before it: the first two change the registers, the third that reaches the bank does not. */
    CHECK(strstr(has_prefix("PAYLOAD XHCI R1 ARENA="), " SMMU=CHANGED") && strstr(has_prefix("PAYLOAD XHCI R2 ARENA="), " SMMU=CHANGED"));
    snprintf(expect, sizeof expect, "PAYLOAD XHCI R%u ARENA=4 NOOP_OK", T ? 3u : 4u);
    CHECK(strstr(has_prefix(expect), " SMMU=SAME"));
    /* No AC64: arena 4 is not offered, however far the others fail. */
    world_default(); W.hcc1 &= ~1u; W.iommu = 1u << R_HIGH; CHECK(!go("no-ac64"));
    CHECK(has_prefix("PAYLOAD XHCI VERDICT NOOP_HSE STAGE=NOOP") && count_prefix("PAYLOAD XHCI NEXT ARENA") == (T ? 2u : 3u));
    /* The memory map decides arenas 1, 3 and 4. */
    world_default(); W.fw_not_free = 1; CHECK(!go("fw-not-free"));
    CHECK(has(T ? "PAYLOAD XHCI ARENAS 2=OK 3=OK 4=OK" : "PAYLOAD XHCI ARENAS 1=NOT_FREE 2=OK 3=OK 4=OK") && VERDICT_IS("NOOP_OK ARENA=2"));
    world_default(); W.low_missing = 1; W.high_not_free = 1; W.iommu = 1u << R_STACK; CHECK(!go("only-stack"));
    CHECK(VERDICT_IS("NOOP_OK ARENA=2"));
    CHECK(has_prefix("PAYLOAD XHCI ARENAS ") && strstr(has_prefix("PAYLOAD XHCI ARENAS "), " 3=NOT_FREE 4=NOT_FREE"));
    /* The last arena of all fails: the final verdict is its answer, the controller is halted, every arena is zero, and every attempt announced its five groups. */
    world_default(); W.iommu = 0; W.knob[K_SILENT] = ALL_ARENAS; CHECK(!go("all-refused"));
    snprintf(expect, sizeof expect, "PAYLOAD XHCI R%u ARENA=4 ", ATTEMPTS_ALL);
    CHECK(has_prefix(expect) && strstr(has_prefix("PAYLOAD XHCI END "), "HALTED=YES"));
    CHECK(nlines <= 40 && count_prefix("PAYLOAD XHCI NEXT ") == (T ? 3u : 4u) * 5);
    return 0;
}

int suite_watch(void)
{
    char expect[160];
    world_default();
    W.scripts = 2;
    W.script[0] = (typeof(W.script[0])){12, 1 - T, 2, 0x81203};          /* the other controller's port 2 connects at 12 s */
    W.script[1] = (typeof(W.script[1])){20, T, 1, 0x200E03};
    CHECK(!go("watch"));
    CHECK(has_prefix("PAYLOAD XHCI CHG T=12.") && has_prefix("PAYLOAD XHCI CHG T=20."));
    snprintf(expect, sizeof expect, "FROM 0X20002A0 TO 0X81203:CCS.PED.U0.SS");
    CHECK(strstr(has_prefix("PAYLOAD XHCI CHG T=12."), expect) && strstr(has_prefix("PAYLOAD XHCI CHG T=12."), T ? " U0P2 " : " U1P2 "));
    CHECK(strstr(has_prefix("PAYLOAD XHCI CHG T=20."), "TO 0X200E03:CCS.PED.U0.HS") && strstr(has_prefix("PAYLOAD XHCI CHG T=20."), T ? " U1P1 " : " U0P1 "));
    snprintf(expect, sizeof expect, "PAYLOAD XHCI WATCH DONE CHANGED=%s N=2", T ? "U0P2.U1P1" : "U0P1.U1P2");
    CHECK(has(expect));
    CHECK(VERDICT_IS("NOOP_OK ARENA=") && !strstr(stores_joined, "PORTSC"));
    /* A port that flaps: only the first lines are printed, the count is whole, the verdict and the end are still there. */
    world_default();
    W.scripts = 8;
    for (unsigned i = 0; i < 8; i++) W.script[i] = (typeof(W.script[0])){1u + 2 * i, T, 1, 0x2A0u + i};
    CHECK(!go("watch-flap"));
    CHECK(count_prefix("PAYLOAD XHCI CHG ") == 4 && has_prefix("PAYLOAD XHCI WATCH DONE CHANGED=") && strstr(has_prefix("PAYLOAD XHCI WATCH DONE"), "N=8"));
    CHECK(nlines <= 40 && VERDICT_IS("NOOP_OK ARENA="));
    /* A port register that stops answering ends the sampling of that controller, and says so. */
    world_default(); W.xhc_fault_off = FAULT_ON(OP(0x410)); W.xhc_fault_after = 200; CHECK(!go("watch-fault"));
    CHECK(strstr(has_prefix("PAYLOAD XHCI WATCH DONE"), T ? "FAULT=U1" : "FAULT=U0") || has_prefix("PAYLOAD XHCI VERDICT"));
    /* The other controller does not answer like an xHC: the watch covers the target alone. */
    world_default(); W.other_cap0 = 0xffffffffu; CHECK(!go("other-ones"));
    CHECK(has(T ? "PAYLOAD XHCI BASE U1P1=0X20002A0 U1P2=0X20002A0" : "PAYLOAD XHCI BASE U0P1=0X20002A0 U0P2=0X20002A0"));
    return 0;
}

/* The line budget when the watch has printed `changes` port changes and the arenas before `success` (1 to 4; 0: none, every arena fails) are refused by the SMMU,
 * each with a change of its registers, `gfsr` being the global fault status the SMMU holds. What gives way is the SMMU reports (`SMMU1 R<k>`, two lines when
 * `gfsr` is not 0): `faulted` are due, `reports` are on the page. */
static const unsigned arena_region[5] = {0, R_FW, R_STACK, R_LOW, R_HIGH};
struct budget { unsigned faulted, reports; int cut; };

static int budget_run(unsigned changes, unsigned success, uint32_t gfsr, struct budget *b)
{
    static char label[48];
    snprintf(label, sizeof label, "budget-c%u-s%u-g%d", changes, success, gfsr != 0);
    world_default();
    W.scripts = changes;
    for (unsigned i = 0; i < changes; i++) W.script[i] = (typeof(W.script[0])){1u + 2 * i, T, 1, 0x2A0u + i};
    W.iommu = success ? 1u << arena_region[success] : 0;
    W.gfsr = gfsr;
    CHECK(!go(label));
    b->faulted = success ? success - FIRST_ARENA : ATTEMPTS_ALL;
    b->reports = 0;
    for (unsigned i = 0; i < nlines && i < LINES_MAX; i++)
        if (!strncmp(lines[i], "PAYLOAD XHCI SMMU1 ", 19) && strstr(lines[i], " FSR=")) b->reports++;
    b->cut = strstr(has_prefix("PAYLOAD XHCI END "), " LINES_CUT") != NULL;
    CHECK(nlines <= 40 && bad_lines == 0 && has_prefix("PAYLOAD XHCI VERDICT ") && has_prefix("PAYLOAD XHCI END "));
    CHECK(count_prefix("PAYLOAD XHCI R") == b->faulted + (success ? 1u : 0) && count_prefix("PAYLOAD XHCI NEXT ") == (b->faulted + (success ? 1u : 0)) * 5);
    CHECK(count_prefix("PAYLOAD XHCI SMMU1 ") == b->reports * (gfsr ? 2u : 1u) && b->reports <= b->faulted && b->cut == (b->reports < b->faulted));
    return 0;
}

/* Corners the other suites do not reach. */
int suite_edges(void)
{
    char expect[160];
    /* The most lines of any run: every arena fails and the SMMU changes in each. Every attempt runs and keeps its six lines; an SMMU report is printed only
     * where the attempts still to come keep theirs, so with a quiet watch, on the controller with four arenas, the last one's report is the line that does not
     * fit (more of them give way when the watch printed port changes: the matrix further down). */
    world_default(); W.iommu = 0; CHECK(!go("most-lines"));
    CHECK(nlines <= 40 && has_prefix("PAYLOAD XHCI END ") && bad_lines == 0);
    CHECK(count_prefix("PAYLOAD XHCI R") == ATTEMPTS_ALL && count_prefix("PAYLOAD XHCI NEXT ") == ATTEMPTS_ALL * 5);
    CHECK(count_prefix("PAYLOAD XHCI SMMU1 ") == 3 && (T ? !strstr(has_prefix("PAYLOAD XHCI END "), "LINES_CUT") : !!strstr(has_prefix("PAYLOAD XHCI END "), " LINES_CUT")));
    /* The same with a watch that saw a port flap: its optional lines may not take what the attempts keep. */
    world_default(); W.iommu = 0; W.scripts = 8;
    for (unsigned i = 0; i < 8; i++) W.script[i] = (typeof(W.script[0])){1u + 2 * i, T, 1, 0x2A0u + i};
    CHECK(!go("most-lines-flap"));
    CHECK(nlines <= 40 && has_prefix("PAYLOAD XHCI VERDICT ") && has_prefix("PAYLOAD XHCI END ") && bad_lines == 0);
    CHECK(count_prefix("PAYLOAD XHCI R") == ATTEMPTS_ALL && count_prefix("PAYLOAD XHCI NEXT ") == ATTEMPTS_ALL * 5 && strstr(has_prefix("PAYLOAD XHCI WATCH DONE"), "N=8"));
    CHECK(has_prefix("PAYLOAD XHCI VERDICT NOOP_HSE STAGE=NOOP WHY=HSE"));
    /* A global fault as well: the SMMU report is two lines, nothing is cut, and the verdict and the end line are still there. */
    world_default(); W.iommu = 0; W.gfsr = 0x1A51CD; CHECK(!go("most-lines-gfsr"));
    CHECK(nlines <= 40 && has_prefix("PAYLOAD XHCI VERDICT ") && has_prefix("PAYLOAD XHCI END ") && bad_lines == 0);
    CHECK(strstr(has_prefix("PAYLOAD XHCI SMMU0 "), " GFAR=0X") && !strstr(has_prefix("PAYLOAD XHCI SMMU0 "), " FSR="));
    CHECK(count_prefix("PAYLOAD XHCI SMMU0 ") == 2 && count_prefix("PAYLOAD XHCI SMMU1 ") >= 2 && count_prefix("PAYLOAD XHCI R") >= 3);
    /* A result of 100 characters or more takes a second line (R<k> STS=..), which no line budget reserves. With four arenas the last attempt starts with 32 lines
     * on the page (a quiet watch, three failed attempts with their reports), so the second line of a bad completion's result is the one that does not fit:
     * END says LINES_CUT and the result line ends before its STS= field. With three arenas the last attempt starts earlier and the second line fits. */
    world_default(); W.iommu = 1u << R_HIGH; W.knob[K_CODE] = 1u << 4; CHECK(!go("long-result-at-line-32"));
    CHECK(VERDICT_IS("NOOP_BAD_COMPLETION STAGE=NOOP WHY=CODE") && nlines <= 40 && bad_lines == 0 && count_prefix("PAYLOAD XHCI SMMU1 ") == ATTEMPTS_ALL - 1);
    snprintf(expect, sizeof expect, "PAYLOAD XHCI R%u ARENA=4 NOOP_BAD_COMPLETION STAGE=NOOP WHY=CODE CC=13", ATTEMPTS_ALL);
    CHECK(has_prefix(expect) && !strstr(has_prefix(expect), " STS="));
    snprintf(expect, sizeof expect, "PAYLOAD XHCI R%u STS=", ATTEMPTS_ALL);
    CHECK(T ? has_prefix(expect) && !strstr(has_prefix("PAYLOAD XHCI END "), " LINES_CUT") : !has_prefix(expect) && strstr(has_prefix("PAYLOAD XHCI END "), " LINES_CUT"));
    /* The load budget under a controller that never settles. */
    world_default(); W.run_stuck = 1; W.halt_stuck = 1; CHECK(!go("budget"));
    CHECK(loads <= Q1N1_PAYLOAD_LOADS_MAX && has_prefix("PAYLOAD XHCI END"));
    /* A slow reset is not a verdict: HCRST, and then CNR, may take most of a second. One that outlasts the second is the controller's answer and ends the run. */
    world_default(); W.hcrst_ms = 600; CHECK(!go("slow-hcrst"));
    CHECK(VERDICT_IS("NOOP_OK ARENA=") && STORES_ARE(ATT_OK) && loads < 700);
    world_default(); W.cnr_ms = 600; CHECK(!go("slow-cnr"));
    CHECK(VERDICT_IS("NOOP_OK ARENA=") && STORES_ARE(ATT_OK) && loads < 700);
    world_default(); W.hcrst_ms = 600; W.cnr_ms = 600; CHECK(!go("slow-both"));
    CHECK(VERDICT_IS("NOOP_OK ARENA=") && STORES_ARE(ATT_OK));
    world_default(); W.hcrst_ms = 1500; CHECK(!go("slower-hcrst"));
    CHECK(has_prefix("PAYLOAD XHCI VERDICT NOOP_TIMEOUT STAGE=RESET WHY=HCRST") && STORES_ARE(S_RESET) && count_prefix("PAYLOAD XHCI NEXT PROGRAM") == 0);
    world_default(); W.cnr_ms = 1500; CHECK(!go("slower-cnr"));
    CHECK(has_prefix("PAYLOAD XHCI VERDICT NOOP_TIMEOUT STAGE=RESET WHY=CNR") && STORES_ARE(S_RESET) && count_prefix("PAYLOAD XHCI NEXT PROGRAM") == 0);
    CHECK(count_prefix("PAYLOAD XHCI NEXT ARENA") == 1 && strstr(has_prefix("PAYLOAD XHCI END "), "HALTED=YES"));
    /* A counter that stops while the plug watch runs ends the watch and then the run, with no store: the watch is bounded like every other wait. */
    world_default(); W.stall_in_watch = 1; CHECK(!go("watch-stall"));
    CHECK(has_prefix("PAYLOAD XHCI WATCH DONE") && has_prefix("PAYLOAD XHCI VERDICT NOOP_TIMEOUT STAGE=ARENA WHY=CLOCK") && nstores == 0 && ram_stores == 0);
    snprintf(expect, sizeof expect, "PAYLOAD XHCI NEXT ARENA %u ", FIRST_ARENA);
    CHECK(has_prefix(expect));
    /* A counter that is set back is not a counter that runs: a read below the first one does not end a wait as if the time had passed (the eight seconds
     * are the filming window), and nothing is stored. */
    world_default(); W.back_ticks = NSEC(1); W.back_after = 2; CHECK(!go("counter-back-at-start"));
    CHECK(!refused("COUNTER_STUCK", ""));
    world_default(); W.back_ticks = NSEC(1); W.back_at_next = 3; CHECK(!go("counter-back-in-wait"));
    CHECK(has_prefix("PAYLOAD XHCI VERDICT NOOP_TIMEOUT STAGE=ARENA WHY=CLOCK") && nstores == 0 && ram_stores == 0 && count_prefix("PAYLOAD XHCI NEXT ") == 1);
    CHECK(has_prefix(expect));
    /* A refused DMA that leaves a trace in the DWC3 alone (the SMMU's own registers as they were) is still a change: the bus error address, and the valid bit
     * on its own. */
    world_default(); W.iommu = 0; W.berr_only = 1; CHECK(!go("berr-only"));
    for (unsigned k = 1; k <= ATTEMPTS_ALL; k++) {
        snprintf(expect, sizeof expect, "PAYLOAD XHCI R%u ARENA=", k);
        CHECK(strstr(has_prefix(expect), " SMMU=CHANGED"));
    }
    CHECK(strstr(has_prefix("PAYLOAD XHCI SMMU1 R1 "), " FSR=0X400 FAR=0X") && strstr(has_prefix("PAYLOAD XHCI SMMU1 R1 "), " BERR=0X") && !strstr(has_prefix("PAYLOAD XHCI SMMU0 "), " BERR="));
    world_default(); W.iommu = 0; W.berr_only = 2; CHECK(!go("berr-valid-only"));
    CHECK(strstr(has_prefix("PAYLOAD XHCI R1 ARENA="), " SMMU=CHANGED") && strstr(has_prefix("PAYLOAD XHCI R2 ARENA="), " SMMU=SAME"));
    CHECK(strstr(has_prefix("PAYLOAD XHCI SMMU1 R1 "), " FSR=0X400 FAR=0X") && has_prefix("PAYLOAD XHCI SMMU1 R1 ") && !strcmp(strchr(has_prefix("PAYLOAD XHCI SMMU1 R1 "), 0) - 9, " BERR=0X0"));
    /* The numbers of the record's section 7 and of the runbook: the SMMU reports are what gives way to the attempts' own lines, as a function of the port
     * changes the watch printed. sGFSR 0 first (S0b read 0: OBSERVED), one-line reports. On the controller with four arenas: all four failing leave 3, 2, 1, 0 of
     * the four reports for 0, 1, 2, 3 or more changes, END says LINES_CUT every time, and a success at arena 2, 3 or 4 says it from 3, 2 or 1 changes on (a
     * success at arena 1 never). The controller with three arenas keeps every report and never cuts. With a global fault status (two-line reports) the same
     * rule holds, more reports give way, and the three-arena controller cuts only when all its arenas fail. */
    static const unsigned changes_tried[6] = {0, 1, 2, 3, 4, 8};
    static const unsigned printed_four_arenas[6] = {3, 2, 1, 0, 0, 0};
    for (unsigned n = 0; n < 6; n++) {
        const unsigned changes = changes_tried[n];
        struct budget b;
        if (budget_run(changes, 0, 0, &b)) return 1;
        CHECK(T ? b.reports == 3 && !b.cut && VERDICT_IS("NOOP_HSE STAGE=NOOP WHY=HSE") : b.reports == printed_four_arenas[n] && b.cut && VERDICT_IS("NOOP_HSE STAGE=NOOP WHY=HSE"));
        for (unsigned success = FIRST_ARENA; success <= 4; success++) {
            snprintf(expect, sizeof expect, "NOOP_OK ARENA=%u", success);
            if (budget_run(changes, success, 0, &b)) return 1;
            CHECK(VERDICT_IS(expect) && b.cut == (!T && success > 1 && changes + success >= 5));
            if (budget_run(changes, success, 0x1A51CD, &b)) return 1;
            CHECK(VERDICT_IS(expect) && (T ? !b.cut : b.cut == (success > 2 || (success == 2 && changes > 0))));
        }
        if (budget_run(changes, 0, 0x1A51CD, &b)) return 1;
        CHECK(T ? b.cut == (changes >= 3) && b.reports == (changes >= 3 ? 2u : 3u) : b.cut && b.reports == (changes == 0 ? 1u : 0u));
    }
    /* The 64-bit registers carry the high word of an arena above 4 GiB: the last attempt is the one in the high bank. */
    world_default(); W.iommu = 1u << R_HIGH; CHECK(!go("high-words"));
    for (unsigned i = 0, last_hi = 0; i < nstores; i++) {
        if (!strcmp(stores[i].name, "DCBAAP_HI")) last_hi = i + 1;
        if (i + 1 == nstores) CHECK(last_hi && stores[last_hi - 1].value == 8);
    }
    for (unsigned i = 0; i < nstores; i++)
        if (!strcmp(stores[i].name, "CRCR_LO")) CHECK((stores[i].value & 1u) == 1u && !(stores[i].value & 0x3e));
    /* The stack: only the arena changed, the guard page and the top of it are as they were. */
    world_default(); CHECK(!go("stack-untouched"));
    if (T) CHECK(arena_base == regions[R_STACK].base + 0x1000 && arena_bytes == 3 * 4096);
    /* The memory of the other arenas is untouched by a run that stopped at the first. */
    for (unsigned i = 0, untouched = 1; i < 5; i++) {
        if (i == R_STACK && T) continue;
        if (i == R_FW && !T) continue;
        for (size_t k = 0; k < regions[i].size; k++) untouched &= regions[i].dram[k] == 0xA5;
        if (i == 4) CHECK(untouched);
    }
    return 0;
}

static uint32_t rng_state = 12345;
static uint32_t rnd(void) { rng_state = rng_state * 1664525u + 1013904223u; return rng_state >> 8; }

int suite_fuzz(void)
{
    for (unsigned n = 0; n < 1500; n++) {
        world_default();
        rng_state = 0x9e3779b9u * (n + 1);
        W.scratch = rnd() % 36;
        W.iommu = rnd() & ((1u << REGIONS) - 1);
        for (unsigned k = 0; k < K_COUNT; k++) W.knob[k] = rnd() % 4 ? 0 : rnd() & ALL_ARENAS;
        W.coherent = rnd() % 3 == 0;
        W.hcc1 = rnd() % 4 ? 0x0110FFC5 : 0x0110FFC4;
        W.fw_not_free = rnd() % 5 == 0; W.low_missing = rnd() % 5 == 0; W.high_not_free = rnd() % 5 == 0; W.map_missing = rnd() % 9 == 0;
        W.hcrst_stuck = rnd() % 25 == 0; W.cnr_after_reset = rnd() % 25 == 0; W.cnr_initial = rnd() % 30 == 0; W.halt_stuck = rnd() % 25 == 0;
        W.run_stuck = rnd() % 25 == 0; W.readback_wrong = rnd() % 25 == 0;
        W.hcrst_ms = rnd() % 20 == 0 ? rnd() % 1800 : 0; W.cnr_ms = rnd() % 20 == 0 ? rnd() % 1800 : 0; W.stall_in_watch = rnd() % 60 == 0;
        W.init_sts = rnd() % 6 ? W.init_sts : (rnd() & 0x1fff);
        W.init_cmd = rnd() % 8 ? 0 : (rnd() & 3);
        W.psc_events = rnd() % 4; W.code = 1 + rnd() % 30;
        W.tick = 5000 + rnd() % 60000;
        W.gfsr = rnd() % 8 ? 0 : rnd();
        W.cb_fsr = rnd() % 2 ? 0x400 : rnd() % 3 ? 0 : rnd();
        if (rnd() % 12 == 0) W.smmu_fault_off = 0x20 + 4 * (rnd() % 4);
        if (rnd() % 20 == 0) { W.xhc_fault_off = FAULT_ON(CAPLENGTH + 4 * (rnd() % 16)); W.xhc_fault_after = 1 + rnd() % 3000; }
        if (rnd() % 6 == 0) {
            W.scripts = 1 + rnd() % 6;
            for (unsigned i = 0; i < W.scripts; i++) W.script[i] = (typeof(W.script[0])){rnd() % 40, rnd() % 2, 1 + rnd() % 2, rnd()};
        }
        CHECK(!go("fuzz"));
        if (has_prefix("PAYLOAD XHCI VERDICT NOOP_OK")) {
            CHECK(strstr(stores_joined, "USBCMD:RS;DB0;") && (count_prefix("PAYLOAD XHCI R") >= 1 || strstr(has_prefix("PAYLOAD XHCI END "), "LINES_CUT")));
        }
    }
    return 0;
}
