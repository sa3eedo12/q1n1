/* SPDX-License-Identifier: MIT */
/* The suites of the host test of the payload "inpsnap2" from the primitives on (tools/test-q1n1-sp11-payload-inpsnap2.c includes this file after its own helpers and first suites, as one
 * translation unit: the model's state is static): the read primitive, the load budget, the line cap, the clock verdict and the gate called directly at their edges, exception levels
 * and arguments, and a build with smaller caps. Nothing here ran on hardware. Evidence: EXPERIMENTAL (host model only). */

static void m_ctx_init(struct ctx *c)
{
    memset(c, 0, sizeof *c);
    c->puts = m_puts;
    c->hex = m_hex;
    c->load32 = m_load32;
}

/* The line is `want` characters, and its text ends there: the failure says how long it was, so that a helper that overran and one that stopped short are told apart. */
static void m_len_is(const struct pl_line *line, unsigned want, const char *what)
{
    m_checks++;
    if (line->len != want || strlen(line->buf) != want) {
        m_fails++;
        fprintf(stderr, "FAIL: %s: the line is %u characters (its text %zu), not %u\n", what, line->len, strlen(line->buf), want);
        m_dump(stderr);
    }
}

static void m_set_gate_word(struct ctx *c, unsigned id, int state, uint32_t value)
{
    c->v[id].st = (uint8_t)state;
    c->v[id].v = state == V_OK ? value : 0;
}

/* The gate of the wrapper's word over every combination of what its four words can be: the payload's against the harness's own rule. */
static int m_gate_matrix(void)
{
    static const uint32_t CLOCK[] = {0, 1, 0x80000000u, 0x80000002u, 0xa0000000u, 0xa0000002u, 0x4000, 0xffffffffu};
    static const uint32_t VOTE[] = {0, 0x40, 0x80, 0xc0, 0x810223d0u, 0x810223d0u & ~0x40u, 0x810223d0u & ~0x80u, 0xffffffffu, 1};
    static const int UNREAD[] = {V_NONE, V_FAULT, V_SKIP};
    unsigned n = 0;
    struct ctx c;
    m_ctx_init(&c);
    for (unsigned a = 0; a < sizeof CLOCK / sizeof CLOCK[0] + 3; a++) {
        for (unsigned b = 0; b < sizeof CLOCK / sizeof CLOCK[0] + 3; b++) {
            for (unsigned d = 0; d < sizeof CLOCK / sizeof CLOCK[0] + 3; d++) {
                for (unsigned e = 0; e < sizeof VOTE / sizeof VOTE[0] + 3; e++) {
                    int known[XN] = {0};
                    uint32_t value[XN] = {0};
                    unsigned ids[4] = {R_MA0, R_SA0, R_CR0, R_VT0};
                    unsigned pick[4] = {a, b, d, e};
                    int got, want;
                    for (unsigned k = 0; k < 4; k++) {
                        unsigned nvals = k < 3 ? sizeof CLOCK / sizeof CLOCK[0] : sizeof VOTE / sizeof VOTE[0];
                        if (pick[k] < nvals) {
                            m_set_gate_word(&c, ids[k], V_OK, k < 3 ? CLOCK[pick[k]] : VOTE[pick[k]]);
                            known[ids[k]] = 1;
                            value[ids[k]] = c.v[ids[k]].v;
                        } else {
                            m_set_gate_word(&c, ids[k], UNREAD[pick[k] - nvals], 0);
                        }
                    }
                    got = (int)wrapper_gate(&c);
                    want = m_gate_of(known, value);
                    m_checks++;
                    n++;
                    if (got != want) {
                        m_fails++;
                        fprintf(stderr, "FAIL: wrapper_gate is %d, the harness's rule says %d for MA0 %u SA0 %u CR0 %u VT0 %u (index into the candidate lists)\n", got, want, a, b, d, e);
                        return 1;
                    }
                }
            }
        }
    }
    CHECK(n == 11u * 11u * 11u * 12u);
    return 0;
}

static int suite_units(void)
{
    static const uint32_t WORDS[] = {0, 1, 2, 3, 0x4000, 0x7fffffffu, 0x80000000u, 0x80000001u, 0x80000002u, 0x80000003u, 0x90000000u, 0x90000002u, 0xa0000000u, 0xa0000002u,
                                     0xb0000000u, 0xc0000002u, 0xe0000000u, 0xf0000000u, 0xf0000002u, 0xfffffffeu, 0xffffffffu};
    struct ctx c;
    struct pl_line line;
    uint32_t value = 7;
    /* The read primitive refuses before it loads: a row the table does not have, a place the windows do not have, a block that aborted, a page that ended, a spent budget. */
    m_fx_unit();
    m_reset_run();
    m_ctx_init(&c);
    CHECKM(rd32(&c, 0xffffu, &value) == RD_RANGE && value == 0, "a row far past the table is refused");
    CHECKM(rd32(&c, R_COUNT, &value) == RD_RANGE && value == 0, "the row one past the table is refused");
    CHECKM(rd32(&c, R_COUNT + 40u, &value) == RD_RANGE, "a row well past the table is refused");
    /* rd_at holds the refusals of a table defect, which the shipped table cannot show: a window the table does not have, an unaligned offset, an offset at or past the end of its window. */
    CHECKM(rd_at(&c, B_GATE, WIN_GCC, 0, &value) == RD_OK, "the first word of the clock controller is loaded");
    CHECKM(rd_at(&c, B_GATE, WIN_GCC, GCC_BYTES - 4u, &value) == RD_OK, "the last word of the clock controller is loaded");
    CHECKM(rd_at(&c, B_QUP, WIN_QUP, 4, &value) == RD_OK, "a word of the wrapper is loaded");
    CHECKM(rd_at(&c, B_QUP, WIN_QUP, QUP_BYTES - 4u, &value) == RD_OK, "the last word of the wrapper is loaded");
    CHECKM(m_nloads == 4, "those four are four loads");
    m_reset_run();
    c.loads = 0;
    CHECKM(rd_at(&c, B_GATE, WINDOWS, 0, &value) == RD_RANGE, "a window the table does not have is refused");
    CHECKM(rd_at(&c, B_GATE, 0xffu, 0, &value) == RD_RANGE, "a window far past the table is refused");
    CHECKM(rd_at(&c, B_GATE, WIN_GCC, 2, &value) == RD_ALIGN, "an unaligned offset is refused");
    CHECKM(rd_at(&c, B_GATE, WIN_GCC, 0x42275u, &value) == RD_ALIGN, "an unaligned offset in the middle of the window is refused");
    CHECKM(rd_at(&c, B_GATE, WIN_GCC, GCC_BYTES, &value) == RD_RANGE, "the first offset past the clock controller is refused");
    CHECKM(rd_at(&c, B_QUP, WIN_QUP, QUP_BYTES, &value) == RD_RANGE, "the first offset past the wrapper is refused");
    CHECKM(rd_at(&c, B_QUP, WIN_QUP, 0x10000u, &value) == RD_RANGE, "an offset past the wrapper that lies inside the clock controller is refused");
    CHECKM(rd_at(&c, B_GATE, WIN_GCC, 0xfffffffcu, &value) == RD_RANGE, "the last aligned offset of 32 bits is refused");
    CHECKM(m_nloads == 0 && c.loads == 0 && value == 0, "no refused place is loaded or counted");
    c.dead = 1u << B_RCG;
    CHECKM(rd32(&c, R_DFS, &value) == RD_DEAD && rd32(&c, R_M, &value) == RD_DEAD, "a block that aborted is not read again");
    c.dead = 1u << B_GATE | 1u << B_PLL | 1u << B_LVL | 1u << B_QUP;
    c.stop = 1;
    CHECKM(rd32(&c, R_DFS, &value) == RD_STOP, "nothing is read after an all-ones word");
    c.stop = 0;
    c.dead = 0;
    c.loads = LOAD_CAP;
    CHECKM(rd32(&c, R_MA0, &value) == RD_BUDGET && value == 0, "a spent budget refuses the load");
    CHECKM(c.loads == LOAD_CAP && m_nloads == 0, "a refused load is not counted");
    c.loads = 0;
    CHECKM(rd32(&c, R_MA0, &value) == RD_OK && value == 0, "a row is loaded");
    CHECKM(c.loads == 1 && m_nloads == 1, "a load is counted once");
    m_flt[R_SA0] = 1;
    CHECKM(rd32(&c, R_SA0, &value) == RD_FAULT && c.err == 6, "an aborted load returns the fault and keeps its code");
    CHECKM(c.dead & 1u << B_GATE, "an abort ends the reads of its block");
    CHECKM(!(c.dead & 1u << B_RCG), "an abort does not end the next block");
    CHECKM(!(c.dead & 1u << B_QUP), "an abort does not end the wrapper's block");
    CHECKM(rd32(&c, R_CR0, &value) == RD_DEAD && c.loads == 2 && m_nloads == 2, "the next row of the block is not loaded");
    /* read_row: the states a row ends in. */
    m_fx_unit();
    m_reset_run();
    m_ctx_init(&c);
    for (unsigned k = 0; k < 5; k++) {
        static const uint32_t KEPT[] = {0x1234, 0, 0x80000000u, 0x7fffffffu, 0xfffffffeu};
        char what[80];
        m_ctx_init(&c);
        m_reset_run();
        m_set("MA0", KEPT[k]);
        read_row(&c, R_MA0);
        snprintf(what, sizeof what, "a word of 0X%X that read is kept and does not stop the page", KEPT[k]);
        CHECKM(c.v[R_MA0].st == V_OK && c.v[R_MA0].v == KEPT[k] && !c.stop, what);
    }
    m_ctx_init(&c);
    m_reset_run();
    m_set("MA0", 0xffffffffu);
    read_row(&c, R_MA0);
    CHECKM(c.v[R_MA0].st == V_OK && c.v[R_MA0].v == 0xffffffffu, "an all-ones word is kept as read");
    CHECKM(c.stop == R_MA0 + 1u, "an all-ones word stops the page and names its row plus one");
    CHECKM(c.skips == 0, "an all-ones word is no skip");
    read_row(&c, R_SA0);
    CHECKM(c.v[R_SA0].st == V_SKIP && m_nloads == 1, "a row after an all-ones word is a skip and no load");
    CHECKM(c.skips == 1, "a skip is counted");
    CHECKM(c.blocks & 1u << B_GATE, "a skip flags its block");
    m_ctx_init(&c);
    m_reset_run();
    m_flt[R_DFS] = 1;
    read_row(&c, R_DFS);
    CHECKM(c.v[R_DFS].st == V_FAULT, "an abort leaves the state FAULT");
    CHECKM(c.v[R_DFS].v == 6, "an abort keeps the code load32 returned");
    CHECKM(c.faults == 1, "an abort is counted");
    CHECKM(c.blocks & 1u << B_RCG, "an abort flags its block");
    CHECKM(!c.stop, "an abort is no all-ones word");
    read_row(&c, R_DIV);
    CHECKM(c.v[R_DIV].st == V_SKIP && m_nloads == 1, "a row after an abort in its block is a skip and no load");
    CHECKM(c.skips == 1, "a skip after an abort is counted");
    c.loads = LOAD_CAP;
    read_row(&c, R_LC0);
    CHECKM(c.v[R_LC0].st == V_BUDGET && c.v[R_LC0].v == 0, "a spent budget leaves the state BUDGET");
    CHECKM(c.blocks & 1u << B_LVL, "a spent budget flags its block");
    CHECKM(c.skips == 1, "a spent budget is no skip");
    /* The clock verdict, word by word, against the harness's own reading. */
    for (unsigned i = 0; i < sizeof WORDS / sizeof WORDS[0]; i++) {
        for (unsigned hwcg = 0; hwcg < 2; hwcg++) {
            char want = m_clock_verdict(WORDS[i], (int)hwcg);
            unsigned got = clock_state(WORDS[i], hwcg);
            CHECKM((got == CK_ON && want == 'N') || (got == CK_OFF && want == 'F') || (got == CK_HW && want == 'H') || (got == CK_ODD && want == 'O'), "clock_state");
        }
    }
    CHECK(m_gate_matrix() == 0);
    /* The line cap at its boundary: a line that would leave fewer lines free than the end line needs is cut and counted; the end line takes the last. */
    m_reset_run();
    m_ctx_init(&c);
    pl_begin(&line);
    tx(&line, PREFIX);
    tx(&line, "T");
    c.lines = LINE_CAP - 1u;
    CHECKM(!room(&c), "the line before the closing slot has no room: the end line keeps the slot");
    CHECKM(emit(&c, &line, 0) == 0, "a line without room is not printed");
    CHECKM(c.cuts == 1, "a line without room is counted as cut");
    CHECKM(c.lines == LINE_CAP - 1u && m_nlines == 0, "a cut line is not counted as a line");
    CHECKM(emit(&c, &line, 1) == 1 && c.lines == LINE_CAP && m_nlines == 1, "the end line takes the closing slot");
    CHECKM(emit(&c, &line, 1) == 0 && c.cuts == 2 && m_nlines == 1, "nothing goes past the line cap, not even the end line");
    c.lines = LINE_CAP - 2u;
    CHECKM(room(&c), "a line that leaves the closing slot free has room");
    CHECKM(emit(&c, &line, 0) == 1 && c.cuts == 2 && m_nlines == 2, "a line with room is printed");
    CHECKM(c.lines == LINE_CAP - 1u, "a printed line is counted");
    /* Nothing is read that cannot be shown: a line without room is not read, a block whose NEXT line cannot go out is not read, and nothing is announced after a stop. */
    m_fx_unit();
    m_reset_run();
    m_ctx_init(&c);
    c.lines = LINE_CAP - 1u;
    table_line(&c, L_GATE0);
    CHECKM(c.loads == 0 && c.v[R_MA0].st == V_NONE && m_nlines == 0, "a line without room is not read");
    CHECKM(c.cuts == 1, "a line that is not read for want of room is counted as cut");
    CHECKM(c.blocks & 1u << B_GATE, "a line that is not read flags its block");
    gcc_block(&c, B_RCG);
    CHECKM(c.loads == 0 && m_nlines == 0, "a block whose NEXT line cannot go out is not read");
    CHECKM(c.cuts == 2, "a block whose NEXT line cannot go out counts one cut and no more");
    CHECKM(c.blocks & 1u << B_RCG, "a block whose NEXT line cannot go out is flagged");
    m_ctx_init(&c);
    c.stop = 1;
    gcc_block(&c, B_PLL);
    qup_block(&c);
    CHECKM(c.loads == 0 && m_nlines == 0 && c.cuts == 0, "nothing is announced or read after a stop");
    m_ctx_init(&c);
    c.lines = LINE_CAP - 1u;
    qup_block(&c);
    CHECKM(c.cuts == 1 && c.loads == 0 && c.v[R_VER].st == V_NONE, "the wrapper's block without room for its NEXT line is cut and not read");
    CHECKM(c.blocks & 1u << B_QUP, "the wrapper's block without room is flagged");
    /* The number helpers: one digit below 10, the runner's hex form from 10 up; decimal of any width. */
    m_ctx_init(&c);
    pl_begin(&line);
    num(&c, &line, 9);
    CHECK(!strcmp(line.buf, "9"));
    pl_begin(&line);
    num(&c, &line, 10);
    CHECK(!strcmp(line.buf, "0XA"));
    pl_begin(&line);
    num(&c, &line, 0);
    CHECK(!strcmp(line.buf, "0"));
    pl_begin(&line);
    dec(&line, 0);
    CHECK(!strcmp(line.buf, "0"));
    pl_begin(&line);
    dec(&line, 10);
    CHECK(!strcmp(line.buf, "10"));
    pl_begin(&line);
    dec(&line, UINT64_MAX);
    CHECK(!strcmp(line.buf, "18446744073709551615"));
    pl_begin(&line);
    for (unsigned i = 0; i < 12; i++) tx(&line, "0123456789");
    CHECK(line.len == Q1N1_PAYLOAD_LINE_MAX);                       /* a line is cut at the ABI's 100, never overrun */
    /* Every helper stops at the ABI's 100 characters: the runner's hex op is given what is left of the line (a word that does not fit is cut, not dropped), a decimal and a check are cut. */
    pl_begin(&line);
    for (unsigned i = 0; i < 9; i++) tx(&line, "0123456789");
    tx(&line, "01234");
    hx(&c, &line, 0xffffffffu);
    m_len_is(&line, Q1N1_PAYLOAD_LINE_MAX, "hx at the end of a line");
    CHECKM(!strcmp(line.buf + 95, "0XFFF"), "hx at the end of a line cuts the word and does not drop it");
    pl_begin(&line);
    for (unsigned i = 0; i < 9; i++) tx(&line, "0123456789");
    tx(&line, "01234567");
    dec(&line, 12345);
    m_len_is(&line, Q1N1_PAYLOAD_LINE_MAX, "dec at the end of a line");
    CHECKM(!strcmp(line.buf + 98, "12"), "dec at the end of a line keeps the leading digits");
    pl_begin(&line);
    for (unsigned i = 0; i < 9; i++) tx(&line, "0123456789");
    tx(&line, "01234567");
    hex4(&line, 0xbeef);
    m_len_is(&line, Q1N1_PAYLOAD_LINE_MAX, "hex4 at the end of a line");
    CHECKM(!strcmp(line.buf + 98, "BE"), "hex4 at the end of a line keeps the leading digits");
    pl_begin(&line);
    for (unsigned i = 0; i < 10; i++) tx(&line, "0123456789");
    dec(&line, 7);
    hex4(&line, 0xbeef);
    CHECKM(line.len == Q1N1_PAYLOAD_LINE_MAX && line.buf[99] == '9' && line.buf[100] == 0, "a full line takes no digit");
    pl_begin(&line);
    hex4(&line, 0x0a5c);
    CHECK(!strcmp(line.buf, "0A5C"));
    /* The text of a word in every state a row can be in; a branch clock word carries its verdict, any other word none. */
    m_ctx_init(&c);
    for (unsigned k = 0; k < 6; k++) {
        static const struct {
            unsigned id, st;
            uint32_t v;
            const char *text;
        } STATES[] = {{R_MA0, V_NONE, 0, " MA0=NA"}, {R_MA0, V_SKIP, 0, " MA0=SKIP"}, {R_MA0, V_BUDGET, 0, " MA0=BUDGET"}, {R_MA0, V_FAULT, 6, " MA0=FAULT:6"},
                      {R_MA0, V_OK, 0x80000002u, " MA0=0X80000002.HW"}, {R_DFS, V_OK, 0x80000002u, " DFS=0X80000002"}};
        c.v[STATES[k].id].st = (uint8_t)STATES[k].st;
        c.v[STATES[k].id].v = STATES[k].v;
        pl_begin(&line);
        put_row(&c, &line, STATES[k].id);
        CHECKM(!strcmp(line.buf, STATES[k].text), STATES[k].text);
    }
    return 0;
}

static int suite_el(void)
{
    struct q1n1_payload_args a;
    uint64_t rc;
    /* Below EL2: one line, no load, nothing but CurrentEL read, and a success. */
    m_fx_unit();
    m_el = 1;
    rc = m_go();
    CHECKM(rc == 0, "below EL2 the payload returns 0");
    CHECKM(m_nlines == 1 && !strcmp(m_lines[0], PREFIX "SKIPPED_NOT_AT_EL2"), "below EL2 one line says so");
    CHECKM(m_nloads == 0, "below EL2 nothing is loaded");
    CHECKM(m_violations == 0 && m_sysreg_reads == 1, "below EL2 CurrentEL is the one register read");
    m_el = 3;
    rc = m_go();
    CHECKM(rc == 0 && m_nlines == 1 && !strcmp(m_lines[0], PREFIX "SKIPPED_NOT_AT_EL2") && m_nloads == 0, "above EL2 as well");
    /* No guarded load: one line, the refusal's return value, no load. */
    m_fx_unit();
    m_have_load32 = 0;
    rc = m_go();
    CHECKM(rc == Q1N1_PAYLOAD_RET_BAD_ARGS, "without load32 the payload returns the bad-arguments code");
    CHECKM(m_nlines == 1 && !strcmp(m_lines[0], PREFIX "REFUSED_NO_LOAD32"), "without load32 one line says so");
    CHECKM(m_nloads == 0 && m_violations == 0, "without load32 nothing is loaded");
    /* Arguments the runner would never pass: refused before anything is printed. */
    m_fx_unit();
    m_bad_args = 1;
    CHECK(m_go() == Q1N1_PAYLOAD_RET_BAD_ARGS && m_nlines == 0 && m_nloads == 0 && m_sysreg_reads == 0);
    m_fx_unit();
    a = m_args();
    a.version = 2;
    m_reset_run();
    CHECK(payload_entry(&a) == Q1N1_PAYLOAD_RET_BAD_ARGS && m_nlines == 0);
    a = m_args();
    a.size = sizeof a - 8;
    CHECK(payload_entry(&a) == Q1N1_PAYLOAD_RET_BAD_ARGS && m_nlines == 0);
    a = m_args();
    a.ops.puts = NULL;
    CHECK(payload_entry(&a) == Q1N1_PAYLOAD_RET_BAD_ARGS && m_nlines == 0);
    a = m_args();
    a.ops.hex = NULL;
    CHECK(payload_entry(&a) == Q1N1_PAYLOAD_RET_BAD_ARGS && m_nlines == 0);
    CHECK(payload_entry(NULL) == Q1N1_PAYLOAD_RET_BAD_ARGS && m_nlines == 0 && m_nloads == 0);
    /* The ordinary run returns 0 and the model saw no violation. */
    m_fx_unit();
    rc = m_go();
    CHECKM(rc == 0, "the ordinary run returns 0");
    CHECKM(m_violations == 0, "the ordinary run has no violation");
    return 0;
}

/* A build with a smaller line or load cap than the shipped one: the cap holds, the closing line is there, nothing is read that could not be shown, and the page is the reference's. */
static int suite_caps(void)
{
    uint64_t state = UINT64_C(0x9E3779B97F4A7C15);
    m_fx_unit();
    RUN_CLEAN();
    CHECK(m_nlines <= LINE_CAP && m_nloads <= LOAD_CAP);
    CHECK(m_end_field("LINES") == m_nlines);
    if (LINE_CAP < PAGE_LINES) CHECK(m_end_field("CUTS") > 0);
    if (LOAD_CAP < LOADS_MAX) CHECK(m_has("BUDGET") && m_end_field("LOADS") == LOAD_CAP);
    for (unsigned n = 0; n < 400; n++) {
        m_fx_random(&state);
        RUN_CLEAN();
        CHECK(m_nlines <= LINE_CAP && m_nloads <= LOAD_CAP && m_end_field("LINES") == m_nlines);
    }
    m_fx_unit();
    m_win_faults = 3;
    RUN_CLEAN();
    m_fx_unit();
    m_fx_all(0xffffffffu);
    RUN_CLEAN();
    return 0;
}
