/* SPDX-License-Identifier: MIT */
/* What the runner does with the pointers a payload gives its ops (tools/test-q1n1-sp11-payload-wtab.c, the chain: the real q1n1_payload_run with the harness' fake platform).
 * In a runner with the write table, ops.hex writes only inside the payload's stack and ops.puts reads only from the stack or the payload's image: a payload that chose another
 * pointer would store or read where the table never said. The pure checks are tried at their edges, and the real ops are called by probes that stand in for the payload and
 * are answered by the real loop; the seeds of the policy tooling (S38 to S40) are run at the end (--seed-run). Hardware: NOT RUN. Evidence: EXPERIMENTAL (host model only). */
#include "test-q1n1-sp11-payload-wtab-fixture.h"

/* The memory a probe payload sees as its stack (with a sentinel on each side: nothing the runner does with a refused pointer may touch it), a buffer outside it, and a
 * string of the host's own (not in the payload's image). The probe is called in place of the reference payload. */
static struct { uint8_t before[64]; uint8_t stack[4096]; uint8_t after[64]; } ops_mem __attribute__((aligned(4096)));
static char ops_other[64] __attribute__((aligned(8)));
static const char ops_host_text[] = "HOSTSTR";
enum { P_HEX_IN, P_HEX_OUT, P_HEX_END, P_HEX_THRICE, P_HEX_DEVICE, P_HEX_AT_BUDGET, P_PUTS_STACK, P_PUTS_IMAGE, P_PUTS_PAST, P_PUTS_HOST, P_PUTS_DEVICE, P_LOAD_OUT,
       P_BOTH_TWICE, P_HEX_IMAGE };
static const char ops_image_bytes[] = "IMAGE-BYTES-THAT-NO-OP-MAY-CHANGE";
static unsigned probe_case;
static uint64_t probe_ret;

static uint64_t ops_probe(const struct q1n1_payload_args *a)
{
    char *in = (char *)ops_mem.stack + 64;
    const char *image = (const char *)table_page + CHAIN_EXTRA_AT;
    switch (probe_case) {
    case P_HEX_IN: probe_ret = a->ops.hex(in, 24, 0x1234); break;
    case P_HEX_OUT: probe_ret = a->ops.hex(ops_other, 24, 0x1234); break;
    case P_HEX_END: probe_ret = a->ops.hex((char *)ops_mem.stack + sizeof ops_mem.stack - 8, 24, 0x1234); break;
    case P_HEX_THRICE: a->ops.hex(ops_other, 24, 1); a->ops.hex(ops_other + 8, 24, 2); a->ops.hex((char *)ops_mem.before, 8, 3); break;
    case P_HEX_DEVICE: probe_ret = a->ops.hex((char *)(uintptr_t)0x03d99108u, 19, 0x1234); break;
    case P_HEX_AT_BUDGET:
        strcpy(in, "FULL");
        for (unsigned i = 0; i < Q1N1_PAYLOAD_LINES_MAX; i++) a->ops.puts(in);
        a->ops.hex(ops_other, 24, 1);
        break;
    case P_PUTS_STACK: strcpy(in, "STACKSTR"); a->ops.puts(in); break;
    case P_PUTS_IMAGE: a->ops.puts(image); break;
    case P_PUTS_PAST: a->ops.puts(image + chain_extra_len); break;
    case P_PUTS_HOST: a->ops.puts(ops_host_text); break;
    case P_PUTS_DEVICE: a->ops.puts((const char *)(uintptr_t)0x03d99108u); break;
    case P_LOAD_OUT: probe_ret = (uint64_t)(int64_t)a->ops.load32(A_GATE, (uint32_t *)ops_other); break;
    case P_BOTH_TWICE:
        a->ops.hex(ops_other, 24, 1);
        a->ops.puts(ops_host_text);
        a->ops.hex(ops_other + 8, 24, 2);
        a->ops.puts(ops_host_text);
        break;
    case P_HEX_IMAGE: probe_ret = a->ops.hex((char *)image + 8, 24, 0x1234); break;
    }
    return 0;
}

/* One run of the chain with the probe `which`; `extra` (`extra_len` bytes) is placed in the payload's image after the table. */
static struct q1n1_payload_result ops_run(unsigned which, const char *extra, size_t extra_len)
{
    struct q1n1_payload_result result;
    struct q1n1_payload_platform plat;
    chain_platform(&plat);
    dev_found();
    chain_extra = extra;
    chain_extra_len = extra_len;
    build_chain(1);
    memset(&ops_mem, 'Z', sizeof ops_mem);
    memset(ops_mem.stack, 0, sizeof ops_mem.stack);
    memset(ops_other, 'Z', sizeof ops_other);
    loaded.stack_base = (uint64_t)(uintptr_t)ops_mem.stack;
    loaded.stack_alloc = sizeof ops_mem.stack;
    q1n1_wtab_attach(0);
    probe_case = which;
    probe_ret = 0;
    chain_probe = ops_probe;
    q1n1_payload_run(&chain_env, &loaded, &plat, &result);
    chain_probe = 0;
    chain_extra = 0;
    chain_extra_len = 0;
    return result;
}

static int untouched(const void *p, size_t n)
{
    const uint8_t *b = p;
    for (size_t i = 0; i < n; i++) if (b[i] != 'Z') return 0;
    return 1;
}

static int done_line_says(const char *text)
{
    int at = line_index("PAYLOAD DONE");
    return at >= 0 && strstr(ev[at].text, text) != 0;
}

void suite_ops(void)
{
    struct q1n1_payload_result r;
    const void *ptr = (const void *)(uintptr_t)0x1000;

    /* the pure checks, at their edges: [dst, dst + cap) inside [0x1000, 0x1100) and no sum that wraps */
    CHECK("hex_ok.first_byte", q1n1_wtab_hex_ok(ptr, 1, 0x1000, 0x100));
    CHECK("hex_ok.the_whole_stack", q1n1_wtab_hex_ok(ptr, 0x100, 0x1000, 0x100));
    CHECK("hex_ok.up_to_the_end", q1n1_wtab_hex_ok((const void *)(uintptr_t)0x10f0, 0x10, 0x1000, 0x100));
    CHECK("hex_ok.nothing_written_is_not_looked_at", q1n1_wtab_hex_ok((const void *)(uintptr_t)0x9999, 0, 0x1000, 0x100));
    CHECK("hex_refused.one_past_the_end", !q1n1_wtab_hex_ok((const void *)(uintptr_t)0x10f0, 0x11, 0x1000, 0x100));
    CHECK("hex_refused.starts_past_the_end", !q1n1_wtab_hex_ok((const void *)(uintptr_t)0x1100, 1, 0x1000, 0x100));
    CHECK("hex_refused.starts_before", !q1n1_wtab_hex_ok((const void *)(uintptr_t)0x0fff, 1, 0x1000, 0x100));
    CHECK("hex_refused.longer_than_the_stack", !q1n1_wtab_hex_ok(ptr, 0x101, 0x1000, 0x100));
    CHECK("hex_refused.an_address_that_wraps", !q1n1_wtab_hex_ok((const void *)(uintptr_t)(UINTPTR_MAX - 3), 8, 0x1000, 0x100));
    CHECK("hex_refused.no_stack", !q1n1_wtab_hex_ok(ptr, 1, 0x1000, 0));

    char stack[104], image[40];
    memset(stack, 'A', sizeof stack);
    memset(image, 'B', sizeof image);
    stack[103] = 0;
    CHECK("puts_ok.ends_at_the_last_byte_of_the_stack", q1n1_wtab_puts_ok(stack + 90, (uintptr_t)stack, sizeof stack, (uintptr_t)image, sizeof image));
    stack[103] = 'A';
    CHECK("puts_refused.unterminated_to_the_end_of_the_stack", !q1n1_wtab_puts_ok(stack + 90, (uintptr_t)stack, sizeof stack, (uintptr_t)image, sizeof image));
    CHECK("puts_ok.reads_exactly_the_bytes_the_runner_reads", q1n1_wtab_puts_ok(stack, (uintptr_t)stack, 101, (uintptr_t)image, sizeof image));
    CHECK("puts_refused.the_hundred_and_first_byte_is_outside", !q1n1_wtab_puts_ok(stack, (uintptr_t)stack, 100, (uintptr_t)image, sizeof image));
    image[39] = 0;
    CHECK("puts_ok.in_the_image", q1n1_wtab_puts_ok(image + 30, (uintptr_t)stack, sizeof stack, (uintptr_t)image, sizeof image));
    image[39] = 'B';
    CHECK("puts_refused.unterminated_to_the_end_of_the_image", !q1n1_wtab_puts_ok(image + 30, (uintptr_t)stack, sizeof stack, (uintptr_t)image, sizeof image));
    CHECK("puts_refused.in_neither", !q1n1_wtab_puts_ok(ops_host_text, (uintptr_t)stack, sizeof stack, (uintptr_t)image, sizeof image));
    CHECK("puts_refused.one_past_the_stack", !q1n1_wtab_puts_ok(stack + sizeof stack, (uintptr_t)stack, sizeof stack, (uintptr_t)image, sizeof image));

    /* the real ops, called by a probe through the real runner loop */
    r = ops_run(P_HEX_IN, 0, 0);
    CHECK("hex_in_the_stack.is_written", probe_ret == 6 && !strcmp((char *)ops_mem.stack + 64, "0X1234") && r.call[0].refused == 0 && lines_with("PAYLOAD OP REFUSED") == 0);
    r = ops_run(P_HEX_OUT, 0, 0);
    CHECK("hex_outside_the_stack.nothing_is_written", probe_ret == 0 && untouched(ops_other, sizeof ops_other));
    CHECK("hex_outside_the_stack.is_counted_and_on_the_page", r.call[0].refused == 1 && lines_with("PAYLOAD OP REFUSED HEX A=0X") == 1 && done_line_says("REFUSED=1"));
    r = ops_run(P_HEX_END, 0, 0);
    CHECK("hex_across_the_end_of_the_stack.nothing_is_written", untouched(ops_mem.after, sizeof ops_mem.after) && r.call[0].refused == 1 && lines_with("PAYLOAD OP REFUSED HEX") == 1);
    r = ops_run(P_HEX_THRICE, 0, 0);
    CHECK("hex_refused_three_times.counted_three_times_on_the_page_once", r.call[0].refused == 3 && lines_with("PAYLOAD OP REFUSED HEX") == 1 && done_line_says("REFUSED=3") &&
          untouched(ops_other, sizeof ops_other) && untouched(ops_mem.before, sizeof ops_mem.before));
    r = ops_run(P_HEX_DEVICE, 0, 0);
    CHECK("hex_at_a_device_address.is_not_touched", probe_ret == 0 && r.call[0].refused == 1);
    r = ops_run(P_HEX_AT_BUDGET, 0, 0);
    CHECK("hex_refused_at_the_line_budget.is_counted_and_the_done_line_says_so", r.call[0].refused == 1 && r.call[0].dropped >= 1 && lines_with("PAYLOAD OP REFUSED") == 0 &&
          done_line_says("REFUSED=1") && done_line_says("DROPPED=1") && untouched(ops_other, sizeof ops_other));

    r = ops_run(P_PUTS_STACK, 0, 0);
    CHECK("puts_in_the_stack.is_printed", lines_with("STACKSTR") == 1 && r.call[0].refused == 0);
    r = ops_run(P_PUTS_IMAGE, "IMAGESTR", 9);
    CHECK("puts_in_the_image.is_printed", lines_with("IMAGESTR") == 1 && r.call[0].refused == 0);
    r = ops_run(P_PUTS_PAST, "IMAGESTR", 9);
    CHECK("puts_past_the_image.is_refused", r.call[0].refused == 1 && lines_with("PAYLOAD OP REFUSED PUTS A=0X") == 1);
    r = ops_run(P_PUTS_IMAGE, "ABCD", 4);
    CHECK("puts_unterminated_in_the_image.is_refused", r.call[0].refused == 1 && lines_with("ABCD") == 0);
    r = ops_run(P_PUTS_HOST, 0, 0);
    CHECK("puts_of_a_string_in_neither.is_not_read", r.call[0].refused == 1 && lines_with("HOSTSTR") == 0 && done_line_says("REFUSED=1"));
    r = ops_run(P_PUTS_DEVICE, 0, 0);
    CHECK("puts_at_a_device_address.is_not_read", r.call[0].refused == 1);

    /* both ops refused in one run: each says so on the page, once (a line bit shared by the two would silence the second op) */
    r = ops_run(P_BOTH_TWICE, 0, 0);
    CHECK("hex_and_puts_both_refused.each_op_has_its_own_line", lines_with("PAYLOAD OP REFUSED HEX") == 1 && lines_with("PAYLOAD OP REFUSED PUTS") == 1);
    CHECK("hex_and_puts_both_refused.all_four_are_counted", r.call[0].refused == 4 && lines_with("PAYLOAD OP REFUSED") == 2 && done_line_says("REFUSED=4") &&
          untouched(ops_other, sizeof ops_other));

    /* the destination of ops.hex is the payload's stack only: its image is not written, though ops.puts reads it */
    r = ops_run(P_HEX_IMAGE, ops_image_bytes, sizeof ops_image_bytes);
    CHECK("hex_into_the_image.nothing_is_written", probe_ret == 0 && !memcmp((const char *)table_page + CHAIN_EXTRA_AT, ops_image_bytes, sizeof ops_image_bytes));
    CHECK("hex_into_the_image.is_counted_and_on_the_page", r.call[0].refused == 1 && lines_with("PAYLOAD OP REFUSED HEX A=0X") == 1 && done_line_says("REFUSED=1"));

    r = ops_run(P_LOAD_OUT, 0, 0);
    CHECK("load32_out_of_the_stack.is_still_refused", probe_ret == (uint64_t)(int64_t)Q1N1_PAYLOAD_LOAD_E_OUT && untouched(ops_other, sizeof ops_other) && r.call[0].refused == 1);
}

/* The seeds of the tools' tests (tools/sp11_payload_wtab_mutants.py: S38 hex, S39 puts, S40 load32) compile the reference payload with SEED_TARGET naming this buffer; what the
 * runner does with the pointer the payload then hands an op is one line for the Python test. */
char seed_buffer[64] __attribute__((aligned(8))) = "SEEDLEAK";

int seed_run(void)
{
    struct q1n1_payload_result result;
    struct q1n1_payload_platform plat;
    chain_platform(&plat);
    dev_found();
    D.block_serror = 1;         /* a read of the closed block that a broken runner lets through raises an error response instead of hanging the host program */
    build_chain(1);
    q1n1_wtab_attach(&wenv);
    q1n1_payload_run(&chain_env, &loaded, &plat, &result);
    printf("SEED status=%d called=%u refused=%u op_lines=%u leaked=%u buffer=", result.status, result.called, result.call[0].refused, lines_with("PAYLOAD OP REFUSED"), lines_with("SEEDLEAK"));
    for (unsigned i = 0; i < 8; i++) printf("%02X", (unsigned)(uint8_t)seed_buffer[i]);
    printf("\n");
    return 0;
}
