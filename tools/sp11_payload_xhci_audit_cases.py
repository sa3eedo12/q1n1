# SPDX-License-Identifier: MIT
"""Texts for the audits of tools/sp11_payload_xhci_audit.py (tools/test-q1n1-sp11-payload-xhci.py): small LLVM IR modules in the form clang writes for
the payload `xhci`, the faulty ones with what the store audit must say about each, and the clean ones it must pass. Hardware: NOT RUN."""

FUNCTION = 'define dso_local void @{name}(ptr noundef %0, i64 noundef %1) local_unnamed_addr #0 {{\n{body}\n  ret void\n}}\n'


def module(name, body, globals_='@g = internal unnamed_addr constant [2 x i32] [i32 1, i32 2], align 4\n'):
    return globals_ + FUNCTION.format(name=name, body=body)


# (what is wrong, the module, a phrase the problems must contain)
FAULTY = [
    ('a store through a pointer loaded from memory', module('f', '  %3 = load ptr, ptr %0, align 8\n  store i32 1, ptr %3, align 4'), "root ['L']"),
    ('a store through a pointer a call returned', module('f', '  %3 = call ptr @other(i64 %1)\n  store i32 1, ptr %3, align 4'), "root ['C']"),
    ('a store through an integer made a pointer', module('f', '  %3 = inttoptr i64 %1 to ptr\n  store i32 1, ptr %3, align 4'), 'integer-to-pointer'),
    ('a volatile store through an integer outside the sinks', module('f', '  %3 = inttoptr i64 %1 to ptr\n  store volatile i32 1, ptr %3, align 4'), 'integer-to-pointer'),
    ('a store to a global', module('f', '  store i32 1, ptr @g, align 4'), "root ['G']"),
    ('a store to an element of a global', module('f', '  %3 = getelementptr inbounds i8, ptr @g, i64 4\n  store i32 1, ptr %3, align 4'), "root ['G']"),
    ('a store through the argument of the entry', module('payload_entry', '  store i32 1, ptr %0, align 4'), "root ['A']"),
    ('a store through an element of the entry\'s argument',
     module('payload_entry', '  %3 = getelementptr inbounds i8, ptr %0, i64 8\n  store i32 1, ptr %3, align 4'), "root ['A']"),
    ('a store through a pointer that is one of two', module('f', '  %3 = load ptr, ptr %0, align 8\n  %4 = alloca i32, align 4\n  %5 = icmp eq i64 %1, 0\n'
                                                              '  %6 = select i1 %5, ptr %3, ptr %4\n  store i32 1, ptr %6, align 4'), "root ['L', 'S']"),
    ('a store through a phi of a stack slot and a loaded pointer',
     module('f', '  %3 = alloca i32, align 4\n  %4 = load ptr, ptr %0, align 8\n  br label %5\n\n5:\n  %6 = phi ptr [ %3, %2 ], [ %4, %5 ]\n  store i32 1, ptr %6, align 4'),
     "root ['L', 'S']"),
    ('a memset into a loaded pointer', module('f', '  %3 = load ptr, ptr %0, align 8\n  call void @llvm.memset.p0.i64(ptr align 4 %3, i8 0, i64 8, i1 false)'),
     'memset or memcpy'),
    ('a memcpy into a global', module('f', '  call void @llvm.memcpy.p0.p0.i64(ptr align 4 @g, ptr align 4 %0, i64 8, i1 false)'), 'memset or memcpy'),
    ('a loaded pointer handed to a function that could store through it',
     module('f', '  %3 = load ptr, ptr %0, align 8\n  call void @helper(ptr noundef %3)'), 'hands helper a pointer'),
    ('the argument of the entry handed on', module('payload_entry', '  call void @helper(ptr noundef %0)'), 'hands helper a pointer'),
    ('an address made from an integer handed on', module('f', '  %3 = inttoptr i64 %1 to ptr\n  call void @helper(ptr noundef %3)'), 'integer-to-pointer'),
    ('an atomic store', module('f', '  store atomic i32 1, ptr %0 seq_cst, align 4'), 'atomic'),
    ('a compare and swap', module('f', '  %3 = cmpxchg ptr %0, i32 0, i32 1 seq_cst seq_cst'), 'atomic'),
    ('a writable global', module('f', '  ret void', globals_='@counter = internal global i32 0, align 4\n'), 'writable global'),
    ('a second store in a sink', module('mmio_store32', '  %3 = inttoptr i64 %1 to ptr\n  store volatile i32 1, ptr %3, align 4\n  store volatile i32 2, ptr %3, align 4'),
     'the sink is one'),
    ('a sink that does not store through its integer', module('ram_store32', '  %3 = alloca i32, align 4\n  store volatile i32 1, ptr %3, align 4'), 'integer-to-pointer'),
]

# What the audit must pass: the shapes the payload's own code has.
CLEAN = [
    ('a store to a stack slot', module('f', '  %3 = alloca i32, align 4\n  store i32 1, ptr %3, align 4')),
    ('a store through a parameter of a helper', module('f', '  store i32 1, ptr %0, align 4')),
    ('a store at an offset computed at run time from a buffer of the function (the audit proves the base of a store and not its offset)',
     module('f', '  %3 = alloca [8 x i8], align 4\n  %4 = getelementptr inbounds i8, ptr %3, i64 %1\n  store i8 1, ptr %4, align 1')),
    ('a store to an element of a parameter', module('f', '  %3 = getelementptr inbounds i8, ptr %0, i64 8\n  store i32 1, ptr %3, align 4')),
    ('a store through a phi of two stack slots',
     module('f', '  %3 = alloca i32, align 4\n  %4 = alloca i32, align 4\n  br label %5\n\n5:\n  %6 = phi ptr [ %3, %2 ], [ %4, %5 ]\n  store i32 1, ptr %6, align 4')),
    ('a volatile store to the stack (the clearing of the context)', module('f', '  %3 = alloca i32, align 4\n  store volatile i8 0, ptr %3, align 1')),
    ('a memset into the stack', module('f', '  %3 = alloca [8 x i8], align 4\n  call void @llvm.memset.p0.i64(ptr align 4 %3, i8 0, i64 8, i1 false)')),
    ('a memcpy from a global into a parameter', module('f', '  call void @llvm.memcpy.p0.p0.i64(ptr align 4 %0, ptr align 4 @g, i64 8, i1 false)')),
    ('a stack slot and a string handed to a call', module('f', '  %3 = alloca i32, align 4\n  call void @helper(ptr noundef %3, ptr noundef @g)')),
    ('a loaded string handed to the text function', module('f', '  %3 = load ptr, ptr %0, align 8\n  call void @say(ptr noundef %0, ptr noundef %3)')),
    ('a constant element of a table handed to a call',
     module('f', '  call void @helper(ptr noundef getelementptr inbounds (i8, ptr @g, i64 4))')),
    ('the one volatile store of a sink', module('mmio_store32', '  %3 = inttoptr i64 %1 to ptr\n  store volatile i32 1, ptr %3, align 4')),
    ('the one volatile load of the RAM helper', module('ram_load32', '  %3 = inttoptr i64 %1 to ptr\n  %4 = load volatile i32, ptr %3, align 4')),
    ('an inline assembly statement', module('f', '  tail call void asm sideeffect "dsb sy", "~{memory}"() #6, !srcloc !10')),
    ('a pointer read from the memory map', module('map_init', '  %3 = inttoptr i64 %1 to ptr\n  %4 = load i32, ptr %3, align 4')),
]
