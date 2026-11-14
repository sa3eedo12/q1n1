# SPDX-License-Identifier: MIT
"""The seeded bugs in tools/sp11_payload_manifest.py that tools/test-q1n1-sp11-payload-chain.py (ManifestChainMutants) applies
to a copy of the tool, each of which its ManifestChain tests must reject. Data only: it is a module of its own because the
chain test is close to the size limit every test file keeps. Hardware: NOT RUN."""


def manifest_mutants():
    """(name, file below tools/, text that occurs exactly once in it, what replaces it) for each seeded bug."""
    tool = 'sp11_payload_manifest.py'
    return [
        ('manifest-calls-everything', tool, "kind = 'payload' if is_payload(name) else 'data'", "kind = 'payload'"),
        ('manifest-calls-only-the-first-file', tool, "kind = 'payload' if is_payload(name) else 'data'",
         "kind = 'payload' if index == 0 else 'data'"),
        ('manifest-matches-the-extension-case-sensitively', tool, "kind = 'payload' if is_payload(name) else 'data'",
         "kind = 'payload' if local.name.endswith('.bin') else 'data'"),
        ('manifest-lets-data-come-first', tool, "if index == 0 and kind != 'payload':", 'if False:'),
        ('manifest-checks-the-length-of-the-first-payload-only', tool, "if kind == 'payload' and size < 4:", 'if index == 0 and size < 4:'),
        ('manifest-reorders-the-files', tool, 'paths = [Path(p) for p in paths]', 'paths = sorted(Path(p) for p in paths)'),
        ('manifest-takes-the-wrong-extension', tool, "CODE_SUFFIX = '.BIN'", "CODE_SUFFIX = '.DAT'"),
        ('manifest-says-data-is-called', tool, "'data, never called'", "'data, called'"),
        ('manifest-does-not-say-the-index', tool, '(INDEX={index}, {role})', '({role})'),
        ('manifest-matches-a-shorter-extension', tool, 'return name.upper().endswith(CODE_SUFFIX)', "return name.upper().endswith('.BI')"),
    ]
