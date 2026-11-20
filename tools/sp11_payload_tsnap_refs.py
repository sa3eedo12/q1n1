# SPDX-License-Identifier: MIT
"""The ledger of citations of the payload tsnap (payloads/tsnap.c, payloads/tsnap-regs.h, docs/SP11-PAYLOAD-TSNAP.md): every `file:line` they cite, with the text that
the cited lines of the pinned copy must hold, and the digests of the pinned copies. tools/test-q1n1-sp11-payload-tsnap-refs.py reads the lines back from the copies, so
that a citation is a checked fact and not a memory. Facts only, nothing copied: the strings below are names and constants that the lines define (a register's name, an
offset, a bit field), not code or comments of the sources. Hardware: NOT RUN. Evidence: VERIFIED means "read in the pinned file", never "true of the unit".

Pins. Linux tag v7.4-rc2, which `git ls-remote https://github.com/torvalds/linux` peels to commit 7475ea8b58616b33c04afb976cf0fbaad9dd63fb (2026-11-17). `hamoa.dtsi` is the
copy that docs/SP11-STICK-LOG.md section 10 pins (BSD-3-Clause). The four others were fetched read-only for this payload from
https://raw.githubusercontent.com/torvalds/linux/7475ea8b58616b33c04afb976cf0fbaad9dd63fb/<path> and are pinned by docs/SP11-PAYLOAD-TSNAP.md (GPL-2.0 for the two
drivers, GPL-2.0 OR MIT for the binding; read for facts, nothing copied)."""
import re

COMMIT = '7475ea8b58616b33c04afb976cf0fbaad9dd63fb'
# name: (path in the Linux tree, SHA-256 of the pinned copy, byte count)
PINS = {
    'hamoa.dtsi': ('arch/arm64/boot/dts/qcom/hamoa.dtsi', 'd5bb1f7ce37c721d75fb5b4cffc8f58bed4d3ef9786a231a0deca05e917529e0', 233339),
    'tsens-v2.c': ('drivers/thermal/qcom/tsens-v2.c', '0f0d41735b468d247f9d648980b31b30d91df4976d9f74c48767014c0ec74a12', 9454),
    'tsens.c': ('drivers/thermal/qcom/tsens.c', '81a23bc20344b0c4803369a95ff2520657c6f5112c48abbcdcf0c73708c065d9', 37688),
    'tsens.h': ('drivers/thermal/qcom/tsens.h', '86e48413e7e36c76674aa4d0108989ce181f47358f38399578f45818fec734fd', 18758),
    'qcom-tsens.yaml': ('Documentation/devicetree/bindings/thermal/qcom-tsens.yaml', 'afee846cd06abc76a6feb3700919669300b3536dc01810c9ba71867b74b90cd8', 13001),
}

# file: {span as cited: [text that the cited lines must hold, each once or more]}
LEDGER = {
    'hamoa.dtsi': {
        '2759-2817': ['tsens0: thermal-sensor@c271000', 'tsens3: thermal-sensor@c274000', '"qcom,x1e80100-tsens", "qcom,tsens-v2"'],
        '2761-2762': ['0x0c271000', '0x0c222000'],
        '2776-2777': ['0x0c272000', '0x0c223000'],
        '2791-2792': ['0x0c273000', '0x0c224000'],
        '2806-2807': ['0x0c274000', '0x0c225000'],
        '2765': ['GIC_SPI 641'], '2780': ['GIC_SPI 642'], '2795': ['GIC_SPI 643'], '2810': ['GIC_SPI 770'],
        '2769': ['#qcom,sensors = <16>'], '2784': ['#qcom,sensors = <16>'], '2799': ['#qcom,sensors = <16>'], '2814': ['#qcom,sensors = <16>'],
        '9123-9915': ['thermal_zones: thermal-zones {', 'aoss0-thermal', 'camera1-thermal'],
        '9574-9915': ['thermal_aoss3: aoss3-thermal', 'thermal_nsp0: nsp0-thermal', 'thermal_gpuss_7: gpuss-7-thermal', 'thermal_camera1: camera1-thermal'],
    },
    'tsens-v2.c': {
        '14-17': ['SROT_HW_VER_OFF', 'SROT_CTRL_OFF', 'SROT_MEASURE_PERIOD', 'SROT_Sn_CONVERSION'],
        '27': ['RESULT_FORMAT_TEMP'],
        '29-32': ['SENSOR_CONVERSION(n)', 'CONVERSION_SHIFT_MASK', 'CONVERSION_SLOPE_MASK', 'CONVERSION_CZERO_MASK'],
        '36': ['TM_UPPER_LOWER_INT_STATUS_OFF'], '37': ['TM_UPPER_LOWER_INT_CLEAR_OFF'], '39': ['TM_CRITICAL_INT_STATUS_OFF'], '40': ['TM_CRITICAL_INT_CLEAR_OFF'],
        '44-45': ['TM_Sn_STATUS_OFF', 'TM_TRDY_OFF'],
        '54': ['.adc'], '56': ['.max_sensors'],
        '86-93': ['VER_MAJOR', 'VER_MINOR', 'VER_STEP', 'TSENS_EN', 'TSENS_SW_RST', 'SENSOR_EN', 'CODE_OR_TEMP'],
        '93': ['CODE_OR_TEMP', 'SROT_CTRL_OFF', '21, 21'],
        '119': ['WDOG_BARK_STATUS', 'TM_CRITICAL_INT_STATUS_OFF', '31, 31'],
        '128-138': ['LAST_TEMP', 'VALID', 'MIN_STATUS', 'LOWER_STATUS', 'UPPER_STATUS', 'CRITICAL_STATUS', 'MAX_STATUS', 'TRDY'],
        '223': ['init_tsens_v2_no_rpm'],
        '253-254': ['Select temperature format', 'deci-Celsius', 'RESULT_FORMAT_TEMP'],
        '263-266': ['ops_generic_v2', '.init', '.get_temp'],
        '280-282': ['ops_ipq5332', 'init_tsens_v2_no_rpm', '.get_temp'],
    },
    'tsens.c': {
        '329-373': ['tsens_read_temp', 'MAX_READ_RETRY', 'stable fallback value'],
        '386-399': ['tsens_hw_to_mC', 'sign_extend32(temp, resolution) * 100'],
        '637': ['regmap_field_read(priv->rf[WDOG_BARK_STATUS]'],
        '834-835': ['tsens_version(priv) == VER_0', 'regmap_field_read(priv->rf[TRDY]'],
        '932': ['init_common'],
        '1018-1031': ['regmap_field_read(priv->rf[TSENS_EN], &enabled)', '!enabled', 'device not enabled'],
        '1092': ['ver_minor > 2'],
        '1216-1217': ['"qcom,tsens-v2"', 'data_tsens_v2'],
        '1424': ['priv->sensor[i].hw_id = i'],
    },
    'tsens.h': {
        '23': ['MAX_SENSORS 16'], '24': ['MAX_READ_RETRY 3'],
    },
    'qcom-tsens.yaml': {
        '92-93': ['qcom,x1e80100-tsens', 'qcom,tsens-v2'],
    },
}
# Spans that must NOT hold a text: the generic v2 driver never calibrates (no `.calibrate` among its ops).
ABSENT = {('tsens-v2.c', '263-266'): ['calibrate']}
# What whole files must not hold or hold a given number of times (the claims "Linux never ..." and "only ..."): the generic v2 path never writes CODE_OR_TEMP (tsens.c has no mention of
# it at all, tsens-v2.c names it only in its field table and in the ipq5332 init, which spans lines 223 to 261), nothing reads the upper, lower or critical interrupt status fields or the
# CC monitor status through a regmap field, TRDY is read once (the VER_0 path) and the TM+0x14 word is read once, as its watchdog bit.
ABSENT_IN_FILE = {'tsens.c': ['CODE_OR_TEMP', 'rf[UP_INT_STATUS', 'rf[LOW_INT_STATUS', 'rf[CRIT_INT_STATUS', 'rf[CC_MON_STATUS']}
EXACTLY = {('tsens.c', 'regmap_field_read(priv->rf[TRDY]'): 1, ('tsens.c', 'regmap_field_read(priv->rf[WDOG_BARK_STATUS]'): 1}
ONLY_IN = {('tsens-v2.c', 'CODE_OR_TEMP'): ['93', '223-261']}

FILES = '|'.join(re.escape(name) for name in PINS)
CITATION = re.compile(rf'\b({FILES}):(\d+(?:-\d+)?(?:,\s*\d+(?:-\d+)?)*)')


def citations(text):
    """{(file, span)} of every `file:span` that `text` cites; a span is one line or a range, as written: `tsens-v2.c:14-17, 29-32` cites two."""
    found = set()
    for name, spans in CITATION.findall(text):
        for span in re.split(r',\s*', spans):
            found.add((name, span))
    return found


def span_lines(span):
    first, _, last = span.partition('-')
    return int(first), int(last or first)


def ledger_pairs():
    return {(name, span) for name, spans in LEDGER.items() for span in spans}
