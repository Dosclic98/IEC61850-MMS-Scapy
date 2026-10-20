"""Exercise fixed-value rewriting using binary MMS report and write fixtures."""

import contextlib
import io
import struct
import unittest
from unittest.mock import patch

from iec61850_mms.mms.rt.report_editor import mutate_unconfirmed_report_floats
from iec61850_mms.mms.rt.request_editor import mutate_write_request_floats
from mitm_mms_proxy import Direction, MmsDirectProxy, main


def tlv(tag, value):
    if len(value) < 128:
        length = bytes([len(value)])
    else:
        encoded = len(value).to_bytes((len(value).bit_length() + 7) // 8, "big")
        length = bytes([0x80 | len(encoded)]) + encoded
    return bytes([tag]) + length + value


def frame(pdu):
    body = b"\x02\xf0\x80\x01\x00\x01\x00" + pdu
    return b"\x03\x00" + (len(body) + 4).to_bytes(2, "big") + body


def data(value):
    floating = tlv(0x87, b"\x08" + struct.pack(">f", value))
    # Include nested floats and non-float fields to check selective byte changes.
    return tlv(0xA2, floating + tlv(0x85, b"\x07") + tlv(0xA1, floating))


def report(first, second, embedded_paths=False):
    paths = tlv(0x8A, b"selected") + tlv(0x8A, b"other")
    values = data(first) + data(second)
    variables = tlv(0xA1, tlv(0x8A, b"dataset") if embedded_paths else paths)
    if embedded_paths:
        values = paths + values
    return frame(tlv(0xA3, tlv(0xA0, variables + tlv(0xA0, values))))


def embedded_report(first, second):
    return report(first, second, embedded_paths=True)


def write(first, second):
    variables = b"".join(
        tlv(0x30, tlv(0xA0, tlv(0xA1, tlv(0x1A, b"domain") + tlv(0x1A, name))))
        for name in (b"selected", b"other")
    )
    request = tlv(0xA5, tlv(0xA0, variables) + tlv(0xA0, data(first) + data(second)))
    return frame(tlv(0xA0, tlv(0x02, b"\x01") + request))


EDITORS = (
    (report, mutate_unconfirmed_report_floats),
    (embedded_report, mutate_unconfirmed_report_floats),
    (write, mutate_write_request_floats),
)


class FixedFloatEditorTests(unittest.TestCase):
    def test_fixed_value_ignores_observed_value_and_other_operations(self):
        for fixture, mutate in EDITORS:
            for observed in (123.5, -82.0, 0.0, float("nan"), float("inf"), -float("inf")):
                for fixed in (42.25, 0.0, -17.5):
                    with self.subTest(fixture=fixture.__name__, observed=observed, fixed=fixed):
                        result, count = mutate(
                            fixture(observed, -5.0), delta=99, percentage=50, fixed_value=fixed,
                        )
                        self.assertEqual(result, fixture(fixed, fixed))
                        self.assertEqual(count, 4)

    def test_regex_only_replaces_selected_nested_values(self):
        for fixture, mutate in EDITORS:
            with self.subTest(fixture=fixture.__name__):
                original = fixture(12.5, -3.0)
                result, count = mutate(original, path_regex="^selected$", fixed_value=0.0)
                self.assertEqual(result, fixture(0.0, -3.0))
                self.assertEqual(count, 2)
                self.assertEqual(len(result), len(original))
                self.assertEqual(
                    mutate(original, path_regex="^missing$", fixed_value=42), (original, 0),
                )

    def test_existing_delta_and_percentage_behavior(self):
        for fixture, mutate in EDITORS:
            with self.subTest(fixture=fixture.__name__):
                self.assertEqual(mutate(fixture(8, -4), delta=2), (fixture(10, -2), 4))
                self.assertEqual(
                    mutate(fixture(8, -4), delta=99, percentage=25), (fixture(10, -5), 4),
                )


class FixedFloatProxyTests(unittest.TestCase):
    def test_cli_values_reach_rewriters_in_both_directions(self):
        with patch.object(MmsDirectProxy, "start", autospec=True) as start:
            self.assertEqual(main([
                "--modify-report-floats", "--report-float-value", "0",
                "--report-float-path-regex", "^selected$",
                "--modify-write-floats", "--write-float-value", "-42.5",
                "--write-float-path-regex", "^selected$",
            ]), 0)
        proxy = start.call_args[0][0]
        self.assertEqual(
            proxy.rewrite_unconfirmed_floats(report(12, 34), Direction.SERVER_TO_CLIENT, 1),
            report(0, 34),
        )
        self.assertEqual(
            proxy.rewrite_write_request_floats(write(12, 34), Direction.CLIENT_TO_SERVER, 1),
            write(-42.5, 34),
        )

    def test_flags_direction_and_delay_still_gate_replacements(self):
        cases = (
            (report, "rewrite_unconfirmed_floats", Direction.SERVER_TO_CLIENT, Direction.CLIENT_TO_SERVER),
            (write, "rewrite_write_request_floats", Direction.CLIENT_TO_SERVER, Direction.SERVER_TO_CLIENT),
        )
        for fixture, method, direction, reverse in cases:
            with self.subTest(fixture=fixture.__name__):
                proxy = MmsDirectProxy(
                    1102, "127.0.0.1", 1103, report_float_value=42, write_float_value=42,
                )
                payload = fixture(12, 34)
                rewrite = getattr(proxy, method)
                self.assertEqual(rewrite(payload, direction, 1), payload)
                proxy.modify_report_floats = proxy.modify_write_floats = True
                self.assertEqual(rewrite(payload, reverse, 1), payload)
                proxy.modification_delay = 5
                proxy.started_at = 100
                with patch("mitm_mms_proxy.time.monotonic", return_value=104):
                    self.assertEqual(rewrite(payload, direction, 1), payload)
                with patch("mitm_mms_proxy.time.monotonic", return_value=105):
                    self.assertEqual(rewrite(payload, direction, 1), fixture(42, 42))

    def test_cli_rejects_invalid_fixed_values_before_starting(self):
        for option in ("--report-float-value", "--write-float-value"):
            for value in ("nan", "inf", "-inf", "1e39", "-1e39", "invalid"):
                with self.subTest(option=option, value=value):
                    stderr = io.StringIO()
                    with patch.object(MmsDirectProxy, "start") as start:
                        with contextlib.redirect_stderr(stderr), self.assertRaises(SystemExit) as error:
                            main([f"{option}={value}"])
                    self.assertEqual(error.exception.code, 2)
                    self.assertIn("finite 32-bit float", stderr.getvalue())
                    start.assert_not_called()


if __name__ == "__main__":
    unittest.main()
