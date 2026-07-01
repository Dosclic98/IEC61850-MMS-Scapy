"""Helpers to edit MMS unconfirmed report PDUs."""

import math
import struct

from .report_decoder import UNCONFIRMED_PDU_TAG, _read_length, _read_tlv


def _extract_mms_candidate_with_offset(payload):
    offset = 0

    # Strip TPKT header: 03 00 <len_hi> <len_lo>
    if len(payload) >= 4 and payload[0] == 0x03 and payload[1] == 0x00:
        offset += 4

    # Drop COTP DT header if present.
    if len(payload) >= offset + 3 and payload[offset] == 0x02 and payload[offset + 1] == 0xF0:
        offset += 3

    # Drop common session bytes in this stack.
    if len(payload) >= offset + 4 and payload[offset:offset + 4] == b"\x01\x00\x01\x00":
        offset += 4

    return payload[offset:], offset


def _mutate_float_tlvs(buf, start, end, delta):
    count = 0
    pos = start

    while pos < end:
        if pos >= len(buf):
            break

        tag = buf[pos]
        pos += 1

        length, pos = _read_length(buf, pos)
        value_start = pos
        value_end = pos + length
        if value_end > end or value_end > len(buf):
            break

        # MMS floating-point: [0x87][len][format_width][4-byte IEEE-754 value]
        if tag == 0x87 and length == 5:
            format_width = buf[value_start]
            float_raw = bytes(buf[value_start + 1:value_start + 5])
            try:
                old_value = struct.unpack(">f", float_raw)[0]
                new_value = old_value + float(delta)
                if math.isfinite(new_value):
                    buf[value_start + 1:value_start + 5] = struct.pack(">f", new_value)
                    # Keep format width unchanged.
                    buf[value_start] = format_width
                    count += 1
            except Exception:
                pass

        if tag & 0x20:
            count += _mutate_float_tlvs(buf, value_start, value_end, delta)

        pos = value_end

    return count


def mutate_unconfirmed_report_floats(payload, delta=21.0):
    """Return payload with UnconfirmedPDU float values shifted by delta.

    Returns (new_payload, modified_float_count). If payload does not contain an
    UnconfirmedPDU, it is returned unchanged with count 0.
    """
    mms, mms_offset = _extract_mms_candidate_with_offset(payload)
    a3_index = mms.find(bytes([UNCONFIRMED_PDU_TAG]))
    if a3_index < 0:
        return payload, 0

    try:
        unconfirmed_tlv, _ = _read_tlv(mms, a3_index)
    except Exception:
        return payload, 0

    if unconfirmed_tlv is None or unconfirmed_tlv["tag"] != UNCONFIRMED_PDU_TAG:
        return payload, 0

    absolute_start = mms_offset + a3_index
    absolute_end = mms_offset + unconfirmed_tlv["end"]
    if absolute_end > len(payload):
        return payload, 0

    out = bytearray(payload)
    modified = _mutate_float_tlvs(out, absolute_start, absolute_end, delta)
    if modified == 0:
        return payload, 0

    return bytes(out), modified