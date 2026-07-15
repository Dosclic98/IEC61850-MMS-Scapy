"""Common BER/MMS helpers shared by request/report decoders and editors."""

import math
import struct


def read_length(buf, pos):
    if pos >= len(buf):
        raise ValueError("Missing BER length")

    first = buf[pos]
    pos += 1

    if (first & 0x80) == 0:
        return first, pos

    num_bytes = first & 0x7F
    if num_bytes == 0:
        raise ValueError("Indefinite BER lengths are not supported")
    if pos + num_bytes > len(buf):
        raise ValueError("Invalid BER length")

    value = int.from_bytes(buf[pos:pos + num_bytes], byteorder="big", signed=False)
    return value, pos + num_bytes


def read_tlv(buf, pos):
    if pos >= len(buf):
        return None, pos

    tag = buf[pos]
    pos += 1
    length, pos = read_length(buf, pos)
    end = pos + length
    if end > len(buf):
        raise ValueError("BER value exceeds buffer length")

    return {"tag": tag, "length": length, "value": buf[pos:end], "start": pos - 2, "end": end}, end


def iter_tlvs(buf):
    pos = 0
    while pos < len(buf):
        tlv, pos = read_tlv(buf, pos)
        if tlv is None:
            break
        yield tlv


def extract_mms_candidate(payload):
    # Strip TPKT header: 03 00 <len_hi> <len_lo>
    if len(payload) >= 4 and payload[0] == 0x03 and payload[1] == 0x00:
        payload = payload[4:]

    # Drop COTP DT header if present.
    if len(payload) >= 3 and payload[0] == 0x02 and payload[1] == 0xF0:
        payload = payload[3:]

    # Drop common session bytes in this stack.
    if len(payload) >= 4 and payload[:4] == b"\x01\x00\x01\x00":
        payload = payload[4:]

    return payload


def extract_mms_candidate_with_offset(payload):
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


def mutate_float_tlvs(buf, start, end, delta):
    count = 0
    pos = start

    while pos < end:
        if pos >= len(buf):
            break

        tag = buf[pos]
        pos += 1

        length, pos = read_length(buf, pos)
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
            count += mutate_float_tlvs(buf, value_start, value_end, delta)

        pos = value_end

    return count
