"""Helpers to decode MMS unconfirmed report PDUs without full Scapy ASN.1 support."""

from datetime import datetime, timezone


UNCONFIRMED_PDU_TAG = 0xA3
INFORMATION_REPORT_TAG = 0xA0
ACCESS_RESULT_LIST_TAG = 0xA0


def _read_length(buf, pos):
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


def _read_tlv(buf, pos):
    if pos >= len(buf):
        return None, pos

    tag = buf[pos]
    pos += 1
    length, pos = _read_length(buf, pos)
    end = pos + length
    if end > len(buf):
        raise ValueError("BER value exceeds buffer length")

    return {"tag": tag, "length": length, "value": buf[pos:end], "start": pos - 2, "end": end}, end


def _iter_tlvs(buf):
    pos = 0
    while pos < len(buf):
        tlv, pos = _read_tlv(buf, pos)
        if tlv is None:
            break
        yield tlv


def _decode_bit_string(value):
    if not value:
        return {"type": "bit-string", "value": "", "unused_bits": 0}

    unused = value[0]
    bit_bytes = value[1:]
    bits = "".join(f"{b:08b}" for b in bit_bytes)
    if unused and unused <= len(bits):
        bits = bits[:-unused]

    return {"type": "bit-string", "value": bits, "unused_bits": unused}


def _decode_float(value):
    # MMS floating-point often uses first byte as format width descriptor.
    # Keep it robust by returning raw hex and a best-effort IEEE decode when possible.
    result = {"type": "float", "raw_hex": value.hex()}
    if len(value) == 5:
        result["format_width"] = value[0]
        result["mantissa_hex"] = value[1:].hex()
    return result


def _decode_binary_time(value):
    out = {"type": "binary-time", "raw_hex": value.hex()}
    if len(value) in (4, 6):
        ms = int.from_bytes(value[:4], byteorder="big", signed=False)
        out["milliseconds"] = ms
    return out


def _decode_utc_time(value):
    out = {"type": "utc-time", "raw_hex": value.hex()}
    if len(value) >= 4:
        secs = int.from_bytes(value[:4], byteorder="big", signed=False)
        try:
            out["timestamp_utc"] = datetime.fromtimestamp(secs, tz=timezone.utc).isoformat()
        except (OverflowError, OSError, ValueError):
            pass
    return out


def _decode_data_tlv(tlv):
    tag = tlv["tag"]
    value = tlv["value"]

    if tag == 0x83:
        return {"type": "boolean", "value": bool(value[0]) if value else False}
    if tag == 0x84:
        return _decode_bit_string(value)
    if tag == 0x85:
        return {"type": "integer", "value": int.from_bytes(value, byteorder="big", signed=True)}
    if tag == 0x86:
        return {"type": "unsigned", "value": int.from_bytes(value, byteorder="big", signed=False)}
    if tag == 0x87:
        return _decode_float(value)
    if tag == 0x89:
        return {"type": "octet-string", "raw_hex": value.hex()}
    if tag == 0x8A:
        try:
            return {"type": "visible-string", "value": value.decode("ascii", errors="replace")}
        except Exception:
            return {"type": "visible-string", "raw_hex": value.hex()}
    if tag == 0x8C:
        return _decode_binary_time(value)
    if tag == 0x90:
        try:
            return {"type": "mms-string", "value": value.decode("utf-8", errors="replace")}
        except Exception:
            return {"type": "mms-string", "raw_hex": value.hex()}
    if tag == 0x91:
        return _decode_utc_time(value)
    if tag == 0xA1:
        return {
            "type": "array",
            "values": [_decode_data_tlv(child) for child in _iter_tlvs(value)],
        }
    if tag == 0xA2:
        return {
            "type": "structure",
            "values": [_decode_data_tlv(child) for child in _iter_tlvs(value)],
        }

    return {"type": f"tag-0x{tag:02x}", "raw_hex": value.hex()}


def _extract_mms_candidate(payload):
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


def decode_unconfirmed_report(payload):
    """Decode MMS UnconfirmedPDU report from a transport payload.

    Returns None when the payload does not contain an UnconfirmedPDU.
    Returns a dict with decoded report details on success.
    """
    mms = _extract_mms_candidate(payload)
    a3_index = mms.find(bytes([UNCONFIRMED_PDU_TAG]))
    if a3_index < 0:
        return None

    try:
        unconfirmed_tlv, _ = _read_tlv(mms, a3_index)
        if unconfirmed_tlv["tag"] != UNCONFIRMED_PDU_TAG:
            return None

        # Child should be InformationReport [0] (0xA0)
        report_children = list(_iter_tlvs(unconfirmed_tlv["value"]))
        if not report_children:
            return {"type": "unconfirmed-pdu", "values": [], "raw_hex": unconfirmed_tlv["value"].hex()}

        info = report_children[0]
        if info["tag"] != INFORMATION_REPORT_TAG:
            return {"type": "unconfirmed-pdu", "values": [], "raw_hex": info["value"].hex()}

        info_children = list(_iter_tlvs(info["value"]))
        variable_spec = None
        access_values = []

        for child in info_children:
            if child["tag"] == 0xA1:
                variable_spec = child
            elif child["tag"] == ACCESS_RESULT_LIST_TAG:
                for access_tlv in _iter_tlvs(child["value"]):
                    access_values.append(_decode_data_tlv(access_tlv))

        variable_names = []
        if variable_spec is not None:
            for tlv in _iter_tlvs(variable_spec["value"]):
                if tlv["tag"] == 0x8A:
                    try:
                        variable_names.append(tlv["value"].decode("ascii", errors="replace"))
                    except Exception:
                        variable_names.append(tlv["value"].hex())

        return {
            "type": "unconfirmed-pdu",
            "variable_names": variable_names,
            "values": access_values,
        }
    except Exception:
        return None
