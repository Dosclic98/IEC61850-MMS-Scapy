"""Common MMS data-value decoding helpers."""

from datetime import datetime, timezone

from .common_ber import iter_tlvs


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


def decode_data_tlv(tlv):
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
            "values": [decode_data_tlv(child) for child in iter_tlvs(value)],
        }
    if tag == 0xA2:
        return {
            "type": "structure",
            "values": [decode_data_tlv(child) for child in iter_tlvs(value)],
        }

    return {"type": f"tag-0x{tag:02x}", "raw_hex": value.hex()}
