"""Helpers to edit MMS unconfirmed report PDUs."""

from .common_ber import extract_mms_candidate_with_offset, mutate_float_tlvs, read_tlv


UNCONFIRMED_PDU_TAG = 0xA3


def mutate_unconfirmed_report_floats(payload, delta=21.0):
    """Return payload with UnconfirmedPDU float values shifted by delta.

    Returns (new_payload, modified_float_count). If payload does not contain an
    UnconfirmedPDU, it is returned unchanged with count 0.
    """
    mms, mms_offset = extract_mms_candidate_with_offset(payload)
    a3_index = mms.find(bytes([UNCONFIRMED_PDU_TAG]))
    if a3_index < 0:
        return payload, 0

    try:
        unconfirmed_tlv, _ = read_tlv(mms, a3_index)
    except Exception:
        return payload, 0

    if unconfirmed_tlv is None or unconfirmed_tlv["tag"] != UNCONFIRMED_PDU_TAG:
        return payload, 0

    absolute_start = mms_offset + a3_index
    absolute_end = mms_offset + unconfirmed_tlv["end"]
    if absolute_end > len(payload):
        return payload, 0

    out = bytearray(payload)
    modified = mutate_float_tlvs(out, absolute_start, absolute_end, delta)
    if modified == 0:
        return payload, 0

    return bytes(out), modified