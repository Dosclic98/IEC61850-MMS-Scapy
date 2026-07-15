"""Helpers to decode MMS confirmed write requests."""

from .common_ber import extract_mms_candidate, iter_tlvs, read_tlv
from .data_decoder import decode_data_tlv


CONFIRMED_REQUEST_PDU_TAG = 0xA0
WRITE_REQUEST_TAG = 0xA5
VISIBLE_STRING_TAG = 0x8A


def _collect_visible_strings(buf):
    names = []
    for tlv in iter_tlvs(buf):
        if tlv["tag"] == VISIBLE_STRING_TAG:
            try:
                names.append(tlv["value"].decode("ascii", errors="replace"))
            except Exception:
                names.append(tlv["value"].hex())

        if tlv["tag"] & 0x20:
            names.extend(_collect_visible_strings(tlv["value"]))

    return names


def decode_write_request(payload):
    """Decode MMS ConfirmedRequestPDU/WriteRequest from transport payload.

    Returns None when payload does not contain a WriteRequest.
    Returns dict with invoke id, variable references, and listOfData values.
    """
    mms = extract_mms_candidate(payload)

    for idx in range(len(mms)):
        if mms[idx] != CONFIRMED_REQUEST_PDU_TAG:
            continue

        try:
            confirmed_tlv, _ = read_tlv(mms, idx)
        except Exception:
            continue

        if confirmed_tlv is None or confirmed_tlv["tag"] != CONFIRMED_REQUEST_PDU_TAG:
            continue

        try:
            children = list(iter_tlvs(confirmed_tlv["value"]))
        except Exception:
            continue

        if not children:
            continue

        invoke_id = None
        write_tlv = None
        for child in children:
            if child["tag"] == 0x02:
                invoke_id = int.from_bytes(child["value"], byteorder="big", signed=False)
            elif child["tag"] == WRITE_REQUEST_TAG:
                write_tlv = child

        if write_tlv is None:
            continue

        try:
            write_children = list(iter_tlvs(write_tlv["value"]))
        except Exception:
            return {
                "type": "write-request",
                "invoke_id": invoke_id,
                "variable_references": [],
                "values": [],
            }

        if not write_children:
            return {
                "type": "write-request",
                "invoke_id": invoke_id,
                "variable_references": [],
                "values": [],
            }

        variable_spec = write_children[0]
        list_of_data = write_children[1] if len(write_children) > 1 else None

        variable_references = _collect_visible_strings(variable_spec["value"])
        values = []
        if list_of_data is not None and list_of_data["tag"] == 0xA0:
            for data_tlv in iter_tlvs(list_of_data["value"]):
                values.append(decode_data_tlv(data_tlv))

        return {
            "type": "write-request",
            "invoke_id": invoke_id,
            "variable_references": variable_references,
            "values": values,
        }

    return None
