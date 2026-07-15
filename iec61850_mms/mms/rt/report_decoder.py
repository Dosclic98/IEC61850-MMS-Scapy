"""Helpers to decode MMS unconfirmed report PDUs without full Scapy ASN.1 support."""

from .common_ber import extract_mms_candidate, iter_tlvs, read_tlv
from .data_decoder import decode_data_tlv


UNCONFIRMED_PDU_TAG = 0xA3
INFORMATION_REPORT_TAG = 0xA0
ACCESS_RESULT_LIST_TAG = 0xA0


def decode_unconfirmed_report(payload):
    """Decode MMS UnconfirmedPDU report from a transport payload.

    Returns None when the payload does not contain an UnconfirmedPDU.
    Returns a dict with decoded report details on success.
    """
    mms = extract_mms_candidate(payload)
    a3_index = mms.find(bytes([UNCONFIRMED_PDU_TAG]))
    if a3_index < 0:
        return None

    try:
        unconfirmed_tlv, _ = read_tlv(mms, a3_index)
        if unconfirmed_tlv["tag"] != UNCONFIRMED_PDU_TAG:
            return None

        # Child should be InformationReport [0] (0xA0)
        report_children = list(iter_tlvs(unconfirmed_tlv["value"]))
        if not report_children:
            return {"type": "unconfirmed-pdu", "values": [], "raw_hex": unconfirmed_tlv["value"].hex()}

        info = report_children[0]
        if info["tag"] != INFORMATION_REPORT_TAG:
            return {"type": "unconfirmed-pdu", "values": [], "raw_hex": info["value"].hex()}

        info_children = list(iter_tlvs(info["value"]))
        variable_spec = None
        access_values = []

        for child in info_children:
            if child["tag"] == 0xA1:
                variable_spec = child
            elif child["tag"] == ACCESS_RESULT_LIST_TAG:
                for access_tlv in iter_tlvs(child["value"]):
                    access_values.append(decode_data_tlv(access_tlv))

        variable_names = []
        if variable_spec is not None:
            for tlv in iter_tlvs(variable_spec["value"]):
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
