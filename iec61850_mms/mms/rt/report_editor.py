"""Helpers to edit MMS unconfirmed report PDUs."""

import re

from .common_ber import extract_mms_candidate_with_offset, iter_tlvs, mutate_float_tlvs, read_tlv


UNCONFIRMED_PDU_TAG = 0xA3
INFORMATION_REPORT_TAG = 0xA0
VARIABLE_SPEC_TAG = 0xA1
ACCESS_RESULT_LIST_TAG = 0xA0
VISIBLE_STRING_TAG = 0x8A


def _iter_tlvs_with_ranges(buf):
    pos = 0
    while pos < len(buf):
        start = pos
        tlv, pos = read_tlv(buf, pos)
        if tlv is None:
            break
        yield tlv, start, pos


def _collect_visible_strings_recursive(buf):
    names = []
    for tlv in iter_tlvs(buf):
        if tlv["tag"] == VISIBLE_STRING_TAG:
            try:
                names.append(tlv["value"].decode("ascii", errors="replace"))
            except Exception:
                names.append(tlv["value"].hex())

        if tlv["tag"] & 0x20:
            names.extend(_collect_visible_strings_recursive(tlv["value"]))

    return names


def _mutate_report_floats_by_path_regex(
    out,
    mms_offset,
    a3_index,
    unconfirmed_tlv,
    delta,
    path_regex,
    percentage=None,
):
    # Compile regex once for the current payload.
    pattern = re.compile(path_regex)

    unconfirmed_value_start = unconfirmed_tlv["end"] - unconfirmed_tlv["length"]
    report_value = unconfirmed_tlv["value"]

    info_tlv = None
    info_start = 0
    info_end = 0
    for child, child_start, child_end in _iter_tlvs_with_ranges(report_value):
        if child["tag"] == INFORMATION_REPORT_TAG:
            info_tlv = child
            info_start = child_start
            info_end = child_end
            break

    if info_tlv is None:
        return 0

    info_value_start = unconfirmed_value_start + (info_end - info_tlv["length"])
    info_children_value = info_tlv["value"]

    variable_paths = []
    access_list_tlv = None
    access_list_start = 0
    access_list_end = 0

    for child, child_start, child_end in _iter_tlvs_with_ranges(info_children_value):
        if child["tag"] == VARIABLE_SPEC_TAG:
            variable_paths = _collect_visible_strings_recursive(child["value"])
        elif child["tag"] == ACCESS_RESULT_LIST_TAG and access_list_tlv is None:
            access_list_tlv = child
            access_list_start = child_start
            access_list_end = child_end

    if access_list_tlv is None:
        return 0

    selected_indexes = {
        idx for idx, path in enumerate(variable_paths) if pattern.search(path)
    }
    if not selected_indexes:
        return 0

    access_list_value_start = info_value_start + (access_list_end - access_list_tlv["length"])

    modified = 0
    for idx, (_access_tlv, access_start, access_end) in enumerate(
        _iter_tlvs_with_ranges(access_list_tlv["value"])
    ):
        if idx not in selected_indexes:
            continue

        abs_start = mms_offset + access_list_value_start + access_start
        abs_end = mms_offset + access_list_value_start + access_end
        if abs_end > len(out):
            continue

        modified += mutate_float_tlvs(out, abs_start, abs_end, delta, percentage)

    return modified


def mutate_unconfirmed_report_floats(payload, delta=21.0, path_regex=None, percentage=None):
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
    if path_regex:
        try:
            modified = _mutate_report_floats_by_path_regex(
                out,
                mms_offset,
                a3_index,
                unconfirmed_tlv,
                delta,
                path_regex,
                percentage,
            )
        except re.error:
            return payload, 0
    else:
        modified = mutate_float_tlvs(out, absolute_start, absolute_end, delta, percentage)

    if modified == 0:
        return payload, 0

    return bytes(out), modified