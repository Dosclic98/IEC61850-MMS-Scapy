"""Helpers to edit MMS confirmed write requests."""

import re

from .common_ber import extract_mms_candidate_with_offset, mutate_float_tlvs, read_tlv


VISIBLE_STRING_TAG = 0x8A
ASN1_VISIBLE_STRING_TAG = 0x1A


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
    pos = 0
    while pos < len(buf):
        tlv, pos = read_tlv(buf, pos)
        if tlv is None:
            break

        if tlv["tag"] in (VISIBLE_STRING_TAG, ASN1_VISIBLE_STRING_TAG):
            try:
                names.append(tlv["value"].decode("ascii", errors="replace"))
            except Exception:
                names.append(tlv["value"].hex())

        if tlv["tag"] & 0x20:
            names.extend(_collect_visible_strings_recursive(tlv["value"]))

    return names


def mutate_write_request_floats(
    payload, delta=0.0, path_regex=None, percentage=None, fixed_value=None,
):
    """Return payload with WriteRequest listOfData float values modified.

    A fixed value takes precedence over percentage, which takes precedence over delta.

    Returns (new_payload, modified_float_count). If payload does not contain a
    WriteRequest, it is returned unchanged with count 0.
    """
    mms, mms_offset = extract_mms_candidate_with_offset(payload)

    # ConfirmedRequestPDU [0xA0], WriteRequest [0xA5], listOfData [0xA0]
    confirmed_tag = 0xA0
    write_tag = 0xA5
    list_of_data_tag = 0xA0

    for idx in range(len(mms)):
        if mms[idx] != confirmed_tag:
            continue

        try:
            confirmed_tlv, _ = read_tlv(mms, idx)
        except Exception:
            continue

        if confirmed_tlv is None or confirmed_tlv["tag"] != confirmed_tag:
            continue

        try:
            confirmed_children = []
            pos = 0
            confirmed_value = confirmed_tlv["value"]
            while pos < len(confirmed_value):
                child, pos = read_tlv(confirmed_value, pos)
                confirmed_children.append(child)
        except Exception:
            continue

        write_tlv = None
        for child in confirmed_children:
            if child["tag"] == write_tag:
                write_tlv = child
                break

        if write_tlv is None:
            continue

        try:
            write_children = []
            write_children_with_ranges = []
            for child, child_start, child_end in _iter_tlvs_with_ranges(write_tlv["value"]):
                write_children.append(child)
                write_children_with_ranges.append((child_start, child_end))
        except Exception:
            continue

        if len(write_children) < 2:
            continue

        variable_spec_tlv = write_children[0]
        list_data_tlv = write_children[1]
        if list_data_tlv["tag"] != list_of_data_tag:
            continue

        data_entries = list(_iter_tlvs_with_ranges(list_data_tlv["value"]))
        data_count = len(data_entries)

        selected_indexes = None
        if path_regex:
            try:
                pattern = re.compile(path_regex)
            except re.error:
                return payload, 0

            variable_paths = _collect_visible_strings_recursive(variable_spec_tlv["value"])

            # Preferred mapping: one variable reference per listOfData element.
            # Some stacks encode each variable as two strings (domain + item),
            # so direct string index matching does not align with listOfData.
            selected_indexes = set()
            if data_count == 1:
                if any(pattern.search(path) for path in variable_paths):
                    selected_indexes.add(0)
            elif data_count > 1 and len(variable_paths) == data_count:
                selected_indexes = {
                    idx for idx, path in enumerate(variable_paths) if pattern.search(path)
                }
            elif data_count > 0 and len(variable_paths) == data_count * 2:
                for idx in range(data_count):
                    domain = variable_paths[2 * idx]
                    item = variable_paths[2 * idx + 1]
                    if (
                        pattern.search(item)
                        or pattern.search(domain)
                        or pattern.search(f"{domain}/{item}")
                    ):
                        selected_indexes.add(idx)
            elif data_count > 0 and len(variable_paths) % data_count == 0:
                group_size = len(variable_paths) // data_count
                for idx in range(data_count):
                    group = variable_paths[idx * group_size:(idx + 1) * group_size]
                    if any(pattern.search(path) for path in group):
                        selected_indexes.add(idx)
            else:
                # Last-resort behavior for uncommon encodings.
                selected_indexes = {
                    idx for idx, path in enumerate(variable_paths) if pattern.search(path)
                }

            if not selected_indexes:
                return payload, 0

        confirmed_value_start = confirmed_tlv["end"] - confirmed_tlv["length"]
        write_value_start = confirmed_value_start + (write_tlv["end"] - write_tlv["length"])
        list_data_value_start = write_value_start + (
            write_children_with_ranges[1][1] - list_data_tlv["length"]
        )

        out = bytearray(payload)

        if selected_indexes is None:
            list_data_value_end = write_value_start + write_children_with_ranges[1][1]
            abs_start = mms_offset + list_data_value_start
            abs_end = mms_offset + list_data_value_end
            if abs_end > len(payload):
                continue

            modified = mutate_float_tlvs(out, abs_start, abs_end, delta, percentage, fixed_value)
        else:
            modified = 0
            for idx, (_data_tlv, data_start, data_end) in enumerate(data_entries):
                if idx not in selected_indexes:
                    continue

                abs_start = mms_offset + list_data_value_start + data_start
                abs_end = mms_offset + list_data_value_start + data_end
                if abs_end > len(payload):
                    continue

                modified += mutate_float_tlvs(out, abs_start, abs_end, delta, percentage, fixed_value)

        if modified == 0:
            return payload, 0

        return bytes(out), modified

    return payload, 0
