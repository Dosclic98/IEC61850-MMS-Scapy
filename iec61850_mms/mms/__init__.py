"""
Limited MMS ASN.1 definitions for scapy.

Source documents for these definitions:
    -   ISO 68150-2
    -   https://github.com/wireshark/wireshark/blob/master/epan/dissectors/asn1/mms/mms.asn

supported types:
    -   ConfirmedRequest (read, write, getnamelist)
    -   InitiateRequest
    -   InitiateResponse
"""
from . import tags
from . import ber
from . import fields
from . import types
from . import packets
from . import report_decoder
from . import report_editor
from .packets import MMS, MMS_Confirmed_Request_PDU, MMS_Initiate_Response_PDU, MMS_Initiate_Request_PDU, MMS_Unconfirmed_PDU
from .report_decoder import decode_unconfirmed_report
from .report_editor import mutate_unconfirmed_report_floats
