"""AegisKey host SDK (stdlib-only). Unifies CTAPHID/TLV framing duplicated in tools."""
from tools.host_sdk.tlv import (
    TAG_WALLET_SLOT, TAG_WALLET_LABEL, TAG_WALLET_ADDRESS, TAG_WALLET_NETWORK,
    TAG_SLOT, TAG_LABEL, TAG_ALG_HINT, TAG_USAGE_HINT,
    TAG_OATH_NAME, TAG_OATH_RESPONSE,
    VENDOR_OP_MIN, VENDOR_OP_MAX, RESCUE_TRANSPORT_OP, FW_LOG_OP,
    MAX_LABEL_BYTES, parse_tlv, find_tlv, write_tlv,
)
from tools.host_sdk import ops, transport, gates

__all__ = [
    "TAG_WALLET_SLOT", "TAG_WALLET_LABEL", "TAG_WALLET_ADDRESS", "TAG_WALLET_NETWORK",
    "TAG_SLOT", "TAG_LABEL", "TAG_ALG_HINT", "TAG_USAGE_HINT",
    "TAG_OATH_NAME", "TAG_OATH_RESPONSE",
    "VENDOR_OP_MIN", "VENDOR_OP_MAX", "RESCUE_TRANSPORT_OP", "FW_LOG_OP",
    "MAX_LABEL_BYTES", "parse_tlv", "find_tlv", "write_tlv",
    "ops", "transport", "gates",
]
