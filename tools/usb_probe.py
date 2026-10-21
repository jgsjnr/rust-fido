#!/usr/bin/env python3
"""Sonda USB-HID nativa: INIT + PING + GetInfo via 303A:AE61.

Sem porta serial: fala CTAPHID puro pelo endpoint HID. Se não enumerar,
imprime o diagnóstico (cabo só-carga é a causa nº 1).
"""
import sys

sys.path.insert(0, "tools")
from app_simulator import Session, CMD_MSG, CMD_CBOR, CMD_PING

s = Session("http://127.0.0.1:9")
try:
    s.connect_usb()
except OSError as e:
    print("USB AUSENTE: %s" % e)
    print(" cheque: 1) cabo com dados (não só carga); 2) Gerenciador de Dispositivos > HID/FIDO;")
    print(" 3) Tanner: com o USB desplugado, COM7/UART some? Replugue ambos e compare hid.enumerate().")
    sys.exit(3)
try:
    s.cmd_init()
    print("USB INIT cid=0x%08X" % s.cid)
    st, body = s._exchange_usb(CMD_PING, b"usb-e2e", timeout_s=10.0, op="e2e")
    print("USB PING eco=%r" % (bytes([st]) + body))
    st, body = s._exchange_usb(CMD_CBOR, bytes([0x04]), timeout_s=10.0, op="e2e")
    print("USB GetInfo status=0x%02X bytes=%d" % (st, len(body)))
finally:
    s.close()
print("USB OK")
