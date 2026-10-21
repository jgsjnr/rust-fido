#!/usr/bin/env python3
"""SCardTransmit cru via ctypes (isola OpenSC da equacao).

Uso: python tools/raw_transmit.py [reader_substring] [apdu_hex]
Padrao: reader com 'AegisKey', APDU = SELECT PIV AID.
"""
import ctypes
import sys

winscard = ctypes.windll.winscard
DWORD = ctypes.c_ulong
LPCWSTR = ctypes.c_wchar_p

winscard.SCardEstablishContext.argtypes = [DWORD, ctypes.c_void_p, ctypes.c_void_p,
                                           ctypes.POINTER(ctypes.c_void_p)]
winscard.SCardEstablishContext.restype = ctypes.c_long
winscard.SCardListReadersW.argtypes = [ctypes.c_void_p, LPCWSTR, ctypes.c_void_p,
                                       ctypes.POINTER(DWORD)]
winscard.SCardListReadersW.restype = ctypes.c_long
winscard.SCardConnectW.argtypes = [ctypes.c_void_p, LPCWSTR, DWORD, DWORD,
                                   ctypes.POINTER(ctypes.c_void_p), ctypes.POINTER(DWORD)]
winscard.SCardConnectW.restype = ctypes.c_long
winscard.SCardTransmit.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_char_p,
                                   DWORD, ctypes.c_void_p, ctypes.c_char_p,
                                   ctypes.POINTER(DWORD)]
winscard.SCardTransmit.restype = ctypes.c_long
winscard.SCardDisconnect.argtypes = [ctypes.c_void_p, DWORD]
winscard.SCardDisconnect.restype = ctypes.c_long
winscard.SCardReleaseContext.argtypes = [ctypes.c_void_p]
winscard.SCardReleaseContext.restype = ctypes.c_long

SCARD_S_SUCCESS = 0
SCARD_SHARE_SHARED = 2
SCARD_PROTOCOL_T0 = 0x0001
SCARD_PROTOCOL_T1 = 0x0002
SCARD_LEAVE_CARD = 0
SCARD_SCOPE_SYSTEM = 2

class SCARD_IO_REQUEST(ctypes.Structure):
    _fields_ = [("dwProtocol", ctypes.c_ulong), ("cbPciLength", ctypes.c_ulong)]

def check(rc, what):
    if rc != SCARD_S_SUCCESS:
        print("%s FALHOU: 0x%08X" % (what, rc & 0xFFFFFFFF))
        sys.exit(1)

# Contexto
h = ctypes.c_void_p()
check(winscard.SCardEstablishContext(SCARD_SCOPE_SYSTEM, None, None, ctypes.byref(h)), "EstablishContext")

# Readers (buffer fixo, sem two-step)
nbuf = 2048
buf = ctypes.create_unicode_buffer(nbuf)
need2 = DWORD(nbuf)
check(winscard.SCardListReadersW(h, None, buf, ctypes.byref(need2)), "ListReaders")
readers = [r for r in buf.value.split("\x00") if r]
print("readers:", readers)
want = sys.argv[1] if len(sys.argv) > 1 else "AegisKey"
rname = next((r for r in readers if want.lower() in r.lower()), None)
if not rname:
    print("sem reader '%s'" % want)
    sys.exit(2)
print("usando:", rname)

# Connect T0|T1
hcard = ctypes.c_void_p()
proto = DWORD(0)
check(
    winscard.SCardConnectW(h, rname, SCARD_SHARE_SHARED,
                           SCARD_PROTOCOL_T0 | SCARD_PROTOCOL_T1,
                           ctypes.byref(hcard), ctypes.byref(proto)),
    "SCardConnect",
)
print("conectado, protocolo ativo: 0x%X" % proto.value)

# Transmit
apdu_hex = sys.argv[2] if len(sys.argv) > 2 else "00A4040005A000000308"
send = bytes.fromhex(apdu_hex)
pci = SCARD_IO_REQUEST(SCARD_PROTOCOL_T1 if proto.value & SCARD_PROTOCOL_T1 else SCARD_PROTOCOL_T0,
                       ctypes.sizeof(SCARD_IO_REQUEST))
recv = ctypes.create_string_buffer(300)
recvlen = DWORD(300)
rc = winscard.SCardTransmit(hcard, ctypes.byref(pci), send, len(send), None,
                            recv, ctypes.byref(recvlen))
print("Transmit1 rc=0x%08X bytes=%d" % (rc & 0xFFFFFFFF, recvlen.value))
recvlen = DWORD(300)
rc = winscard.SCardTransmit(hcard, ctypes.byref(pci), send, len(send), None,
                            recv, ctypes.byref(recvlen))
print("Transmit2 rc=0x%08X bytes=%d" % (rc & 0xFFFFFFFF, recvlen.value))
if rc == 0:
    print("resp:", recv.raw[: recvlen.value].hex(" ").upper())

winscard.SCardDisconnect(hcard, SCARD_LEAVE_CARD)
winscard.SCardReleaseContext(h)
print("fim")
