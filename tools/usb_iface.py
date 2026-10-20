"""Enumera interfaces HID via SetupAPI e tenta CreateFile (acha onde trava)."""
import ctypes
from ctypes import wintypes

setup = ctypes.WinDLL("setupapi")
kernel = ctypes.WinDLL("kernel32")
hid_guid = ctypes.create_string_buffer(
    bytes([0xB2, 0x55, 0x1E, 0x4D, 0x6E, 0xF1, 0xCE, 0x11,
           0xBE, 0xB7, 0x08, 0x00, 0x2B, 0xE1, 0x03, 0x18]))  # GUID_DEVINTERFACE_HID

DIGCF_PRESENT = 0x02
DIGCF_DEVICEINTERFACE = 0x10
GENERIC_READ = 0x80000000
GENERIC_WRITE = 0x40000000
FILE_SHARE_READ = 1
FILE_SHARE_WRITE = 2
OPEN_EXISTING = 3
INVALID = wintypes.HANDLE(-1).value


class DevInfoData(ctypes.Structure):
    _fields_ = [("cbSize", wintypes.DWORD), ("ClassGuid", ctypes.c_byte * 16),
                ("DevInst", wintypes.DWORD), ("Reserved", ctypes.c_void_p)]


class IfaceData(ctypes.Structure):
    _fields_ = [("cbSize", wintypes.DWORD), ("InterfaceClassGuid", ctypes.c_byte * 16),
                ("Flags", wintypes.DWORD), ("Reserved", ctypes.c_void_p)]


hdev = setup.SetupDiGetClassDevsA(hid_guid, None, None, DIGCF_PRESENT | DIGCF_DEVICEINTERFACE)
print("hdev:", hex(hdev))
ours = []
i = 0
while True:
    data = IfaceData()
    data.cbSize = ctypes.sizeof(IfaceData)
    ok = setup.SetupDiEnumDeviceInterfaces(hdev, None, hid_guid, i, ctypes.byref(data))
    if not ok:
        break
    # tamanho do detalhe
    need = wintypes.DWORD(0)
    setup.SetupDiGetDeviceInterfaceDetailA(hdev, ctypes.byref(data), None, 0, ctypes.byref(need), None)
    buf = ctypes.create_string_buffer(need.value)
    buf[0:4] = (8).to_bytes(4, "little")  # cbSize do DETAIL (x64)
    ok2 = setup.SetupDiGetDeviceInterfaceDetailA(
        hdev, ctypes.byref(data), buf, need.value, None, None)
    path = buf[4:need.value].split(b"\x00")[0].decode("ascii", "replace")
    if "303a" in path.lower() or "ae61" in path.lower():
        ours.append(path)
        print("NOSSO PATH:", path)
    i += 1
print("interfaces HID presentes:", i, "| nossas:", len(ours))
setup.SetupDiDestroyDeviceInfoList(hdev)

for p in ours:
    h = kernel.CreateFileW(p, GENERIC_READ | GENERIC_WRITE,
                           FILE_SHARE_READ | FILE_SHARE_WRITE, None,
                           OPEN_EXISTING, 0, None)
    if h == INVALID:
        print("CreateFile FALHOU err=", kernel.GetLastError())
    else:
        print("CreateFile OK handle=", h)
        kernel.CloseHandle(h)
