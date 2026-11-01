#!/usr/bin/env python3
"""AegisKey Native Notification Manager — Cross-Platform System Alerts.

Dispatches native desktop notifications on Windows (Shell_NotifyIconW / Toast),
Linux (notify-send), and macOS (osascript).
Maintains an auditable log of sent security alerts for verification and automated tests.
"""

from __future__ import annotations

import ctypes
import logging
import os
import platform
import subprocess
import threading
from typing import Any, Callable, Dict, List, Optional

logger = logging.getLogger("AegisNotifier")


class NativeNotifier:
    """Dispatches native OS notifications and triggers security UI callbacks."""

    def __init__(self):
        self._lock = threading.Lock()
        self.history: List[Dict[str, Any]] = []
        self._listeners: List[Callable[[str, str, str], None]] = []
        self.win32_nid: Optional[Any] = None

    def register_listener(self, callback: Callable[[str, str, str], None]):
        """Registers a callback hook invoked when a notification is dispatched."""
        with self._lock:
            self._listeners.append(callback)

    def attach_win32_nid(self, nid: Any):
        """Attaches active Win32 NOTIFYICONDATAW struct from the tray app."""
        self.win32_nid = nid

    def notify(self, title: str, message: str, level: str = "info"):
        """Dispatches a native desktop notification to the operating system."""
        with self._lock:
            entry = {"title": title, "message": message, "level": level}
            self.history.append(entry)
            listeners = list(self._listeners)

        for cb in listeners:
            try:
                cb(title, message, level)
            except Exception as e:
                logger.debug(f"Notification listener error: {e}")

        os_name = platform.system()
        try:
            if os_name == "Windows":
                self._notify_windows(title, message, level)
            elif os_name == "Linux":
                self._notify_linux(title, message, level)
            elif os_name == "Darwin":
                self._notify_macos(title, message, level)
        except Exception as ex:
            logger.debug(f"Failed to show native notification: {ex}")

    def _notify_windows(self, title: str, message: str, level: str):
        if self.win32_nid is not None:
            NIM_MODIFY = 0x00000001
            NIF_INFO = 0x00000010
            # NIIF_INFO = 1, NIIF_WARNING = 2, NIIF_ERROR = 3
            flags_map = {"info": 1, "warning": 2, "error": 3}
            icon_flag = flags_map.get(level, 1)

            self.win32_nid.uFlags |= NIF_INFO
            self.win32_nid.szInfoTitle = title[:63]
            self.win32_nid.szInfo = message[:255]
            self.win32_nid.dwInfoFlags = icon_flag
            ctypes.windll.shell32.Shell_NotifyIconW(NIM_MODIFY, ctypes.byref(self.win32_nid))
            return

        # Headless/fallback: Windows PowerShell BurntToast or balloon
        try:
            ps_script = (
                f'[reflection.assembly]::loadwithpartialname("System.Windows.Forms");'
                f'$notify = new-object system.windows.forms.notifyicon;'
                f'$notify.icon = [system.drawing.systemicons]::Information;'
                f'$notify.visible = $true;'
                f'$notify.showballoontip(3000, "{title}", "{message}", [system.windows.forms.tooltipicon]::Info);'
            )
            subprocess.run(
                ["powershell", "-NoProfile", "-NonInteractive", "-Command", ps_script],
                timeout=2.0,
                creationflags=0x08000000,  # CREATE_NO_WINDOW
            )
        except Exception:
            pass

    def _notify_linux(self, title: str, message: str, level: str):
        try:
            urgency = "critical" if level in ("error", "warning") else "normal"
            subprocess.run(
                ["notify-send", "-u", urgency, "-a", "AegisKey", title, message],
                timeout=2.0,
            )
        except Exception:
            pass

    def _notify_macos(self, title: str, message: str, level: str):
        try:
            osa_cmd = f'display notification "{message}" with title "{title}" subtitle "AegisKey Security"'
            subprocess.run(["osascript", "-e", osa_cmd], timeout=2.0)
        except Exception:
            pass

    def get_history(self) -> List[Dict[str, Any]]:
        with self._lock:
            return list(self.history)

    def clear_history(self):
        with self._lock:
            self.history.clear()


# Global default notifier singleton
NOTIFIER = NativeNotifier()
