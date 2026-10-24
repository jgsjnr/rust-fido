"""Flags e helpers da lane HIL (sem HW por padrao; skip elegante)."""
from __future__ import annotations

import pytest


def pytest_addoption(parser):
    parser.addoption("--uart", action="store", default=None,
                     help="porta UART p/ L2 (ex. COM7). Ausente => skip.")
    parser.addoption("--tcp", action="store", default=None,
                     help="host:port do sim p/ L1 (ex. 127.0.0.1:5678). Ausente => skip.")
    parser.addoption("--ap-base", action="store", default="http://192.168.4.1",
                     help="base do AP WiFi p/ probes (associar no SSID antes).")
    parser.addoption("--ble-addr", action="store", default=None,
                     help="endereco BLE p/ probe FFF1-FFF4. Ausente => skip.")
    parser.addoption("--confirm", action="store", default=None,
                     help="token p/ passos destrutivos (ex. --confirm OTA-COMMIT). Ausente => skip.")


def pytest_configure(config):
    config.addinivalue_line("markers", "hil: testes que exigem HW/sim real")


@pytest.fixture
def uart_port(request):
    return request.config.getoption("--uart")


@pytest.fixture
def tcp_target(request):
    return request.config.getoption("--tcp")


@pytest.fixture
def ap_base(request):
    return request.config.getoption("--ap-base")


@pytest.fixture
def ble_addr(request):
    return request.config.getoption("--ble-addr")


@pytest.fixture
def confirm_token(request):
    return request.config.getoption("--confirm")


def require(cond, msg):
    if not cond:
        pytest.skip(msg)
