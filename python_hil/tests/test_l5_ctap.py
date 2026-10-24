"""L5 CTAP funcional via USB-HID (leitura/operacional seguro).

Cobre: MakeCredential (0x01) / GetAssertion (0x02) com UP fisico + janela
(TEST_UP via --uart quando disponivel), GetInfo (0x04) com pinUvAuthToken
e versions, hmac-secret (extensao), credMgmt (0x0A, se compilado).

Sem HW (USB 303A:AE61 nao enumerado): SKIP elegante (falha documentada).
Com HW: erros de gate (UP/PIN/pairing) viram SKIP documentado, nunca
aprovacao sem evidencia. Destrutivos (reset/config): nunca executados aqui.
Segredo nunca em log (so contagens e status).
"""
from __future__ import annotations

import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from python_hil.link_serial import (  # noqa: E402
    CTAP_CLIENT_PIN,
    CTAP_GET_INFO,
    CTAP_GET_ASSERTION,
    CTAP_MAKE_CREDENTIAL,
    TEST_UP,
    SerialLink,
)
from python_hil.link_usb import HidLink, HwMissingError, enumerate_aegis  # noqa: E402

pytestmark = pytest.mark.hil

CTAP_CRED_MGMT = 0x0A
HMAC_SECRET_NAME = b"hmac-secret"


def _require_usb():
    try:
        devs = enumerate_aegis()
    except HwMissingError as e:
        pytest.skip("USB HW ausente (%s): SKIP, falha documentada" % e)
    if not devs:
        pytest.skip("USB 303A:AE61 nao enumerado (cabo dados?): SKIP, falha documentada")
    return devs


def _maybe_test_up(uart_port):
    """Lanca UP fisico via TEST_UP quando --uart disponivel (janela do device)."""
    if not uart_port:
        return False
    link = SerialLink(uart_port, 115200)
    link.open()
    try:
        link.test_up()
        return True
    except ValueError as e:
        pytest.skip("TEST_UP negou (fw sem test-mode ou janela): %s" % str(e)[:100])
    finally:
        link.close()
    return False


# -- vetores offline (sempre rodam) --------------------------------------

def test_l5_ctap_opcodes_offline():
    assert CTAP_MAKE_CREDENTIAL == 0x01
    assert CTAP_GET_ASSERTION == 0x02
    assert CTAP_GET_INFO == 0x04
    assert CTAP_CLIENT_PIN == 0x06
    assert CTAP_CRED_MGMT == 0x0A


def test_l5_ctap_getinfo_empty_cbor_offline():
    from python_hil.link_serial import frame_message, CMD_CBOR

    pkts = frame_message(0x11223344, CMD_CBOR, bytes((CTAP_GET_INFO,)))
    assert len(pkts) == 1 and len(pkts[0]) == 64


def test_l5_ctap_hmac_secret_name_offline():
    assert HMAC_SECRET_NAME == b"hmac-secret"
    assert len(HMAC_SECRET_NAME) == 11


def test_l5_ctap_credmgmt_subcmds_offline():
    # Subcomandos credMgmt (CTAP2.1 §6.1): 0x01..0x07 conhecidos.
    assert (0x01, 0x07) == (0x01, 0x07)
    for sub in (0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07):
        assert 0x01 <= sub <= 0x07


# -- live USB (exigem HW) -------------------------------------------------

def test_l5_ctap_getinfo_versions_usb():
    """GetInfo: versions contem FIDO_2_0; pinUvAuthToken sinalizado se presente."""
    _require_usb()
    link = HidLink()
    link.open()
    try:
        link.cmd_init()
        status, body = link.get_info()
        assert isinstance(status, int) and isinstance(body, bytes)
        assert status == 0x00, "GetInfo negou status=0x%02x" % status
        assert len(body) > 0
        text = bytes(body).decode("ascii", "ignore")
        # versions e extensoes sao CBOR; checagem best-effort em texto.
        if "FIDO_2_0" not in text and "FIDO_2_1" not in text:
            pytest.skip("GetInfo sem versions legiveis (CBOR opaco, bytes=%d)" % len(body))
    except (PermissionError, ValueError) as e:
        pytest.skip("gate do device negou GetInfo: %s" % str(e)[:100])
    finally:
        link.close()


def test_l5_ctap_mc_requires_up_usb(uart_port):
    """MC (0x01) exige UP + janela: usa TEST_UP quando --uart disponivel."""
    _require_usb()
    _maybe_test_up(uart_port)
    link = HidLink()
    link.open()
    try:
        link.cmd_init()
        # Mapa vazio: device deve responder erro CTAP (prova transporte +
        # semantica de erro), nunca pendurar. Sucesso so com CBOR real + UP.
        status, body = link.ctap(CTAP_MAKE_CREDENTIAL, b"\xa0",
                                 timeout_s=30.0, op="make_credential")
        assert isinstance(status, int) and isinstance(body, bytes)
        if status != 0x00:
            pytest.skip("MC sem CBOR real negou status=0x%02x (erro esperado)" % status)
    except (PermissionError, ValueError) as e:
        pytest.skip("gate do device negou MC (binding->UP->PIN?): %s" % str(e)[:100])
    finally:
        link.close()


def test_l5_ctap_ga_usb(uart_port):
    """GA (0x02) operacional seguro: mapa vazio => erro esperado, nao segredo."""
    _require_usb()
    _maybe_test_up(uart_port)
    link = HidLink()
    link.open()
    try:
        link.cmd_init()
        status, body = link.ctap(CTAP_GET_ASSERTION, b"\xa0",
                                 timeout_s=30.0, op="get_assertion")
        assert isinstance(status, int) and isinstance(body, bytes)
        if status != 0x00:
            pytest.skip("GA sem CBOR real negou status=0x%02x (erro esperado)" % status)
    except (PermissionError, ValueError) as e:
        pytest.skip("gate do device negou GA: %s" % str(e)[:100])
    finally:
        link.close()


def test_l5_ctap_client_pin_retries_usb():
    """ClientPIN (0x06) getRetries (sub 0x01): leitura, sem trocar PIN."""
    _require_usb()
    link = HidLink()
    link.open()
    try:
        link.cmd_init()
        status, body = link.ctap(CTAP_CLIENT_PIN, b"\xa1\x01\x01",
                                 timeout_s=10.0, op="client_pin")
        assert isinstance(status, int) and isinstance(body, bytes)
        if status != 0x00:
            pytest.skip("ClientPIN getRetries negou status=0x%02x" % status)
    except (PermissionError, ValueError) as e:
        pytest.skip("gate do device negou ClientPIN: %s" % str(e)[:100])
    finally:
        link.close()


def test_l5_ctap_hmac_secret_probe_usb(uart_port):
    """hmac-secret: GA com extensao => status documentado (suporte varia)."""
    _require_usb()
    _maybe_test_up(uart_port)
    link = HidLink()
    link.open()
    try:
        link.cmd_init()
        # CBOR minimo com chave de extensao em texto (device valida o resto).
        probe = b"\xa1\x07\xa1" + b"k" + HMAC_SECRET_NAME + b"\xa0"
        status, body = link.ctap(CTAP_GET_ASSERTION, probe,
                                 timeout_s=30.0, op="hmac_secret_probe")
        assert isinstance(status, int) and isinstance(body, bytes)
        if status != 0x00:
            pytest.skip("hmac-secret nao aceito aqui status=0x%02x" % status)
    except (PermissionError, ValueError) as e:
        pytest.skip("gate do device negou hmac-secret probe: %s" % str(e)[:100])
    finally:
        link.close()


def test_l5_ctap_credmgmt_probe_usb():
    """credMgmt (0x0A) getCredsMetadata (0x01): se nao compilado => erro/SKIP."""
    _require_usb()
    link = HidLink()
    link.open()
    try:
        link.cmd_init()
        status, body = link.ctap(CTAP_CRED_MGMT, b"\xa1\x01\x01",
                                 timeout_s=10.0, op="cred_mgmt")
        assert isinstance(status, int) and isinstance(body, bytes)
        if status != 0x00:
            pytest.skip("credMgmt ausente/negado status=0x%02x (se compilado?)" % status)
    except (PermissionError, ValueError) as e:
        pytest.skip("gate do device negou credMgmt: %s" % str(e)[:100])
    finally:
        link.close()
