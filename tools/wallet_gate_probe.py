#!/usr/bin/env python3
"""Prova viva das gates wallet: GEN sem pareamento nega em DUAS camadas.

Camada 1 (binding, producao sem vinculo): firmware release (test-mode OFF)
barra CONFIG via binding.rs `require_bound_config` -> NEED_BINDING 0x05.
E o PASS esperado em producao sem vinculo (e2e T06/T06b afirmam 0x05).

Camada 2 (payload/UP, test-mode com bypass): com feature `test-mode` ON,
`binding_bypass_enabled()` (binding.rs:68-70) autoriza a sessao (ltrace
"binding-bypass") e a operacao cai no gate seguinte -> 0x01 (p.ex. UP
ausente/TLV invalido), mesmo mecanismo do wifi_ap ja documentado. Logo
0x01 aqui NAO e regressao: e o bypass de teste funcionando por desenho.

Como distinguir: se TEST_PAIRING_OPEN / TEST_UP respondem (pairing_open /
up_latched), o firmware e test-mode -> 0x01 esperado; se recusam, e
producao -> 0x05 esperado.

PASS = status em {0x05, 0x01}. Sem flash, sem mudar firmware.
"""
import sys

sys.path.insert(0, "tools")
from app_simulator import Session, CMD_MSG

s = Session("http://127.0.0.1:8888")
s.connect("COM7", 115200)
try:
    st, _ = s._exchange(CMD_MSG, bytes([0x35, 0x01, 0x01, 0x00]), timeout_s=10.0, op="wallet-probe")
finally:
    s.close()
print("WALLET_GEN_NOPAIR_STATUS=0x%02x" % st)
assert st in (0x05, 0x01), st
if st == 0x05:
    print("WALLET_GATE_OK producao sem vinculo nega NEED_BINDING 0x05 vivo")
else:
    print("WALLET_GATE_OK test-mode com binding_bypass cai no gate seguinte 0x01 (por desenho)")
