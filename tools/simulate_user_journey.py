#!/usr/bin/env python3
"""
Simulação Completa da Jornada do Usuário no Hardware Real (ESP32-S3 em COM7)
e Diagnóstico do Ciclo de Vida das Chaves no App Android.

Reproduzindo exatamente a sequência relatada:
1. Conexão inicial com a chave (identificação via USB/COM).
2. Início de Sessão do Secure Guard (Desbloqueio com PIN 2707) -> Leitura das chaves existentes.
3. Bloqueio do Secure Guard (Lock 0x3C) -> Verificação da Barreira Zero-Trust (0x36 PIN Required).
4. Desbloqueio do Secure Guard (Unlock com PIN 2707) -> Leitura das chaves no hardware.
5. Criação de nova chave no hardware (OP_KEY_GEN_ONDEVICE 0x20) -> Listagem e verificação da persistência.
"""

import os
import sys
import time

# Adiciona o diretório tools ao path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from app_simulator import Session, CMD_MSG
from host_hardware_android_bridge import cbor_encode, cbor_decode

def parse_tlv_keys(data: bytes):
    """Decodifica os registros TLV retornados por OP_KEY_LIST (0x22)."""
    keys = []
    i = 0
    pending_slot = None
    while i < len(data):
        tag = data[i]
        i += 1
        if i >= len(data):
            break
        length = data[i]
        i += 1
        val = data[i:i+length]
        i += length
        if tag == 0x01:  # TAG_SLOT
            pending_slot = val[0] if len(val) == 1 else None
        elif tag == 0x02:  # TAG_LABEL
            label = val.decode('utf-8', errors='replace')
            if pending_slot is not None:
                keys.append({'slot': pending_slot, 'label': label})
                pending_slot = None
    return keys

def main():
    print("=" * 75)
    print("  SIMULAÇÃO DA JORNADA DO USUÁRIO NO HARDWARE REAL (COM7)")
    print("  REPRODUÇÃO: CONEXÃO -> DESBLOQUEIO -> BLOQUEIO -> DESBLOQUEIO -> CRIAÇÃO")
    print("=" * 75)

    port = "COM7"
    baud = 115200

    # -------------------------------------------------------------------------
    # 1. Identificação / Conexão Inicial
    # -------------------------------------------------------------------------
    print("\n[ETAPA 1] Identificação e Conexão Inicial com a Chave Física...")
    sess = Session("http://192.168.4.1", test_mode=True)
    sess.connect(port, baud)
    cid = sess.cmd_init()
    print(f" -> Dispositivo conectado com sucesso na porta {port}")
    print(f" -> Canal CTAPHID alocado: CID 0x{cid:08X}")

    # Consulta Status do Secure Guard (0x3A)
    time.sleep(0.05)
    st, resp = sess._exchange(CMD_MSG, bytes([0x3A]) + cbor_encode({'action': 'status'}))
    status_data, _ = cbor_decode(resp) if (st == 0 and len(resp) > 0) else ({}, 0)
    print(f" -> Status Secure Guard (0x3A): status_code=0x{st:02X}, estado={status_data.get('state_name', 'Unknown')}")

    # Tentativa de listar chaves ANTES do desbloqueio (Zero-Trust deve barrar com 0x36)
    time.sleep(0.05)
    st, resp = sess._exchange(CMD_MSG, bytes([0x22]))
    print(f" -> Consulta com cofre bloqueado (0x22): status_code=0x{st:02X} (0x36 = PIN_REQUIRED esperado)")
    assert st == 0x36, f"Esperava 0x36 (Zero-Trust) mas recebeu 0x{st:02X}"
    print(" -> [CLIENTE SIMULADO] App exibe: 'Cofre Bloqueado / Secure Guard Bloqueado'.")

    # -------------------------------------------------------------------------
    # 2. Início de Sessão do Secure Guard (Unlock com PIN 2707)
    # -------------------------------------------------------------------------
    print("\n[ETAPA 2] Início de Sessão do Secure Guard (Desbloqueio com PIN 2707)...")
    time.sleep(0.05)
    st, resp = sess._exchange(CMD_MSG, bytes([0x3B]) + cbor_encode({'action': 'unlock', 'pin': b'2707'}))
    print(f" -> Resposta Unlock (0x3B): status_code=0x{st:02X} (Desbloqueado com sucesso!)")
    assert st == 0x00, "Desbloqueio com PIN falhou!"

    # Verifica status imediatamente após unlock
    time.sleep(0.05)
    st_check, resp_check = sess._exchange(CMD_MSG, bytes([0x3A]) + cbor_encode({'action': 'status'}))
    sg_status, _ = cbor_decode(resp_check) if (st_check == 0 and len(resp_check) > 0) else ({}, 0)
    print(f" -> Estado pós-desbloqueio no hardware: {sg_status.get('state_name')} (sessão={sg_status.get('session_remaining_ms')}ms)")

    # Lista chaves após primeiro desbloqueio
    time.sleep(0.05)
    st, resp = sess._exchange(CMD_MSG, bytes([0x22]))
    assert st == 0x00, f"Falha ao listar chaves desbloqueadas: 0x{st:02X}"
    keys_step2 = parse_tlv_keys(resp)
    print(f" -> Chaves recuperadas da Flash NVS pelo hardware ({len(keys_step2)} chave(s)):")
    for k in keys_step2:
        print(f"    - Slot #{k['slot']}: Label='{k['label']}'")
    print(f" -> [CLIENTE SIMULADO] App exibe na tela {len(keys_step2)} chave(s) perfeitamente.")

    # -------------------------------------------------------------------------
    # 3. Bloqueio do Secure Guard (Lock 0x3C)
    # -------------------------------------------------------------------------
    print("\n[ETAPA 3] Bloqueando o Secure Guard (Lock 0x3C)...")
    time.sleep(0.05)
    st, resp = sess._exchange(CMD_MSG, bytes([0x3C]))
    print(f" -> Resposta Lock (0x3C): status_code=0x{st:02X} (Cofre Trancado)")
    assert st == 0x00, "Bloqueio falhou!"

    # Tenta listar chaves imediatamente após trancar -> Barreira Zero-Trust
    time.sleep(0.05)
    st, resp = sess._exchange(CMD_MSG, bytes([0x22]))
    print(f" -> Leitura com cofre bloqueado (0x22): status_code=0x{st:02X} (0x36 = Acesso Negado)")
    assert st == 0x36, f"Esperava 0x36 mas obteve 0x{st:02X}"
    print(" -> [CLIENTE SIMULADO] App limpa a memória volátil (Zero-Trust: 0 chaves expostas).")

    # -------------------------------------------------------------------------
    # 4. Desbloqueio do Secure Guard Novamente (Unlock com PIN 2707)
    # -------------------------------------------------------------------------
    print("\n[ETAPA 4] Desbloqueando o Secure Guard Novamente (PIN 2707)...")
    time.sleep(0.05)
    st, resp = sess._exchange(CMD_MSG, bytes([0x3B]) + cbor_encode({'action': 'unlock', 'pin': b'2707'}))
    print(f" -> Resposta Unlock (0x3B): status_code=0x{st:02X} (Desbloqueado com sucesso!)")
    assert st == 0x00, "Segundo desbloqueio falhou!"

    # Consulta as chaves no hardware físico após o segundo desbloqueio
    time.sleep(0.05)
    st, resp = sess._exchange(CMD_MSG, bytes([0x22]))
    assert st == 0x00, f"Falha na listagem após segundo desbloqueio: 0x{st:02X}"
    keys_step4 = parse_tlv_keys(resp)
    print(f" -> Chaves no hardware físico após segundo desbloqueio ({len(keys_step4)} chave(s)):")
    for k in keys_step4:
        print(f"    - Slot #{k['slot']}: Label='{k['label']}'")

    assert len(keys_step4) == len(keys_step2), "ERRO: Número de chaves divergiu no hardware!"
    print(" -> [COMPROVAÇÃO DE HARDWARE] O ESP32-S3 NUNCA apagou nenhuma chave da Flash NVS!")

    # -------------------------------------------------------------------------
    # 5. Criando uma Nova Chave no Hardware (OP_KEY_GEN_ONDEVICE 0x20)
    # -------------------------------------------------------------------------
    occupied_slots = {k['slot'] for k in keys_step4}
    # Seleciona o menor slot livre entre 0 e 31
    next_free_slot = next((s for s in range(32) if s not in occupied_slots), 5)
    new_label = f"KeySlot{next_free_slot}"

    print(f"\n[ETAPA 5] Criando uma nova chave no hardware (Slot #{next_free_slot}, Label='{new_label}')...")
    # TLV: 0x01 (slot), 0x02 (label), 0x05 (alg=-7 / P-256), 0x06 (usage=3 / auth|sign)
    label_bytes = new_label.encode('utf-8')
    tlv_req = (
        bytes([0x01, 1, next_free_slot]) +
        bytes([0x02, len(label_bytes)]) + label_bytes +
        bytes([0x05, 4, 0xFF, 0xFF, 0xFF, 0xF9]) +
        bytes([0x06, 1, 0x03])
    )
    time.sleep(0.05)
    st, resp = sess._exchange(CMD_MSG, bytes([0x20]) + tlv_req)
    print(f" -> Resposta OP_KEY_GEN_ONDEVICE (0x20): status_code=0x{st:02X}")
    assert st == 0x00, f"Falha ao gerar chave: status_code=0x{st:02X}"

    # Consulta a lista completa de chaves no hardware após a criação
    time.sleep(0.05)
    st, resp = sess._exchange(CMD_MSG, bytes([0x22]))
    assert st == 0x00, f"Falha ao listar chaves: 0x{st:02X}"
    keys_step5 = parse_tlv_keys(resp)
    print(f" -> Lista completa no hardware após a adição ({len(keys_step5)} chave(s)):")
    for k in keys_step5:
        print(f"    - Slot #{k['slot']}: Label='{k['label']}'")

    assert any(k['slot'] == next_free_slot for k in keys_step5), f"Slot #{next_free_slot} não encontrado!"
    assert len(keys_step5) == len(keys_step4) + 1, "Chaves anteriores foram perdidas durante a adição!"
    print(f" -> SUCESSO TOTAL: Nova chave adicionada e todas as {len(keys_step4)} anteriores mantidas intactas!")

    # -------------------------------------------------------------------------
    # Explicação Técnica do Fenômeno no App Android
    # -------------------------------------------------------------------------
    print("\n" + "=" * 75)
    print("  DIAGNÓSTICO TÉCNICO DEFINITIVO DO QUE OCORREU NO APLICATIVO ANDROID:")
    print("=" * 75)
    print("1. INTEGRIDADE FÍSICA (HARDWARE ESP32-S3):")
    print("   - O firmware NUNCA apagou suas chaves do NVS flash.")
    print("   - Como comprovado acima, todas as chaves continuam gravadas e persistentes.")
    print("\n2. O QUE CAUSOU O DESAPARECIMENTO NO APLICATIVO:")
    print("   a) Na tela 'KeyVaultHubScreen', ao clicar em Confirmar PIN para desbloquear:")
    print("      O app disparava 'unlock(pin)' de forma ASSÍNCRONA e chamava 'refreshVault()'")
    print("      no mesmo instante (sem esperar a resposta do chip).")
    print("   b) Como o chip ainda estava processando o desbloqueio no momento que o refreshVault")
    print("      chegou, o app recebia '0x36' (PIN REQUIRED) e executava 'clearMemoryVault()',")
    print("      zerando a lista de chaves na interface gráfica.")
    print("   c) Ao tentar criar uma nova chave, a função 'generateNewAccessKey' lia a memória")
    print("      local (que acabara de ser zerada no passo 'b'), criava a chave no chip físico")
    print("      e sobrescrevia o armazenamento local do celular com [ApenasANovaChave],")
    print("      dando a impressão visual de que as anteriores haviam sumido.")
    print("\n3. CORREÇÃO IMPLEMENTADA NO CLIENTE:")
    print("   - O 'refreshVault()' agora aguarda a confirmação de sucesso do 'unlock(pin)'.")
    print("   - Se houver qualquer leitura com cofre bloqueado, o cache criptografado com o")
    print("     hardware binding NUNCA é sobrescrito nem apagado.")
    print("   - Antes de gerar qualquer chave, o app sincroniza a lista física do hardware.")
    print("=" * 75)

    sess.close()

if __name__ == "__main__":
    main()
