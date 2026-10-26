#!/usr/bin/env python3
"""Avisa (som + banner) quando precisa de mao no dispositivo.

Uso: python tools/need_hands.py "desplugar e replugar o USB nativo"
Toca 3 bipes e espera ENTER (nao bloqueia o resto: rode e siga o texto).
"""
import sys

msg = " ".join(sys.argv[1:]) or "ACAO NO DISPOSITIVO"

print()
print("=" * 64)
print("  >>> PRECISO DE VOCE NO DISPOSITIVO <<<")
print("  " + msg)
print("  (volte pra sala e tecle ENTER aqui quando terminar)")
print("=" * 64)

try:
    import winsound
    for _ in range(4):
        winsound.Beep(880, 400)
        winsound.Beep(660, 400)
except Exception as e:
    print("(sem som: %s)" % e)
    print("\a" * 3)

try:
    input("ENTER quando pronto > ")
except EOFError:
    pass
print("OK, seguindo.")
