"""
=============================================================
  Module RSA — Projet VaultGCSE2
  Adapté pour grands nombres premiers (n > 2^128)
  afin de chiffrer une clé AES de 128 bits
=============================================================
"""
import math

# ── Grands premiers pré-générés (n > 2^128) ──────────────
# p et q sont des premiers de ~70 bits chacun
# n = p*q fait 138 bits > 2^128 ✓
# Générés avec seed=2226 (matricule 2220...)
P_DEFAULT = 895012521705992052691
Q_DEFAULT = 320097664377407181899
E_DEFAULT = 65537   # exposant public standard RSA


def pgcd_etendu(a, b):
    if b == 0:
        return a, 1, 0
    pgcd, u1, v1 = pgcd_etendu(b, a % b)
    u = v1
    v = u1 - (a // b) * v1
    return pgcd, u, v


def puissance_modulaire(m, e, n):
    result = 1
    m = m % n
    while e > 0:
        if e % 2 == 1:
            result = (result * m) % n
        m = (m * m) % n
        e = e // 2
    return result


def genere_cle(p, q, e):
    n     = p * q
    phi_n = (p - 1) * (q - 1)
    pgcd, u, _ = pgcd_etendu(e, phi_n)
    if pgcd != 1:
        raise ValueError("e et phi(n) doivent être premiers entre eux")
    d = u % phi_n
    return n, phi_n, d


def chiffrer(M, e, n):
    if M >= n:
        raise ValueError(f"Message M={M} >= n={n}. Choisir de plus grands premiers.")
    return puissance_modulaire(M, e, n)


def dechiffrer(C, d, n):
    return puissance_modulaire(C, d, n)


def get_cles_admin():
    """
    Retourne les clés RSA prêtes à l'emploi pour le projet.
    n > 2^128 garantit que toute clé AES de 128 bits peut être chiffrée.
    """
    n, phi_n, d = genere_cle(P_DEFAULT, Q_DEFAULT, E_DEFAULT)
    return {
        'e': E_DEFAULT,
        'n': n,
        'd': d,
        'p': P_DEFAULT,
        'q': Q_DEFAULT,
        'bits_n': n.bit_length(),
    }


if __name__ == "__main__":
    cles = get_cles_admin()
    print(f"p          = {cles['p']}")
    print(f"q          = {cles['q']}")
    print(f"e          = {cles['e']}")
    print(f"n          = {cles['n']}")
    print(f"d          = {cles['d']}")
    print(f"bits(n)    = {cles['bits_n']}  (> 128 ✓)")
    print(f"n > 2^128  : {cles['n'] > 2**128}")

    # Test avec vraie clé AES 128 bits
    import os
    aes_key = os.urandom(16)
    aes_int = int.from_bytes(aes_key, 'big')
    print(f"\nClé AES test : {aes_key.hex().upper()}")
    print(f"Entier       : {aes_int}")
    print(f"< n          : {aes_int < cles['n']}")

    C = chiffrer(aes_int, cles['e'], cles['n'])
    M = dechiffrer(C, cles['d'], cles['n'])
    recovered = M.to_bytes(16, 'big')
    print(f"Chiffré RSA  : {C}")
    print(f"Déchiffré    : {recovered.hex().upper()}")
    print(f"Correct      : {recovered == aes_key}")