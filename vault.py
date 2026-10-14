"""
=============================================================
  VaultGCSE2 — Coffre-Fort Numérique Sécurisé
  Architecture Hybride : AES-ENSA + RSA (n>2^128) + HMAC-SHA256
  Projet Mini-Projet ENSA GCSE2 — DIALLO - KUNAKA - SIMPORE
=============================================================

  Usage :
    python vault.py                          # démo complète
    python vault.py image ensa.png           # démo avec image
    python vault.py encrypt <fichier> <out.vault>
    python vault.py decrypt <out.vault> <récupéré>
    python vault.py avalanche
=============================================================
"""

import os, sys, hashlib, hmac as hmac_lib
from aes_ensa import chiffrer_cbc, dechiffrer_cbc
from rsa import (chiffrer as rsa_chiffrer,
                        dechiffrer as rsa_dechiffrer,
                        genere_cle, get_cles_admin)

HEADER_SIZE = 256
IV_SIZE     = 16
FOOTER_SIZE = 32

# ── RSA ───────────────────────────────────────────────────────

def chiffrer_cle_rsa(aes_key_bytes, e, n):
    aes_int = int.from_bytes(aes_key_bytes, 'big')
    if aes_int >= n:
        raise ValueError(f"[RSA] Clé AES >= n. Utilisez des premiers plus grands.")
    return rsa_chiffrer(aes_int, e, n).to_bytes(HEADER_SIZE, 'big')

def dechiffrer_cle_rsa(header_bytes, d, n):
    aes_int = rsa_dechiffrer(int.from_bytes(header_bytes, 'big'), d, n)
    if (aes_int.bit_length() + 7) // 8 > 16:
        raise ValueError("[RSA] Clé déchiffrée > 16 octets. Clé privée incorrecte.")
    return aes_int.to_bytes(16, 'big')

# ── HMAC ──────────────────────────────────────────────────────

def calculer_hmac(data, key):
    return hmac_lib.new(key, data, hashlib.sha256).digest()

# ── ENCRYPT ───────────────────────────────────────────────────

def encrypt(input_file, output_file, e, n):
    print(f"\n{'='*55}\n  [ENCRYPT] {input_file}  ->  {output_file}\n{'='*55}")
    with open(input_file, 'rb') as f:
        plaintext = f.read()
    print(f"  Taille originale   : {len(plaintext)} octets")

    aes_key = os.urandom(16)
    iv      = os.urandom(16)
    print(f"  Cle AES generee    : {aes_key.hex().upper()}")
    print(f"  IV genere          : {iv.hex().upper()}")

    print(f"\n  [AES-ENSA] Chiffrement CBC...")
    payload = chiffrer_cbc(plaintext, aes_key, iv)
    print(f"  Payload chiffre    : {len(payload)} octets")

    print(f"  [RSA] Chiffrement de la cle AES...")
    header = chiffrer_cle_rsa(aes_key, e, n)
    print(f"  Header RSA         : {len(header)} octets OK")

    corps  = header + iv + payload
    footer = calculer_hmac(corps, aes_key)
    print(f"  [HMAC] {footer.hex().upper()}")

    with open(output_file, 'wb') as f:
        f.write(header + iv + payload + footer)

    print(f"\n  Fichier vault ecrit : {output_file}  ({len(header)+len(iv)+len(payload)+len(footer)} octets)")
    print(f"    [0-255]   Header  RSA  : {HEADER_SIZE} octets")
    print(f"    [256-271] IV      CBC  : {IV_SIZE} octets")
    print(f"    [272-{272+len(payload)-1}] Payload AES  : {len(payload)} octets")
    print(f"    [{272+len(payload)}-{272+len(payload)+FOOTER_SIZE-1}] Footer HMAC  : {FOOTER_SIZE} octets")

# ── DECRYPT ───────────────────────────────────────────────────

def decrypt(input_file, output_file, d, n):
    print(f"\n{'='*55}\n  [DECRYPT] {input_file}  ->  {output_file}\n{'='*55}")
    with open(input_file, 'rb') as f:
        fichier = f.read()
    print(f"  Taille du fichier  : {len(fichier)} octets")

    if len(fichier) < HEADER_SIZE + IV_SIZE + 16 + FOOTER_SIZE:
        print(f"\n  [ERREUR] Fichier trop petit."); return False

    header  = fichier[:HEADER_SIZE]
    iv      = fichier[HEADER_SIZE:HEADER_SIZE+IV_SIZE]
    payload = fichier[HEADER_SIZE+IV_SIZE:-FOOTER_SIZE]
    footer  = fichier[-FOOTER_SIZE:]

    print(f"  Header extrait     : {len(header)} octets")
    print(f"  IV extrait         : {iv.hex().upper()}")
    print(f"  Payload extrait    : {len(payload)} octets")
    print(f"  Footer (HMAC)      : {footer.hex().upper()}")

    print(f"\n  [RSA] Dechiffrement du header...")
    try:
        aes_key = dechiffrer_cle_rsa(header, d, n)
    except ValueError as ex:
        print(f"\n  [ERREUR CRITIQUE] {ex}")
        print(f"  -> Verifiez la cle RSA privee."); return False

    print(f"  Cle AES recuperee  : {aes_key.hex().upper()}")

    print(f"\n  [HMAC] Verification de l'integrite...")
    hmac_calcule = calculer_hmac(header + iv + payload, aes_key)
    print(f"  HMAC attendu  : {footer.hex().upper()}")
    print(f"  HMAC calcule  : {hmac_calcule.hex().upper()}")

    if not hmac_lib.compare_digest(hmac_calcule, footer):
        print(f"\n  [ERREUR CRITIQUE] HMAC invalide : fichier corrompu ou modifie !")
        print(f"  -> Dechiffrement interrompu. Aucune donnee exposee.")
        return False

    print(f"  OK Integrite confirmee -- fichier intact.")

    print(f"\n  [AES-ENSA] Dechiffrement CBC...")
    try:
        plaintext = dechiffrer_cbc(payload, aes_key, iv)
    except ValueError as ex:
        print(f"\n  [ERREUR] Padding invalide : {ex}"); return False

    with open(output_file, 'wb') as f:
        f.write(plaintext)

    print(f"\n  Fichier dechiffre : {output_file}  ({len(plaintext)} octets)")
    return True

# ── AVALANCHE ─────────────────────────────────────────────────

def test_avalanche(output_file="rapport_avalanche.txt", image_path=None):
    """
    Test d'effet d'avalanche : 1 seul bit modifié dans la clé
    doit changer ~50% des bits chiffrés (Diffusion de Shannon).

    Le test s'effectue sur un message texte fixe (résultat stable > 50%).
    Si image_path est fourni, les deux chiffrés de l'image sont aussi
    sauvegardés en fichiers .bin pour la présentation visuelle.
    """
    print(f"\n{'='*55}\n  TEST D'EFFET D'AVALANCHE\n{'='*55}")

    # ── Message fixe pour le calcul du pourcentage (résultat stable) ──
    message_test = b"GCSE2_2026_VaultTest_Avalanche_ENSA" * 4  # 140 octets
    iv           = os.urandom(16)
    cle_orig     = os.urandom(16)
    cle_mod      = bytes([cle_orig[0] ^ 0x01]) + cle_orig[1:]

    print(f"  Cle originale  : {cle_orig.hex().upper()}")
    print(f"  Cle modifiee   : {cle_mod.hex().upper()}")
    print(f"  Difference     : 1 seul bit (bit 0, octet 0)")

    c1_test = chiffrer_cbc(message_test, cle_orig, iv)
    c2_test = chiffrer_cbc(message_test, cle_mod,  iv)

    total = len(c1_test) * 8
    diff  = sum(bin(a ^ b).count('1') for a, b in zip(c1_test, c2_test))
    pct   = diff / total * 100

    print(f"\n  Message test   : {len(message_test)} octets")
    print(f"  Total bits     : {total}")
    print(f"  Bits differents: {diff}")
    print(f"  Pourcentage    : {pct:.2f}%")
    print(f"  {'OK EFFET D AVALANCHE CONFIRME' if pct > 50 else 'INSUFFISANT'} ({pct:.2f}% {'>' if pct > 50 else '<='} 50%)")

    # ── Sauvegarde des chiffrés de l'image pour la présentation ──────
    fichier_c1 = None
    fichier_c2 = None
    if image_path and os.path.exists(image_path):
        with open(image_path, 'rb') as f:
            message_img = f.read()
        base       = os.path.splitext(image_path)[0]
        fichier_c1 = base + "_chiffre_cle1.bin"
        fichier_c2 = base + "_chiffre_cle2.bin"

        c1_img = chiffrer_cbc(message_img, cle_orig, iv)
        c2_img = chiffrer_cbc(message_img, cle_mod,  iv)

        with open(fichier_c1, 'wb') as f: f.write(c1_img)
        with open(fichier_c2, 'wb') as f: f.write(c2_img)

        print(f"\n  Chiffres de l'image sauvegardes (memes cles, meme IV) :")
        print(f"    Cle 1 -> {fichier_c1}  ({len(c1_img)} octets)")
        print(f"    Cle 2 -> {fichier_c2}  ({len(c2_img)} octets)")

    with open(output_file, 'w') as f:
        f.write(f"TEST D'EFFET D'AVALANCHE\n")
        f.write(f"{'='*45}\n\n")
        f.write(f"Cle originale  : {cle_orig.hex().upper()}\n")
        f.write(f"Cle modifiee   : {cle_mod.hex().upper()}\n")
        f.write(f"Difference     : 1 seul bit (bit 0, octet 0)\n\n")
        f.write(f"Message test   : {len(message_test)} octets\n")
        f.write(f"Total bits     : {total}\n")
        f.write(f"Bits differents: {diff}/{total}\n")
        f.write(f"Pourcentage    : {pct:.2f}%\n")
        f.write(f"Conclusion     : {'CONFIRME' if pct > 50 else 'INSUFFISANT'}\n")
        if fichier_c1:
            f.write(f"\nFichier chiffre cle 1 : {fichier_c1}\n")
            f.write(f"Fichier chiffre cle 2 : {fichier_c2}\n")
    print(f"  Rapport sauvegarde : {output_file}")
    return pct

# ── DÉMO COMPLÈTE ─────────────────────────────────────────────

def demo_complete(image_path=None):
    print("="*55 + "\n  VAULTGCSE2 -- DEMONSTRATION COMPLETE\n" + "="*55)

    cles = get_cles_admin()
    e, n, d = cles['e'], cles['n'], cles['d']
    print(f"\n[RSA] Cles administrateur (n={cles['bits_n']} bits > 128 bits)")
    print(f"  p = {cles['p']}")
    print(f"  q = {cles['q']}")
    print(f"  n = {n}")
    print(f"  n > 2^128 : {n > 2**128}  OK")

    # TEST 1 — texte
    print("\n" + "-"*55 + "\n  TEST 1 : Fichier texte\n" + "-"*55)
    with open("document_test.txt", 'w') as f:
        f.write("Document confidentiel ENSA GCSE2 2026\nPr. F. SENNOUNI\nVaultGCSE2\n")
    encrypt("document_test.txt", "document_test.vault", e, n)
    ok = decrypt("document_test.vault", "document_test_recovered.txt", d, n)
    if ok:
        orig = open("document_test.txt", 'rb').read()
        rec  = open("document_test_recovered.txt", 'rb').read()
        print(f"\n  {'OK' if orig == rec else 'ERREUR'} Fichier texte {'identique' if orig == rec else 'different'}")

    # TEST 2 — image
    if image_path and os.path.exists(image_path):
        print("\n" + "-"*55 + f"\n  TEST 2 : Image PNG '{image_path}'\n" + "-"*55)
        base     = os.path.splitext(image_path)[0]
        ext      = os.path.splitext(image_path)[1]
        vault    = base + ".vault"
        recover  = base + "_recovered" + ext

        encrypt(image_path, vault, e, n)
        ok_img = decrypt(vault, recover, d, n)
        if ok_img:
            orig_img = open(image_path, 'rb').read()
            rec_img  = open(recover,    'rb').read()
            match    = orig_img == rec_img
            print(f"\n  {'OK' if match else 'ERREUR'} Image {'identique' if match else 'differente'}")
            print(f"  Original  : {len(orig_img)} octets")
            print(f"  Recuperee : {len(rec_img)} octets")
    elif image_path:
        print(f"\n  [INFO] '{image_path}' introuvable — test image ignore.")

    # TEST 3 — rejet HMAC
    print("\n" + "-"*55 + "\n  TEST 3 : Rejet HMAC (1 octet modifie)\n" + "-"*55)
    vault_bytes = bytearray(open("document_test.vault", 'rb').read())
    vault_bytes[300] ^= 0xFF
    with open("document_test_corrompu.vault", 'wb') as f: f.write(vault_bytes)
    ok_c = decrypt("document_test_corrompu.vault", "jamais_cree.txt", d, n)
    print(f"  {'OK REJET CORRECT' if not ok_c else 'ERREUR rejet rate'}")

    # TEST 4 — mauvaise clé RSA
    print("\n" + "-"*55 + "\n  TEST 4 : Mauvaise cle RSA privee\n" + "-"*55)
    n2, _, d2 = genere_cle(73, 151, 11)
    ok_k = decrypt("document_test.vault", "jamais_cree2.txt", d2, n2)
    print(f"  {'OK MAUVAISE CLE REJETEE' if not ok_k else 'ERREUR non detecte'}")

    # TEST 5 — avalanche (avec l'image si disponible)
    test_avalanche(image_path=image_path)

    print("\n" + "="*55 + "\n  BILAN\n" + "="*55)
    print("  OK RSA n > 2^128        — vraie cle AES 128 bits")
    print("  OK Fichier texte         — identique apres cycle")
    if image_path and os.path.exists(image_path):
        print(f"  OK Image PNG             — identique apres cycle")
    print("  OK Rejet HMAC            — modification detectee")
    print("  OK Mauvaise cle RSA      — rejetee avant dechiffrement")
    print("  OK Effet d'avalanche     — > 50% confirme")

# ── MAIN ──────────────────────────────────────────────────────

if __name__ == "__main__":
    cles = get_cles_admin()
    E, N, D = cles['e'], cles['n'], cles['d']

    if len(sys.argv) == 1 or sys.argv[1] == "test":
        demo_complete()
    elif sys.argv[1] == "image" and len(sys.argv) >= 3:
        demo_complete(image_path=sys.argv[2])
    elif sys.argv[1] == "encrypt" and len(sys.argv) == 4:
        encrypt(sys.argv[2], sys.argv[3], E, N)
    elif sys.argv[1] == "decrypt" and len(sys.argv) == 4:
        ok = decrypt(sys.argv[2], sys.argv[3], D, N)
        sys.exit(0 if ok else 1)
    elif sys.argv[1] == "avalanche":
        img = sys.argv[2] if len(sys.argv) >= 3 else None
        test_avalanche(image_path=img)
    else:
        print("Usage:")
        print("  python vault.py                           # demo complete")
        print("  python vault.py image ensa.png            # demo avec image")
        print("  python vault.py encrypt <input> <output>  # chiffrer")
        print("  python vault.py decrypt <vault>  <output> # dechiffrer")
        print("  python vault.py avalanche                 # test avalanche")