"""
=============================================================
  Module AES-ENSA — Variante personnalisée de l'AES-128
  Projet VaultGCSE2 — ENSA GCSE2 Cryptographie - DIALLO - KUNAKA - SIMPORE
  Pr. F. SENNOUNI
=============================================================
"""

# ──────────────────────────────────────────────────────────────
# 0. PARAMÈTRES PERSONNELS 
# ──────────────────────────────────────────────────────────────

# Matricule 22... : a=2 est pair (pgcd(2,256)=2≠1), corrigé en a=3 (impair)
A = 3   # dérivé du 1er chiffre du matricule (forcé impair pour bijectivité)
B = 2   # 2ème chiffre du matricule


# ──────────────────────────────────────────────────────────────
# 1. GÉNÉRATION DE LA S-BOX AFFINE  f(x) = (A*x + B) mod 256
# ──────────────────────────────────────────────────────────────

def generer_sbox(a, b):

    if a % 2 == 0:
        raise ValueError(
            f"[ERREUR] a={a} est pair → la S-Box n'est pas bijective !\n"
            "Choisissez un 'a' impair (1, 3, 5, 7, 9...)."
        )

    sbox = [(a * x + b) % 256 for x in range(256)]

    # Vérification : toutes les valeurs doivent être distinctes (permutation)
    assert len(set(sbox)) == 256, "S-Box non bijective — vérifiez la valeur de 'a'"
    return sbox


def generer_sbox_inverse(sbox):
    """
    Génère la S-Box inverse pour le déchiffrement.
    Si sbox[x] = y, alors inv_sbox[y] = x.
    """
    inv_sbox = [0] * 256
    for x, y in enumerate(sbox):
        inv_sbox[y] = x
    return inv_sbox


# Génération au chargement du module
SBOX     = generer_sbox(A, B)
INV_SBOX = generer_sbox_inverse(SBOX)


# ──────────────────────────────────────────────────────────────
# 2. MULTIPLICATION DANS GF(2^8) 
# ──────────────────────────────────────────────────────────────

def xtime(a):
    """
    Multiplication par 2 dans GF(2^8).
    Décalage à gauche + XOR avec 0x1B si le bit de poids fort est 1.
    Ceci correspond à la réduction modulo le polynôme irréductible
    x^8 + x^4 + x^3 + x + 1 (polynôme standard de l'AES).
    """
    if a & 0x80:  # bit 7 à 1 → risque de débordement
        return ((a << 1) ^ 0x1B) & 0xFF
    else:
        return (a << 1) & 0xFF


def gmul(a, b):
    """
    Multiplication de deux octets dans GF(2^8) par la méthode
    des multiplications successives (algorithme du paysan russe).
    Utilisé par MixColumns pour les coefficients 1, 2, 3.
    """
    result = 0
    for _ in range(8):
        if b & 1:           # si bit de poids faible de b = 1
            result ^= a     # on ajoute a (XOR = addition dans GF)
        a = xtime(a)        # on double a
        b >>= 1             # on passe au bit suivant de b
    return result


# ──────────────────────────────────────────────────────────────
# 3. ÉTAPE 1 : SubBytes — Substitution octet par octet
# ──────────────────────────────────────────────────────────────

def sub_bytes(state, inverse=False):
    """
    Remplace chaque octet de la matrice 4x4 par sa valeur dans la S-Box.
    - Chiffrement  : utilise SBOX
    - Déchiffrement: utilise INV_SBOX
    
    'state' est une liste de 4 listes de 4 octets (matrice 4×4).
    """
    box = INV_SBOX if inverse else SBOX
    return [[box[state[r][c]] for c in range(4)] for r in range(4)]


# ──────────────────────────────────────────────────────────────
# 4. ÉTAPE 2 : ShiftRows — Décalage cyclique des lignes
# ──────────────────────────────────────────────────────────────

def shift_rows(state, inverse=False):
    """
    Décale chaque ligne de la matrice vers la gauche (chiffrement)
    ou vers la droite (déchiffrement) :
      - Ligne 0 : décalage de 0
      - Ligne 1 : décalage de 1
      - Ligne 2 : décalage de 2
      - Ligne 3 : décalage de 3
    
    Ceci assure la DIFFUSION horizontale (principe de Shannon).
    """
    new_state = [row[:] for row in state]  # copie profonde

    for r in range(1, 4):
        if not inverse:
            new_state[r] = state[r][r:] + state[r][:r]      # décalage gauche
        else:
            new_state[r] = state[r][4-r:] + state[r][:4-r]  # décalage droite

    return new_state


# ──────────────────────────────────────────────────────────────
# 5. ÉTAPE 3 : MixColumns — Brassage des colonnes
# ──────────────────────────────────────────────────────────────

def mix_single_column(col):
    """
    Multiplie une colonne de 4 octets par la matrice de MixColumns :
    
        | 2 3 1 1 |
        | 1 2 3 1 |
        | 1 1 2 3 |
        | 3 1 1 2 |
    
    Cette multiplication est faite dans GF(2^8).
    C'est la DIFFUSION verticale (principe de Shannon).
    """
    s0, s1, s2, s3 = col
    return [
        gmul(2, s0) ^ gmul(3, s1) ^ s2        ^ s3,
        s0          ^ gmul(2, s1) ^ gmul(3, s2) ^ s3,
        s0          ^ s1          ^ gmul(2, s2) ^ gmul(3, s3),
        gmul(3, s0) ^ s1          ^ s2          ^ gmul(2, s3),
    ]


def mix_single_column_inv(col):
    """
    Matrice inverse de MixColumns pour le déchiffrement :
    
        | 14  11  13   9 |
        |  9  14  11  13 |
        | 13   9  14  11 |
        | 11  13   9  14 |
    """
    s0, s1, s2, s3 = col
    return [
        gmul(14, s0) ^ gmul(11, s1) ^ gmul(13, s2) ^ gmul(9,  s3),
        gmul(9,  s0) ^ gmul(14, s1) ^ gmul(11, s2) ^ gmul(13, s3),
        gmul(13, s0) ^ gmul(9,  s1) ^ gmul(14, s2) ^ gmul(11, s3),
        gmul(11, s0) ^ gmul(13, s1) ^ gmul(9,  s2) ^ gmul(14, s3),
    ]


def mix_columns(state, inverse=False):
    """
    Applique MixColumns sur chacune des 4 colonnes de la matrice.
    On travaille colonne par colonne (les 4 lignes d'une même colonne).
    """
    new_state = [[0]*4 for _ in range(4)]

    for c in range(4):
        col = [state[r][c] for r in range(4)]  # extraire la colonne c
        col_mixed = mix_single_column_inv(col) if inverse else mix_single_column(col)
        for r in range(4):
            new_state[r][c] = col_mixed[r]     # remettre en place

    return new_state


# ──────────────────────────────────────────────────────────────
# 6. ÉTAPE 4 : AddRoundKey — XOR avec la sous-clé du tour
# ──────────────────────────────────────────────────────────────

def add_round_key(state, round_key):
    """
    XOR bit à bit entre la matrice d'état et la sous-clé du tour.
    C'est l'opération fondamentale du cours : (A ⊕ K) ⊕ K = A
    
    'round_key' est une liste de 16 octets (4 mots de 4 octets).
    On la remet en forme 4×4 pour le XOR.
    """
    # Convertir la round_key (liste plate de 16 octets) en matrice 4×4
    key_matrix = [[round_key[r + 4*c] for c in range(4)] for r in range(4)]

    return [[state[r][c] ^ key_matrix[r][c] for c in range(4)] for r in range(4)]


# ──────────────────────────────────────────────────────────────
# 7. KEY EXPANSION — Génération des 11 sous-clés
# ──────────────────────────────────────────────────────────────

# Constantes de ronde (Rcon) 
RCON = [
    0x01, 0x02, 0x04, 0x08, 0x10,
    0x20, 0x40, 0x80, 0x1B, 0x36
]


def sub_word(word):
    """
    Applique la S-Box AES-ENSA sur les 4 octets d'un mot (utilisé dans KeyExpansion).
    """
    return [SBOX[b] for b in word]


def rot_word(word):
    """
    Rotation cyclique d'un mot de 4 octets vers la gauche.
    [a0, a1, a2, a3] → [a1, a2, a3, a0]
    """
    return word[1:] + word[:1]


def key_expansion(key):
    """
    Génère les 11 sous-clés (round keys) à partir de la clé initiale de 128 bits.
    
    - La clé initiale fait 16 octets = 4 mots de 4 octets.
    - On génère 44 mots au total (11 round keys × 4 mots).
    - Chaque nouveau mot dépend du précédent et du mot 4 positions avant.
    
    Retourne une liste de 11 round_keys, chacune étant une liste de 16 octets.
    """
    if len(key) != 16:
        raise ValueError("La clé doit faire exactement 16 octets (128 bits).")

    # Initialisation : les 4 premiers mots = la clé elle-même
    W = [list(key[i*4:(i+1)*4]) for i in range(4)]

    # Génération des 40 mots suivants
    for i in range(4, 44):
        temp = W[i - 1][:]  # copie du mot précédent

        if i % 4 == 0:
            # Transformation spéciale tous les 4 mots :
            temp = sub_word(rot_word(temp))  # RotWord puis SubWord
            temp[0] ^= RCON[i // 4 - 1]     # XOR avec la constante de ronde

        # Nouveau mot = mot 4 positions avant XOR temp
        new_word = [W[i - 4][j] ^ temp[j] for j in range(4)]
        W.append(new_word)

    # Regrouper les 44 mots en 11 round_keys de 16 octets chacune
    round_keys = []
    for i in range(11):
        rk = []
        for j in range(4):
            rk.extend(W[i*4 + j])
        round_keys.append(rk)

    return round_keys


# ──────────────────────────────────────────────────────────────
# 8. CHIFFREMENT D'UN BLOC (16 octets)
# ──────────────────────────────────────────────────────────────

def bytes_to_state(block):
    """
    Convertit 16 octets en matrice d'état 4×4 (colonne par colonne).
    Ordre AES : bloc[0]=state[0][0], bloc[1]=state[1][0], etc.
    """
    return [[block[r + 4*c] for c in range(4)] for r in range(4)]


def state_to_bytes(state):
    """
    Reconvertit la matrice 4×4 en liste de 16 octets (colonne par colonne).
    """
    return [state[r][c] for c in range(4) for r in range(4)]


def afficher_state(state, label=""):
    """
    Affiche la matrice d'état de manière lisible pour le fichier de trace.
    """
    if label:
        print(f"\n{'='*40}")
        print(f"  {label}")
        print(f"{'='*40}")
    for r in range(4):
        print("  " + " ".join(f"{state[r][c]:02X}" for c in range(4)))


def chiffrer_bloc(block, round_keys, verbose=False):
    """
    Chiffre un seul bloc de 16 octets avec AES-ENSA (10 rounds).
    
    Si verbose=True, affiche la matrice d'état après chaque étape
    (utile pour générer le fichier de trace).
    
    Structure d'un round AES-ENSA :
        1. SubBytes  (S-Box affine personnalisée)
        2. ShiftRows
        3. MixColumns (sauf au dernier round)
        4. AddRoundKey
    """
    state = bytes_to_state(block)

    if verbose:
        afficher_state(state, "État INITIAL (avant Round 0)")

    # Round 0 : uniquement AddRoundKey avec la clé initiale
    state = add_round_key(state, round_keys[0])

    if verbose:
        afficher_state(state, "État après AddRoundKey initial (Round 0)")

    # Rounds 1 à 9 : les 4 transformations complètes
    for rnd in range(1, 10):
        state = sub_bytes(state)
        state = shift_rows(state)
        state = mix_columns(state)
        state = add_round_key(state, round_keys[rnd])

        if verbose and rnd == 1:
            afficher_state(state, f"État après ROUND 1 (SubBytes→ShiftRows→MixColumns→AddRoundKey)")

    # Round 10 (final) : pas de MixColumns
    state = sub_bytes(state)
    state = shift_rows(state)
    state = add_round_key(state, round_keys[10])

    if verbose:
        afficher_state(state, "État après ROUND 10 (état FINAL chiffré)")

    return state_to_bytes(state)


def dechiffrer_bloc(block, round_keys, verbose=False):
    """
    Déchiffre un seul bloc de 16 octets avec AES-ENSA (10 rounds inverses).
    
    L'ordre inverse des opérations :
        1. AddRoundKey
        2. InvShiftRows
        3. InvSubBytes
        4. InvMixColumns (sauf au premier round inverse)
    """
    state = bytes_to_state(block)

    # Round 10 inverse
    state = add_round_key(state, round_keys[10])
    state = shift_rows(state, inverse=True)
    state = sub_bytes(state, inverse=True)

    # Rounds 9 à 1 inverses
    for rnd in range(9, 0, -1):
        state = add_round_key(state, round_keys[rnd])
        state = mix_columns(state, inverse=True)
        state = shift_rows(state, inverse=True)
        state = sub_bytes(state, inverse=True)

    # Round 0 inverse
    state = add_round_key(state, round_keys[0])

    return state_to_bytes(state)


# ──────────────────────────────────────────────────────────────
# 9. MODE CBC — Chiffrement de données longues
# ──────────────────────────────────────────────────────────────

def pkcs7_pad(data, block_size=16):
    """
    Ajoute le padding PKCS#7 pour que len(data) soit un multiple de block_size.
    
    Exemple (cours) : si 13 octets → on ajoute 3 octets valant 0x03 chacun.
    Si les données font déjà un multiple de 16 → on ajoute un bloc entier (0x10).
    """
    pad_len = block_size - (len(data) % block_size)
    return data + bytes([pad_len] * pad_len)


def pkcs7_unpad(data):
    """
    Retire le padding PKCS#7 après déchiffrement.
    Vérifie la validité du padding (protection contre les attaques padding oracle).
    """
    if not data:
        raise ValueError("Données vides — impossible de retirer le padding.")

    pad_len = data[-1]

    if pad_len == 0 or pad_len > 16:
        raise ValueError(f"Padding invalide : valeur {pad_len} hors plage [1, 16].")

    # Vérifier que tous les octets de padding ont la bonne valeur
    if data[-pad_len:] != bytes([pad_len] * pad_len):
        raise ValueError("Padding PKCS#7 corrompu — fichier modifié ou mauvaise clé.")

    return data[:-pad_len]


def chiffrer_cbc(plaintext, key, iv):
    """
    Chiffre des données de longueur quelconque en mode CBC.
    
    Principe du cours :
        C_i = AES_ENSA( M_i XOR C_{i-1} )
        C_0 = IV  (vecteur d'initialisation aléatoire)
    
    Paramètres :
        plaintext : bytes — données à chiffrer
        key       : bytes de 16 octets — clé AES-128
        iv        : bytes de 16 octets — vecteur d'initialisation aléatoire
    
    Retourne : bytes — données chiffrées (sans padding visible)
    """
    round_keys = key_expansion(list(key))
    padded     = pkcs7_pad(plaintext)
    ciphertext = b""
    prev_block = list(iv)  # le premier "bloc précédent" est l'IV

    for i in range(0, len(padded), 16):
        bloc_clair   = list(padded[i:i+16])
        # XOR avec le bloc chiffré précédent (ou l'IV pour le 1er bloc)
        bloc_xored   = [bloc_clair[j] ^ prev_block[j] for j in range(16)]
        bloc_chiffre = chiffrer_bloc(bloc_xored, round_keys)
        ciphertext  += bytes(bloc_chiffre)
        prev_block   = bloc_chiffre  # ce bloc devient le "précédent"

    return ciphertext


def dechiffrer_cbc(ciphertext, key, iv):
    """
    Déchiffre des données en mode CBC et retire le padding PKCS#7.
    
    Principe (inverse du CBC) :
        M_i = AES_ENSA_inv( C_i ) XOR C_{i-1}
        C_0 = IV
    """
    round_keys = key_expansion(list(key))
    plaintext  = b""
    prev_block = list(iv)

    for i in range(0, len(ciphertext), 16):
        bloc_chiffre = list(ciphertext[i:i+16])
        bloc_dechif  = dechiffrer_bloc(bloc_chiffre, round_keys)
        # XOR avec le bloc chiffré précédent pour retrouver le clair
        bloc_clair   = bytes([bloc_dechif[j] ^ prev_block[j] for j in range(16)])
        plaintext   += bloc_clair
        prev_block   = bloc_chiffre  # avancer le pointeur

    return pkcs7_unpad(plaintext)


# ──────────────────────────────────────────────────────────────
# 10. GÉNÉRATION DU FICHIER DE TRACE (pour trace_test.txt)
# ──────────────────────────────────────────────────────────────

def generer_trace(message_hex, key_hex, output_file="trace_test.txt"):
    
    import sys

    message_bytes = bytes.fromhex(message_hex)
    key_bytes     = bytes.fromhex(key_hex)

    # Padding du message pour faire exactement 16 octets si nécessaire
    message_padded = pkcs7_pad(message_bytes)
    bloc           = list(message_padded[:16])

    round_keys = key_expansion(list(key_bytes))

    # Rediriger print vers le fichier ET la console
    import io
    buffer = io.StringIO()

    original_stdout = sys.stdout

    class Tee:
        def write(self, msg):
            original_stdout.write(msg)
            buffer.write(msg)
        def flush(self):
            original_stdout.flush()

    sys.stdout = Tee()

    print("=" * 60)
    print("  TRACE DE CHIFFREMENT AES-ENSA")
    print(f"  Message   : {message_hex}")
    print(f"  Message   : '{bytes.fromhex(message_hex).decode('ascii', errors='replace')}'")
    print(f"  Clé (hex) : {key_hex}")
    print(f"  a = {A}, b = {B} ")
    print("=" * 60)

    # Affichage de la S-Box complète
    print("\n[ S-BOX PERSONNALISÉE  f(x) = ({}*x + {}) mod 256 ]".format(A, B))
    print("     " + "  ".join(f"{j:2X}" for j in range(16)))
    print("    " + "----" * 16)
    for row in range(16):
        vals = "  ".join(f"{SBOX[row*16 + col]:02X}" for col in range(16))
        print(f"  {row:X}x | {vals}")

    # Chiffrement avec affichage verbeux
    print("\n\n[ DÉROULEMENT DU CHIFFREMENT ]")
    chiffrer_bloc(bloc, round_keys, verbose=True)

    sys.stdout = original_stdout

    # Sauvegarde dans le fichier
    with open(output_file, "w", encoding="utf-8") as f:
        f.write(buffer.getvalue())

    print(f"\n✓ Fichier de trace sauvegardé : {output_file}")


# ──────────────────────────────────────────────────────────────
# 11. TEST RAPIDE — Vérifie que chiffrement/déchiffrement est cohérent
# ──────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import os

    print("=" * 60)
    print("  TEST DE COHÉRENCE AES-ENSA")
    print("=" * 60)

    # Clé de test (16 octets = 128 bits)
    key = bytes([0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6,
                 0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF, 0x4F, 0x3C])

    # IV aléatoire (16 octets)
    iv = os.urandom(16)

    # Message de test
    message = b"Bonjour ENSA 2026 !"

    print(f"\nMessage original   : {message}")
    print(f"Clé (hex)          : {key.hex().upper()}")
    print(f"IV  (hex)          : {iv.hex().upper()}")

    # Chiffrement
    chiffre = chiffrer_cbc(message, key, iv)
    print(f"\nChiffré (hex)      : {chiffre.hex().upper()}")

    # Déchiffrement
    dechiffre = dechiffrer_cbc(chiffre, key, iv)
    print(f"Déchiffré          : {dechiffre}")

    # Vérification
    if dechiffre == message:
        print("\n✓ TEST RÉUSSI — Le chiffrement et le déchiffrement sont cohérents.")
    else:
        print("\n✗ ERREUR — Le déchiffrement ne correspond pas au message original !")

    # Génération du fichier de trace obligatoire
    print("\n" + "=" * 60)
    print("  GÉNÉRATION DU FICHIER DE TRACE")
    print("=" * 60)

    MSG_TEST = "47435345325F32303236"   # "GCSE2_2026" en hex
    KEY_TEST = key.hex()

    generer_trace(MSG_TEST, KEY_TEST, output_file="trace_test.txt")