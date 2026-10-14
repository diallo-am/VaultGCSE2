import sys
import os

def corrompre(input_vault, output_vault=None):
    if not os.path.exists(input_vault):
        print(f"[ERREUR] Fichier '{input_vault}' introuvable.")
        return

    if output_vault is None:
        base = os.path.splitext(input_vault)[0]
        output_vault = base + "_corrompu.vault"

    with open(input_vault, 'rb') as f:
        data = bytearray(f.read())

    # Structure : Header(256) + IV(16) + Payload(...) + Footer(32)
    # On modifie l'octet 300 — bien dans le Payload (après 256+16=272)
    octet_cible        = 300
    valeur_avant       = data[octet_cible]
    data[octet_cible] ^= 0xFF   # inverser tous les bits de cet octet
    valeur_apres       = data[octet_cible]

    with open(output_vault, 'wb') as f:
        f.write(data)

    print(f"Fichier original   : {input_vault}  ({len(data)} octets)")
    print(f"Fichier corrompu   : {output_vault}")
    print(f"Octet modifié      : position {octet_cible} (dans le Payload)")
    print(f"Valeur avant       : 0x{valeur_avant:02X}  ({valeur_avant})")
    print(f"Valeur après       : 0x{valeur_apres:02X}  ({valeur_apres})")
    print(f"\n-> Lancez maintenant :")
    print(f"   python vault.py decrypt {output_vault} test_recovered.png")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage : python corrompre_vault.py <fichier.vault>")
        print("Exemple : python corrompre_vault.py ensa.vault")
    else:
        corrompre(sys.argv[1])