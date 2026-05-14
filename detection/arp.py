"""
arp.py - Détection d'ARP spoofing (attaque MITM)

Ce module maintient une table ARP de référence (IP → MAC) et détecte
toute tentative de falsification : si une IP annonce une MAC différente
de celle enregistrée, c'est un indicateur fort d'ARP spoofing.

L'ARP spoofing est la base de nombreuses attaques Man-in-the-Middle (MITM) :
l'attaquant empoisonne la table ARP de la victime pour intercepter son trafic.
"""

from config import ARP_TABLE
from core.alerts import raise_alert


def check_arp(ip, mac):
    """
    Vérifie la cohérence de l'annonce ARP reçue.

    Logique :
      - Si l'IP est inconnue → on l'enregistre (premier contact)
      - Si l'IP est connue et que la MAC correspond → rien à signaler
      - Si l'IP est connue mais que la MAC a changé → ARP spoofing détecté !

    Args:
        ip (str): IP source de la trame ARP (ex: "192.168.1.1")
        mac (str): MAC source de la trame ARP (ex: "aa:bb:cc:dd:ee:ff")
    """
    if ip in ARP_TABLE:
        if ARP_TABLE[ip] != mac:
            # Changement de MAC pour une IP connue → ARP spoofing probable
            print(f"[MITM] ARP spoofing détecté : {ip} était {ARP_TABLE[ip]}, maintenant {mac}")
            raise_alert("mitm")

    # Met à jour ou enregistre la correspondance IP → MAC
    ARP_TABLE[ip] = mac
