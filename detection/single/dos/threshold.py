"""
threshold.py - Détection par seuils DoS (côté source)

Première phase de détection d'un déni de service centralisé : filtre rapide
par seuil de volume avant la comparaison de paquets plus coûteuse (dos_packet_comparison).

Un DoS est suspecté si une seule IP source envoie un nombre anormalement élevé
de paquets vers une ou plusieurs destinations. C'est le critère le plus simple :
volume brut, sans analyse de la structure des paquets.
"""

from config import GLOBAL_SOURCE_THRESHOLDS


def is_dos_suspicious(window_label, potential_attacker, global_stats):
    """
    Détermine si une IP source est suspecte pour une attaque DoS.

    Critère unique :
      - Nombre de paquets envoyés >= seuil max_nb_packets
        → volume de trafic sortant anormalement élevé depuis cette IP

    C'est un filtre large intentionnellement permissif : le but est d'écarter
    rapidement les IPs inoffensives et de passer les suspects à la phase
    de corrélation de paquets (dos_packet_comparison) qui vérifiera si
    les paquets sont réellement répétitifs (pattern de flood).

    Args:
        window_label (str): "short" ou "long"
        potential_attacker (dict): Statistiques de l'IP source, avec :
            - nb_packets_main (int): Total de paquets envoyés par cette IP
        global_stats (dict): Statistiques globales

    Returns:
        bool: True si le volume de paquets dépasse le seuil DoS
    """
    threshold = GLOBAL_SOURCE_THRESHOLDS[window_label]["dos"]
    ip_nb_packets_in = potential_attacker["nb_packets_main"]

    return ip_nb_packets_in >= threshold["max_nb_packets"]