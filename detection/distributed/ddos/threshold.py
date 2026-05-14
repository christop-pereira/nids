"""
threshold.py - Détection par seuils DDoS (côté victime)

Première phase de détection DDoS : filtre rapide par seuils bruts avant
la corrélation de flows plus coûteuse (ddos_flow_comparison).

Un DDoS est suspecté si la victime reçoit simultanément un volume massif
de paquets provenant d'un grand nombre d'IPs sources distinctes.
Les deux conditions doivent être vraies : volume élevé ET multi-sources.
"""

from config import GLOBAL_DEST_THRESHOLDS


def is_ddos_suspicious(window_label, potential_victim, global_stats):
    """
    Détermine si une IP destination est suspecte pour une attaque DDoS.

    Critères (les deux doivent être satisfaits) :
      1. Nombre de paquets reçus >= seuil max_nb_packets
         → volume de trafic anormalement élevé sur cette IP
      2. Nombre d'IPs sources distinctes > seuil max_nb_ips
         → trafic provenant de nombreuses sources différentes = caractère distribué

    Args:
        window_label (str): "short" ou "long"
        potential_victim (dict): Statistiques de l'IP destination, avec :
            - nb_packets_main (int): Total de paquets reçus
            - nb_ips (int): Nombre d'IPs sources distinctes
        global_stats (dict): Statistiques globales de tous les flows (non utilisé)

    Returns:
        bool: True si les deux critères de suspicion DDoS sont dépassés
    """
    threshold = GLOBAL_DEST_THRESHOLDS[window_label]["ddos"]
    ip_nb_packets_in = potential_victim["nb_packets_main"]
    ip_nb_ips = potential_victim["nb_ips"]

    return (
        ip_nb_packets_in >= threshold["max_nb_packets"] and   # Volume massif
        ip_nb_ips > threshold["max_nb_ips"]                   # Sources multiples
    )
