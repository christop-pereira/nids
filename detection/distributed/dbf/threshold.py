"""
threshold.py - Détection par seuils : identification des IPs suspectes

Ce module implémente la première phase de détection : le filtrage par seuils.

Il analyse les statistiques agrégées (nb paquets, nb IPs, ports ciblés) et
identifie les IPs dépassant les limites configurées, avant la phase de
corrélation plus fine (correlation.py).
"""

from config import GLOBAL_DEST_THRESHOLDS, BRUTE_FORCE_PORTS


def is_dbf_suspicious(window_label, potential_victim, proto):
    """
    Détermine si une IP destination est suspecte pour une attaque de brute force distribué (DBF).

    Critères (les deux doivent être satisfaits) :
      1. Nombre d'IPs sources distinctes > seuil max_nb_ips
         → plusieurs attaquants distincts = caractère distribué
      2. Part cumulée du trafic vers des ports brute force > seuil max_top_port_share
         → la majorité du trafic cible des ports d'authentification (SSH, RDP, FTP…)

    Ne s'applique qu'au protocole TCP (le brute force réseau est TCP-only).

    Args:
        window_label (str): "short" ou "long"
        potential_victim (dict): Statistiques de l'IP destination, avec les clés :
            - nb_ips (int): Nombre d'IPs sources distinctes
            - volume_per_main_port (Counter): Volume de trafic par port destination
            - volume_per_main_port_shares (dict): Part relative par port destination
        proto (str): Protocole (retourne False si pas TCP)

    Returns:
        bool: True si l'IP satisfait les deux critères de suspicion DBF
    """
    if proto != "tcp":
        return False   # Le brute force réseau est exclusivement TCP

    threshold = GLOBAL_DEST_THRESHOLDS[window_label]["dbf"]
    ip_nb_ips = potential_victim["nb_ips"]
    ip_volume_per_main_port = potential_victim["volume_per_main_port"]
    ip_volume_per_main_port_shares = potential_victim["volume_per_main_port_shares"]

    # Identifie les ports brute force effectivement ciblés dans ce flow
    bf_ports_hit = [port for port in ip_volume_per_main_port if port in BRUTE_FORCE_PORTS]

    # Cumule la part de trafic sur ces ports
    cumulative_bf_share = sum(ip_volume_per_main_port_shares.get(port, 0) for port in bf_ports_hit)

    return (
        ip_nb_ips > threshold["max_nb_ips"] and           # Critère distribué
        cumulative_bf_share > threshold["max_top_port_share"]  # Critère brute force
    )
