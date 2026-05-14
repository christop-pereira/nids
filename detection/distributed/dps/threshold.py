"""
threshold.py - Détection par seuils DPS (côté victime)

Première phase de détection de port scan distribué : filtre rapide par seuils
avant la corrélation de flows plus coûteuse (dps_flow_comparison).

Un DPS est suspecté quand une victime reçoit des connexions depuis de nombreuses
IPs sources différentes, sur de nombreux ports différents, avec une distribution
de volume équilibrée entre ces ports - signature d'un scan horizontal réparti
entre plusieurs sondes.
"""

from config import GLOBAL_DEST_THRESHOLDS


def is_dps_suspicious(window_label, potential_victim, global_stats, proto):
    """
    Détermine si une IP destination est suspecte pour un port scan distribué (DPS).

    Non applicable à ICMP (ICMP n'a pas de ports, donc pas de scan de ports).

    Critères (les trois doivent être satisfaits) :
      1. Nombre d'IPs sources > seuil max_nb_ips
         → plusieurs sondes distinctes = caractère distribué
      2. Nombre de ports ciblés > seuil max_nb_ports
         → de nombreux ports sont sondés = comportement de scan
      3. Distribution équilibrée du volume entre les ports sources (cond_uniform)
         → chaque sonde envoie à peu près le même volume, sans port dominant
         → signature d'un scan systématique plutôt que d'un flood ciblé

    La condition d'uniformité (cond_uniform) est calculée ainsi :
      - On prend la première valeur de shares comme référence
      - On compte combien d'autres valeurs sont "proches" (tolérance 20%)
      - Si au moins la moitié des valeurs sont proches → distribution uniforme

    Args:
        window_label (str): "short" ou "long"
        potential_victim (dict): Statistiques de l'IP destination, avec :
            - nb_main_ports (int): Nombre de ports de destination distincts
            - nb_ips (int): Nombre d'IPs sources distinctes
            - volume_per_sec_port_shares (dict): Part du volume par port source
        global_stats (dict): Statistiques globales
        proto (str): Protocole — retourne False si "icmp"

    Returns:
        bool: True si les trois critères de suspicion DPS sont satisfaits
    """
    if proto == "icmp":
        return False   # ICMP n'a pas de ports → pas de port scan possible

    threshold = GLOBAL_DEST_THRESHOLDS[window_label]["dps"]
    ip_nb_ports = potential_victim["nb_main_ports"]
    ip_nb_ips = potential_victim["nb_ips"]
    shares = potential_victim["volume_per_sec_port_shares"]

    def close(a, b, tol=0.2):
        """Vérifie si deux valeurs sont proches avec une tolérance relative."""
        if max(a, b) == 0:
            return True
        return abs(a - b) / max(a, b) <= tol

    values = list(shares.values())

    # Calcul de l'uniformité : on vérifie que les volumes par port sont équilibrés
    # (chaque sonde contribue à peu près autant → pas de port dominant = scan, pas flood)
    ref = values[0]
    close_count = 0
    for v in values:
        if close(ref, v):
            close_count += 1

    # Uniforme si au moins la moitié des ports ont un volume proche de la référence
    cond_uniform = close_count >= len(values) / 2

    return (
        ip_nb_ips > threshold["max_nb_ips"] and        # Sources multiples (distribué)
        ip_nb_ports > threshold["max_nb_ports"] and    # Ports multiples ciblés (scan)
        cond_uniform                                   # Volume équilibré (pas de flood ciblé)
    )
