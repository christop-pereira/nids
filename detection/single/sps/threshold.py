"""
threshold.py - Détection par seuils SPS (côté source)

Première phase de détection de port scan source unique : filtre rapide
avant la comparaison de paquets (sps_packet_comparison).

Un SPS est suspecté si une IP source contacte un grand nombre de ports
différents avec une distribution équilibrée du volume entre ces ports.
Cette uniformité distingue le scan (un paquet par port, tous les ports
traités également) du trafic normal (quelques ports dominants) et du
brute force (un seul port ciblé massivement).

Non applicable à ICMP (pas de ports).
"""

from config import GLOBAL_SOURCE_THRESHOLDS, BRUTE_FORCE_PORTS


def is_sps_suspicious(window_label, potential_attacker, proto):
    """
    Détermine si une IP source est suspecte pour un port scan (SPS).

    Non applicable à ICMP (retourne False immédiatement).

    Garde-fou anti-confusion SPS/SBF :
      Si le trafic est majoritairement concentré sur des ports brute force
      (cumulative_bf_share > 0.7), c'est du SBF, pas du SPS → retourne False.
      Cela évite de déclencher une alerte SPS pour un brute force multi-port.

    Critères (les deux doivent être satisfaits) :
      1. Nombre de ports destination distincts > seuil max_nb_ports
         → l'IP source contacte un grand nombre de ports = comportement de scan
      2. Distribution équilibrée du volume entre les ports sources (cond_uniform)
         → chaque port reçoit à peu près le même volume = scan systématique,
            pas un flood ciblé sur un seul port

    La condition d'uniformité est calculée sur les parts de volume par port source
    (volume_per_sec_port_shares) : si au moins la moitié des valeurs sont proches
    de la première valeur de référence (tolérance 20%), le trafic est considéré uniforme.

    Args:
        window_label (str): "short" ou "long"
        potential_attacker (dict): Statistiques de l'IP source, avec :
            - nb_sec_ports (int): Nombre de ports destination distincts
            - volume_per_sec_port_shares (dict): Part du volume par port destination
            - volume_per_main_port (Counter): Volume par port source
            - volume_per_main_port_shares (dict): Part du volume par port source
        proto (str): Protocole — retourne False si "icmp"

    Returns:
        bool: True si les critères de suspicion SPS sont satisfaits
    """
    if proto == "icmp":
        return False   # ICMP n'a pas de ports → pas de port scan possible

    threshold = GLOBAL_SOURCE_THRESHOLDS[window_label]["sps"]
    ip_nb_sec_ports = potential_attacker["nb_sec_ports"]
    shares = potential_attacker["volume_per_sec_port_shares"]
    volume_per_main_port = potential_attacker["volume_per_main_port"]

    # Garde-fou : si le trafic est concentré sur des ports brute force → SBF, pas SPS
    bf_ports_hit = [p for p in volume_per_main_port if p in BRUTE_FORCE_PORTS]
    cumulative_bf_share = sum(
        potential_attacker["volume_per_main_port_shares"].get(p, 0) for p in bf_ports_hit
    )
    if cumulative_bf_share > 0.7:
        return False   # Trafic trop concentré sur ports BF → laisser SBF le gérer

    def close(a, b, tol=0.2):
        """Vérifie si deux valeurs sont proches avec une tolérance relative."""
        if max(a, b) == 0:
            return True
        return abs(a - b) / max(a, b) <= tol

    values = list(shares.values())

    # Critère 1 : assez de ports distincts contactés
    cond_ports = ip_nb_sec_ports > threshold["max_nb_ports"]

    # Critère 2 : uniformité de la distribution (scan = tous les ports traités pareil)
    ref = values[0]
    close_count = sum(1 for v in values if close(ref, v))
    cond_uniform = close_count >= len(values) / 2

    return cond_ports and cond_uniform
