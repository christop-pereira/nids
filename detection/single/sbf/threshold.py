"""
threshold.py - Détection par seuils SBF (côté source)

Première phase de détection de brute force source unique : filtre rapide
avant la comparaison de paquets (sbf_packet_comparison).

Un SBF est suspecté si une IP source envoie un volume significatif de paquets
concentrés sur des ports typiquement ciblés par le brute force (SSH, RDP, FTP…).
Les deux conditions doivent être vraies : volume suffisant ET concentration sur
des ports d'authentification connus.

Exclusivement TCP (les protocoles d'authentification brute-forcés sont tous TCP).
"""

from config import GLOBAL_SOURCE_THRESHOLDS, BRUTE_FORCE_PORTS


def is_sbf_suspicious(window_label, potential_attacker, proto):
    """
    Détermine si une IP source est suspecte pour une attaque de brute force (SBF).

    Non applicable à UDP et ICMP (brute force = authentification = TCP uniquement).

    Critères (les deux doivent être satisfaits) :
      1. Nombre de paquets envoyés > seuil max_nb_packets
         → volume suffisant pour du brute force (pas juste quelques connexions)
      2. Part cumulée du trafic vers des ports brute force > seuil max_top_port_share
         → la majorité du trafic est concentrée sur des ports d'auth connus
         (SSH:22, RDP:3389, FTP:21, Telnet:23, SMTP:25/587, SMB:445, VNC:5900)

    Le critère de concentration sur les ports brute force est crucial pour
    distinguer le brute force d'un simple DoS TCP : un DoS peut cibler n'importe
    quel port, le brute force cible spécifiquement les services d'authentification.

    Args:
        window_label (str): "short" ou "long"
        potential_attacker (dict): Statistiques de l'IP source, avec :
            - nb_packets_main (int): Total de paquets envoyés
            - volume_per_sec_port (Counter): Volume par port destination
            - volume_per_sec_port_shares (dict): Part relative par port destination
        proto (str): Protocole — retourne False si pas "tcp"

    Returns:
        bool: True si les deux critères de suspicion SBF sont satisfaits
    """
    if proto != "tcp":
        return False   # Le brute force réseau est exclusivement TCP

    threshold = GLOBAL_SOURCE_THRESHOLDS[window_label]["sbf"]
    ip_nb_packets_in = potential_attacker["nb_packets_main"]
    ip_volume_per_sec_port = potential_attacker["volume_per_sec_port"]
    ip_volume_per_sec_port_shares = potential_attacker["volume_per_sec_port_shares"]

    # Identifie les ports brute force effectivement présents dans le trafic de cette IP
    bf_ports_hit = []
    for port in ip_volume_per_sec_port:
        if port in BRUTE_FORCE_PORTS:
            bf_ports_hit.append(port)

    # Cumule la part de trafic dirigée vers des ports brute force
    # (peut couvrir plusieurs ports : ex: SSH + RDP simultanément)
    cumulative_bf_share = 0
    for port in bf_ports_hit:
        cumulative_bf_share += ip_volume_per_sec_port_shares.get(port, 0)

    return (
        ip_nb_packets_in > threshold["max_nb_packets"] and           # Volume suffisant
        cumulative_bf_share > threshold["max_top_port_share"]        # Concentration sur ports BF
    )
