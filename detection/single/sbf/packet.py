"""
packet.py - Détection de Brute Force par comparaison de paquets (SBF)

Ce module détecte les attaques de brute force lancées depuis une seule source
en cherchant des paquets répétés avec les mêmes caractéristiques.

Exclusivement TCP : le brute force cible des protocoles d'authentification
(SSH, RDP, FTP…) qui fonctionnent tous sur TCP.

La clé de regroupement combine flags + taille + intervalle arrondi à 100ms,
ce qui reflète la structure d'une tentative d'auth : même handshake (flags),
même payload d'authentification (taille), même cadence de l'outil.
"""

from config import SBF_PACKET_COMPARISON_THRESHOLDS


def sbf_packet_comparison(packets, window_label, proto):
    """
    Détecte un brute force source unique par répétition de paquets TCP d'authentification.

    Logique :
      Pour chaque paire de paquets consécutifs, on construit une clé :
        (flags_tcp, taille_paquet, intervalle_arrondi_à_100ms)

      Si plusieurs paquets partagent la même clé → tentatives répétées avec
      les mêmes caractéristiques = signature d'un outil de brute force automatisé.

      La tolérance à 100ms (round 0.1) est plus large que pour le DoS (10ms)
      car les outils de brute force ont une cadence moins
      précise que les outils de flood, et introduisent un délai entre tentatives.

    Exclusif TCP : retourne False immédiatement pour UDP et ICMP.

    Args:
        packets (list): Liste de tuples TCP triés par timestamp :
                        (ts, ip_src, port_src, ip_dst, port_dst, flags, size)
        window_label (str): "short" ou "long"
        proto (str): Protocole — retourne False si pas "tcp"

    Returns:
        bool: True si le nombre de paquets répétés dépasse le seuil SBF
    """
    if proto != "tcp":
        return False   # Le brute force réseau cible uniquement des services TCP

    thresholds = SBF_PACKET_COMPARISON_THRESHOLDS[window_label]
    groups = {}

    for i in range(len(packets) - 1):
        current_packet = packets[i]
        next_packet = packets[i + 1]
        flags = current_packet[5]          # Flags TCP (ex: ["SYN"] pour l'ouverture)
        size = current_packet[6]           # Taille du paquet (payload d'auth uniforme)
        interval_to_next = next_packet[0] - current_packet[0]
        # Tolérance à 100ms : plus souple que DoS (10ms) car brute force moins précis
        rounded_interval = round(interval_to_next, 1)
        # Clé : même flags + même taille + même intervalle → même type de tentative
        key = (flags, size, rounded_interval)

        if key not in groups:
            groups[key] = []
        groups[key].append(current_packet)

    # Compte les paquets faisant partie d'un groupe de 2+ (= répétés)
    repeated_packets = 0
    for key, group in groups.items():
        if len(group) > 1:
            repeated_packets += len(group)

    return repeated_packets >= thresholds["min_repeated_packets"]
