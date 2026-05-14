"""
packet.py - Détection DoS par comparaison de paquets répétés (source unique)

Ce module implémente la détection de Déni de service centralisé.
La méthode repose sur l'identification de paquets "répétés" : des paquets
avec les mêmes caractéristiques (flags, payload, type ICMP) envoyés
à intervalles réguliers - signature typique d'un outil de flood automatisé.

Pour chaque protocole, les paquets sont regroupés par clé (caractéristique + intervalle arrondi).
Un groupe de 2+ paquets identiques est considéré comme "répété".
Si le total de paquets répétés dépasse le seuil, le flow est considéré suspect.
"""

from config import DOS_PACKET_COMPARISON_THRESHOLDS


def _tcp_packet_comparison(packets, window_label):
    """
    Détecte un flood TCP par répétition de paquets avec mêmes flags et même intervalle.

    Logique : on groupe les paquets par (flags, intervalle_arrondi_à_10ms).
    Si un groupe contient 2+ paquets, ils sont "répétés" (comportement automatisé).

    Args:
        packets (list): Liste triée de tuples TCP
                        (ts, ip_src, port_src, ip_dst, port_dst, flags, size)
        window_label (str): "short" ou "long"

    Returns:
        bool: True si le nombre de paquets répétés dépasse le seuil TCP
    """
    thresholds = DOS_PACKET_COMPARISON_THRESHOLDS[window_label]
    groups = {}

    for i in range(len(packets) - 1):
        current_packet = packets[i]
        next_packet = packets[i + 1]
        flags = current_packet[5]
        # Arrondi à 10ms pour regrouper des paquets envoyés à intervalles quasi-identiques
        interval_to_next = next_packet[0] - current_packet[0]
        rounded_interval = round(interval_to_next, 2)
        key = (tuple(flags), rounded_interval)

        if key not in groups:
            groups[key] = []
        groups[key].append(current_packet)

    repeated_packets = 0
    for key, group in groups.items():
        print(f"TCP : {len(group)}")
        if len(group) > 1:
            repeated_packets += len(group)
            # Optimisation : arrêt anticipé si le seuil est déjà dépassé
            if repeated_packets > thresholds["min_repeated_packets_tcp"]:
                return True

    return repeated_packets >= thresholds["min_repeated_packets_tcp"]


def _udp_packet_comparison(packets, window_label):
    """
    Détecte un flood UDP par répétition de paquets avec même payload et même intervalle.

    UDP n'ayant pas de flags, la clé de regroupement utilise le payload
    (contenu du paquet) et l'intervalle arrondi à 1ms (tolérance plus fine).

    Args:
        packets (list): Liste de tuples UDP
                        (ts, ip_src, port_src, ip_dst, port_dst, payload, size)
        window_label (str): "short" ou "long"

    Returns:
        bool: True si le nombre de paquets répétés dépasse le seuil UDP
    """
    thresholds = DOS_PACKET_COMPARISON_THRESHOLDS[window_label]
    groups = {}

    for i in range(len(packets) - 1):
        current_packet = packets[i]
        next_packet = packets[i + 1]
        payload = current_packet[5]
        interval_to_next = next_packet[0] - current_packet[0]
        rounded_interval = round(interval_to_next, 3)   # Tolérance à 1ms
        key = (payload, rounded_interval)

        if key not in groups:
            groups[key] = []
        groups[key].append(current_packet)

    repeated_packets = 0
    for key, group in groups.items():
        print(f"UDP : {len(group)}")
        if len(group) > 1:
            repeated_packets += len(group)

    return repeated_packets >= thresholds["min_repeated_packets_udp"]


def _icmp_packet_comparison(packets, window_label):
    """
    Détecte un flood ICMP par répétition de paquets avec même type et même intervalle.

    Typiquement utilisé pour détecter un Ping Flood (type 8 répété à intervalle fixe).

    Args:
        packets (list): Liste de tuples ICMP (ts, ip_src, ip_dst, icmp_type, size)
        window_label (str): "short" ou "long"

    Returns:
        bool: True si le nombre de paquets répétés dépasse le seuil ICMP
    """
    thresholds = DOS_PACKET_COMPARISON_THRESHOLDS[window_label]
    groups = {}

    for i in range(len(packets) - 1):
        current_packet = packets[i]
        next_packet = packets[i + 1]
        icmp_type = current_packet[3]
        interval_to_next = next_packet[0] - current_packet[0]
        rounded_interval = round(interval_to_next, 2)   # Tolérance à 10ms
        key = (icmp_type, rounded_interval)

        if key not in groups:
            groups[key] = []
        groups[key].append(current_packet)

    repeated_packets = 0
    for key, group in groups.items():
        print(f"ICMP : {len(group)}")
        if len(group) > 1:
            repeated_packets += len(group)

    return repeated_packets >= thresholds["min_repeated_packets_icmp"]


def dos_packet_comparison(packets, window_label, proto):
    """
    Point d'entrée unifié pour la détection DoS par comparaison de paquets.

    Dispatche vers la fonction spécifique selon le protocole.

    Args:
        packets (list): Liste de paquets du flow (format dépend du protocole)
        window_label (str): "short" ou "long"
        proto (str): "tcp", "udp" ou "icmp"

    Returns:
        bool: True si un pattern de flood DoS est détecté
    """
    if proto == "tcp":
        return _tcp_packet_comparison(packets, window_label)
    elif proto == "udp":
        return _udp_packet_comparison(packets, window_label)
    elif proto == "icmp":
        return _icmp_packet_comparison(packets, window_label)
    else:
        return False
