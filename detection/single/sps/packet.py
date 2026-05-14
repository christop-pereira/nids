"""
packet.py - Détection de Port Scan source unique par comparaison de paquets (SPS)

Ce module détecte les scans de ports lancés depuis une seule source
en cherchant des paquets répétés avec les mêmes caractéristiques.

La clé de regroupement combine flags/payload/icmp_type + taille + intervalle,
ce qui capture la régularité mécanique d'un outil de scan automatisé :
toujours le même type de sonde, toujours la même taille, toujours le même rythme.
"""

from config import SPS_PACKET_COMPARISON_THRESHOLDS


def _tcp_packet_comparison(packets, window_label):
    """
    Détecte un scan TCP par répétition de sondes avec mêmes flags, même taille
    et même intervalle entre paquets.

    Args:
        packets (list): Tuples TCP (ts, ip_src, port_src, ip_dst, port_dst, flags, size)
        window_label (str): "short" ou "long"

    Returns:
        bool: True si le nombre de paquets répétés dépasse le seuil TCP
    """
    thresholds = SPS_PACKET_COMPARISON_THRESHOLDS[window_label]
    groups = {}

    for i in range(len(packets) - 1):
        current_packet = packets[i]
        next_packet = packets[i + 1]
        flags = current_packet[5]          # Flags TCP (ex: SYN pur pour un SYN scan)
        size = current_packet[6]           # Taille de la sonde (fixe pour un même outil)
        interval_to_next = next_packet[0] - current_packet[0]
        # Tolérance à 100ms : capture la régularité d'un scanner sans être trop strict
        rounded_interval = round(interval_to_next, 1)
        key = (flags, size, rounded_interval)

        if key not in groups:
            groups[key] = []
        groups[key].append(current_packet)

    repeated_packets = 0
    for key, group in groups.items():
        if len(group) > 1:
            repeated_packets += len(group)

    return repeated_packets >= thresholds["min_repeated_packets_tcp"]


def _udp_packet_comparison(packets, window_label):
    """
    Détecte un scan UDP par répétition de sondes avec même payload, même taille
    et même intervalle.

    Args:
        packets (list): Tuples UDP (ts, ip_src, port_src, ip_dst, port_dst, payload, size)
        window_label (str): "short" ou "long"

    Returns:
        bool: True si le nombre de paquets répétés dépasse le seuil UDP
    """
    thresholds = SPS_PACKET_COMPARISON_THRESHOLDS[window_label]
    groups = {}

    for i in range(len(packets) - 1):
        current_packet = packets[i]
        next_packet = packets[i + 1]
        payload = current_packet[5]        # Payload UDP (None si non extrait)
        size = current_packet[6]           # Taille de la sonde
        interval_to_next = next_packet[0] - current_packet[0]
        rounded_interval = round(interval_to_next, 1)   # Tolérance à 100ms
        key = (payload, size, rounded_interval)

        if key not in groups:
            groups[key] = []
        groups[key].append(current_packet)

    repeated_packets = 0
    for key, group in groups.items():
        if len(group) > 1:
            repeated_packets += len(group)

    return repeated_packets >= thresholds["min_repeated_packets_udp"]


def _icmp_packet_comparison(packets, window_label):
    """
    Détecte un scan ICMP par répétition de sondes avec même type ICMP, même taille
    et même intervalle.

    Args:
        packets (list): Tuples ICMP (ts, ip_src, ip_dst, icmp_type, size)
        window_label (str): "short" ou "long"

    Returns:
        bool: True si le nombre de paquets répétés dépasse le seuil ICMP
    """
    thresholds = SPS_PACKET_COMPARISON_THRESHOLDS[window_label]
    groups = {}

    for i in range(len(packets) - 1):
        current_packet = packets[i]
        next_packet = packets[i + 1]
        icmp_type = current_packet[3]      # Type ICMP (8 = Echo Request typique d'un scan)
        size = current_packet[4]           # Taille de la sonde ICMP
        interval_to_next = next_packet[0] - current_packet[0]
        rounded_interval = round(interval_to_next, 1)   # Tolérance à 100ms
        key = (icmp_type, size, rounded_interval)

        if key not in groups:
            groups[key] = []
        groups[key].append(current_packet)

    repeated_packets = 0
    for key, group in groups.items():
        if len(group) > 1:
            repeated_packets += len(group)

    return repeated_packets >= thresholds["min_repeated_packets_icmp"]


def sps_packet_comparison(packets, window_label, proto):
    """
    Point d'entrée unifié pour la détection SPS par comparaison de paquets.

    Dispatche vers la fonction spécifique selon le protocole.

    Args:
        packets (list): Liste de paquets du flow (format dépend du protocole)
        window_label (str): "short" ou "long"
        proto (str): "tcp", "udp" ou "icmp"

    Returns:
        bool: True si un pattern de scan est détecté
    """
    if proto == "tcp":
        return _tcp_packet_comparison(packets, window_label)
    elif proto == "udp":
        return _udp_packet_comparison(packets, window_label)
    elif proto == "icmp":
        return _icmp_packet_comparison(packets, window_label)
    else:
        return False
