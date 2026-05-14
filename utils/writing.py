"""
writing.py - Écriture des paquets capturés dans les structures d'événements en mémoire

Ce module stocke chaque paquet réseau dans deux index complémentaires :
  - BY_SOURCE : indexé par (IP source, port) → permet d'analyser le comportement d'un attaquant
  - BY_DEST   : indexé par (IP destination, port) → permet d'analyser ce que reçoit une victime

Chaque flow est limité à MAX_FLOW_SIZE paquets pour éviter une saturation.
"""

import time
from config import (
    ICMP_EVENTS_BY_SOURCE, ICMP_EVENTS_BY_DEST,
    TCP_EVENTS_BY_SOURCE, TCP_EVENTS_BY_DEST,
    UDP_EVENTS_BY_SOURCE, UDP_EVENTS_BY_DEST,
    MAX_FLOW_SIZE
)


def _is_flow_full(flow):
    """
    Vérifie si un flow a atteint sa capacité maximale.

    Args:
        flow (deque): File de paquets d'un échange donné

    Returns:
        bool: True si le flow contient déjà MAX_FLOW_SIZE paquets
    """
    return len(flow) >= MAX_FLOW_SIZE


def write_icmp_events(ip_source, ip_destination, icmp_type, packet_size):
    """
    Enregistre un paquet ICMP dans les deux index source et destination.

    Le tuple stocké est : (timestamp, ip_src, ip_dst, icmp_type, taille)

    Args:
        ip_source (str): IP source du paquet
        ip_destination (str): IP destination du paquet
        icmp_type (int): Type ICMP (ex: 8 = Echo Request, 0 = Echo Reply)
        packet_size (int): Taille du paquet en octets
    """
    now = time.time()
    packet = (now, ip_source, ip_destination, icmp_type, packet_size)

    # Index source : permet de détecter un attaquant qui flood en ICMP (DoS)
    if not _is_flow_full(ICMP_EVENTS_BY_SOURCE[ip_source][ip_destination]):
        ICMP_EVENTS_BY_SOURCE[ip_source][ip_destination].append(packet)

    # Index destination : permet de détecter une victime qui reçoit un flood ICMP (DDoS)
    if not _is_flow_full(ICMP_EVENTS_BY_DEST[ip_destination][ip_source]):
        ICMP_EVENTS_BY_DEST[ip_destination][ip_source].append(packet)


def write_tcp_events(ip_source, source_port, ip_destination, destination_port, flags, packet_size):
    """
    Enregistre un paquet TCP dans les deux index source et destination.

    Le tuple stocké est :
        (timestamp, ip_src, port_src, ip_dst, port_dst, flags_hex, taille)

    Les clés sont des tuples (IP, port) pour distinguer les connexions
    sur des ports différents de la même IP.

    Args:
        ip_source (str): IP source
        source_port (int): Port source TCP
        ip_destination (str): IP destination
        destination_port (int): Port destination TCP
        flags (str): Flags TCP en hexadécimal (ex: "0x002" pour SYN)
        packet_size (int): Taille du paquet en octets
    """
    now = time.time()
    src_key = (ip_source, source_port)
    dst_key = (ip_destination, destination_port)

    packet = (
        now,
        ip_source,
        source_port,
        ip_destination,
        destination_port,
        flags,
        packet_size
    )

    # Index source : (ip_src, port_src) → (ip_dst, port_dst)
    if not _is_flow_full(TCP_EVENTS_BY_SOURCE[src_key][dst_key]):
        TCP_EVENTS_BY_SOURCE[src_key][dst_key].append(packet)

    # Index destination : (ip_dst, port_dst) → (ip_src, port_src)
    if not _is_flow_full(TCP_EVENTS_BY_DEST[dst_key][src_key]):
        TCP_EVENTS_BY_DEST[dst_key][src_key].append(packet)


def write_udp_events(ip_source, source_port, ip_destination, destination_port, payload, packet_size):
    """
    Enregistre un paquet UDP dans les deux index source et destination.

    Le tuple stocké est :
        (timestamp, ip_src, port_src, ip_dst, port_dst, payload, taille)

    Args:
        ip_source (str): IP source
        source_port (int): Port source UDP
        ip_destination (str): IP destination
        destination_port (int): Port destination UDP
        payload: Contenu applicatif (None ici car non extrait par tshark)
        packet_size (int): Taille du paquet en octets
    """
    now = time.time()
    src_key = (ip_source, source_port)
    dst_key = (ip_destination, destination_port)

    packet = (
        now,
        ip_source,
        source_port,
        ip_destination,
        destination_port,
        payload,
        packet_size
    )

    if not _is_flow_full(UDP_EVENTS_BY_SOURCE[src_key][dst_key]):
        UDP_EVENTS_BY_SOURCE[src_key][dst_key].append(packet)

    if not _is_flow_full(UDP_EVENTS_BY_DEST[dst_key][src_key]):
        UDP_EVENTS_BY_DEST[dst_key][src_key].append(packet)
