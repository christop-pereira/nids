"""
process.py - Traitement et dispatch de chaque paquet capturé

Pour chaque paquet reçu de main.py, ce module détermine son protocole
(TCP, UDP, ICMP, ou ARP) et appelle la fonction d'écriture correspondante
pour stocker l'événement dans les structures de données en mémoire.
"""

from detection.arp import check_arp
from utils.writing import write_icmp_events, write_udp_events, write_tcp_events


def process(packet):
    """
    Dispatche un paquet vers le bon handler selon son protocole.

    Les vérifications sont mutuellement exclusives (TCP, UDP, ICMP).
    ARP est traité en parallèle car une trame peut contenir à la fois
    des infos IP/ARP.

    Args:
        packet (dict): Paquet normalisé issu de main.py avec les clés :
            ip_src, ip_dst, tcp_src, tcp_dst, tcp_flags,
            udp_src, udp_dst, icmp_type, size, arp_ip, arp_mac
    """
    ip_src = packet["ip_src"]
    ip_dst = packet["ip_dst"]
    size = packet["size"]

    # TCP : les deux champs TCP sont présents → paquet TCP
    if packet["tcp_src"] and packet["tcp_dst"]:
        write_tcp_events(
            ip_src,
            int(packet["tcp_src"]),
            ip_dst,
            int(packet["tcp_dst"]),
            packet["tcp_flags"],   # Flags sous forme hexadécimale (ex: "0x002" pour SYN)
            size
        )

    # UDP : les deux champs UDP sont présents → paquet UDP
    elif packet["udp_src"] and packet["udp_dst"]:
        write_udp_events(
            ip_src,
            int(packet["udp_src"]),
            ip_dst,
            int(packet["udp_dst"]),
            None,    # Payload non extrait (tshark ne l'exporte pas ici)
            size
        )

    # ICMP : le champ ICMP est présent → paquet ICMP
    elif packet["icmp_type"]:
        write_icmp_events(
            ip_src,
            ip_dst,
            int(packet["icmp_type"]),
            size
        )

    # ARP : traitement MITM indépendant du protocole réseau
    # Vérifie si l'IP annoncée dans l'ARP correspond à la MAC connue
    if packet["arp_ip"] and packet["arp_mac"]:
        check_arp(packet["arp_ip"], packet["arp_mac"])
