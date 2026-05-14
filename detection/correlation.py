"""
correlation.py - Corrélation de paquets et de flows pour la détection d'attaques

Ce module fournit deux fonctions de corrélation de haut niveau :
  - are_packets_correlated() : détecte les attaques centralisées (DoS, SPS, SBF)
    en cherchant des paquets répétés dans les flows d'un attaquant
  - are_flows_correlated()   : détecte les attaques distribuées (DDoS, DPS, DBF)
    en cherchant des clusters de flows similaires vers une victime

Les deux fonctions délèguent la comparaison effective aux modules spécialisés
(packet.py, flow.py) de chaque type d'attaque.
"""

from detection.distributed.dbf.flow import dbf_flow_comparison
from detection.distributed.ddos.flow import ddos_flow_comparison
from detection.distributed.dps.flow import dps_flow_comparison
from detection.single.dos.packet import dos_packet_comparison
from detection.single.sbf.packet import sbf_packet_comparison
from detection.single.sps.packet import sps_packet_comparison
from stats.flows.icmp import get_icmp_flows_global_stats
from stats.flows.tcp import get_tcp_flows_global_stats
from stats.flows.udp import get_udp_flows_global_stats
from utils.events import get_correct_events


def _get_correct_flow_stats(proto, victim_ip, window_label, set_of_ports=None):
    """
    Retourne les statistiques de flows de la victime selon le protocole.

    Args:
        proto (str): "tcp", "udp" ou "icmp"
        victim_ip (str): IP de la victime à analyser
        window_label (str): "short" ou "long"
        set_of_ports (set | None): Ports ciblés

    Returns:
        list[dict]: Liste de statistiques de flows
    """
    if proto == "tcp":
        return get_tcp_flows_global_stats(set_of_ports, victim_ip, window_label)
    elif proto == "udp":
        return get_udp_flows_global_stats(set_of_ports, victim_ip, window_label)
    elif proto == "icmp":
        return get_icmp_flows_global_stats(victim_ip, window_label)


def are_packets_correlated(attacker_ip, window_label, proto, type_detection, set_of_ports):
    """
    Vérifie si les paquets envoyés par un suspect montrent un pattern d'attaque répétitive.

    Pour TCP/UDP : agrège tous les paquets de tous les ports et les trie par timestamp
               avant d'appliquer la comparaison (un seul flux global d'attaque).
    Pour ICMP : les événements sont indexés par IP seule (pas de tuple IP/port),
               chaque échange est donc analysé directement sans agrégation par port.

    Args:
        attacker_ip (str): IP du suspect à analyser
        window_label (str): "short" ou "long"
        proto (str): "tcp", "udp" ou "icmp"
        type_detection (str): "dos", "sps" ou "sbf"
        set_of_ports (set): Ports depuis lesquels le suspect a envoyé des paquets

    Returns:
        bool: True si un pattern de paquets répétés est détecté
    """
    events = get_correct_events(proto, window_label, "source")

    # Sélection de la fonction de comparaison selon le type d'attaque
    if type_detection == "dos":
        packet_comparison_function = dos_packet_comparison
    elif type_detection == "sps":
        packet_comparison_function = sps_packet_comparison
    elif type_detection == "sbf":
        packet_comparison_function = sbf_packet_comparison
    else:
        return False

    if proto == "tcp" or proto == "udp":
        # TCP/UDP : fusion de tous les paquets de tous les ports suspects,
        # puis tri chronologique avant comparaison
        all_packets = []
        for port in set_of_ports:
            for (suspect_ip, suspect_port), packets in events[(attacker_ip, port)].items():
                for packet in packets:
                    all_packets.append(packet)

        all_packets.sort(key=lambda p: p[0])  # Tri par timestamp
        if packet_comparison_function(all_packets, window_label, proto):
            return True
        else:
            return False
    else:
        # ICMP : contrairement à TCP/UDP, les événements ICMP sont indexés par IP seule
        # (pas de tuple (IP, port)), set_of_ports est donc vide et inutilisé ici.
        # On itère directement sur les échanges de l'attaquant vers chaque destination.
        for port in set_of_ports:
            for (suspect_ip, suspect_port), packets in events[(attacker_ip, port)].items():
                if packet_comparison_function(packets, window_label, proto):
                    return True
                else:
                    return False


def are_flows_correlated(victim_ip, window_label, proto, type_detection, set_of_ports=None):
    """
    Vérifie si plusieurs flows reçus par une victime présentent des similarités
    caractéristiques d'une attaque distribuée.

    Algorithme de clustering :
      Pour chaque flow, compte combien d'autres flows lui sont similaires
      (selon la fonction de comparaison du type d'attaque).
      Si un flow a >= MIN_SIMILAR_NEIGHBORS voisins similaires,
      il contribue au cluster. Si le cluster atteint MIN_SIMILAR_FLOWS,
      l'attaque est confirmée.

    Seuils utilisés :
      - MIN_SIMILAR_FLOWS = 20     : nb minimum de flows dans le cluster
      - MIN_SIMILAR_NEIGHBORS = 5  : nb minimum de voisins similaires par flow

    Args:
        victim_ip (str): IP de la victime
        window_label (str): "short" ou "long"
        proto (str): "tcp", "udp" ou "icmp"
        type_detection (str): "ddos", "dps" ou "dbf"
        set_of_ports (set | None): Ports ciblés

    Returns:
        bool: True si un cluster d'attaque distribuée est détecté
    """
    all_stats = _get_correct_flow_stats(proto, victim_ip, window_label, set_of_ports)
    MIN_SIMILAR_FLOWS = 20       # Taille minimale du cluster pour confirmer l'attaque
    MIN_SIMILAR_NEIGHBORS = 5    # Nb minimum de flows similaires autour d'un flow
    similar_flows = 0

    # Sélection de la fonction de comparaison de flows selon le type d'attaque
    if type_detection == "ddos":
        flow_comparison_function = ddos_flow_comparison
    elif type_detection == "dps":
        flow_comparison_function = dps_flow_comparison
    elif type_detection == "dbf":
        flow_comparison_function = dbf_flow_comparison
    else:
        return False

    for i, flow1 in enumerate(all_stats):
        similarity_count = 0   # Reset du compteur de voisins pour chaque flow

        for j, flow2 in enumerate(all_stats):
            if i == j:
                continue   # Évite l'auto-comparaison d'un flow avec lui-même

            if flow_comparison_function(flow1, flow2, window_label, proto):
                similarity_count += 1
                # Optimisation : arrêt anticipé une fois le seuil de voisins atteint
                if similarity_count >= MIN_SIMILAR_NEIGHBORS:
                    break

        # Si ce flow a suffisamment de voisins similaires → il appartient au cluster
        if similarity_count >= MIN_SIMILAR_NEIGHBORS:
            similar_flows += 1
            if similar_flows >= MIN_SIMILAR_FLOWS:
                return True   # Cluster détecté, attaque confirmée

    return similar_flows >= MIN_SIMILAR_FLOWS
