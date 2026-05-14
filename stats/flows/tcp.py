"""
tcp.py - Calcul des statistiques de flows TCP par échange IP:port ↔ IP:port

Pour chaque paire (victime, suspect) sur un port donné, ce module calcule
un ensemble de métriques permettant de caractériser le comportement du flow :
flags dominants, taille de paquet, ratio in/out, intervalle moyen, etc.

Ces statistiques sont ensuite comparées entre flows pour détecter des
patterns d'attaque distribuée (DDoS, brute force distribué, port scan).
"""

from collections import Counter
from config import TCP_EVENTS_BY_DEST
from utils.events import tcp_udp_get_victim_len_exchange, get_events_by_window
from utils.flows import calcul_mean_interval, get_dominant


def get_tcp_flows_global_stats(set_of_ports, victim_ip, window_label):
    """
    Calcule les statistiques de tous les flows TCP reçus par une victime
    sur un ensemble de ports donnés.

    Itère sur chaque port ciblé et chaque IP source ayant communiqué
    avec la victime sur ce port.

    Args:
        set_of_ports (set): Ports de la victime à analyser
        victim_ip (str): IP de la victime (destinataire des paquets)
        window_label (str): "short" ou "long"

    Returns:
        list[dict]: Liste de statistiques, une entrée par échange (suspect → victime:port)
    """
    events = get_events_by_window(TCP_EVENTS_BY_DEST, window_label)
    list_of_stats = []
    for port in set_of_ports:
        for (suspect_ip, suspect_port), packets in events[(victim_ip, port)].items():
            stats = _get_tcp_flows_stats_per_exchange(packets, victim_ip, port, suspect_ip, suspect_port)
            list_of_stats.append(stats)

    return list_of_stats


def _get_tcp_flows_stats_per_exchange(packets, main_ip, main_port, sec_ip, sec_port):
    """
    Calcule les statistiques détaillées d'un échange TCP entre deux endpoints.

    Métriques calculées :
      - dominant_flag / share_of_dominant_flag : flag TCP le plus fréquent et sa part
      - flags_distribution : distribution complète des flags
      - dominant_packets_size / share_of_dominant_packet_size : taille de paquet la plus courante
      - flows_length : nombre total de paquets dans ce flow
      - main_port : port de la victime
      - sec_ports : distribution des ports sources du suspect
      - nb_packets_main : paquets envoyés par le suspect vers la victime
      - nb_packets_sec : paquets envoyés par la victime vers le suspect (réponses)
      - ratio_in / ratio_out : proportion de paquets dans chaque sens
      - timestamps : liste des timestamps pour calcul d'intervalle et durée
      - duration : durée totale du flow (max - min des timestamps)
      - mean_packet_interval : intervalle moyen entre paquets consécutifs

    Args:
        packets: Séquence de tuples (ts, ip_src, port_src, ip_dst, port_dst, flags, size)
        main_ip (str): IP de la victime
        main_port (int): Port de la victime
        sec_ip (str): IP du suspect
        sec_port (int): Port du suspect

    Returns:
        dict: Dictionnaire de statistiques du flow
    """
    packets_size = Counter()  # Compteur de tailles de paquets
    flags_distribution = Counter()  # Compteur de flags TCP
    sec_ports = Counter()  # Compteur de ports sources du suspect
    nb_packets_main = 0  # Paquets envoyés par le suspect
    # Récupère le nombre de paquets de réponse de la victime
    nb_packets_sec = tcp_udp_get_victim_len_exchange(main_ip, main_port, sec_ip, sec_port)
    timestamps = []

    for packet in packets:
        timestamp = packet[0]
        src_ip = packet[1]
        src_prt = packet[2]
        dst_ip = packet[3]
        dst_port = packet[4]
        flags = packet[5]  # Liste de flags (ex: ["SYN"] ou ["SYN", "ACK"])
        packet_size = packet[6]

        nb_packets_main += 1
        timestamps.append(timestamp)
        packets_size[packet_size] += 1
        sec_ports[src_prt] += 1
        for flag in flags:
            flags_distribution[flag] += 1

    flow_length = len(packets)
    mean_packet_interval = calcul_mean_interval(timestamps)
    dominant_flag, share_of_dominant_flag = get_dominant(flags_distribution)
    dominant_packet_size, share_of_dominant_packet_size = get_dominant(packets_size)
    # ratio_in = part des paquets venant du suspect (> 0.5 = sens attaque dominant)
    ratio_in = nb_packets_main / (nb_packets_main + nb_packets_sec)
    ratio_out = nb_packets_sec / (nb_packets_main + nb_packets_sec)

    stats_per_exchange = {
        "dominant_flag": dominant_flag,
        "share_of_dominant_flag": share_of_dominant_flag,
        "flags_distribution": flags_distribution,
        "dominant_packets_size": dominant_packet_size,
        "share_of_dominant_packet_size": share_of_dominant_packet_size,
        "packets_size": packets_size,
        "flows_length": flow_length,
        "main_port": main_port,
        "sec_ports": sec_ports,
        "nb_packets_main": nb_packets_main,
        "nb_packets_sec": nb_packets_sec,
        "ratio_in": ratio_in,
        "ratio_out": ratio_out,
        "timestamps": timestamps,
        "duration": max(timestamps) - min(timestamps),  # Durée totale du flow
        "mean_packet_interval": mean_packet_interval
    }

    return stats_per_exchange
