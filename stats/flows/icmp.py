"""
icmp.py - Calcul des statistiques de flows ICMP par échange IP ↔ IP

ICMP n'a pas de ports, donc les flows sont indexés uniquement par paire d'IPs.
La caractérisation repose sur le type ICMP (Echo Request/Reply, etc.),
la taille des paquets et le rythme d'envoi.

Un flood ICMP (type 8 dominant, intervalle très court, ratio in élevé)
est typique d'une attaque Ping Flood ou Smurf.
"""

from collections import Counter
from config import ICMP_EVENTS_BY_DEST
from utils.events import icmp_get_victim_len_exchange, get_events_by_window
from utils.flows import calcul_mean_interval, get_dominant


def get_icmp_flows_global_stats(victim_ip, window_label):
    """
    Calcule les statistiques de tous les flows ICMP reçus par une victime.

    Itère sur toutes les IPs sources ayant envoyé des paquets ICMP
    à la victime dans la fenêtre temporelle donnée.

    Args:
        victim_ip (str): IP de la victime
        window_label (str): "short" ou "long"

    Returns:
        list[dict]: Liste de statistiques, une par IP source suspecte
    """
    events = get_events_by_window(ICMP_EVENTS_BY_DEST, window_label)
    list_of_stats = []
    for suspect_ip, packets in events[victim_ip].items():
        stats = _get_icmp_flows_stats_per_exchange(packets, victim_ip, suspect_ip)
        list_of_stats.append(stats)

    return list_of_stats


def _get_icmp_flows_stats_per_exchange(packets, victim_ip, suspect_ip):
    """
    Calcule les statistiques détaillées d'un échange ICMP entre deux IPs.

    Métriques spécifiques à ICMP :
      - dominant_icmp_type / share_of_dominant_icmp_type :
            type ICMP le plus fréquent (ex: 8 = Echo Request dominant → Ping Flood)
      - icmp_type_distribution : distribution complète des types ICMP

    Métriques communes avec TCP/UDP :
      - dominant_packets_size, ratio_in/out, mean_packet_interval, duration

    Args:
        packets: Séquence de tuples (ts, ip_src, ip_dst, icmp_type, size)
        victim_ip (str): IP de la victime
        suspect_ip (str): IP du suspect

    Returns:
        dict: Dictionnaire de statistiques du flow ICMP
    """
    packets_size = Counter()  # Distribution des tailles de paquets
    icmp_type_distribution = Counter()  # Distribution des types ICMP
    flows_length = Counter()  # Longueur du flow
    nb_packets_main = 0
    # Nombre de réponses ICMP envoyées par la victime (ex: Echo Reply)
    nb_packets_sec = icmp_get_victim_len_exchange(victim_ip, suspect_ip)
    timestamps = []

    for packet in packets:
        timestamp = packet[0]
        src_ip = packet[1]
        dst_ip = packet[2]
        icmp_type = packet[3]  # Type ICMP : 8=Echo Request, 0=Reply, 3=Dest Unreachable...
        packet_size = packet[4]

        nb_packets_main += 1
        timestamps.append(timestamp)
        packets_size[packet_size] += 1
        icmp_type_distribution[icmp_type] += 1

    flows_length[len(packets)] += 1
    mean_packet_interval = calcul_mean_interval(timestamps)
    dominant_icmp_type, share_of_dominant_icmp_type = get_dominant(icmp_type_distribution)
    dominant_packet_size, share_of_dominant_packet_size = get_dominant(packets_size)
    ratio_in = nb_packets_main / (nb_packets_main + nb_packets_sec)
    ratio_out = nb_packets_sec / (nb_packets_main + nb_packets_sec)

    stats_per_exchange = {
        "dominant_icmp_type": dominant_icmp_type,
        "share_of_dominant_icmp_type": share_of_dominant_icmp_type,
        "dominant_packets_size": dominant_packet_size,
        "share_of_dominant_packet_size": share_of_dominant_packet_size,
        "packets_size": packets_size,
        "icmp_type_distribution": icmp_type_distribution,
        "flows_length": flows_length,
        "nb_packets_main": nb_packets_main,
        "nb_packets_sec": nb_packets_sec,
        "ratio_in": ratio_in,
        "ratio_out": ratio_out,
        "timestamps": timestamps,
        "duration": max(timestamps) - min(timestamps),
        "mean_packet_interval": mean_packet_interval
    }

    return stats_per_exchange
