"""
udp.py - Calcul des statistiques de flows UDP par échange IP:port ↔ IP:port

Similaire à tcp.py mais adapté au protocole UDP (sans connexion, sans flags).
La caractérisation du flow repose sur le payload, la taille des paquets
et le rythme d'envoi plutôt que sur les flags TCP.
"""

from collections import Counter
from config import UDP_EVENTS_BY_DEST
from utils.events import tcp_udp_get_victim_len_exchange, get_events_by_window
from utils.flows import calcul_mean_interval, get_dominant


def get_udp_flows_global_stats(set_of_ports, victim_ip, window_label):
    """
    Calcule les statistiques de tous les flows UDP reçus par une victime
    sur un ensemble de ports donnés.

    Args:
        set_of_ports (set): Ports de la victime à analyser
        victim_ip (str): IP de la victime
        window_label (str): "short" ou "long"

    Returns:
        list[dict]: Liste de statistiques, une par échange (suspect → victime:port)
    """
    events = get_events_by_window(UDP_EVENTS_BY_DEST, window_label)
    list_of_stats = []
    for port in set_of_ports:
        for (suspect_ip, suspect_port), packets in events[(victim_ip, port)].items():
            stats = _get_udp_flows_stats_per_exchange(packets, victim_ip, port, suspect_ip, suspect_port)
            list_of_stats.append(stats)

    return list_of_stats


def _get_udp_flows_stats_per_exchange(packets, victim_ip, main_port, suspect_ip, suspect_port):
    """
    Calcule les statistiques détaillées d'un échange UDP entre deux endpoints.

    Métriques spécifiques à UDP (par rapport à TCP) :
      - dominant_payload / share_of_dominant_payload : contenu dominant des paquets
      - payload_distribution : distribution des payloads observés
      - flows_length : compteur de la longueur du flow (nb de paquets par session)

    Métriques communes :
      - dominant_packets_size, ratio_in/out, mean_packet_interval, duration, etc.

    Args:
        packets: Séquence de tuples (ts, ip_src, port_src, ip_dst, port_dst, payload, size)
        victim_ip (str): IP de la victime
        main_port (int): Port de la victime
        suspect_ip (str): IP du suspect
        suspect_port (int): Port du suspect

    Returns:
        dict: Dictionnaire de statistiques du flow UDP
    """
    packets_size = Counter()  # Distribution des tailles de paquets
    payload_distribution = Counter()  # Distribution des payloads
    flows_length = Counter()  # Compteur du nb de paquets dans ce flow
    sec_ports = Counter()  # Distribution des ports sources du suspect
    nb_packets_main = 0
    nb_packets_sec = tcp_udp_get_victim_len_exchange(victim_ip, main_port, suspect_ip, suspect_port)
    timestamps = []

    for packet in packets:
        timestamp = packet[0]
        src_ip = packet[1]
        src_prt = packet[2]
        dst_ip = packet[3]
        dst_port = packet[4]
        payload = packet[5]  # Payload
        packet_size = packet[6]

        nb_packets_main += 1
        timestamps.append(timestamp)
        packets_size[packet_size] += 1
        sec_ports[src_prt] += 1
        payload_distribution[payload] += 1

    # Enregistre la longueur totale de ce flow comme entrée du compteur
    flows_length[len(packets)] += 1
    mean_packet_interval = calcul_mean_interval(timestamps)
    dominant_payload, share_of_dominant_payload = get_dominant(payload_distribution)
    dominant_packet_size, share_of_dominant_packet_size = get_dominant(packets_size)
    ratio_in = nb_packets_main / (nb_packets_main + nb_packets_sec)
    ratio_out = nb_packets_sec / (nb_packets_main + nb_packets_sec)

    stats_per_exchange = {
        "dominant_payload": dominant_payload,
        "share_of_dominant_payload": share_of_dominant_payload,
        "dominant_packets_size": dominant_packet_size,
        "share_of_dominant_packet_size": share_of_dominant_packet_size,
        "packets_size": packets_size,
        "payload_distribution": payload_distribution,
        "flows_length": flows_length,
        "main_port": main_port,
        "sec_ports": sec_ports,
        "nb_packets_main": nb_packets_main,
        "nb_packets_sec": nb_packets_sec,
        "ratio_in": ratio_in,
        "ratio_out": ratio_out,
        "timestamps": timestamps,
        "duration": max(timestamps) - min(timestamps),
        "mean_packet_interval": mean_packet_interval
    }

    return stats_per_exchange
