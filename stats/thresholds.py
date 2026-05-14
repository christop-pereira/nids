"""
thresholds.py - Calcul des statistiques agrégées pour la détection par seuils

Ce module collecte et agrège les statistiques de tous les événements en mémoire
pour chaque IP (source ou destination), afin d'alimenter les règles de détection
par seuils (threshold.py).

Les statistiques calculées incluent : nombre de paquets, flows, IPs distinctes,
ports ciblés, et distribution du volume par port (permettant de détecter
si le trafic est concentré sur un type de port spécifique).
"""

from collections import Counter, defaultdict
from utils.events import get_shares, get_correct_events


def _get_tcp_udp_threshold_stats(window_label, proto, sorting_label):
    """
    Calcule les statistiques agrégées pour TCP ou UDP.

    Pour chaque IP principale (source ou destination selon sorting_label),
    collecte :
      - nb_packets_main : total de paquets envoyés/reçus
      - nb_flows : nombre d'échanges distincts
      - nb_main_ports : nombre de ports principaux utilisés
      - nb_sec_ports : nombre de ports secondaires distincts
      - nb_ips : nombre d'IPs secondaires distinctes
      - volume_per_main_port : volume de paquets par port principal (Counter)
      - volume_per_main_port_shares : parts relatives par port principal
      - volume_per_sec_port : volume de paquets par port secondaire (Counter)
      - volume_per_sec_port_shares : parts relatives par port secondaire

    Args:
        window_label (str): "short" ou "long"
        proto (str): "tcp" ou "udp"
        sorting_label (str): "source" ou "destination"

    Returns:
        dict: {
            "per_ip": {ip: stats_dict, ...},
            "global": {statistiques globales de tous les flows}
        }
    """
    events = get_correct_events(proto, window_label, sorting_label)

    # Compteurs globaux (agrégés sur toutes les IPs)
    global_nb_packets_main = 0
    global_nb_flows = 0
    global_main_ports_set = set()
    global_sec_ports_set = set()
    global_ips_set = set()
    global_volume_per_main_port = Counter()
    global_volume_per_sec_port = Counter()

    # Compteurs par IP principale
    stats_per_ip = defaultdict(lambda: {
        "nb_packets_main": 0,
        "nb_flows": 0,
        "nb_main_ports": set(),     # set pour dédupliquer les ports
        "nb_sec_ports": set(),
        "ips_set": set(),           # set pour dédupliquer les IPs secondaires
        "volume_per_main_port": Counter(),
        "volume_per_sec_port": Counter()
    })

    # Itération sur tous les échanges : (main_ip, main_port) → (sec_ip, sec_port) → paquets
    for (main_ip, main_port), package in events.items():
        global_main_ports_set.add(main_port)
        ip_stats = stats_per_ip[main_ip]

        for (sec_ip, sec_port), packets in package.items():
            global_sec_ports_set.add(main_port)   # Note: indexé sur main_port (port destination)
            global_ips_set.add(sec_ip)
            global_nb_flows += 1
            ip_stats["nb_flows"] += 1
            ip_stats["ips_set"].add(sec_ip)

            for packet in packets:
                global_nb_packets_main += 1
                ip_stats["nb_packets_main"] += 1
                ip_stats["volume_per_main_port"][main_port] += 1
                ip_stats["volume_per_sec_port"][sec_port] += 1
                global_volume_per_main_port[main_port] += 1
                global_volume_per_sec_port[sec_port] += 1

            ip_stats["nb_sec_ports"].add(sec_port)
        ip_stats["nb_main_ports"].add(main_port)

    # Finalisation : conversion des sets en longueurs, calcul des parts relatives
    final_stats_per_ip = {}
    for ip, stats in stats_per_ip.items():
        volume_per_main_port_shares = get_shares(
            stats["volume_per_main_port"], stats["nb_packets_main"]
        )
        volume_per_sec_port_shares = get_shares(
            stats["volume_per_sec_port"], stats["nb_packets_main"]
        )
        final_stats_per_ip[ip] = {
            "nb_packets_main": stats["nb_packets_main"],
            "nb_flows": stats["nb_flows"],
            "nb_main_ports": len(stats["nb_main_ports"]),
            "nb_sec_ports": len(stats["nb_sec_ports"]),
            "nb_ips": len(stats["ips_set"]),
            "volume_per_main_port": stats["volume_per_main_port"],
            "volume_per_main_port_shares": volume_per_main_port_shares,
            "volume_per_sec_port": stats["volume_per_sec_port"],
            "volume_per_sec_port_shares": volume_per_sec_port_shares
        }

    global_volume_per_main_port_shares = get_shares(global_volume_per_main_port, global_nb_packets_main)
    global_volume_per_sec_port_shares = get_shares(global_volume_per_sec_port, global_nb_packets_main)

    global_stats = {
        "per_ip": final_stats_per_ip,
        "global": {
            "global_nb_packets_main": global_nb_packets_main,
            "global_nb_flows": global_nb_flows,
            "global_nb_main_ports": len(global_main_ports_set),
            "global_nb_sec_ports": len(global_sec_ports_set),
            "global_nb_ips": len(global_ips_set),
            "global_volume_per_main_port": global_volume_per_main_port,
            "global_volume_per_main_port_shares": global_volume_per_main_port_shares,
            "global_volume_per_sec_port": global_volume_per_sec_port,
            "global_volume_per_sec_port_shares": global_volume_per_sec_port_shares
        }
    }

    return global_stats


def _get_icmp_threshold_stats(window_label, proto, sorting_label):
    """
    Calcule les statistiques agrégées pour ICMP.

    ICMP n'ayant pas de ports, les statistiques sont simplifiées :
      - nb_packets_main : total de paquets ICMP
      - nb_flows : nombre d'échanges distincts (paires d'IPs)
      - nb_ips : nombre d'IPs secondaires distinctes

    Args:
        window_label (str): "short" ou "long"
        proto (str): "icmp"
        sorting_label (str): "source" ou "destination"

    Returns:
        dict: {"per_ip": {ip: stats}, "global": {stats globales}}
    """
    events = get_correct_events(proto, window_label, sorting_label)
    global_nb_packets_main = 0
    global_nb_flows = 0
    global_ips_set = set()

    stats_per_ip = defaultdict(lambda: {
        "nb_packets_main": 0,
        "nb_flows": 0,
        "ips_set": set()
    })

    for main_ip, package in events.items():
        ip_stats = stats_per_ip[main_ip]

        for sec_ip, packets in package.items():
            global_ips_set.add(sec_ip)
            global_nb_flows += 1
            ip_stats["nb_flows"] += 1
            ip_stats["ips_set"].add(sec_ip)

            for packet in packets:
                global_nb_packets_main += 1
                ip_stats["nb_packets_main"] += 1

    final_stats_per_ip = {}
    for ip, stats in stats_per_ip.items():
        final_stats_per_ip[ip] = {
            "nb_packets_main": stats["nb_packets_main"],
            "nb_flows": stats["nb_flows"],
            "nb_ips": len(stats["ips_set"])
        }

    global_stats = {
        "per_ip": final_stats_per_ip,
        "global": {
            "global_nb_packets_main": global_nb_packets_main,
            "global_nb_flows": global_nb_flows,
            "global_nb_ips": len(global_ips_set),
        }
    }

    return global_stats


def get_threshold_stats(window_label, proto, sorting_label):
    """
    Point d'entrée pour le calcul des statistiques de seuil selon le protocole.

    Args:
        window_label (str): "short" ou "long"
        proto (str): "tcp", "udp" ou "icmp"
        sorting_label (str): "source" ou "destination"

    Returns:
        dict: Statistiques agrégées (format dépend du protocole)
    """
    if proto == "tcp" or proto == "udp":
        return _get_tcp_udp_threshold_stats(window_label, proto, sorting_label)
    else:
        return _get_icmp_threshold_stats(window_label, proto, sorting_label)