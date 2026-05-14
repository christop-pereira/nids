"""
config.py - Configuration globale et état partagé du NIDS

Ce module centralise :
  - Les paramètres généraux (interface, fenêtres temporelles, limites)
  - L'état partagé en mémoire (tables d'événements par protocole)
  - Tous les seuils de détection utilisés par les algorithmes d'analyse
"""

import time
from collections import defaultdict, deque

# --------------------------
# GENERAL CONFIG
# --------------------------

INTERFACE = "Wi-Fi"                             # Interface réseau écoutée par tshark
SHORT_WINDOW = 60                               # Fenêtre courte d'analyse (en secondes)
LONG_WINDOW = 300                               # Fenêtre longue d'analyse (en secondes)
CLEANUP_INTERVAL = 30                           # Intervalle entre deux nettoyages mémoire (en secondes)
LAST_CLEANUP = {"time": time.time()}            # Timestamp du dernier nettoyage
LAST_SHORT_DETECTION = {"time": time.time()}    # Timestamp de la dernière détection courte
LAST_LONG_DETECTION = {"time": time.time()}     # Timestamp de la dernière détection longue
MAX_PACKETS_PER_SECOND = 5000                   # Nombre maximum de paquets traités par seconde (rate limiting)
MAX_FLOW_SIZE = 10_000                          # Taille maximale d'un flow (nb de paquets stockés par échange)

# --- MITM ---
# Table ARP : associe chaque IP connue à sa MAC. Utilisée pour détecter l'ARP spoofing.
ARP_TABLE = {}

# --- TCP EVENTS ---
# Structures de type defaultdict(deque) indexées par (IP, port) source/destination
# TCP_EVENTS_BY_SOURCE[(ip_src, port_src)][(ip_dst, port_dst)] = deque de paquets
# TCP_EVENTS_BY_DEST[(ip_dst, port_dst)][(ip_src, port_src)] = deque de paquets
TCP_EVENTS_BY_SOURCE = defaultdict(lambda: defaultdict(deque))
TCP_EVENTS_BY_DEST = defaultdict(lambda: defaultdict(deque))

# --- ICMP EVENTS ---
# ICMP_EVENTS_BY_SOURCE[ip_src][ip_dst] = deque de paquets ICMP
# ICMP_EVENTS_BY_DEST[ip_dst][ip_src] = deque de paquets ICMP
ICMP_EVENTS_BY_SOURCE = defaultdict(lambda: defaultdict(deque))
ICMP_EVENTS_BY_DEST = defaultdict(lambda: defaultdict(deque))

# --- UDP EVENTS ---
# Même structure que TCP mais pour les paquets UDP
UDP_EVENTS_BY_SOURCE = defaultdict(lambda: defaultdict(deque))
UDP_EVENTS_BY_DEST = defaultdict(lambda: defaultdict(deque))

# --------------------------
# GLOBAL THRESHOLDS
# --------------------------
# Seuils de détection côté destination (victime potentielle)
# Clés de premier niveau : "short" / "long" (fenêtre temporelle)
# Clés de second niveau : type d'attaque ("ddos", "dps", "dbf")

GLOBAL_DEST_THRESHOLDS = {
    "short": {
        "ddos": {
            "max_nb_packets": 10000,          # Nb total de paquets reçus avant suspicion DDoS
            "max_nb_ips": 10                  # Nb d'IPs sources distinctes avant suspicion DDoS
        },
        "dps": {
            "max_nb_ips": 8,                  # Nb d'IPs sources avant suspicion de port scan distribué
            "max_nb_ports": 7                 # Nb de ports ciblés avant suspicion
        },
        "dbf": {
            "max_nb_ips": 10,                 # Nb d'IPs sources avant suspicion de brute force distribué
            "max_top_port_share": 0.7         # Part minimale du trafic sur ports brute force
        }
    },
    "long": {
        "ddos": {
            "max_nb_packets": 50000,
            "max_nb_ips": 20
        },
        "dps": {
            "max_nb_ips": 11,
            "max_nb_ports": 20
        },
        "dbf": {
            "max_nb_ips": 20,
            "max_top_port_share": 0.6
        }
    },
}

# Seuils de détection côté source (attaquant potentiel)
GLOBAL_SOURCE_THRESHOLDS = {
    "short": {
        "dos": {
            "max_nb_packets": 10000          # Nb de paquets envoyés avant suspicion DoS
        },
        "sps": {
            "max_nb_ports": 8                # Nb de ports différents ciblés avant suspicion de scan
        },
        "sbf": {
            "max_nb_packets": 100,           # Nb de paquets envoyés sur ports brute force
            "max_top_port_share": 0.75       # Part du trafic concentrée sur un port précis
        }
    },
    "long": {
        "dos": {
            "max_nb_packets": 50000
        },
        "sps": {
            "max_nb_ports": 11
        },
        "sbf": {
            "max_nb_packets": 500,
            "max_top_port_share": 0.75,
        }
    },
}

# --------------------------
# PORT SCANNING
# --------------------------
# Seuils pour la comparaison de flows dans le cadre d'un scan de ports distribué (DPS)
# Un DPS est détecté quand plusieurs flows vers la même victime présentent des similarités
DPS_FLOW_COMPARISON_THRESHOLDS = {
    "short": {
        "min_correspondances": 5,               # Nb minimum de critères similaires entre deux flows
        "min_dominant_flag_share": 0.7,         # Part minimale du flag dominant (ex: SYN pur)
        "min_dominant_payload_share": 0.7,      # Part minimale du payload dominant
        "min_dominant_icmp_type_share": 0.7,    # Part minimale du type ICMP dominant
        "min_dominant_packet_share": 0.7,       # Part minimale de la taille de paquet dominante
        "packet_volume_tolerance": 0.3,         # Tolérance relative sur le nb de paquets
        "packet_interval_tolerance": 0.2,       # Tolérance sur l'intervalle moyen entre paquets
        "max_start_time_diff": 5,               # Écart maximal entre les débuts de deux flows
        "max_flows_length": 5,                  # Longueur maximale d'un flow (nb de paquets)
        "flows_length_tolerance": 0.2           # Tolérance relative sur la longueur des flows
    },
    "long": {
        "min_correspondances": 6,
        "min_dominant_flag_share": 0.6,
        "min_dominant_payload_share": 0.6,
        "min_dominant_icmp_type_share": 0.6,
        "min_dominant_packet_share": 0.6,
        "packet_volume_tolerance": 0.3,
        "packet_interval_tolerance": 0.2,
        "max_start_time_diff": 30,
        "max_flows_length": 10,
        "flows_length_tolerance": 0.2
    }
}

# Seuils pour la comparaison de paquets individuels dans un scan source unique (SPS)
# Détection basée sur la répétition de paquets identiques (même flags/payload, même intervalle)
SPS_PACKET_COMPARISON_THRESHOLDS = {
    "short": {
        "min_repeated_packets_tcp":  15,   # Nb min de paquets répétés (TCP) pour déclencher
        "min_repeated_packets_udp":  10,
        "min_repeated_packets_icmp": 10,
    },
    "long": {
        "min_repeated_packets_tcp":  50,
        "min_repeated_packets_udp":  30,
        "min_repeated_packets_icmp": 30,
    }
}

# --------------------------
# DENIAL OF SERVICE
# --------------------------
# Seuils pour la comparaison de flows DDoS (multi-sources vers une victime)
DDOS_FLOW_COMPARISON_THRESHOLDS = {
    "short": {
        "min_correspondances": 5,
        "min_dominant_flag_share": 0.6,
        "min_dominant_payload_share": 0.7,
        "min_dominant_icmp_type_share": 0.7,
        "min_dominant_packet_share": 0.7,
        "packet_volume_tolerance": 0.2,
        "ratio_in_tolerance": 0.2,          # Tolérance sur le ratio paquets entrants/sortants
        "packet_interval_tolerance": 0.2,
        "max_start_time_diff": 5,
    },
    "long": {
        "min_correspondances": 6,
        "min_dominant_flag_share": 0.6,
        "min_dominant_payload_share": 0.6,
        "min_dominant_icmp_type_share": 0.6,
        "min_dominant_packet_share": 0.6,
        "packet_volume_tolerance": 0.3,
        "ratio_in_tolerance": 0.2,
        "packet_interval_tolerance": 0.3,
        "max_start_time_diff": 30,
    }
}

# Seuils pour la comparaison de paquets DoS (source unique)
DOS_PACKET_COMPARISON_THRESHOLDS = {
    "short": {
        "min_repeated_packets_tcp":  50,
        "min_repeated_packets_udp":  80,
        "min_repeated_packets_icmp": 80,
    },
    "long": {
        "min_repeated_packets_tcp":  200,
        "min_repeated_packets_udp":  300,
        "min_repeated_packets_icmp": 300,
    }
}

# --------------------------
# BRUTE FORCE
# --------------------------
# Ports typiquement ciblés lors d'attaques par brute force
# SSH (22), FTP (21), Telnet (23), SMTP (25/587), SMB (445), RDP (3389), VNC (5900)
BRUTE_FORCE_PORTS = {21, 22, 23, 25, 445, 587, 3389, 5900}

# Seuils pour la comparaison de flows brute force distribué (DBF)
DBF_FLOW_COMPARISON_THRESHOLDS = {
    "short": {
        "min_correspondances": 6,
        "min_dominant_flag_share": 0.7,         # Comportement automatisé typique (SYN/PSH dominant)
        "min_duration_tolerance": 0.2,          # Tolérance sur la durée des sessions
        "min_dominant_packet_share": 0.7,       # Payload d'authentification uniforme
        "packet_volume_tolerance": 0.2,
        "ratio_in_tolerance": 0.2,
        "packet_interval_tolerance": 0.2,
        "flows_length_tolerance": 0.2
    },
    "long": {
        "min_correspondances": 7,
        "min_dominant_flag_share": 0.6,
        "min_duration_tolerance": 0.2,
        "min_dominant_packet_share": 0.6,
        "packet_volume_tolerance": 0.3,
        "ratio_in_tolerance": 0.2,
        "packet_interval_tolerance": 0.3,
        "flows_length_tolerance": 0.2
    }
}

# Seuils pour la comparaison de paquets brute force source unique (SBF)
SBF_PACKET_COMPARISON_THRESHOLDS = {
    "short": {
        "min_repeated_packets": 10,   # Nb min de paquets répétés sur un port brute force
    },
    "long": {
        "min_repeated_packets": 30,
    }
}
