"""
events.py - Utilitaires d'accès et de filtrage des événements en mémoire

Ce module fournit des fonctions pour :
  - Parser les flags TCP depuis leur représentation hexadécimale
  - Filtrer les événements selon la fenêtre temporelle ("short" / "long")
  - Accéder aux structures d'événements correctes selon le protocole et le sens (source/destination)
  - Calculer des statistiques d'échange (nb de paquets de retour, parts relatives)
"""

import time
from collections import deque, defaultdict
from config import (
    SHORT_WINDOW,
    TCP_EVENTS_BY_SOURCE, TCP_EVENTS_BY_DEST,
    UDP_EVENTS_BY_SOURCE, UDP_EVENTS_BY_DEST,
    ICMP_EVENTS_BY_SOURCE, ICMP_EVENTS_BY_DEST
)


def parse_flags(flags):
    """
    Convertit les flags TCP depuis leur valeur hexadécimale vers une liste de noms.

    Exemples :
        "0x002" → ["SYN"]
        "0x012" → ["SYN", "ACK"]
        "0x000" → ["NULL"]

    Args:
        flags (str | int): Valeur hex des flags TCP (ex: "0x002" ou 18)

    Returns:
        list[str]: Liste des flags actifs parmi SYN, ACK, FIN, RST, PSH, URG
    """
    flags_int = int(flags, 16) if isinstance(flags, str) else int(flags)

    if flags_int == 0:
        return ["NULL"]

    result = []

    if flags_int & 0x02:
        result.append("SYN")   # Synchronize - ouverture de connexion
    if flags_int & 0x10:
        result.append("ACK")   # Acknowledge - accusé de réception
    if flags_int & 0x01:
        result.append("FIN")   # Finish - fermeture de connexion
    if flags_int & 0x04:
        result.append("RST")   # Reset - fermeture brutale
    if flags_int & 0x08:
        result.append("PSH")   # Push - envoi immédiat des données
    if flags_int & 0x20:
        result.append("URG")   # Urgent - données urgentes

    return result


def get_events_by_window(events, window_label):
    """
    Filtre les événements selon la fenêtre temporelle.

    - "long" : retourne tous les événements sans filtrage (fenêtre = durée totale de capture)
    - "short" : ne retourne que les paquets des SHORT_WINDOW dernières secondes

    Args:
        events (defaultdict): Structure d'événements (TCP/UDP/ICMP BY_SOURCE ou BY_DEST)
        window_label (str): "short" ou "long"

    Returns:
        defaultdict: Événements filtrés (même structure que l'entrée)
    """
    if window_label != "short":
        return events   # Fenêtre longue : pas de filtrage, on garde tout

    cutoff = time.time() - SHORT_WINDOW
    filtered = defaultdict(lambda: defaultdict(deque))

    for main_key, secondary in events.items():
        for sec_key, packets in secondary.items():
            # Ne conserve que les paquets plus récents que le cutoff
            recent = deque(p for p in packets if p[0] >= cutoff)
            if recent:
                filtered[main_key][sec_key] = recent

    return filtered


def get_correct_distributed_events(proto, window_label):
    """
    Retourne les événements indexés par destination (victime) pour un protocole donné.
    Utilisé pour la détection d'attaques distribuées (DDoS, DPS, DBF).

    Args:
        proto (str): "tcp", "udp" ou "icmp"
        window_label (str): "short" ou "long"

    Returns:
        defaultdict: Événements BY_DEST filtrés par fenêtre
    """
    if proto == "tcp":
        return get_events_by_window(TCP_EVENTS_BY_DEST, window_label)
    elif proto == "udp":
        return get_events_by_window(UDP_EVENTS_BY_DEST, window_label)
    elif proto == "icmp":
        return get_events_by_window(ICMP_EVENTS_BY_DEST, window_label)


def get_correct_single_events(proto, window_label):
    """
    Retourne les événements indexés par source (attaquant) pour un protocole donné.
    Utilisé pour la détection d'attaques centralisée (DoS, SPS, SBF).

    Args:
        proto (str): "tcp", "udp" ou "icmp"
        window_label (str): "short" ou "long"

    Returns:
        defaultdict: Événements BY_SOURCE filtrés par fenêtre
    """
    if proto == "tcp":
        return get_events_by_window(TCP_EVENTS_BY_SOURCE, window_label)
    elif proto == "udp":
        return get_events_by_window(UDP_EVENTS_BY_SOURCE, window_label)
    elif proto == "icmp":
        return get_events_by_window(ICMP_EVENTS_BY_SOURCE, window_label)


def get_correct_events(proto, window_label, sorting_label):
    """
    Point d'entrée unifié pour récupérer les événements selon le protocole,
    la fenêtre temporelle, et le sens d'analyse (source ou destination).

    Args:
        proto (str): "tcp", "udp" ou "icmp"
        window_label (str): "short" ou "long"
        sorting_label (str): "source" (attaquant) ou "destination" (victime)

    Returns:
        defaultdict: Structure d'événements correspondante
    """
    if sorting_label == "source":
        return get_correct_single_events(proto, window_label)
    elif sorting_label == "destination":
        return get_correct_distributed_events(proto, window_label)
    else:
        return


def tcp_udp_get_victim_len_exchange(victim_ip, victim_port, suspect_ip, suspect_port):
    """
    Retourne le nombre de paquets envoyés par la victime vers le suspect
    sur un échange TCP/UDP donné.

    Utilisé pour calculer le ratio in/out (paquets reçus vs envoyés),
    qui permet de détecter un comportement asymétrique typique des attaques.

    Args:
        victim_ip (str): IP de la victime (répondant)
        victim_port (int): Port de la victime
        suspect_ip (str): IP du suspect (initiateur)
        suspect_port (int): Port du suspect

    Returns:
        int: Nombre de paquets de réponse de la victime
    """
    packets = TCP_EVENTS_BY_SOURCE[(victim_ip, victim_port)][(suspect_ip, suspect_port)]
    return len(packets)


def icmp_get_victim_len_exchange(victim_ip, suspect_ip):
    """
    Retourne le nombre de paquets ICMP envoyés par la victime vers le suspect.

    Args:
        victim_ip (str): IP de la victime
        suspect_ip (str): IP du suspect

    Returns:
        int: Nombre de paquets de réponse de la victime
    """
    packets = ICMP_EVENTS_BY_SOURCE[victim_ip][suspect_ip]
    return len(packets)


def get_shares(counter_dict, total):
    """
    Calcule la part relative (proportion) de chaque valeur d'un Counter.

    Exemple :
        counter_dict = {"SYN": 80, "ACK": 20}, total = 100
        → {"SYN": 0.8, "ACK": 0.2}

    Args:
        counter_dict (dict): Compteur de valeurs
        total (int): Total des occurrences (dénominateur)

    Returns:
        dict: Dictionnaire {valeur: proportion (float entre 0 et 1)}
    """
    if total == 0:
        return {k: 0 for k in counter_dict}

    return {
        k: v / total
        for k, v in counter_dict.items()
    }
