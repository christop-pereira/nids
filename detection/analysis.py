"""
analysis.py - Orchestration de l'analyse de détection par seuils

Ce module fait le lien entre le calcul de statistiques (thresholds.py)
et les algorithmes de détection (threshold.py). Pour chaque protocole
et chaque fenêtre temporelle, il collecte les stats, applique la détection,
puis lève les alertes correspondantes.
"""

from core.alerts import raise_alert
from detection.threshold import threshold_detection
from stats.thresholds import get_threshold_stats


def analyse_by(window_label, sorting_label):
    """
    Lance l'analyse de détection pour tous les protocoles réseau.

    Pour chaque protocole (TCP, UDP, ICMP) :
      1. Calcule les statistiques agrégées des événements récents
      2. Applique les règles de détection par seuils
      3. Lève une alerte pour chaque IP suspecte détectée

    Args:
        window_label (str): Fenêtre temporelle d'analyse - "short" (60s) ou "long" (300s)
        sorting_label (str): Sens d'analyse - "source" (attaquant) ou "destination" (victime)
    """
    protos = ["tcp", "udp", "icmp"]

    for proto in protos:
        # Étape 1 : calcul des statistiques (nb paquets, nb IPs, ports ciblés, etc.)
        stats = get_threshold_stats(window_label, proto, sorting_label)

        # Étape 2 : détection - retourne un dict {ip: {attack_type: bool}}
        suspicions = threshold_detection(window_label, proto, stats, sorting_label)

        # Étape 3 : levée d'alerte pour chaque attaque confirmée
        for ip, suspicion_dict in suspicions.items():
            for attack_type, is_suspicious in suspicion_dict.items():
                if is_suspicious:
                    raise_alert(attack_type)
