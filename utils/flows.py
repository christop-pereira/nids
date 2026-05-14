"""
flows.py - Fonctions utilitaires pour l'analyse statistique des flows

Ce module fournit deux fonctions utilisées dans le calcul des statistiques
de flows (TCP, UDP, ICMP) :
  - get_dominant() : identifie la valeur la plus fréquente d'un Counter
  - calcul_mean_interval() : calcule l'intervalle moyen entre paquets consécutifs
"""

from collections import Counter


def get_dominant(counter):
    """
    Retourne la valeur dominante d'un Counter et sa part relative.

    Utilisé pour identifier par exemple :
      - Le flag TCP le plus utilisé dans un flow (ex: SYN dominant → scan ou DoS)
      - La taille de paquet la plus fréquente (uniformité = outil automatisé)
      - Le type ICMP le plus courant

    Args:
        counter (Counter): Compteur de valeurs quelconques

    Returns:
        tuple: (valeur_dominante, part_relative)
            - valeur_dominante : la valeur la plus fréquente (ou None si vide)
            - part_relative : proportion entre 0.0 et 1.0 (ou 0 si vide/total=0)
    """
    if not counter:
        return None, 0

    total = sum(counter.values())
    if total == 0:
        return None, 0

    dominant_value, dominant_count = counter.most_common(1)[0]
    return dominant_value, dominant_count / total


def calcul_mean_interval(timestamps):
    """
    Calcule l'intervalle moyen (en secondes) entre paquets consécutifs.

    Un intervalle faible et régulier est typique d'un outil automatisé
    (scanner, bot de brute force, flood DoS), contrairement à un trafic
    humain plus irrégulier.

    Args:
        timestamps (list[float]): Liste de timestamps Unix (peuvent être non triés)

    Returns:
        float: Intervalle moyen en secondes, ou 0 si moins de 2 timestamps
    """
    if len(timestamps) >= 2:
        timestamps = sorted(timestamps)
        intervals = [
            timestamps[i] - timestamps[i - 1]
            for i in range(1, len(timestamps))
        ]
        return sum(intervals) / len(intervals)
    else:
        return 0   # Pas assez de données pour calculer un intervalle
