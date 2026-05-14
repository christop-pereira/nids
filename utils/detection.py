"""
detection.py - Utilitaires de temporisation pour les cycles de détection

Ce module détermine si les fenêtres temporelles SHORT et LONG sont écoulées
depuis la dernière détection, déclenchant ainsi un nouveau cycle d'analyse.

Fenêtres :
  - SHORT_WINDOW (60s)  : détection réactive, sensible aux attaques courtes
  - LONG_WINDOW (300s)  : détection sur la durée, résistante aux attaques lentes
"""

import time
from config import SHORT_WINDOW, LONG_WINDOW, LAST_SHORT_DETECTION, LAST_LONG_DETECTION


def is_time_to_short_detect():
    """
    Vérifie si la fenêtre courte (SHORT_WINDOW secondes) est écoulée
    depuis la dernière détection courte.

    Returns:
        bool: True si SHORT_WINDOW secondes se sont écoulées
    """
    now = time.time()
    if now - LAST_SHORT_DETECTION["time"] > SHORT_WINDOW:
        return True
    return False


def is_time_to_long_detect():
    """
    Vérifie si la fenêtre longue (LONG_WINDOW secondes) est écoulée
    depuis la dernière détection longue.

    Returns:
        bool: True si LONG_WINDOW secondes se sont écoulées
    """
    now = time.time()
    if now - LAST_LONG_DETECTION["time"] > LONG_WINDOW:
        return True
    return False


def is_time_to_detect():
    """
    Vérifie si au moins une des deux fenêtres de détection est écoulée.
    Utilisé dans la boucle principale de main.py pour décider s'il faut
    lancer un cycle de détection.

    Returns:
        bool: True si la détection courte OU longue doit être déclenchée
    """
    if is_time_to_short_detect() or is_time_to_long_detect():
        return True
    return False
