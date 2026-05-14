"""
detect.py - Orchestration des cycles de détection périodique

Déclenche l'analyse des événements accumulés selon deux fenêtres temporelles :
  - "short" (60s) : détection réactive, seuils bas
  - "long" (300s) : détection sur le long terme, seuils plus élevés
"""

import time
from config import LAST_SHORT_DETECTION, LAST_LONG_DETECTION
from detection.analysis import analyse_by
from utils.detection import is_time_to_short_detect, is_time_to_long_detect


def detect():
    """
    Lance la détection si la fenêtre temporelle correspondante est écoulée.
    Analyse les événements depuis la source ET depuis la destination
    pour couvrir les attaques centralisées (DoS, brute force) et
    distribuées (DDoS, port scan distribué).
    """
    if is_time_to_short_detect():
        print("--- SHORT DETECTION ---")
        analyse_by("short", "source")       # Détecte attaques lancées depuis une IP source
        analyse_by("short", "destination")  # Détecte attaques reçues sur une IP destination
        LAST_SHORT_DETECTION["time"] = time.time()

    if is_time_to_long_detect():
        print("--- LONG DETECTION ---")
        analyse_by("long", "source")
        analyse_by("long", "destination")
        LAST_LONG_DETECTION["time"] = time.time()
