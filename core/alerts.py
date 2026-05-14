"""
alerts.py - Gestion de la file d'alertes et écriture dans le log

Ce module expose deux fonctions publiques :
  - raise_alert() : enfile une nouvelle alerte
  - alert()       : vide la file et écrit chaque alerte dans alerts.log (format JSONL)

Le passage par une file (deque) permet de découpler la détection (raise_alert)
de l'écriture (alert), qui est appelée depuis la boucle principale.
"""

import json
from collections import deque
from datetime import datetime

# Chemin du fichier de log des alertes (format JSON)
ALERTS_FILE = "alerts.log"

# File interne des alertes en attente d'écriture
_alert_queue = deque()


def raise_alert(scan_type):
    """
    Enfile une nouvelle alerte détectée.

    Cette fonction est appelée par les modules de détection dès qu'une
    activité suspecte est identifiée. L'alerte n'est pas encore écrite
    dans les logs à ce stade.

    Args:
        scan_type (str): Type d'attaque détectée (ex: "ddos", "sps", "mitm")
    """
    print(f"ALERTE : {scan_type}")
    _alert_queue.append({
        "timestamp": datetime.now(),
        "scan_type": scan_type,
    })


def _write_jsonl(record):
    """
    Sérialise une alerte au format JSON et l'ajoute dans alerts.log.

    Args:
        record (dict): Dictionnaire avec les clés "timestamp" et "scan_type"
    """
    payload = {
        "timestamp": record["timestamp"].isoformat(),
        "scan_type": record["scan_type"],
    }
    with open(ALERTS_FILE, "a") as f:
        f.write(json.dumps(payload, default=str) + "\n")


def alert():
    """
    Vide la file d'alertes et écrit chaque entrée dans le log.

    Appelée depuis la boucle principale de main.py après chaque cycle
    de détection.
    """
    while _alert_queue:
        a = _alert_queue.popleft()
        _write_jsonl(a)
