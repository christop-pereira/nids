"""
clean.py - Nettoyage périodique des structures d'événements en mémoire

Ce module supprime les paquets trop anciens des tables d'événements
pour éviter une accumulation. Appelé périodiquement
depuis la boucle principale de main.py.
"""

import time
from config import (
    LAST_CLEANUP,
    TCP_EVENTS_BY_SOURCE, TCP_EVENTS_BY_DEST,
    UDP_EVENTS_BY_SOURCE, UDP_EVENTS_BY_DEST,
    ICMP_EVENTS_BY_SOURCE, ICMP_EVENTS_BY_DEST
)
from utils.clean import clean_events


def clean_tcp():
    """Supprime les anciens événements TCP (source et destination)."""
    clean_events(TCP_EVENTS_BY_SOURCE)
    clean_events(TCP_EVENTS_BY_DEST)


def clean_udp():
    """Supprime les anciens événements UDP (source et destination)."""
    clean_events(UDP_EVENTS_BY_SOURCE)
    clean_events(UDP_EVENTS_BY_DEST)


def clean_icmp():
    """Supprime les anciens événements ICMP (source et destination)."""
    clean_events(ICMP_EVENTS_BY_SOURCE)
    clean_events(ICMP_EVENTS_BY_DEST)


def clean():
    """
    Lance le nettoyage de toutes les structures d'événements (TCP, UDP, ICMP)
    et met à jour le timestamp du dernier nettoyage.
    """
    clean_tcp()
    clean_udp()
    clean_icmp()
    LAST_CLEANUP["time"] = time.time()
