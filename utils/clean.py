"""
clean.py - Nettoyage des événements expirés en mémoire

Ce module fournit deux fonctions utilitaires pour la gestion mémoire du NIDS :
  - clean_events()    : supprime les paquets trop anciens des structures d'événements
  - is_time_to_clean(): vérifie si le prochain cycle de nettoyage est dû

Le nettoyage est nécessaire car les structures TCP/UDP/ICMP_EVENTS_BY_* accumulent
des paquets en continu. Sans nettoyage, la mémoire croîtrait sans limite.
Seuls les paquets de la LONG_WINDOW (300s) sont conservés car c'est la fenêtre
la plus longue utilisée pour la détection.
"""

import time
from config import LAST_CLEANUP, CLEANUP_INTERVAL, LONG_WINDOW


def clean_events(events_dict):
    """
    Supprime les paquets expirés de toutes les deques d'une structure d'événements,
    puis supprime les entrées vides pour libérer la mémoire.

    Stratégie de nettoyage en trois passes :
      1. Pour chaque paire (source, destination), dépile les paquets anciens
         depuis le début de la deque (les paquets sont triés par timestamp croissant,
         donc les plus anciens sont en tête).
      2. Supprime les destinations dont la deque est devenue vide.
      3. Supprime les sources qui n'ont plus aucune destination active.

    Seuil de rétention : LONG_WINDOW (300s) - on garde les paquets des 5 dernières
    minutes car c'est la fenêtre maximale utilisée par la détection longue.

    Args:
        events_dict (defaultdict): Structure d'événements TCP, UDP ou ICMP
            Format : {src_key: {dst_key: deque(paquets)}}
            où src_key et dst_key sont des tuples (IP, port) ou juste IP pour ICMP
    """
    now = time.time()
    sources_to_delete = []

    for src_key, destinations in events_dict.items():
        destinations_to_delete = []

        for dst_key, packets in destinations.items():
            # Dépile les paquets expirés depuis la tête de la deque
            # (les paquets sont dans l'ordre chronologique : le plus ancien est à gauche)
            while packets and now - packets[0][0] > LONG_WINDOW:
                packets.popleft()

            # Si la deque est vide après nettoyage → marquer pour suppression
            if not packets:
                destinations_to_delete.append(dst_key)

        # Suppression différée des destinations vides
        for dst_key in destinations_to_delete:
            del destinations[dst_key]

        # Si cette source n'a plus aucune destination active → marquer pour suppression
        if not destinations:
            sources_to_delete.append(src_key)

    # Suppression différée des sources vides
    for src_key in sources_to_delete:
        del events_dict[src_key]


def is_time_to_clean():
    """
    Vérifie si l'intervalle de nettoyage (CLEANUP_INTERVAL secondes) est écoulé
    depuis le dernier nettoyage.

    Utilisé dans la boucle principale de main.py pour décider s'il faut
    lancer un cycle de nettoyage mémoire.

    Returns:
        bool: True si CLEANUP_INTERVAL secondes se sont écoulées depuis LAST_CLEANUP
    """
    now = time.time()
    if now - LAST_CLEANUP["time"] > CLEANUP_INTERVAL:
        return True
    return False
