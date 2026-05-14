"""
flow.py - Comparaison de flows pour la détection DDoS

Ce module compare deux flows reçus par une même victime afin de détecter
une attaque DDoS distribuée (plusieurs sources coordonnées).

La comparaison est adaptée au protocole :
  - TCP  : basée sur les flags (ex: SYN flood) et le port ciblé
  - UDP  : basée sur le payload dominant et le port ciblé
  - ICMP : basée sur le type ICMP dominant (ex: Echo Request)

Les critères communs (4 à 9) s'appliquent à tous les protocoles.
"""

from config import DDOS_FLOW_COMPARISON_THRESHOLDS


def ddos_flow_comparison(flow1, flow2, window_label, proto):
    """
    Compare deux flows pour détecter une similarité caractéristique d'un DDoS.

    Critères TCP (3) :
      1. Même flag dominant (ex: SYN pur → SYN flood)
      2. Forte dominance du flag (> seuil) → comportement de bot automatisé
      3. Même port attaqué → cible commune identique

    Critères UDP (3) :
      1. Même payload dominant → même outil d'attaque
      2. Forte dominance du payload → trafic uniforme et automatisé
      3. Même port attaqué

    Critères ICMP (2) :
      1. Même type ICMP dominant (ex: type 8 = Echo Request pour Ping Flood)
      2. Forte dominance du type ICMP

    Critères communs à tous les protocoles (6) :
      4. Taille de paquet dominante identique → paquets de même gabarit
      5. Forte dominance en taille de paquet → uniformité = outil automatisé
      6. Volume de paquets similaire → cadence homogène entre attaquants
      7. Ratio in/out similaire → la victime ne répond pas (saturée ou drop)
      8. Synchronisation temporelle → vague d'attaque coordonnée (même début)
      9. Rythme d'envoi similaire → même outil, même cadence de flood

    Args:
        flow1 (dict): Statistiques du premier flow (format retourné par tcp/udp/icmp.py)
        flow2 (dict): Statistiques du deuxième flow
        window_label (str): "short" ou "long"
        proto (str): "tcp", "udp" ou "icmp"

    Returns:
        bool: True si les deux flows présentent suffisamment de similarités DDoS
    """
    thresholds = DDOS_FLOW_COMPARISON_THRESHOLDS[window_label]
    correspondances = 0

    def close(a, b, tol=0.2):
        """
        Vérifie si deux valeurs sont proches avec une tolérance relative.
        """
        if max(a, b) == 0:
            return True
        return abs(a - b) / max(a, b) <= tol

    # --- Critères spécifiques au protocole ---
    if proto == "tcp":
        # Critère 1 : même flag dominant (SYN pur typique d'un SYN flood)
        if flow1["dominant_flag"] == flow2["dominant_flag"]:
            correspondances += 1
        # Critère 2 : forte dominance du flag → pattern de bot (peu de variation)
        if (flow1["share_of_dominant_flag"] > thresholds["min_dominant_flag_share"] and
                flow2["share_of_dominant_flag"] > thresholds["min_dominant_flag_share"]):
            correspondances += 1
        # Critère 3 : même port attaqué → les sources ciblent le même service
        if flow1["main_port"] == flow2["main_port"]:
            correspondances += 1

    elif proto == "udp":
        # Critère 1 : même payload dominant → même contenu de paquet UDP forgé
        if flow1["dominant_payload"] == flow2["dominant_payload"]:
            correspondances += 1
        # Critère 2 : forte dominance du payload → trafic uniforme et automatisé
        if (flow1["share_of_dominant_payload"] > thresholds["min_dominant_payload_share"] and
                flow2["share_of_dominant_payload"] > thresholds["min_dominant_payload_share"]):
            correspondances += 1
        # Critère 3 : même port attaqué
        if flow1["main_port"] == flow2["main_port"]:
            correspondances += 1

    elif proto == "icmp":
        # Critère 1 : même type ICMP dominant (type 8 = Echo Request → Ping Flood)
        if flow1["dominant_icmp_type"] == flow2["dominant_icmp_type"]:
            correspondances += 1
        # Critère 2 : forte dominance du type → quasi-exclusivement ce type de paquet
        if (flow1["share_of_dominant_icmp_type"] > thresholds["min_dominant_icmp_type_share"] and
                flow2["share_of_dominant_icmp_type"] > thresholds["min_dominant_icmp_type_share"]):
            correspondances += 1

    # --- Critères communs à tous les protocoles ---

    # Critère 4 : taille de paquet dominante identique → paquets forgés de même gabarit
    if flow1["dominant_packets_size"] == flow2["dominant_packets_size"]:
        correspondances += 1

    # Critère 5 : forte dominance en taille de paquet → uniformité typique d'un outil
    if (flow1["share_of_dominant_packet_size"] > thresholds["min_dominant_packet_share"] and
            flow2["share_of_dominant_packet_size"] > thresholds["min_dominant_packet_share"]):
        correspondances += 1

    # Critère 6 : volume de paquets similaire → cadence homogène entre attaquants (botnet)
    if close(flow1["nb_packets_main"], flow2["nb_packets_main"], thresholds["packet_volume_tolerance"]):
        correspondances += 1

    # Critère 7 : ratio in/out similaire → la victime ne répond pas ou très peu
    if close(flow1["ratio_in"], flow2["ratio_in"], thresholds["ratio_in_tolerance"]):
        correspondances += 1

    # Critère 8 : synchronisation temporelle → vague coordonnée, même début d'attaque
    if abs(flow1["timestamps"][0] - flow2["timestamps"][0]) <= thresholds["max_start_time_diff"]:
        correspondances += 1

    # Critère 9 : rythme d'envoi similaire → même outil ou même configuration de flood
    if close(flow1["mean_packet_interval"], flow2["mean_packet_interval"],
             thresholds["packet_interval_tolerance"]):
        correspondances += 1

    return correspondances >= thresholds["min_correspondances"]
