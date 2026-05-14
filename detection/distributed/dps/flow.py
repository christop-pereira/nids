"""
flow.py - Comparaison de flows pour la détection de Port Scan Distribué (DPS)

Ce module compare deux flows reçus par une même victime afin de détecter
un port scan distribué : plusieurs sources différentes sondent les ports
de la victime de manière coordonnée.

La comparaison est adaptée au protocole (TCP, UDP, ICMP) pour les critères
spécifiques, puis applique des critères communs sur le comportement de scan.
"""

from config import DPS_FLOW_COMPARISON_THRESHOLDS


def dps_flow_comparison(flow1, flow2, window_label, proto):
    """
    Compare deux flows pour détecter une similarité caractéristique d'un port scan distribué.

    Critères TCP (3) :
      1. Même flag dominant (ex: SYN pur → SYN scan, NULL → NULL scan)
      2. Forte dominance du flag → comportement de sonde automatisée (nmap)
      3. Ports attaqués DIFFÉRENTS → chaque source sonde un port distinct (scan réparti)

    Critères UDP (3) :
      1. Même payload dominant → même outil de scan UDP
      2. Forte dominance du payload
      3. Ports attaqués DIFFÉRENTS

    Critères ICMP (2) :
      1. Même type ICMP dominant
      2. Forte dominance du type ICMP

    Critères communs à tous les protocoles (7) :
      4. Flows très courts (≤ max_flows_length paquets) → sonde, pas flood
      5. Longueur de flow similaire → même outil, même nombre de sondes par port
      6. Forte dominance en taille de paquet → sondes standardisées
      7. Part dominante similaire → uniformité des sondes entre sources
      8. Volume de paquets similaire → même cadence de scan
      9. Rythme d'envoi similaire → même cadence de scan
      10. Synchronisation temporelle → vague de scan coordonnée

    Args:
        flow1 (dict): Statistiques du premier flow
        flow2 (dict): Statistiques du deuxième flow
        window_label (str): "short" ou "long"
        proto (str): "tcp", "udp" ou "icmp"

    Returns:
        bool: True si les deux flows présentent suffisamment de similarités DPS
    """
    thresholds = DPS_FLOW_COMPARISON_THRESHOLDS[window_label]
    correspondances = 0

    def close(a, b, tol=0.2):
        """Vérifie si deux valeurs sont proches avec une tolérance relative."""
        if max(a, b) == 0:
            return True
        return abs(a - b) / max(a, b) <= tol

    # --- Critères spécifiques au protocole ---
    if proto == "tcp":
        # Critère 1 : même flag dominant → même technique de scan (SYN, FIN, NULL, XMAS…)
        if flow1["dominant_flag"] == flow2["dominant_flag"]:
            correspondances += 1
        # Critère 2 : forte dominance du flag → sondes pures, peu de variation
        if (flow1["share_of_dominant_flag"] > thresholds["min_dominant_flag_share"] and
                flow2["share_of_dominant_flag"] > thresholds["min_dominant_flag_share"]):
            correspondances += 1
        # Critère 3 : ports DIFFÉRENTS → chaque source sonde un port distinct (scan distribué)
        # C'est l'inverse du DDoS où tous les flows ciblent le même port
        if flow1["main_port"] != flow2["main_port"]:
            correspondances += 1

    elif proto == "udp":
        # Critère 1 : même payload dominant → même outil de scan UDP
        if flow1["dominant_payload"] == flow2["dominant_payload"]:
            correspondances += 1
        # Critère 2 : forte dominance du payload
        if (flow1["share_of_dominant_payload"] > thresholds["min_dominant_payload_share"] and
                flow2["share_of_dominant_payload"] > thresholds["min_dominant_payload_share"]):
            correspondances += 1
        # Critère 3 : ports DIFFÉRENTS
        if flow1["main_port"] != flow2["main_port"]:
            correspondances += 1

    elif proto == "icmp":
        # Critère 1 : même type ICMP dominant
        if flow1["dominant_icmp_type"] == flow2["dominant_icmp_type"]:
            correspondances += 1
        # Critère 2 : forte dominance du type ICMP
        if (flow1["share_of_dominant_icmp_type"] > thresholds["min_dominant_icmp_type_share"] and
                flow2["share_of_dominant_icmp_type"] > thresholds["min_dominant_icmp_type_share"]):
            correspondances += 1

    # --- Critères communs à tous les protocoles ---

    # Critère 4 : flows très courts → sonde rapide (1-2 paquets par port), pas un flood
    if (flow1["flows_length"] <= thresholds["max_flows_length"] and
            flow2["flows_length"] <= thresholds["max_flows_length"]):
        correspondances += 1

    # Critère 5 : longueur de flow similaire → même comportement de scan (même outil)
    if close(flow1["flows_length"], flow2["flows_length"], thresholds["flows_length_tolerance"]):
        correspondances += 1

    # Critère 6 : forte dominance en taille de paquet → sondes de taille standardisée
    if (flow1["share_of_dominant_packet_size"] > thresholds["min_dominant_packet_share"] and
            flow2["share_of_dominant_packet_size"] > thresholds["min_dominant_packet_share"]):
        correspondances += 1

    # Critère 7 : parts dominantes similaires entre les deux flows → uniformité des sondes
    if close(flow1["share_of_dominant_packet_size"], flow2["share_of_dominant_packet_size"],
             thresholds["min_dominant_packet_share"]):
        correspondances += 1

    # Critère 8 : volume de paquets similaire → cadence homogène entre sources
    if close(flow1["nb_packets_main"], flow2["nb_packets_main"], thresholds["packet_volume_tolerance"]):
        correspondances += 1

    # Critère 9 : rythme d'envoi similaire → même cadence de scan entre sources
    if close(flow1["mean_packet_interval"], flow2["mean_packet_interval"],
             thresholds["packet_interval_tolerance"]):
        correspondances += 1

    # Critère 10 : synchronisation temporelle → vague de scan coordonnée (même début)
    if abs(flow1["timestamps"][0] - flow2["timestamps"][0]) <= thresholds["max_start_time_diff"]:
        correspondances += 1

    return correspondances >= thresholds["min_correspondances"]
