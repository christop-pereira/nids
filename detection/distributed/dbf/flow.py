"""
flow.py - Comparaison de flows pour la détection de Brute Force Distribué (DBF)

Ce module implémente la fonction de comparaison de deux flows TCP dans le cadre
d'une détection de brute force distribué (plusieurs IPs attaquant le même service).

La comparaison accumule un score de correspondance sur 11 critères. Si ce score
dépasse le seuil min_correspondances, les deux flows sont considérés similaires.
"""

from config import DBF_FLOW_COMPARISON_THRESHOLDS


def dbf_flow_comparison(flow1, flow2, window_label, proto):
    """
    Compare deux flows TCP pour détecter une similarité caractéristique
    d'une attaque par brute force distribué.

    Critères évalués (11 au total) :
      1.  Même flag dominant (SYN ou PSH typiques en brute force)
      2.  Forte dominance du flag (> seuil) → comportement automatisé/bot
      3.  Même port attaqué (ex: port 22 pour SSH)
      4.  Présence de RST dans les deux flows → tentatives rejetées (connexions échouées)
      5.  Durée de flow similaire → sessions courtes et répétitives
      6.  Taille de paquet dominante identique → payload d'auth uniforme
      7.  Forte dominance de la taille de paquet → requêtes standardisées par l'outil
      8.  Volume de paquets entrants similaire → cadence d'envoi régulière
      9.  Ratio in/out similaire → la victime répond peu ou uniformément (reject/deny)
      10. Rythme d'envoi similaire (intervalle moyen) → outil automatisé
      11. Flows de longueur similaire → nb de tentatives par session cohérent

    Args:
        flow1 (dict): Statistiques du premier flow (format retourné par tcp.py)
        flow2 (dict): Statistiques du deuxième flow
        window_label (str): "short" ou "long"
        proto (str): Protocole

    Returns:
        bool: True si les deux flows présentent suffisamment de similarités DBF
    """
    thresholds = DBF_FLOW_COMPARISON_THRESHOLDS[window_label]
    correspondances = 0

    def close(a, b, tol=0.2):
        """
        Vérifie si deux valeurs numériques sont proches avec une tolérance relative.

        Ex: close(100, 115, 0.2) → True (écart de 15% < 20%)

        Args:
            a, b (float): Valeurs à comparer
            tol (float): Tolérance relative (0.2 = 20%)

        Returns:
            bool: True si |a - b| / max(a, b) <= tol
        """
        if max(a, b) == 0:
            return True
        return abs(a - b) / max(a, b) <= tol

    # Critère 1 : même flag dominant (SYN ou PSH typiques en brute force)
    if flow1["dominant_flag"] == flow2["dominant_flag"]:
        correspondances += 1

    # Critère 2 : forte dominance du flag → comportement automatisé/bot
    if (flow1["share_of_dominant_flag"] > thresholds["min_dominant_flag_share"] and
            flow2["share_of_dominant_flag"] > thresholds["min_dominant_flag_share"]):
        correspondances += 1

    # Critère 3 : même port attaqué (même service ciblé)
    if flow1["main_port"] == flow2["main_port"]:
        correspondances += 1

    # Critère 4 : présence de RST/FIN → tentatives rejetées, caractéristiques du brute force
    if "RST" in flow1["flags_distribution"] and "RST" in flow2["flags_distribution"]:
        correspondances += 1

    # Critère 5 : durée de flow similaire → sessions courtes et répétitives
    if close(flow1["duration"], flow2["duration"], thresholds["min_duration_tolerance"]):
        correspondances += 1

    # Critère 6 : taille de paquet dominante identique → payload d'authentification uniforme
    if flow1["dominant_packets_size"] == flow2["dominant_packets_size"]:
        correspondances += 1

    # Critère 7 : forte dominance en taille de paquet → requêtes standardisées par l'outil
    if (flow1["share_of_dominant_packet_size"] > thresholds["min_dominant_packet_share"] and
            flow2["share_of_dominant_packet_size"] > thresholds["min_dominant_packet_share"]):
        correspondances += 1

    # Critère 8 : volume de paquets entrants similaire → cadence d'envoi régulière
    if close(flow1["nb_packets_main"], flow2["nb_packets_main"], thresholds["packet_volume_tolerance"]):
        correspondances += 1

    # Critère 9 : ratio in/out similaire → la victime répond peu ou de manière uniforme
    if close(flow1["ratio_in"], flow2["ratio_in"], thresholds["ratio_in_tolerance"]):
        correspondances += 1

    # Critère 10 : rythme d'envoi similaire → intervalle régulier = outil automatisé
    if close(flow1["mean_packet_interval"], flow2["mean_packet_interval"],
             thresholds["packet_interval_tolerance"]):
        correspondances += 1

    # Critère 11 : flows de longueur similaire → nb de tentatives par session cohérent
    if close(flow1["flows_length"], flow2["flows_length"], thresholds["flows_length_tolerance"]):
        correspondances += 1

    return correspondances >= thresholds["min_correspondances"]
