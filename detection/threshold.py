"""
threshold.py - Orchestration de la détection par seuils (deux phases)

Ce module est le coeur de la pipeline de détection. Pour chaque IP analysée,
il applique une détection en deux phases :

  Phase 1 - Filtre par seuils (is_*_suspicious) :
    Vérifie rapidement si les métriques brutes (volume, nb IPs, nb ports)
    dépassent les seuils configurés. Peu coûteux, élimine les IPs innocentes.

  Phase 2 - Corrélation (are_packets/flows_correlated) :
    Analyse la structure fine des paquets ou des flows pour confirmer
    le pattern d'attaque. Plus coûteux, déclenché seulement si phase 1 positive.

Deux pipelines distinctes selon le sens d'analyse :
  - _threshold_detection_by_source : détecte les attaquants (DoS, SPS, SBF)
  - _threshold_detection_by_dest   : détecte les victimes (DDoS, DPS, DBF)
"""

from detection.distributed.dbf.threshold import is_dbf_suspicious
from detection.distributed.ddos.threshold import is_ddos_suspicious
from detection.distributed.dps.threshold import is_dps_suspicious
from detection.correlation import are_flows_correlated, are_packets_correlated
from detection.single.dos.threshold import is_dos_suspicious
from detection.single.sbf.threshold import is_sbf_suspicious
from detection.single.sps.threshold import is_sps_suspicious


def _get_set_of_ports(potential_victim):
    """
    Extrait l'ensemble des ports principaux actifs pour une IP donnée.

    Utilisé pour passer à la phase de corrélation uniquement les ports
    effectivement présents dans le trafic, réduisant le coût de l'analyse.

    Args:
        potential_victim (dict): Statistiques d'une IP, avec optionnellement
            la clé "volume_per_main_port" (Counter des ports principaux)

    Returns:
        set: Ensemble des ports actifs, ou set vide si aucun port présent
    """
    volume = potential_victim.get("volume_per_main_port")
    if not volume:
        return set()
    return set(volume.keys())


def _threshold_detection_by_source(window_label, proto, stats):
    """
    Détecte les attaques centralisées : DoS, SPS (port scan), SBF (brute force).

    Pour chaque IP source dans les stats, applique les deux phases :
      1. is_dos_suspicious  → si positif, are_packets_correlated("dos")
      2. is_sps_suspicious  → si positif, are_packets_correlated("sps")
      3. is_sbf_suspicious  → si positif, are_packets_correlated("sbf")

    Les trois types sont vérifiés indépendamment : une même IP peut déclencher
    plusieurs types simultanément (ex: DoS + SPS si elle flood et scanne).

    Args:
        window_label (str): "short" ou "long"
        proto (str): "tcp", "udp" ou "icmp"
        stats (dict): Statistiques retournées par get_threshold_stats(),
                      avec clés "per_ip" et "global"

    Returns:
        dict: {ip: {"dos": bool|None, "sps": bool|None, "sbf": bool|None}}
              None = seuil non atteint (phase 1 négative, phase 2 non exécutée)
              True/False = résultat de la corrélation (phase 2 exécutée)
    """
    stats_per_ip = stats["per_ip"]
    stats_global = stats["global"]
    suspicion_dict_by = {}

    for ip, potential_attacker in stats_per_ip.items():
        sps_ts = None
        dos_ts = None
        sbf_ts = None
        attacker_ip = ip

        # Phase 1 + 2 : DoS - volume élevé depuis une source unique
        if is_dos_suspicious(window_label, potential_attacker, stats_global):
            print("DOS")
            set_of_ports = _get_set_of_ports(potential_attacker)
            dos_ts = are_packets_correlated(attacker_ip, window_label, proto, "dos", set_of_ports)

        # Phase 1 + 2 : SPS - scan de ports (nombreux ports, distribution uniforme)
        if is_sps_suspicious(window_label, potential_attacker, proto):
            print("SPS")
            set_of_ports = _get_set_of_ports(potential_attacker)
            sps_ts = are_packets_correlated(attacker_ip, window_label, proto, "sps", set_of_ports)

        # Phase 1 + 2 : SBF - brute force (volume sur ports d'auth connus)
        if is_sbf_suspicious(window_label, potential_attacker, proto):
            print("SBF")
            set_of_ports = _get_set_of_ports(potential_attacker)
            sbf_ts = are_packets_correlated(attacker_ip, window_label, proto, "sbf", set_of_ports)

        suspicion_dict_by[attacker_ip] = {
            "dos": dos_ts,
            "sps": sps_ts,
            "sbf": sbf_ts
        }

    return suspicion_dict_by


def _threshold_detection_by_dest(window_label, proto, stats):
    """
    Détecte les attaques distribuées côté victime : DDoS, DPS, DBF.

    Pour chaque IP destination dans les stats, applique les deux phases :
      1. is_ddos_suspicious → si positif, are_flows_correlated("ddos")
      2. is_dps_suspicious  → si positif, are_flows_correlated("dps")
      3. is_dbf_suspicious  → si positif, are_flows_correlated("dbf")

    Contrairement aux attaques source (paquets individuels), les attaques
    distribuées sont confirmées par la corrélation de flows complets
    (are_flows_correlated), qui détecte des clusters de flows similaires.

    Args:
        window_label (str): "short" ou "long"
        proto (str): "tcp", "udp" ou "icmp"
        stats (dict): Statistiques retournées par get_threshold_stats()

    Returns:
        dict: {ip: {"ddos": bool|None, "dps": bool|None, "dbf": bool|None}}
    """
    stats_per_ip = stats["per_ip"]
    stats_global = stats["global"]
    suspicion_dict_by = {}

    for ip, potential_victim in stats_per_ip.items():
        dps_ts = None
        ddos_ts = None
        dbf_ts = None
        victim_ip = ip

        # Phase 1 + 2 : DDoS - volume massif depuis sources multiples
        if is_ddos_suspicious(window_label, potential_victim, stats_global):
            print("DDOS")
            set_of_ports = _get_set_of_ports(potential_victim)
            ddos_ts = are_flows_correlated(victim_ip, window_label, proto, "ddos", set_of_ports)

        # Phase 1 + 2 : DPS - scan distribué (ports multiples, sources multiples)
        if is_dps_suspicious(window_label, potential_victim, stats_global, proto):
            print("DPS")
            set_of_ports = _get_set_of_ports(potential_victim)
            dps_ts = are_flows_correlated(victim_ip, window_label, proto, "dps", set_of_ports)

        # Phase 1 + 2 : DBF - brute force distribué (ports d'auth, sources multiples)
        if is_dbf_suspicious(window_label, potential_victim, proto):
            print("DBF")
            set_of_ports = _get_set_of_ports(potential_victim)
            dbf_ts = are_flows_correlated(victim_ip, window_label, proto, "dbf", set_of_ports)

        suspicion_dict_by[victim_ip] = {
            "ddos": ddos_ts,
            "dps": dps_ts,
            "dbf": dbf_ts
        }

    return suspicion_dict_by


def threshold_detection(window_label, proto, stats, sorting_label):
    """
    Point d'entrée unifié pour la détection par seuils.

    Dispatche vers la pipeline source ou destination selon sorting_label.

    Args:
        window_label (str): "short" ou "long"
        proto (str): "tcp", "udp" ou "icmp"
        stats (dict): Statistiques retournées par get_threshold_stats()
        sorting_label (str): "source" (attaquants) ou "destination" (victimes)

    Returns:
        dict: Résultats de suspicion par IP (format dépend du sorting_label)
              None si sorting_label invalide
    """
    if sorting_label == "source":
        return _threshold_detection_by_source(window_label, proto, stats)
    elif sorting_label == "destination":
        return _threshold_detection_by_dest(window_label, proto, stats)
    else:
        return
