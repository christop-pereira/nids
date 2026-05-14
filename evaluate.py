"""
evaluate.py - Évaluation des performances de détection du NIDS

Ce module compare les alertes générées par le NIDS (alerts.log)
avec les attaques réellement lancées (attacks.log) pour calculer
les métriques de performance classiques en détection d'intrusion :

  - Vrais Positifs  (TP) : alertes qui correspondent à une vraie attaque
  - Faux Positifs   (FP) : alertes sur du trafic légitime
  - Faux Négatifs   (FN) : attaques non détectées
  - Précision  : TP / (TP + FP)  - qualité des alertes
  - Rappel     : TP / (TP + FN)  - couverture des attaques
  - F1 Score   : moyenne harmonique de précision et rappel
"""

import argparse
import json
import sys
from datetime import datetime

# Mapping des types d'attaques vers leurs catégories génériques
# Permet de faire correspondre "tcp_dos" avec "dos", "ssh_brute_force" avec "sbf", etc.
CATEGORY_PATTERNS = {
    "dos": ["dos"],
    "ddos": ["ddos"],
    "sbf": ["brute force", "sbf"],
    "dbf": ["brute force", "dbf"],
    "sps": ["scan", "sps"],
    "dps": ["scan", "dps"],
    "mitm": ["mitm", "arp"],
}


def _category_of(declared_type):
    """
    Détermine la catégorie d'une attaque déclarée dans attacks.log.

    Logique :
      1. Si le type correspond exactement à une catégorie → retourne la catégorie
      2. Si le type se termine par un nom de catégorie → retourne cette catégorie
      3. Sinon → None (type inconnu)

    Args:
        declared_type (str): Type d'attaque déclaré (ex: "tcp_dos", "ddos", "ssh_brute_force")

    Returns:
        str | None: Catégorie normalisée ou None si non reconnue
    """
    declared = declared_type.lower()
    if declared in CATEGORY_PATTERNS:
        return declared
    for cat in CATEGORY_PATTERNS:
        if declared.endswith(cat):
            return cat
    return None


def _alert_category(scan_type):
    """
    Détermine la catégorie d'une alerte générée par le NIDS.

    Logique :
      1. Correspondance exacte avec une catégorie connue
      2. Recherche de patterns dans le type d'alerte (ex: "brute force" → "sbf")
      3. Sinon → None

    Args:
        scan_type (str): Type d'alerte (ex: "ddos", "mitm", "tcp_sps")

    Returns:
        str | None: Catégorie normalisée ou None si non reconnue
    """
    s = scan_type.lower()
    if s in CATEGORY_PATTERNS:
        return s
    for cat, patterns in CATEGORY_PATTERNS.items():
        if any(p in s for p in patterns):
            return cat
    return None


def _parse_iso_timestamp(s):
    """
    Convertit un timestamp.

    Args:
        s (str): Timestamp (ex: "2024-01-15T14:30:00")

    Returns:
        float: Timestamp correspondant
    """
    return datetime.fromisoformat(s).timestamp()


def _read_jsonl(path):
    """
    Lit un fichier JSON ligne par ligne.
    Ignore les lignes vides et affiche un warning pour les lignes mal formées.

    Args:
        path (str): Chemin du fichier JSONL

    Yields:
        dict: Entrée JSON parsée
    """
    try:
        with open(path) as f:
            for i, line in enumerate(f, start=1):
                line = line.strip()
                if not line:
                    continue
                try:
                    yield json.loads(line)
                except json.JSONDecodeError as e:
                    print(f"warning: {path}:{i}: malformed JSON ({e})", file=sys.stderr)
    except FileNotFoundError:
        print(f"error: {path} not found", file=sys.stderr)
        sys.exit(1)


def _load_alerts(path):
    """
    Charge et normalise les alertes depuis alerts.log.

    Args:
        path (str): Chemin du fichier d'alertes

    Returns:
        list[dict]: Liste d'alertes avec clés : ts (float), scan_type (str), category (str|None)
    """
    out = []
    for entry in _read_jsonl(path):
        raw = entry["timestamp"]
        try:
            ts = float(raw)
        except (ValueError, TypeError):
            ts = datetime.fromisoformat(raw).timestamp()
        scan_type = entry.get("scan_type", "")
        out.append({
            "ts": ts,
            "scan_type": scan_type,
            "category": _alert_category(scan_type),
        })
    return out


def _load_attacks(path):
    """
    Charge et normalise les attaques déclarées depuis attacks.log.

    Chaque attaque a un timestamp de début et une durée, permettant de définir
    une fenêtre temporelle dans laquelle les alertes sont considérées valides.

    Args:
        path (str): Chemin du fichier d'attaques

    Returns:
        list[dict]: Liste d'attaques avec clés :
            type (str), category (str|None), ts_start (float), ts_end (float)
    """
    out = []
    for entry in _read_jsonl(path):
        start = float(entry["timestamp_start"])
        duration = float(entry["duration"])
        out.append({
            "type": entry["type"],
            "category": _category_of(entry["type"]),
            "ts_start": start,
            "ts_end": start + duration,
        })
    return out


def _alert_matches_attack(alert, attack):
    """
    Détermine si une alerte correspond à une attaque déclarée.

    Critères de correspondance (les trois doivent être vérifiés) :
      1. La catégorie de l'alerte est connue (non None)
      2. La catégorie de l'attaque est connue (non None)
      3. Les catégories sont identiques
      4. Le timestamp de l'alerte est dans la fenêtre temporelle de l'attaque

    Args:
        alert (dict): Alerte avec clés ts et category
        attack (dict): Attaque avec clés ts_start, ts_end et category

    Returns:
        bool: True si l'alerte correspond à cette attaque
    """
    print(f"  Comparing [{attack['type']}] window "
          f"[{datetime.fromtimestamp(attack['ts_start'])} → {datetime.fromtimestamp(attack['ts_end'])}] "
          f"vs alert [{datetime.fromtimestamp(alert['ts'])}]")

    if alert["category"] is None or attack["category"] is None:
        return False
    if alert["category"] != attack["category"]:
        return False
    return attack["ts_start"] <= alert["ts"] <= attack["ts_end"]


def evaluate(alerts, attacks):
    """
    Calcule les métriques de performance du NIDS.

    Pour chaque alerte :
      - Si elle correspond à au moins une attaque → TP
      - Sinon → FP

    Pour chaque attaque :
      - Si aucune alerte ne la couvre → FN

    Args:
        alerts (list[dict]): Alertes chargées via _load_alerts()
        attacks (list[dict]): Attaques chargées via _load_attacks()

    Returns:
        dict: Métriques avec clés :
            nb_attacks, nb_alerts, true_positives, false_positives, false_negatives,
            precision, recall, f1, per_attack (liste de résultats par attaque)
    """
    tp = 0
    fp = 0

    detected_attacks = [False] * len(attacks)  # Indique si chaque attaque a été détectée
    matches_per_attack = [0] * len(attacks)  # Nb d'alertes correspondantes par attaque

    for alert in alerts:
        matched_any = False
        for i, attack in enumerate(attacks):
            if _alert_matches_attack(alert, attack):
                detected_attacks[i] = True
                matches_per_attack[i] += 1
                matched_any = True
        if matched_any:
            tp += 1
        else:
            fp += 1

    # FN = attaques sans aucune alerte correspondante
    fn = sum(1 for d in detected_attacks if not d)

    # Calcul des métriques (protection contre division par zéro)
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) else 0.0

    # Résultats détaillés par attaque
    per_attack = []
    for attack, detected, n_matches in zip(attacks, detected_attacks, matches_per_attack):
        per_attack.append({
            "type": attack["type"],
            "duration": attack["ts_end"] - attack["ts_start"],
            "detected": detected,
            "alerts_matched": n_matches,
        })

    return {
        "nb_attacks": len(attacks),
        "nb_alerts": len(alerts),
        "true_positives": tp,
        "false_positives": fp,
        "false_negatives": fn,
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "per_attack": per_attack,
    }


def _print_report(result):
    """
    Affiche le rapport de détection formaté dans la console.

    Args:
        result (dict): Résultat retourné par evaluate()
    """
    print("=" * 60)
    print("DETECTION REPORT")
    print("=" * 60)
    print()
    print("Per-attack verdict:")
    if not result["per_attack"]:
        print("  (no attacks declared)")
    for r in result["per_attack"]:
        verdict = f"DETECTED ({r['alerts_matched']} alerts)" if r["detected"] else "MISSED"
        print(f"  [{verdict:24}] {r['type']:20} ({r['duration']:.0f}s)")
    print()
    print(f"Attacks declared      : {result['nb_attacks']}")
    print(f"Alerts raised         : {result['nb_alerts']}")
    print(f"True positives  (TP)  : {result['true_positives']}")
    print(f"False positives (FP)  : {result['false_positives']}")
    print(f"False negatives (FN)  : {result['false_negatives']}")
    print()
    print(f"Precision : {result['precision']:.2%}  (alertes qui étaient de vraies attaques)")
    print(f"Recall    : {result['recall']:.2%}  (vraies attaques détectées)")
    print(f"F1 score  : {result['f1']:.2%}")
    print("=" * 60)


def main():
    """
    Point d'entrée CLI : parse les arguments, charge les fichiers et affiche le rapport.
    """
    parser = argparse.ArgumentParser()
    parser.add_argument("--alerts", default="alerts.log")
    parser.add_argument("--attacks", default="attacks.log")
    args = parser.parse_args()

    alerts = _load_alerts(args.alerts)
    attacks = _load_attacks(args.attacks)
    result = evaluate(alerts, attacks)
    _print_report(result)


if __name__ == "__main__":
    main()
