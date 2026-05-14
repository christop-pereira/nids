"""
declare_attack.py - Outil CLI pour déclarer manuellement le début d'une attaque

Ce script permet à l'opérateur de marquer le début et la durée d'une attaque
dans le fichier attacks.log, au format JSON Lines.

Ces entrées sont ensuite utilisées par evaluate.py pour calculer les métriques
de détection (TP, FP, FN, précision, rappel, F1).

Usage :
    python declare_attack.py <type> <duration_seconds>

Exemples :
    python declare_attack.py dos 120
    python declare_attack.py mitm 60
    python declare_attack.py ddos 300
"""

import json
import sys
import time

# Fichier de log des attaques déclarées (format JSON)
ATTACKS_FILE = "attacks.log"


def declare_attack(attack_type, duration=60):
    """
    Enregistre une attaque dans attacks.log avec le timestamp courant.

    Le timestamp de début est l'heure à laquelle la fonction est appelée.
    La durée permet à evaluate.py de définir la fenêtre temporelle
    dans laquelle les alertes du NIDS sont considérées comme des vrais positifs.

    Args:
        attack_type (str): Type d'attaque (ex: "dos", "ddos", "mitm", "sps")
        duration (float): Durée de l'attaque en secondes (défaut: 60)

    Returns:
        dict: L'entrée enregistrée (type, timestamp_start, duration)
    """
    entry = {
        "type": attack_type,
        "timestamp_start": time.time(),
        "duration": float(duration),
    }
    with open(ATTACKS_FILE, "a") as f:
        f.write(json.dumps(entry) + "\n")
    return entry


def _main():
    """
    Point d'entrée CLI : valide les arguments et appelle declare_attack().
    Affiche une erreur et quitte avec code 2 en cas d'arguments invalides.
    """
    if len(sys.argv) != 3:
        print("Usage: python declare_attack.py <type> <duration_seconds>", file=sys.stderr)
        sys.exit(2)

    attack_type, duration_str = sys.argv[1:]
    try:
        duration = float(duration_str)
    except ValueError:
        print(f"Invalid duration {duration_str!r}", file=sys.stderr)
        sys.exit(2)

    declare_attack(attack_type, duration=duration)
    print(f"Declared {attack_type} for {duration:.0f}s")


if __name__ == "__main__":
    _main()
