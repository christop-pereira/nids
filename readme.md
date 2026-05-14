# NIDS - Network Intrusion Detection System

Système de détection d'intrusion réseau (NIDS) basé sur l'analyse de flows et la détection par seuils, développé en Python. Conçu pour un environnement réseau domestique (smart home), il capture le trafic en temps réel via **tshark** et détecte plusieurs classes d'attaques réseau sans inspection du payload.

---

## Attaques détectées

| Code | Nom | Description |
|------|-----|-------------|
| **DoS** | Denial of Service (source unique) | Flood massif depuis une seule IP |
| **DDoS** | Distributed Denial of Service | Flood coordonné depuis plusieurs IPs |
| **SPS** | Single-source Port Scan | Scan de ports depuis une seule IP (nmap) |
| **DPS** | Distributed Port Scan | Scan de ports réparti entre plusieurs IPs |
| **SBF** | Single-source Brute Force | Brute force SSH/RDP/FTP depuis une seule IP |
| **DBF** | Distributed Brute Force | Brute force coordonné depuis plusieurs IPs |
| **MITM** | Man-in-the-Middle (ARP Spoofing) | Falsification de la table ARP |

---

## Prérequis

- Python 3.10+
- [Wireshark / tshark](https://www.wireshark.org/) installé et accessible dans le PATH
- Droits suffisants pour capturer le trafic réseau (administrateur / sudo)

---

## Installation

```bash
git clone https://github.com/christop-pereira/nids.git
cd nids
```

---

## Configuration

Tous les paramètres sont centralisés dans `config.py` :

```python
INTERFACE = "Wi-Fi"            # Interface réseau à écouter
SHORT_WINDOW = 60              # Fenêtre courte d'analyse (secondes)
LONG_WINDOW = 300              # Fenêtre longue d'analyse (secondes)
CLEANUP_INTERVAL = 30          # Intervalle de nettoyage mémoire (secondes)
MAX_PACKETS_PER_SECOND = 5000  # Limite de paquets traités par seconde
MAX_FLOW_SIZE = 10_000         # Taille max d'un flow en mémoire
```

Les seuils de détection (volumes, nombre d'IPs, ports, etc.) sont également dans `config.py` sous les sections `GLOBAL_SOURCE_THRESHOLDS`, `GLOBAL_DEST_THRESHOLDS`, et les seuils de comparaison de flows/paquets (`*_FLOW_COMPARISON_THRESHOLDS`, `*_PACKET_COMPARISON_THRESHOLDS`).

---

## Lancement

```bash
# Lancer le NIDS (capture en temps réel)
python main.py

# Déclarer manuellement le début d'une attaque (pour les tests)
python declare_attack.py <type> <durée_secondes>
# Exemple :
python declare_attack.py dos 120
python declare_attack.py mitm 60
```
---

## Évaluation des performances

```bash
python evaluate.py --alerts alerts.log --attacks attacks.log
```

Exemple de sortie :

```
============================================================
DETECTION REPORT
============================================================

Per-attack verdict:
  [DETECTED (3 alerts)    ] dos                  (10s)
  [DETECTED (7 alerts)    ] ddos                 (10s)
  [MISSED                 ] sps                  (10s)

Attacks declared      : 3
Alerts raised         : 10
True positives  (TP)  : 10
False positives (FP)  : 0
False negatives (FN)  : 1

Precision : 100.00%  (alertes qui étaient de vraies attaques)
Recall    : 66.67%   (vraies attaques détectées)
F1 score  : 80.00%
============================================================
```

---

## Auteur

Christopher Pereira Tomas - Centre universitaire d'informatique, cours Advanced Security (2026)