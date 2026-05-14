"""
main.py - Point d'entrée du NIDS (Network Intrusion Detection System)

Lance tshark en sous-processus pour capturer les paquets réseau en temps réel,
les parse ligne par ligne, applique un rate limiting, puis délègue le traitement
à process(), detect() et clean().
"""

import subprocess
from datetime import datetime
import time
from core.alerts import alert
from core.detect import detect
from core.process import process
from utils.detection import is_time_to_detect
from utils.clean import is_time_to_clean
from core.clean import clean
from config import INTERFACE, MAX_PACKETS_PER_SECOND

# Chemin vers l'exécutable tshark (Wireshark CLI) sur Windows
TSHARK_PATH = r"C:\Program Files\Wireshark\tshark.exe"

# Commande tshark : capture sur l'interface configurée, sortie en champs séparés par '|'
cmd = [
    TSHARK_PATH,
    "-i", INTERFACE,              # Interface réseau à écouter (ex: "Wi-Fi")
    "-l",                         # Mode ligne par ligne

    "-T", "fields",               # Format de sortie : champs individuels
    "-E", "separator=|",          # Séparateur entre champs

    "-e", "frame.time_epoch",     # Timestamp
    "-e", "ip.src",               # IP source
    "-e", "ip.dst",               # IP destination

    "-e", "tcp.srcport",          # Port source TCP
    "-e", "tcp.dstport",          # Port destination TCP
    "-e", "tcp.flags",            # Flags TCP (en hexadécimal)

    "-e", "udp.srcport",          # Port source UDP
    "-e", "udp.dstport",          # Port destination UDP

    "-e", "icmp.type",            # Type ICMP (ex: 8 = Echo Request)

    "-e", "frame.len",            # Taille totale du paquet en octets

    "-e", "arp.src.proto_ipv4",   # IP source de la trame ARP
    "-e", "arp.src.hw_mac",       # MAC source de la trame ARP
]

# Lancement du sous-processus tshark : stdout est lu ligne par ligne
process_tshark = subprocess.Popen(cmd, stdout=subprocess.PIPE, text=True)
print(f"Start of the NIDS... ({datetime.now().strftime('%Y-%m-%d %H:%M:%S')})")

# Compteur de paquets pour le rate limiting (fenêtre glissante d'1 seconde)
packet_count = 0
window_start = time.time()

# Boucle principale : chaque ligne de tshark correspond à un paquet capturé
for line in process_tshark.stdout:
    fields = line.strip().split("|")

    # --- Rate Limiting ---
    # Réinitialise le compteur à chaque nouvelle fenêtre d'1 seconde
    now = time.time()
    if now - window_start >= 1.0:
        packet_count = 0
        window_start = now

    # Si le quota de paquets par seconde est atteint, on ignore ce paquet
    if packet_count >= MAX_PACKETS_PER_SECOND:
        continue

    packet_count += 1
    # ---------------------

    # Déstructuration des 12 champs extraits par tshark
    (ts, ip_src, ip_dst, tcp_src, tcp_dst, tcp_flags,
     udp_src, udp_dst, icmp_type, pkt_len, arp_ip, arp_mac) = fields

    # Construction du dictionnaire représentant le paquet normalisé
    packet = {
        "timestamp": float(ts) if ts else None,       # Timestamp (float)
        "ip_src": ip_src,                             # IP source (str)
        "ip_dst": ip_dst,                             # IP destination (str)
        "tcp_src": tcp_src,                           # Port TCP source (str ou "")
        "tcp_dst": tcp_dst,                           # Port TCP destination (str ou "")
        "tcp_flags": tcp_flags,                       # Flags TCP hex (str ou "")
        "udp_src": udp_src,                           # Port UDP source (str ou "")
        "udp_dst": udp_dst,                           # Port UDP destination (str ou "")
        "icmp_type": icmp_type,                       # Type ICMP (str ou "")
        "size": int(pkt_len) if pkt_len else 0,       # Taille (int)
        "arp_ip": arp_ip,                             # IP de la trame ARP (str ou "")
        "arp_mac": arp_mac,                           # MAC de la trame ARP (str ou "")
    }

    # Traitement du paquet : enregistrement dans les structures de données internes
    process(packet)

    # Déclenchement périodique de la détection (court et long terme)
    if is_time_to_detect():
        detect()   # Analyse les événements accumulés et lève des alertes si besoin
        alert()    # Vide la file d'alertes et les écrit dans le log

    # Nettoyage périodique des anciennes entrées en mémoire
    if is_time_to_clean():
        clean()
