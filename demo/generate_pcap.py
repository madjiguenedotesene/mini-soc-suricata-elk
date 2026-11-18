"""Génère une capture réseau (PCAP) rejouant le scénario d'attaque du Mini-SOC.

Scénario (≈ 12 minutes, réseau de laboratoire 10.10.0.0/24) :
  1. trafic légitime (HTTP, DNS) en fond ;
  2. ping de reconnaissance de l'attaquant ;
  3. scan de ports TCP SYN ;
  4. brute-force SSH (tentatives de connexion répétées) ;
  5. requête HTTP d'inclusion de fichier local (LFI).

La capture est rejouée hors ligne par Suricata (`suricata -r`) : aucune machine
réelle n'est attaquée. Usage : python demo/generate_pcap.py demo/scenario.pcap
"""

import random
import sys

from scapy.all import DNS, DNSQR, ICMP, IP, TCP, UDP, Raw, wrpcap

random.seed(42)

ATTACKER = "10.10.0.66"
TARGET = "10.10.0.10"          # serveur Ubuntu supervisé (SSH + web)
CLIENTS = ["10.10.0.21", "10.10.0.22", "10.10.0.23"]
DNS_SERVER = "10.10.0.1"
T0 = 1767985200.0              # 09/01/2026 20:00:00 (UTC+1), date du TP

packets = []


def add(pkt, t):
    pkt.time = t
    packets.append(pkt)


def tcp_session(src, dst, dport, t, payload_out=b"", payload_back=b""):
    """Session TCP complète : handshake, échange de données, fermeture."""
    sport = random.randint(32768, 60999)
    seq_c, seq_s = random.randint(1, 2**31), random.randint(1, 2**31)
    add(IP(src=src, dst=dst) / TCP(sport=sport, dport=dport, flags="S", seq=seq_c), t)
    add(IP(src=dst, dst=src) / TCP(sport=dport, dport=sport, flags="SA", seq=seq_s, ack=seq_c + 1), t + 0.001)
    add(IP(src=src, dst=dst) / TCP(sport=sport, dport=dport, flags="A", seq=seq_c + 1, ack=seq_s + 1), t + 0.002)
    seq_c += 1
    seq_s += 1
    if payload_out:
        add(IP(src=src, dst=dst) / TCP(sport=sport, dport=dport, flags="PA", seq=seq_c, ack=seq_s) / Raw(payload_out), t + 0.003)
        seq_c += len(payload_out)
    if payload_back:
        add(IP(src=dst, dst=src) / TCP(sport=dport, dport=sport, flags="PA", seq=seq_s, ack=seq_c) / Raw(payload_back), t + 0.004)
        seq_s += len(payload_back)
    add(IP(src=src, dst=dst) / TCP(sport=sport, dport=dport, flags="FA", seq=seq_c, ack=seq_s), t + 0.005)
    add(IP(src=dst, dst=src) / TCP(sport=dport, dport=sport, flags="FA", seq=seq_s, ack=seq_c + 1), t + 0.006)
    add(IP(src=src, dst=dst) / TCP(sport=sport, dport=dport, flags="A", seq=seq_c + 1, ack=seq_s + 1), t + 0.007)


def http_get(src, path, t):
    req = f"GET {path} HTTP/1.1\r\nHost: intranet.lab\r\nUser-Agent: Mozilla/5.0\r\n\r\n".encode()
    resp = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nContent-Type: text/html\r\n\r\nOK"
    tcp_session(src, TARGET, 80, t, req, resp)


# 1. Trafic légitime réparti sur toute la fenêtre
for i in range(60):
    t = T0 + i * 12 + random.random() * 5
    client = random.choice(CLIENTS)
    http_get(client, random.choice(["/", "/accueil", "/rapports", "/static/app.css"]), t)
    add(IP(src=client, dst=DNS_SERVER) / UDP(sport=random.randint(1024, 65000), dport=53)
        / DNS(rd=1, qd=DNSQR(qname="intranet.lab")), t + 1)

# 2. Reconnaissance ICMP (20:02)
for i in range(4):
    t = T0 + 120 + i
    add(IP(src=ATTACKER, dst=TARGET) / ICMP(type=8, id=1, seq=i), t)
    add(IP(src=TARGET, dst=ATTACKER) / ICMP(type=0, id=1, seq=i), t + 0.0005)

# 3. Scan de ports SYN (20:03) : 100 ports en ~5 s
for i, port in enumerate(random.sample(range(1, 1024), 100)):
    t = T0 + 180 + i * 0.05
    add(IP(src=ATTACKER, dst=TARGET) / TCP(sport=40000 + i, dport=port, flags="S"), t)
    flags = "SA" if port in (22, 80) else "RA"
    add(IP(src=TARGET, dst=ATTACKER) / TCP(sport=port, dport=40000 + i, flags=flags), t + 0.001)

# 4. Brute-force SSH (20:06) : 120 tentatives en ~2 minutes (type Hydra)
banner = b"SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13\r\n"
for i in range(120):
    t = T0 + 360 + i * 1.0 + random.random() * 0.3
    tcp_session(ATTACKER, TARGET, 22, t, b"SSH-2.0-libssh_0.10.6\r\n", banner)

# 5. Tentative LFI (20:09)
http_get(ATTACKER, "/index.php?page=../../../../etc/passwd", T0 + 540)

packets.sort(key=lambda p: p.time)
out = sys.argv[1] if len(sys.argv) > 1 else "demo/scenario.pcap"
wrpcap(out, packets)
print(f"{len(packets)} paquets écrits dans {out}")
