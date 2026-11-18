#!/usr/bin/env bash
# Démonstration hors ligne du Mini-SOC (aucune machine attaquée) :
#   PCAP du scénario -> Suricata -> eve.json -> test du filtre Fail2Ban -> graphiques
# Prérequis : suricata, fail2ban (fail2ban-regex), python3 + requirements.txt
set -euo pipefail
cd "$(dirname "$0")/.."

OUT=demo/output
rm -rf "$OUT" && mkdir -p "$OUT"

echo "[1/4] Génération de la capture réseau du scénario"
python3 demo/generate_pcap.py demo/scenario.pcap

echo "[2/4] Analyse de la capture par Suricata"
suricata -c /etc/suricata/suricata.yaml \
  -S suricata/rules/local.rules \
  --set 'vars.address-groups.HOME_NET=[10.10.0.0/24]' \
  -k none -r demo/scenario.pcap -l "$OUT" >/dev/null
echo "      $(grep -c '"event_type":"alert"' "$OUT/eve.json") alertes produites"

echo "[3/4] Test du filtre Fail2Ban sur eve.json"
fail2ban-regex "$OUT/eve.json" fail2ban/filter.d/suricata-alert.conf | grep -E "^Lines:"

echo "[4/4] Graphiques et fiche d'incident"
python3 demo/analyze_alerts.py "$OUT/eve.json" "$OUT"
