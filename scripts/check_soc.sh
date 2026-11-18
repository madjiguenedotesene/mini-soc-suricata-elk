#!/usr/bin/env bash
# Vérifications rapides du SOC (à lancer sur l'hôte de la pile Docker)
set -euo pipefail
cd "$(dirname "$0")/.."
source .env

echo "== Conteneurs";              docker compose ps
echo "== Dernières alertes";        docker compose exec suricata sh -c 'tail -n 5 /var/log/suricata/fast.log' || true
echo "== Prison Fail2Ban";          docker compose exec fail2ban fail2ban-client status suricata || true
echo "== Documents indexés";       docker compose exec es01 curl -s --cacert config/certs/ca/ca.crt \
  -u "elastic:${ELASTIC_PASSWORD}" "https://localhost:9200/filebeat-*/_count?q=event.kind:alert"; echo
