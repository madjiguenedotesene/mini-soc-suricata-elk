# Rapport d'incident – démonstration Mini-SOC

- Événements analysés par Suricata : **676**
- Alertes : **31** dont **27** de sévérité 1-2
- Sources bannies (simulation Fail2Ban, 3 alertes graves en 10 min) : **1**

| SID | Signature | Sévérité | Alertes |
|---|---|---|---|
| 1000001 | MINI-SOC ICMP echo vers le réseau surveillé | 3 | 4 |
| 1000002 | MINI-SOC Brute-force SSH probable | 1 | 23 |
| 1000003 | MINI-SOC Scan de ports TCP SYN | 2 | 3 |
| 1000004 | MINI-SOC Tentative LFI (traversée de répertoire) | 1 | 1 |

## Fiche d'incident – source 10.10.0.66

- **Première alerte** : 09/01/2026 20:02:00 (Ping ICMP)
- **Bannissement** : 20:06:04, soit 244 s après la première alerte
- **Cible** : 10.10.0.10
- **Chaîne d'attaque** : Ping ICMP → Scan de ports → Brute-force SSH → Tentative LFI
- **Action** : blocage de tous les ports de la source (iptables-allports)
- **Effet** : en conditions réelles, les 24 alertes postérieures au bannissement (fin du brute-force, tentative LFI) n'auraient pas eu lieu : les paquets de la source sont rejetés par le pare-feu
