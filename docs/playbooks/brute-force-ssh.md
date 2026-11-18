# Playbook SOC – Brute-force SSH

| | |
|---|---|
| **Signature** | `MINI-SOC Brute-force SSH probable` (SID 1000002, sévérité 1) |
| **Tactique MITRE ATT&CK** | Credential Access – [T1110.001 Password Guessing](https://attack.mitre.org/techniques/T1110/001/) |
| **Réponse automatique** | Fail2Ban : bannissement de la source après 3 alertes graves en 10 min |

## 1. Qualifier l'alerte (N1)
1. Dans Kibana › Discover, filtrer : `suricata.eve.alert.signature_id : 1000002`.
2. Identifier la **source** (`source.ip`), la **cible** (`destination.ip`) et la **fenêtre de temps**.
3. Vérifier si la source est interne (poste d'administration ?) ou externe.
4. Rechercher d'autres alertes de la même source : `source.ip : "<IP>"` (scan préalable ? tentative web ?).

## 2. Vérifier l'impact
1. Sur la cible : `sudo journalctl -u ssh --since "-1h" | grep -E "Accepted|Failed"`.
2. **Une ligne `Accepted` depuis la source = compromission possible → escalade N2 immédiate.**
3. Contrôler l'état du bannissement : `fail2ban-client status suricata`.

## 3. Contenir et remédier
- Source bannie automatiquement : confirmer, documenter.
- Faux positif (source légitime) : `fail2ban-client set suricata unbanip <IP>` puis ajouter l'IP à `ignoreip`.
- Durcissement : authentification SSH par clé uniquement (`PasswordAuthentication no`), pas de connexion root, port d'administration filtré.

## 4. Clôturer
Remplir la fiche d'incident : date, source, cible, chaîne d'attaque, action, statut (voir `docs/rapport_incident_demo.md`).
