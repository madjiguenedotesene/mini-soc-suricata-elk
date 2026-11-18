"""Analyse les alertes Suricata (eve.json) : graphiques et fiche d'incident.

Usage : python demo/analyze_alerts.py <eve.json> <dossier_sortie>

Produit :
  - alertes_par_minute.png   : chronologie des alertes, par signature
  - alertes_par_signature.png: volume d'alertes par signature
  - rapport_incident.md      : synthèse et décision de bannissement simulée
    (mêmes paramètres que la prison Fail2Ban : 3 alertes graves en 10 minutes)
"""

import json
import sys
from collections import Counter, defaultdict
from datetime import datetime, timedelta
from pathlib import Path
from zoneinfo import ZoneInfo

import matplotlib

matplotlib.use("Agg")
import matplotlib.dates as mdates  # noqa: E402
import matplotlib.pyplot as plt  # noqa: E402

PARIS = ZoneInfo("Europe/Paris")
MAXRETRY, FINDTIME = 3, timedelta(minutes=10)  # identiques à fail2ban/jail.d/suricata.local

# Palette catégorielle validée (ordre fixe, une couleur par signature)
SURFACE, INK, INK_2, GRID = "#fcfcfb", "#0b0b0b", "#52514e", "#e4e3df"
COLORS = {
    1000002: "#2a78d6",  # Brute-force SSH
    1000003: "#eb6834",  # Scan de ports
    1000004: "#1baf7a",  # LFI
    1000001: "#eda100",  # ICMP
}
SHORT = {
    1000001: "Ping ICMP",
    1000002: "Brute-force SSH",
    1000003: "Scan de ports",
    1000004: "Tentative LFI",
}


def load_alerts(path):
    alerts = []
    with open(path, encoding="utf-8") as f:
        for line in f:
            ev = json.loads(line)
            if ev.get("event_type") != "alert":
                continue
            ts = datetime.strptime(ev["timestamp"], "%Y-%m-%dT%H:%M:%S.%f%z").astimezone(PARIS)
            a = ev["alert"]
            alerts.append({"ts": ts, "src": ev["src_ip"], "dst": ev.get("dest_ip"),
                           "dport": ev.get("dest_port"), "sid": a["signature_id"],
                           "sig": a["signature"], "sev": a["severity"]})
    return sorted(alerts, key=lambda x: x["ts"])


def simulate_fail2ban(alerts):
    """Reproduit la logique de la prison : bannit à la 3e alerte grave en 10 min."""
    hits, bans = defaultdict(list), {}
    for a in alerts:
        if a["sev"] > 2 or a["src"] in bans:
            continue
        window = [t for t in hits[a["src"]] if a["ts"] - t <= FINDTIME] + [a["ts"]]
        hits[a["src"]] = window
        if len(window) >= MAXRETRY:
            bans[a["src"]] = a["ts"]
    return bans


def style(ax):
    ax.set_facecolor(SURFACE)
    for side in ("top", "right", "left"):
        ax.spines[side].set_visible(False)
    ax.spines["bottom"].set_color(GRID)
    ax.tick_params(colors=INK_2, labelsize=10, length=0)
    ax.grid(axis="y", color=GRID, linewidth=0.8)
    ax.set_axisbelow(True)


def chart_timeline(alerts, bans, out):
    t0 = alerts[0]["ts"].replace(second=0, microsecond=0)
    t_end = alerts[-1]["ts"].replace(second=0, microsecond=0)
    minutes = [t0 + timedelta(minutes=i) for i in range(int((t_end - t0).total_seconds() // 60) + 2)]
    counts = {sid: Counter() for sid in COLORS}
    for a in alerts:
        counts[a["sid"]][a["ts"].replace(second=0, microsecond=0)] += 1

    fig, ax = plt.subplots(figsize=(10, 4.2), dpi=200)
    fig.patch.set_facecolor(SURFACE)
    style(ax)
    width = timedelta(seconds=44)
    bottom = [0] * len(minutes)
    for sid in [1000001, 1000003, 1000002, 1000004]:
        vals = [counts[sid][m] for m in minutes]
        if not any(vals):
            continue
        ax.bar([m + timedelta(seconds=30) for m in minutes], vals, width=width, bottom=bottom,
               color=COLORS[sid], label=SHORT[sid], edgecolor=SURFACE, linewidth=1.5)
        bottom = [b + v for b, v in zip(bottom, vals)]
    for src, t in bans.items():
        ax.axvline(t, color=INK, linewidth=1.2, linestyle=(0, (4, 3)))
        ax.annotate(f"Bannissement Fail2Ban\n{src} à {t:%H:%M:%S}", xy=(t, max(bottom) * 0.6),
                    xytext=(-8, 0), textcoords="offset points", fontsize=9, color=INK,
                    va="center", ha="right")
    ax.set_ylim(0, max(bottom) * 1.2)
    ax.xaxis.set_major_formatter(mdates.DateFormatter("%H:%M", tz=PARIS))
    ax.set_ylabel("Alertes par minute", color=INK_2, fontsize=10)
    ax.set_title("Chronologie de l'attaque détectée par Suricata", loc="left", color=INK,
                 fontsize=13, fontweight="bold", pad=24)
    ax.legend(loc="upper left", bbox_to_anchor=(0, 1.08), ncol=4, frameon=False,
              fontsize=9, labelcolor=INK_2, handlelength=1, handleheight=1)
    fig.tight_layout()
    fig.savefig(out, facecolor=SURFACE)
    plt.close(fig)


def chart_by_signature(alerts, out):
    c = Counter(a["sid"] for a in alerts)
    sids = sorted(c, key=c.get)
    fig, ax = plt.subplots(figsize=(10, 3.2), dpi=200)
    fig.patch.set_facecolor(SURFACE)
    style(ax)
    ax.grid(False)
    labels = [f"{SHORT[s]}  (sévérité {next(a['sev'] for a in alerts if a['sid'] == s)})" for s in sids]
    bars = ax.barh(labels, [c[s] for s in sids], color=[COLORS[s] for s in sids], height=0.55)
    for b, s in zip(bars, sids):
        ax.text(b.get_width() + 0.3, b.get_y() + b.get_height() / 2, str(c[s]),
                va="center", fontsize=10, color=INK)
    ax.set_xticks([])
    ax.spines["bottom"].set_visible(False)
    ax.set_title("Alertes par signature", loc="left", color=INK, fontsize=13, fontweight="bold")
    fig.tight_layout()
    fig.savefig(out, facecolor=SURFACE)
    plt.close(fig)


def write_report(alerts, bans, total_events, out):
    severe = [a for a in alerts if a["sev"] <= 2]
    c = Counter((a["sid"], a["sig"], a["sev"]) for a in alerts)
    lines = [
        "# Rapport d'incident – démonstration Mini-SOC",
        "",
        f"- Événements analysés par Suricata : **{total_events}**",
        f"- Alertes : **{len(alerts)}** dont **{len(severe)}** de sévérité 1-2",
        f"- Sources bannies (simulation Fail2Ban, {MAXRETRY} alertes graves en "
        f"{int(FINDTIME.total_seconds() // 60)} min) : **{len(bans)}**",
        "",
        "| SID | Signature | Sévérité | Alertes |",
        "|---|---|---|---|",
    ]
    lines += [f"| {sid} | {sig} | {sev} | {n} |" for (sid, sig, sev), n in sorted(c.items())]
    for src, t in bans.items():
        first = next(a for a in alerts if a["src"] == src)
        to_ban = (t - first["ts"]).total_seconds()
        lines += [
            "",
            f"## Fiche d'incident – source {src}",
            "",
            f"- **Première alerte** : {first['ts']:%d/%m/%Y %H:%M:%S} ({SHORT[first['sid']]})",
            f"- **Bannissement** : {t:%H:%M:%S}, soit {to_ban:.0f} s après la première alerte",
            f"- **Cible** : {first['dst']}",
            "- **Chaîne d'attaque** : " + " → ".join(dict.fromkeys(SHORT[a['sid']] for a in alerts if a['src'] == src)),
            "- **Action** : blocage de tous les ports de la source (iptables-allports)",
            f"- **Effet** : en conditions réelles, les {sum(1 for a in alerts if a['src'] == src and a['ts'] > t)} "
            "alertes postérieures au bannissement (fin du brute-force, tentative LFI) "
            "n'auraient pas eu lieu : les paquets de la source sont rejetés par le pare-feu",
        ]
    Path(out).write_text("\n".join(lines) + "\n", encoding="utf-8")


def main():
    eve, out_dir = sys.argv[1], Path(sys.argv[2])
    out_dir.mkdir(parents=True, exist_ok=True)
    with open(eve, encoding="utf-8") as f:
        total_events = sum(1 for _ in f)
    alerts = load_alerts(eve)
    if not alerts:
        sys.exit("Aucune alerte trouvée dans " + eve)
    bans = simulate_fail2ban(alerts)
    chart_timeline(alerts, bans, out_dir / "alertes_par_minute.png")
    chart_by_signature(alerts, out_dir / "alertes_par_signature.png")
    write_report(alerts, bans, total_events, out_dir / "rapport_incident.md")
    print(f"{len(alerts)} alertes, {len(bans)} source(s) bannie(s) -> {out_dir}")


if __name__ == "__main__":
    main()
