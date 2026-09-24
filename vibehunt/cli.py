"""vibehunt — interface en ligne de commande.

Usage :
    vibehunt scan <repo|url-github> [--json] [--out rapport.md] [--no-store]
    vibehunt stats
    vibehunt live <url-app> --supabase-url <url> --anon-key <clé>

'scan'  : analyse statique d'un dépôt (local ou GitHub, cloné en temp).
'stats' : statistiques agrégées de toutes les collectes.
'live'  : confirmation dynamique — teste si des tables Supabase répondent sans
          authentification (preuve que RLS est off). À utiliser SUR VOS apps.
"""
from __future__ import annotations
import argparse
import subprocess
import sys
import tempfile
from pathlib import Path

from . import engine, report, collector, sarif, webui


def _clone_if_url(target: str) -> tuple[str, bool]:
    if target.startswith(("http://", "https://", "git@")):
        tmp = tempfile.mkdtemp(prefix="vibehunt_")
        print(f"Clonage de {target} …")
        r = subprocess.run(["git", "clone", "--depth", "1", target, tmp],
                           capture_output=True, text=True)
        if r.returncode != 0:
            print(r.stderr, file=sys.stderr)
            sys.exit(2)
        return tmp, True
    return target, False


def cmd_scan(args):
    path, cloned = _clone_if_url(args.target)
    result = engine.scan(path)

    md = report.to_markdown(result)
    if args.json:
        print(report.to_json(result))
    else:
        print(md)

    if args.out:
        Path(args.out).write_text(md, encoding="utf-8")
        print(f"\nRapport Markdown écrit dans {args.out}", file=sys.stderr)

    if args.html:
        Path(args.html).write_text(report.to_html(result), encoding="utf-8")
        print(f"Rapport HTML écrit dans {args.html}", file=sys.stderr)

    if args.sarif:
        Path(args.sarif).write_text(sarif.to_sarif(result), encoding="utf-8")
        print(f"Rapport SARIF écrit dans {args.sarif}", file=sys.stderr)

    if not args.no_store:
        sid = collector.store(result, args.db)
        print(f"Findings collectés (scan #{sid}) dans {args.db}", file=sys.stderr)

    # code de sortie : 1 si au moins une faille critique/élevée (utile en CI)
    crit = any(f["severity"] in ("critique", "elevee") for f in result["findings"])
    sys.exit(1 if crit else 0)


def cmd_stats(args):
    import json
    print(json.dumps(collector.stats(args.db), ensure_ascii=False, indent=2))


def cmd_serve(args):
    webui.serve(host=args.host, port=args.port)


def cmd_report(args):
    """Comparatif des dernières collectes : classe les apps par risque et montre
    les failles les plus répandues (volet analyse du mémoire)."""
    data = collector.comparison(args.db)
    apps = sorted(data["apps"], key=lambda a: (a["critique"], a["elevee"], a["total"]), reverse=True)
    print("# Comparatif multi-apps — vibehunt\n")
    if not apps:
        print("Aucune collecte. Lance d'abord des scans (sans --no-store).")
        return
    print("| App | Plateforme | 🔴 Crit | 🟠 Élev | 🟡 Moy | Total |")
    print("|---|---|---|---|---|---|")
    for a in apps:
        name = a["target"].split("/")[-1]
        print(f"| {name} | {a['platform']} | {a['critique']} | {a['elevee']} | {a['moyenne']} | {a['total']} |")
    print("\n## Failles les plus répandues (nb d'apps concernées)\n")
    for title, n in data["failles_repandues"]:
        print(f"- {n} app(s) : {title}")


def cmd_live(args):
    """Confirmation dynamique de RLS off sur Supabase. Preuve minimale : on
    demande une seule ligne d'une table et on regarde si l'API répond sans
    authentification. NE dump PAS les données."""
    try:
        import urllib.request, urllib.error, json
    except ImportError:
        print("urllib requis", file=sys.stderr); sys.exit(2)

    base = args.supabase_url.rstrip("/")
    tables = args.tables.split(",") if args.tables else ["users", "profiles", "todos", "messages"]
    print(f"Test dynamique RLS sur {base} (preuve minimale, 1 ligne max)\n")
    exposed = []
    for t in tables:
        t = t.strip()
        url = f"{base}/rest/v1/{t}?select=*&limit=1"
        req = urllib.request.Request(url, headers={
            "apikey": args.anon_key, "Authorization": f"Bearer {args.anon_key}"})
        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                body = resp.read(2000).decode(errors="ignore")
                rows = json.loads(body) if body.strip().startswith("[") else None
                if isinstance(rows, list):
                    status = "🔴 LISIBLE SANS AUTH (RLS off)" if rows else "⚠️ répond (vide) — RLS probablement off"
                    if rows:
                        exposed.append(t)
                else:
                    status = "ok (réponse non tabulaire)"
        except urllib.error.HTTPError as e:
            status = "✅ protégée (401/403)" if e.code in (401, 403) else f"HTTP {e.code}"
        except Exception as e:
            status = f"erreur : {e}"
        print(f"  {t:20} {status}")
    if exposed:
        print(f"\n🔴 CRITIQUE : {len(exposed)} table(s) exposée(s) sans auth : {', '.join(exposed)}")
        print("Correctif : ENABLE ROW LEVEL SECURITY + politiques sur ces tables.")


def main(argv=None):
    p = argparse.ArgumentParser(prog="vibehunt",
                                description="Scanner de sécurité pour apps vibe codées.")
    p.add_argument("--db", default=str(collector.DEFAULT_DB), help="base SQLite de collecte")
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("scan", help="analyse statique d'un dépôt")
    s.add_argument("target", help="chemin local ou URL GitHub")
    s.add_argument("--json", action="store_true")
    s.add_argument("--out", help="écrire le rapport Markdown dans un fichier")
    s.add_argument("--html", help="écrire un rapport HTML autonome dans un fichier")
    s.add_argument("--sarif", help="écrire un rapport SARIF 2.1.0 (GitHub Code Scanning)")
    s.add_argument("--no-store", action="store_true", help="ne pas collecter en base")
    s.set_defaults(func=cmd_scan)

    st = sub.add_parser("stats", help="statistiques des collectes")
    st.set_defaults(func=cmd_stats)

    rp = sub.add_parser("report", help="rapport comparatif multi-apps depuis la collecte")
    rp.set_defaults(func=cmd_report)

    sv = sub.add_parser("serve", help="lancer l'interface web locale")
    sv.add_argument("--port", type=int, default=8000)
    sv.add_argument("--host", default="127.0.0.1")
    sv.set_defaults(func=cmd_serve)

    lv = sub.add_parser("live", help="confirmation dynamique RLS Supabase (vos apps)")
    lv.add_argument("url", help="URL de l'app (informatif)")
    lv.add_argument("--supabase-url", required=True)
    lv.add_argument("--anon-key", required=True)
    lv.add_argument("--tables", help="liste de tables séparées par des virgules")
    lv.set_defaults(func=cmd_live)

    args = p.parse_args(argv)
    args.func(args)


if __name__ == "__main__":
    main()
