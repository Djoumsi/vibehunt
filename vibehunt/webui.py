"""Interface web locale de vibehunt.

Un serveur HTTP minimal (bibliothèque standard, aucune dépendance) qui offre
une interface graphique pour lancer des scans et visualiser les rapports, sans
passer par la ligne de commande. Pensé pour une démonstration (soutenance) et
pour les utilisateurs non techniciens.

Lancement : `vibehunt serve` puis ouvrir http://127.0.0.1:8000
Écoute uniquement en local (127.0.0.1) : l'outil clone et analyse du code, il
ne doit pas être exposé sur le réseau.
"""
from __future__ import annotations
import html
import json
import subprocess
import tempfile
import threading
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from . import engine, report, collector, sarif, webscan

_PAGE = """<!DOCTYPE html><html lang="fr"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>vibehunt</title>
<style>
:root {{ --bg:#f8fafc; --card:#fff; --fg:#0f172a; --muted:#64748b; --border:#e2e8f0; --accent:#2563eb; }}
@media (prefers-color-scheme:dark) {{ :root {{ --bg:#0f172a; --card:#1e293b; --fg:#e2e8f0; --muted:#94a3b8; --border:#334155; --accent:#60a5fa; }} }}
*{{box-sizing:border-box}} body{{margin:0;padding:24px 16px;background:var(--bg);color:var(--fg);
font-family:system-ui,-apple-system,Segoe UI,Roboto,sans-serif;line-height:1.5}}
.wrap{{max-width:920px;margin:0 auto}}
h1{{font-size:1.6rem;margin:0 0 2px}} .sub{{color:var(--muted);margin:0 0 24px}}
.card{{background:var(--card);border:1px solid var(--border);border-radius:12px;padding:20px;margin-bottom:18px}}
.card h2{{font-size:1.05rem;margin:0 0 12px}}
label{{display:block;font-size:.85rem;color:var(--muted);margin:10px 0 4px}}
input[type=text]{{width:100%;padding:10px 12px;border:1px solid var(--border);border-radius:8px;
background:var(--bg);color:var(--fg);font-size:.95rem}}
button{{margin-top:14px;background:var(--accent);color:#fff;border:0;border-radius:8px;
padding:11px 20px;font-size:.95rem;font-weight:600;cursor:pointer}}
button:hover{{opacity:.9}} .row{{display:flex;gap:12px;flex-wrap:wrap}} .row>div{{flex:1;min-width:200px}}
.tabs{{display:flex;gap:8px;margin-bottom:18px;flex-wrap:wrap}}
.tab{{padding:8px 16px;border:1px solid var(--border);border-radius:20px;cursor:pointer;
background:var(--card);color:var(--fg);text-decoration:none;font-size:.9rem}}
.tab.active{{background:var(--accent);color:#fff;border-color:var(--accent)}}
.hint{{font-size:.8rem;color:var(--muted);margin-top:8px}}
.result{{margin-top:20px}}
</style></head><body><div class="wrap">
<h1>🔍 vibehunt</h1>
<p class="sub">Scanner de sécurité pour applications vibe codées — interface locale</p>
<div class="tabs">
  <a class="tab {t_scan}" href="/">Scan statique</a>
  <a class="tab {t_url}" href="/url">App en ligne (URL)</a>
  <a class="tab {t_live}" href="/live">Vérification live (Supabase)</a>
  <a class="tab {t_hist}" href="/history">Comparatif</a>
</div>
{body}
</div></body></html>"""

_FORM_SCAN = """
<div class="card"><h2>Analyser un dépôt</h2>
<form method="post" action="/scan">
  <label>Chemin local ou URL GitHub</label>
  <input type="text" name="target" placeholder="https://github.com/moi/mon-app  ou  /chemin/vers/app" required>
  <p class="hint">Une URL est clonée temporairement. Fonctionne sur toute app, quel que soit l'outil qui l'a générée.</p>
  <button type="submit">Lancer le scan</button>
</form></div>
"""

_FORM_URL = """
<div class="card"><h2>Analyser une application en ligne (URL seule)</h2>
<p class="hint">Scan black-box passif d'une app déployée dont vous êtes propriétaire : en-têtes de sécurité, cookies, chemins sensibles, secrets dans le bundle JS, et test RLS Supabase automatique si des identifiants sont trouvés.</p>
<form method="post" action="/url">
  <label>URL de l'application</label>
  <input type="text" name="url" placeholder="https://mon-app.com" required>
  <button type="submit">Analyser l'app en ligne</button>
</form></div>
"""

_FORM_LIVE = """
<div class="card"><h2>Vérification dynamique — RLS Supabase</h2>
<p class="hint">À utiliser sur VOS applications uniquement. Teste si des tables répondent sans authentification (preuve que la RLS est désactivée). Preuve minimale, aucune donnée extraite.</p>
<form method="post" action="/live">
  <div class="row">
    <div><label>URL Supabase</label><input type="text" name="supabase_url" placeholder="https://xxxx.supabase.co" required></div>
    <div><label>Clé anon (publique)</label><input type="text" name="anon_key" required></div>
  </div>
  <label>Tables à tester (séparées par des virgules)</label>
  <input type="text" name="tables" placeholder="profiles, todos, messages, users">
  <button type="submit">Tester en direct</button>
</form></div>
"""


def _tabs(active):
    return {"t_scan": "active" if active == "scan" else "",
            "t_url": "active" if active == "url" else "",
            "t_live": "active" if active == "live" else "",
            "t_hist": "active" if active == "hist" else ""}


def _clone_if_url(target):
    if target.startswith(("http://", "https://", "git@")):
        tmp = tempfile.mkdtemp(prefix="vibehunt_web_")
        r = subprocess.run(["git", "clone", "--depth", "1", target, tmp],
                           capture_output=True, text=True, timeout=600)
        if r.returncode != 0:
            raise RuntimeError(r.stderr[-500:])
        return tmp
    return target


def _live_check(supabase_url, anon_key, tables):
    import urllib.request, urllib.error
    base = supabase_url.rstrip("/")
    tbls = [t.strip() for t in (tables or "users,profiles,todos,messages").split(",") if t.strip()]
    rows_out = []
    exposed = []
    for t in tbls:
        url = f"{base}/rest/v1/{t}?select=*&limit=1"
        req = urllib.request.Request(url, headers={"apikey": anon_key,
                                                   "Authorization": f"Bearer {anon_key}"})
        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                body = resp.read(2000).decode(errors="ignore")
                data = json.loads(body) if body.strip().startswith("[") else None
                if isinstance(data, list):
                    if data:
                        status, cls = "🔴 LISIBLE SANS AUTH (RLS off)", "#dc2626"
                        exposed.append(t)
                    else:
                        status, cls = "⚠️ répond (vide) — RLS probablement off", "#ca8a04"
                else:
                    status, cls = "réponse non tabulaire", "#64748b"
        except urllib.error.HTTPError as e:
            status, cls = (("✅ protégée (%d)" % e.code), "#16a34a") if e.code in (401, 403) else (f"HTTP {e.code}", "#64748b")
        except Exception as e:
            status, cls = (f"erreur : {e}", "#64748b")
        rows_out.append(f'<tr><td><code>{html.escape(t)}</code></td><td style="color:{cls}">{html.escape(status)}</td></tr>')
    banner = ""
    if exposed:
        banner = (f'<p style="color:#dc2626;font-weight:600">🔴 {len(exposed)} table(s) exposée(s) '
                  f'sans authentification : {html.escape(", ".join(exposed))}. '
                  'Correctif : activer la RLS + politiques d\'accès.</p>')
    return ('<div class="card result"><h2>Résultat de la vérification live</h2>'
            f'{banner}<table style="width:100%;border-collapse:collapse">'
            '<tr><th style="text-align:left">Table</th><th style="text-align:left">État</th></tr>'
            f'{"".join(rows_out)}</table></div>')


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):  # silencieux
        pass

    def _send(self, html_body, code=200):
        data = html_body.encode()
        self.send_response(code)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _page(self, active, body):
        d = _tabs(active)
        return _PAGE.format(body=body, **d)

    def do_GET(self):
        if self.path.startswith("/url"):
            self._send(self._page("url", _FORM_URL))
        elif self.path.startswith("/live"):
            self._send(self._page("live", _FORM_LIVE))
        elif self.path.startswith("/history"):
            self._send(self._page("hist", self._history_body()))
        else:
            self._send(self._page("scan", _FORM_SCAN))

    def _history_body(self):
        data = collector.comparison()
        apps = sorted(data["apps"], key=lambda a: (a["critique"], a["elevee"], a["total"]), reverse=True)
        if not apps:
            return '<div class="card"><p>Aucune collecte encore. Lance des scans pour comparer.</p></div>'
        rows = "".join(
            f'<tr><td>{html.escape(a["target"].split("/")[-1])}</td><td>{html.escape(a["platform"])}</td>'
            f'<td style="color:#dc2626">{a["critique"]}</td><td style="color:#ea580c">{a["elevee"]}</td>'
            f'<td>{a["moyenne"]}</td><td>{a["total"]}</td></tr>' for a in apps)
        spread = "".join(f"<li>{n} app(s) : {html.escape(t)}</li>" for t, n in data["failles_repandues"])
        return (f'<div class="card"><h2>Comparatif des apps scannées</h2>'
                '<table style="width:100%;border-collapse:collapse">'
                '<tr><th style="text-align:left">App</th><th style="text-align:left">Plateforme</th>'
                '<th>🔴</th><th>🟠</th><th>🟡</th><th>Total</th></tr>'
                f'{rows}</table></div>'
                f'<div class="card"><h2>Failles les plus répandues</h2><ul>{spread}</ul></div>')

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        raw = self.rfile.read(length).decode()
        params = {k: v[0] for k, v in urllib.parse.parse_qs(raw).items()}
        try:
            if self.path == "/scan":
                path = _clone_if_url(params.get("target", "").strip())
                result = engine.scan(path)
                collector.store(result)
                body = report.to_html(result)
                # on réinjecte le rapport dans l'onglet
                inner = body[body.find("<body>") + 6: body.rfind("</body>")]
                self._send(self._page("scan", _FORM_SCAN + f'<div class="result">{inner}</div>'))
            elif self.path == "/url":
                result = webscan.scan_url(params.get("url", "").strip())
                collector.store(result)
                full = report.to_html(result)
                inner = full[full.find("<body>") + 6: full.rfind("</body>")]
                self._send(self._page("url", _FORM_URL + f'<div class="result">{inner}</div>'))
            elif self.path == "/live":
                body = _live_check(params.get("supabase_url", ""), params.get("anon_key", ""),
                                   params.get("tables", ""))
                self._send(self._page("live", _FORM_LIVE + body))
            else:
                self._send(self._page("scan", _FORM_SCAN), 404)
        except Exception as e:
            err = f'<div class="card"><h2>Erreur</h2><p style="color:#dc2626">{html.escape(str(e))}</p></div>'
            self._send(self._page("scan", _FORM_SCAN + err), 500)


def serve(host="127.0.0.1", port=8000):
    srv = ThreadingHTTPServer((host, port), Handler)
    print(f"vibehunt — interface web sur http://{host}:{port}  (Ctrl+C pour arrêter)")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print("\narrêt.")
        srv.shutdown()
