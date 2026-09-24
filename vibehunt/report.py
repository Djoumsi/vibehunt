"""Génération du rapport : Markdown lisible + JSON machine."""
from __future__ import annotations
import json

SEV_LABEL = {"critique": "🔴 CRITIQUE", "elevee": "🟠 ÉLEVÉE",
             "moyenne": "🟡 MOYENNE", "faible": "⚪ FAIBLE", "info": "ℹ️ INFO"}
CONF_LABEL = {"confirme": "confirmé", "probable": "probable", "a_verifier": "à vérifier"}


def to_json(result: dict) -> str:
    return json.dumps(result, ensure_ascii=False, indent=2)


def to_markdown(result: dict) -> str:
    f = result["findings"]
    counts = {}
    for x in f:
        counts[x["severity"]] = counts.get(x["severity"], 0) + 1

    out = []
    out.append(f"# Rapport vibehunt — {result['target']}\n")
    out.append(f"- **Plateforme détectée** : {result['platform']}")
    out.append(f"- **Utilise Supabase** : {'oui' if result['uses_supabase'] else 'non'}")
    out.append(f"- **Total findings** : {len(f)}\n")

    out.append("## Synthèse\n")
    if not f:
        out.append("Aucune faille détectée par les détecteurs actifs. "
                   "Rappel : l'absence de détection n'est pas une preuve d'absence de faille.\n")
    else:
        out.append("| Sévérité | Nombre |")
        out.append("|---|---|")
        for sev in ("critique", "elevee", "moyenne", "faible", "info"):
            if sev in counts:
                out.append(f"| {SEV_LABEL[sev]} | {counts[sev]} |")
        out.append("")

    if f:
        out.append("## Findings détaillés\n")
        for i, x in enumerate(f, 1):
            loc = x["file"] + (f":{x['line']}" if x.get("line") else "") if x.get("file") else "(global)"
            out.append(f"### {i}. {SEV_LABEL.get(x['severity'], x['severity'])} — {x['title']}")
            out.append(f"- **Où** : `{loc}`")
            out.append(f"- **Catégorie** : {x['category']}")
            out.append(f"- **Score de risque** : {x.get('score', '—')}/100  ·  "
                       f"**Confiance** : {CONF_LABEL.get(x['confidence'], x['confidence'])}")
            if x.get("evidence"):
                out.append(f"- **Preuve** : `{x['evidence']}`")
            out.append(f"- **Impact** : {x['impact']}")
            out.append(f"- **Correctif** : {x['remediation']}")
            out.append("")

    out.append("---")
    out.append("_vibehunt — scanner de sécurité pour apps vibe codées. "
               "Test sur vos propres applications uniquement._")
    return "\n".join(out)


# --------------------------------------------------------------------------
# Rapport HTML autonome (présentable, thème clair/sombre, sans dépendance)
# --------------------------------------------------------------------------
import html as _html

_SEV_COLOR = {"critique": "#dc2626", "elevee": "#ea580c", "moyenne": "#ca8a04",
              "faible": "#2563eb", "info": "#64748b"}
_SEV_TXT = {"critique": "CRITIQUE", "elevee": "ÉLEVÉE", "moyenne": "MOYENNE",
            "faible": "FAIBLE", "info": "INFO"}


def to_html(result: dict) -> str:
    f = result["findings"]
    counts = {}
    for x in f:
        counts[x["severity"]] = counts.get(x["severity"], 0) + 1
    target = _html.escape(result["target"])
    platform = _html.escape(result["platform"])

    tiles = "".join(
        f'<div class="tile" style="border-color:{_SEV_COLOR[s]}">'
        f'<div class="num" style="color:{_SEV_COLOR[s]}">{counts.get(s,0)}</div>'
        f'<div class="lbl">{_SEV_TXT[s]}</div></div>'
        for s in ("critique", "elevee", "moyenne", "faible", "info")
    )

    rows = []
    for i, x in enumerate(f, 1):
        loc = _html.escape((x["file"] + (f":{x['line']}" if x.get("line") else "")) or "(global)")
        color = _SEV_COLOR.get(x["severity"], "#64748b")
        rows.append(f"""
        <details class="finding">
          <summary>
            <span class="badge" style="background:{color}">{_SEV_TXT.get(x['severity'], x['severity'])}</span>
            <span class="ftitle">{i}. {_html.escape(x['title'])}</span>
            <span class="score">{x.get('score','—')}/100</span>
          </summary>
          <div class="body">
            <p><b>Où</b> : <code>{loc}</code></p>
            <p><b>Catégorie</b> : {_html.escape(x['category'])} · <b>Confiance</b> : {_html.escape(x['confidence'])}</p>
            {f'<p><b>Preuve</b> : <code>{_html.escape(x["evidence"])}</code></p>' if x.get('evidence') else ''}
            <p><b>Impact</b> : {_html.escape(x['impact'])}</p>
            <p class="fix"><b>Correctif</b> : {_html.escape(x['remediation'])}</p>
          </div>
        </details>""")
    findings_html = "\n".join(rows) if rows else '<p class="clean">Aucune faille détectée par les détecteurs actifs.</p>'

    return f"""<!DOCTYPE html>
<html lang="fr"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Rapport vibehunt</title>
<style>
:root {{ --bg:#f8fafc; --card:#fff; --fg:#0f172a; --muted:#64748b; --border:#e2e8f0; }}
@media (prefers-color-scheme: dark) {{
  :root {{ --bg:#0f172a; --card:#1e293b; --fg:#e2e8f0; --muted:#94a3b8; --border:#334155; }}
}}
* {{ box-sizing:border-box; }}
body {{ margin:0; padding:24px 16px; background:var(--bg); color:var(--fg);
  font-family:system-ui,-apple-system,Segoe UI,Roboto,sans-serif; line-height:1.5; }}
.wrap {{ max-width:900px; margin:0 auto; }}
h1 {{ font-size:1.5rem; margin:0 0 4px; }}
.meta {{ color:var(--muted); font-size:.9rem; margin-bottom:20px; }}
.meta code {{ background:var(--card); padding:2px 6px; border-radius:4px; }}
.tiles {{ display:flex; gap:12px; flex-wrap:wrap; margin-bottom:28px; }}
.tile {{ flex:1; min-width:90px; background:var(--card); border:2px solid; border-radius:10px;
  padding:14px; text-align:center; }}
.num {{ font-size:1.8rem; font-weight:700; }}
.lbl {{ font-size:.75rem; color:var(--muted); letter-spacing:.05em; }}
.finding {{ background:var(--card); border:1px solid var(--border); border-radius:10px;
  margin-bottom:10px; overflow:hidden; }}
summary {{ cursor:pointer; padding:14px 16px; display:flex; align-items:center; gap:12px;
  list-style:none; }}
summary::-webkit-details-marker {{ display:none; }}
.badge {{ color:#fff; font-size:.7rem; font-weight:700; padding:3px 9px; border-radius:20px;
  letter-spacing:.03em; white-space:nowrap; }}
.ftitle {{ flex:1; font-weight:600; }}
.score {{ color:var(--muted); font-variant-numeric:tabular-nums; font-size:.85rem; }}
.body {{ padding:0 16px 16px; border-top:1px solid var(--border); }}
.body p {{ margin:10px 0; }}
.body code {{ background:var(--bg); padding:2px 6px; border-radius:4px; word-break:break-all; }}
.fix {{ background:rgba(37,99,235,.08); border-left:3px solid #2563eb; padding:10px 12px;
  border-radius:0 6px 6px 0; }}
.clean {{ text-align:center; color:var(--muted); padding:40px; }}
footer {{ margin-top:28px; color:var(--muted); font-size:.8rem; text-align:center; }}
</style></head>
<body><div class="wrap">
  <h1>Rapport de sécurité — vibehunt</h1>
  <div class="meta">Cible : <code>{target}</code> · Plateforme : {platform} ·
    Supabase : {'oui' if result['uses_supabase'] else 'non'} · {len(f)} finding(s)</div>
  <div class="tiles">{tiles}</div>
  {findings_html}
  <footer>Généré par vibehunt · Test sur vos propres applications uniquement.</footer>
</div></body></html>"""
