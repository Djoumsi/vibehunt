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
