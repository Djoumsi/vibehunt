"""Export SARIF 2.1.0 — le format standard d'échange de résultats d'analyse
statique, directement ingéré par GitHub Code Scanning et les IDE. Permet
d'afficher les findings de vibehunt en annotations dans les pull requests.
"""
from __future__ import annotations
import json

# SARIF n'a que 4 niveaux ; on mappe nos sévérités dessus + un score dans les propriétés.
_LEVEL = {"critique": "error", "elevee": "error", "moyenne": "warning",
          "faible": "note", "info": "note"}


def to_sarif(result: dict) -> str:
    rules, rule_index, sarif_results = [], {}, []
    for f in result["findings"]:
        rule_id = f["detector"]
        if rule_id not in rule_index:
            rule_index[rule_id] = len(rules)
            rules.append({
                "id": rule_id,
                "name": rule_id,
                "shortDescription": {"text": f"Détecteur vibehunt : {rule_id}"},
                "helpUri": "https://github.com/Djoumsi/vibehunt",
            })
        loc = [{
            "physicalLocation": {
                "artifactLocation": {"uri": f["file"] or "(global)"},
                "region": {"startLine": max(1, f.get("line") or 1)},
            }
        }]
        sarif_results.append({
            "ruleId": rule_id,
            "ruleIndex": rule_index[rule_id],
            "level": _LEVEL.get(f["severity"], "warning"),
            "message": {"text": f"{f['title']} — {f['impact']} Correctif : {f['remediation']}"},
            "locations": loc,
            "properties": {"severity": f["severity"], "score": f.get("score"),
                           "category": f["category"], "confidence": f["confidence"]},
        })
    doc = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": "vibehunt",
                "informationUri": "https://github.com/Djoumsi/vibehunt",
                "version": "0.4.0",
                "rules": rules,
            }},
            "results": sarif_results,
        }],
    }
    return json.dumps(doc, ensure_ascii=False, indent=2)
