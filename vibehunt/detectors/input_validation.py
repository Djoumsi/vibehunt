"""Détecteur : puits dangereux (XSS et injection).

On repère les endroits où une donnée arrive dans un interpréteur sans passage
par une API sûre. On ne prétend pas suivre le flux complet (taint analysis) —
on signale les puits classiques et on ajuste la confiance : un puits alimenté
par une variable est plus suspect qu'un puits sur une constante.
"""
from __future__ import annotations
import re
from ..model import Finding

# puits XSS côté front
XSS_SINKS = [
    ("dangerouslySetInnerHTML", re.compile(r"dangerouslySetInnerHTML"), "React"),
    ("v-html", re.compile(r"\bv-html\b"), "Vue"),
    ("innerHTML =", re.compile(r"\.innerHTML\s*="), "DOM"),
    ("document.write", re.compile(r"document\.write\s*\("), "DOM"),
    ("insertAdjacentHTML", re.compile(r"\.insertAdjacentHTML\s*\("), "DOM"),
]
# exécution dynamique
EXEC_SINKS = [
    ("eval", re.compile(r"\beval\s*\(")),
    ("new Function", re.compile(r"\bnew\s+Function\s*\(")),
    ("child_process exec", re.compile(r"\b(exec|execSync)\s*\(")),
    ("os.system / subprocess shell", re.compile(r"(os\.system\s*\(|shell\s*=\s*True)")),
]
# injection SQL par concaténation / f-string
# Concaténation SQL avec une VARIABLE (pas de l'arithmétique sur une colonne,
# pas une requête préparée). On exige un fragment qui ressemble à une variable.
SQL_CONCAT = re.compile(
    r"""(?ix)
    (select|insert|update|delete|from|where)\b[^;\n]*?
    (\+\s*[$]?[a-zA-Z_]\w*        # + variable (JS/PHP), pas + 42
     |\$\{[^}]+\}                 # ${expr}
     |\.\s*[a-zA-Z_]\w*\s*\+    # 'str' . var (PHP) suivi de concat
     |\bf["'][^"']*\{             # f-string Python
     |%\s*\([^)]*\)              # %(name)s à la main
     |\.\s*format\s*\()
    """
)
# indices d'une requête paramétrée (donc SÛRE) — on n'alerte pas dans ce cas
PARAMETERIZED = re.compile(r"(?i)(\?\s*[),]|:\w+\b|%s\b|\bprepare\s*\(|execute\s*\(\s*\[)")
# indices qu'une donnée variable alimente le puits (vs constante)
VAR_HINT = re.compile(r"(\{|\$\{|\+\s*\w|props\.|state\.|req\.|params|query|body|input|value|data\b)")


def run(ctx):
    for path in ctx.iter_files():
        rel = ctx.rel(path)
        if path.suffix not in (".js", ".jsx", ".ts", ".tsx", ".vue", ".svelte",
                               ".py", ".php", ".mjs", ".cjs", ".html"):
            continue
        text = ctx.read(path)
        if not text:
            continue
        for line_no, line in enumerate(text.splitlines(), 1):
            if len(line) > 2000:
                continue
            # XSS
            for name, rx, fw in XSS_SINKS:
                if rx.search(line):
                    variable = bool(VAR_HINT.search(line))
                    ctx.add(Finding(
                        detector="input_validation",
                        title=f"Puits XSS potentiel ({name}, {fw})",
                        severity="elevee" if variable else "moyenne",
                        category="CWE-79 / OWASP A03",
                        file=rel, line=line_no, evidence=line.strip()[:120],
                        impact="Si du contenu contrôlé par l'utilisateur atteint ce puits, "
                               "un attaquant peut injecter du script exécuté chez les autres "
                               "utilisateurs (vol de session, actions à leur place).",
                        remediation="Éviter le HTML brut ; afficher via le rendu texte du "
                                    "framework. Si le HTML est indispensable, l'assainir avec "
                                    "une bibliothèque (DOMPurify) avant insertion.",
                        confidence="probable" if variable else "a_verifier",
                        exposure="internet",
                    ))
            # exécution dynamique
            for name, rx in EXEC_SINKS:
                if rx.search(line) and VAR_HINT.search(line):
                    ctx.add(Finding(
                        detector="input_validation",
                        title=f"Exécution dynamique avec donnée variable ({name})",
                        severity="elevee",
                        category="CWE-95 / CWE-78 / OWASP A03",
                        file=rel, line=line_no, evidence=line.strip()[:120],
                        impact="Une donnée non fiable passée à une exécution dynamique permet "
                               "l'exécution de code ou de commandes arbitraires côté serveur/client.",
                        remediation="Supprimer eval/Function. Pour une commande, utiliser une API "
                                    "avec arguments séparés (pas de shell) et une liste blanche.",
                        confidence="probable", exposure="internet",
                    ))
            # SQL par concaténation
            if SQL_CONCAT.search(line) and not PARAMETERIZED.search(line):
                ctx.add(Finding(
                    detector="input_validation",
                    title="Requête SQL construite par concaténation",
                    severity="elevee",
                    category="CWE-89 / OWASP A03",
                    file=rel, line=line_no, evidence=line.strip()[:120],
                    impact="Injection SQL possible : lecture/modification/suppression de "
                           "données arbitraires si l'entrée n'est pas assainie.",
                    remediation="Utiliser des requêtes paramétrées (placeholders), jamais la "
                                "concaténation ni l'interpolation de variables dans le SQL.",
                    confidence="probable", exposure="internet",
                ))
