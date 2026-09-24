"""Détecteur : configuration CORS trop permissive.

Le duo dangereux est « origine = * » + « credentials autorisés » : le
navigateur envoie alors les cookies/jetons de session vers n'importe quelle
origine, ce qui ouvre la porte au vol de session inter-sites. En vibe code,
le générateur met souvent `cors()` sans configuration (Express autorise alors
toutes les origines) « pour que ça marche ».
"""
from __future__ import annotations
import re
from ..model import Finding

WILDCARD_ORIGIN = re.compile(r"""(?ix)
    access-control-allow-origin['"]?\s*[:,]\s*['"]\*['"]        # header brut
  | \borigin\s*:\s*['"]\*['"]                                    # objet de config
  | \bcors\(\s*\)                                                # cors() nu = tout ouvert
""")
CREDENTIALS_TRUE = re.compile(r"(?ix)(access-control-allow-credentials['\"]?\s*[:,]\s*['\"]?true|credentials\s*:\s*true)")


def run(ctx):
    for path in ctx.iter_files():
        rel = ctx.rel(path)
        text = ctx.read(path)
        if not text:
            continue
        low = text.lower()
        if "cors" not in low and "access-control-allow-origin" not in low:
            continue
        has_wild = bool(WILDCARD_ORIGIN.search(text))
        has_cred = bool(CREDENTIALS_TRUE.search(text))
        if not has_wild:
            continue
        # localiser
        line_no = 1
        for i, line in enumerate(text.splitlines(), 1):
            if WILDCARD_ORIGIN.search(line):
                line_no = i
                break
        if has_cred:
            ctx.add(Finding(
                detector="cors",
                title="CORS ouvert à toutes les origines AVEC credentials",
                severity="elevee",
                category="CWE-942 / OWASP A05",
                file=rel, line=line_no, evidence="origin: *  +  credentials: true",
                impact="N'importe quel site peut envoyer des requêtes authentifiées "
                       "au nom de l'utilisateur (cookies/session transmis), permettant "
                       "vol de session et actions non autorisées inter-sites.",
                remediation="Remplacer l'origine * par une liste blanche d'origines de "
                            "confiance. Ne jamais combiner origine * et credentials:true.",
                confidence="confirme", exposure="internet",
            ))
        else:
            ctx.add(Finding(
                detector="cors",
                title="CORS ouvert à toutes les origines",
                severity="moyenne",
                category="CWE-942 / OWASP A05",
                file=rel, line=line_no, evidence="origin: * (ou cors() sans config)",
                impact="Toute origine peut appeler l'API. Sans credentials l'impact est "
                       "limité, mais expose les données publiques de l'API à tout site.",
                remediation="Restreindre à une liste blanche d'origines. Configurer cors() "
                            "explicitement plutôt que de l'appeler sans argument.",
                confidence="probable", exposure="internet",
            ))
