"""Détecteur : fichiers sensibles committés et endpoints de debug exposés.

Deux problèmes distincts :
  1. Un fichier sensible réellement versionné (un .env avec des vraies valeurs,
     un dump SQL, une clé, une sauvegarde) — il est dans l'historique, donc
     public de fait pour un dépôt public et récupérable pour qui a accès.
  2. Des routes de debug/seed/admin laissées dans le code — points d'entrée
     dangereux si atteignables sans authentification.
"""
from __future__ import annotations
import re
from pathlib import Path
from ..model import Finding

# noms de fichiers qui ne devraient jamais être versionnés (hors .example/.sample)
SENSITIVE_NAMES = re.compile(
    r"(?i)^(\.env(\.(local|production|prod|development))?|"
    r".*\.pem|.*\.key|.*\.p12|.*\.pfx|id_rsa|"
    r".*\.(dump|bak|backup)|.*(dump|backup|export)\.sql|db\.sqlite3?|.*credentials.*\.json|"
    r"serviceaccount.*\.json|.*-key\.json)$"
)
ALLOW_SUFFIX = (".example", ".sample", ".dist", ".template")

# routes de debug/seed dangereuses
DEBUG_ROUTE = re.compile(
    r"""(?ix)
    (app|router|route|get|post)\s*[.(]\s*['"][^'"]*(/debug|/seed|/__|/test-|
      /reset-db|/drop|/migrate|/phpinfo|/adminer|/\.env)[^'"]*['"]
    """
)


def _has_real_content(text: str) -> bool:
    """Un .env avec au moins une valeur non vide et non placeholder."""
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        _, _, val = line.partition("=")
        val = val.strip().strip("'\"")
        if val and not re.search(r"(?i)(your|example|xxx|<|change|placeholder|ici|votre|todo)", val):
            return True
    return False


def run(ctx):
    for path in ctx.iter_files():
        name = path.name
        rel = ctx.rel(path)

        # 1. fichier sensible versionné
        if SENSITIVE_NAMES.match(name) and not any(name.lower().endswith(s) for s in ALLOW_SUFFIX):
            text = ctx.read(path)
            is_env = name.startswith(".env")
            # un .env n'est un problème que s'il contient de vraies valeurs
            if is_env and not _has_real_content(text):
                continue
            sev = "critique" if (is_env and _has_real_content(text)) or name.endswith((".pem", ".key")) else "elevee"
            ctx.add(Finding(
                detector="exposed_files",
                title=f"Fichier sensible versionné : {name}",
                severity=sev,
                category="CWE-538 / OWASP A05",
                file=rel, line=0, evidence=name,
                impact="Fichier de secrets/données versionné dans Git : présent dans "
                       "l'historique (récupérable même s'il est supprimé ensuite), et "
                       "public si le dépôt l'est.",
                remediation="Retirer le fichier du suivi Git (git rm --cached), l'ajouter "
                            "à .gitignore, purger l'historique si nécessaire, et RÉVOQUER "
                            "tout secret qu'il contenait.",
                confidence="confirme", exposure="internet_no_auth",
            ))

        # 2. routes de debug/seed
        if path.suffix in (".js", ".ts", ".jsx", ".tsx", ".py", ".php", ".mjs", ".cjs"):
            text = ctx.read(path)
            for line_no, line in enumerate(text.splitlines(), 1):
                if DEBUG_ROUTE.search(line):
                    ctx.add(Finding(
                        detector="exposed_files",
                        title="Route de debug/seed/admin exposée dans le code",
                        severity="elevee",
                        category="CWE-489 / OWASP A05",
                        file=rel, line=line_no, evidence=line.strip()[:120],
                        impact="Un endpoint de debug/seed atteignable peut réinitialiser la "
                               "base, exposer la configuration ou contourner la logique métier.",
                        remediation="Supprimer ces routes en production, ou les protéger par "
                                    "authentification forte et les désactiver hors développement.",
                        confidence="probable", exposure="internet",
                    ))
