"""Détecteur : contrôle d'autorisation effectué côté client seulement.

Motif classique du vibe code : l'IA « sécurise » une page admin en cachant un
bouton ou en redirigeant dans le composant React. Mais le contrôle est en
JavaScript, donc contournable : l'utilisateur modifie l'état, appelle l'API
directement, ou lit les données que le composant a déjà chargées. La vraie
autorisation doit être côté serveur / dans les politiques RLS.

On repère les vérifications de rôle/admin situées dans du code client, sans
équivalent côté serveur. C'est un signal (confidence=probable), pas une preuve
absolue — d'où une sévérité élevée plutôt que critique par défaut.
"""
from __future__ import annotations
import re
from ..model import Finding

# vérifications de privilège fréquentes
ROLE_CHECK = re.compile(
    r"(?i)(is_?admin|isAdmin|role\s*===?\s*['\"]admin['\"]|"
    r"user\.role|profile\.role|hasRole|requireAdmin|=== *['\"]superadmin['\"]|"
    r"user_metadata\.role|app_metadata\.role)"
)
# indices que c'est purement cosmétique / redirection client
CLIENT_GUARD = re.compile(
    r"(?i)(navigate\(|router\.(push|replace)\(|redirect\(|return null|"
    r"\{.*&&.*<|useEffect|window\.location)"
)


def _is_client(rel: str) -> bool:
    r = rel.replace("\\", "/").lower()
    if any(h in r for h in ("/api/", "/server", "supabase/functions", "/functions/", "/backend/")):
        return False
    return any(h in r for h in ("/src/", "/components/", "/app/", "/pages/",
                                ".jsx", ".tsx", ".vue", ".svelte"))


def run(ctx):
    flagged_files = set()
    for path in ctx.iter_files():
        rel = ctx.rel(path)
        if not _is_client(rel) or rel in flagged_files:
            continue
        text = ctx.read(path)
        if not text:
            continue
        lines = text.splitlines()
        for i, line in enumerate(lines):
            if not ROLE_CHECK.search(line):
                continue
            # contexte : la vérification est-elle suivie d'une garde purement client ?
            window = "\n".join(lines[max(0, i - 2): i + 4])
            if CLIENT_GUARD.search(window):
                ctx.add(Finding(
                    detector="client_authz",
                    title="Contrôle de rôle/admin effectué côté client",
                    severity="elevee",
                    category="CWE-602 / OWASP A01",
                    file=rel, line=i + 1, evidence=line.strip()[:120],
                    impact="Le contrôle d'accès est en JavaScript, donc contournable : "
                           "un utilisateur peut appeler l'API directement ou modifier "
                           "l'état pour accéder à des fonctions ou données réservées.",
                    remediation="Dupliquer OBLIGATOIREMENT le contrôle côté serveur : "
                                "vérification dans la fonction/route API et/ou politique RLS "
                                "basée sur auth.uid()/le rôle. Le contrôle client ne sert "
                                "qu'au confort d'affichage.",
                    confidence="probable", exposure="internet",
                ))
                flagged_files.add(rel)  # un signal par fichier suffit
                break
