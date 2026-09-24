"""Détecteur : mauvaise configuration Supabase (la faille reine du vibe code).

Supabase expose une API REST publique sur toutes les tables. La SEULE barrière
est la Row Level Security (RLS). Si RLS est désactivée — ce qui est le défaut
historique et ce que les générateurs oublient — n'importe qui muni de la clé
anon (publique par design) lit et écrit toute la base.

On ne peut pas prouver l'état RLS en statique (il vit dans la base, pas dans le
code). Mais on peut lever des signaux forts :
  1. usage de la clé service_role côté client -> critique (contourne RLS) ;
  2. requêtes .from('table') directes depuis le client sans politique visible ;
  3. migrations SQL qui créent des tables sans jamais 'ENABLE ROW LEVEL SECURITY' ;
  4. 'DISABLE ROW LEVEL SECURITY' explicite dans les migrations.

Le mode dynamique (--live) confirme (2) en interrogeant réellement l'API.
"""
from __future__ import annotations
import re
from pathlib import Path
from ..model import Finding

CREATE_TABLE = re.compile(r"create\s+table\s+(?:if\s+not\s+exists\s+)?[\"']?([a-zA-Z0-9_.]+)", re.I)
ENABLE_RLS = re.compile(r"enable\s+row\s+level\s+security", re.I)
DISABLE_RLS = re.compile(r"disable\s+row\s+level\s+security", re.I)
FROM_CALL = re.compile(r"\.from\(\s*['\"]([a-zA-Z0-9_]+)['\"]\s*\)")
SERVICE_ROLE_CLIENT = re.compile(r"(?i)service_role|SUPABASE_SERVICE_ROLE_KEY|serviceRole")


def _is_client(rel: str) -> bool:
    r = rel.replace("\\", "/").lower()
    if any(h in r for h in ("/api/", "/server", "/functions/", "supabase/functions", "/backend/")):
        return False
    return any(h in r for h in ("/src/", "/components/", "/app/", "/pages/", "/lib/",
                                ".jsx", ".tsx", ".vue", ".svelte", "index.html"))


def run(ctx):
    sql_files, uses_from, defines_rls = [], False, False
    tables_created, tables_with_rls = set(), set()

    for path in ctx.iter_files():
        rel = ctx.rel(path)
        text = ctx.read(path)
        if not text:
            continue

        # 1. service_role côté client = accès admin exposé, contourne RLS
        if _is_client(rel):
            for line_no, line in enumerate(text.splitlines(), 1):
                if SERVICE_ROLE_CLIENT.search(line):
                    ctx.add(Finding(
                        detector="supabase_rls",
                        title="Clé service_role Supabase référencée côté client",
                        severity="critique",
                        category="CWE-269 / OWASP A01",
                        file=rel, line=line_no, evidence=line.strip()[:120],
                        impact="La clé service_role a les droits d'administration et "
                               "CONTOURNE la RLS. Côté client, elle donne un accès total "
                               "en lecture/écriture à toute la base à n'importe quel visiteur.",
                        remediation="N'utiliser service_role QUE dans une fonction serveur/edge. "
                                    "Côté client, utiliser exclusivement la clé anon + RLS. "
                                    "Révoquer et régénérer la clé service_role exposée.",
                        confidence="confirme", exposure="internet_no_auth",
                    ))
                    break

        # 2. requêtes directes depuis le client
        if _is_client(rel):
            for line_no, line in enumerate(text.splitlines(), 1):
                m = FROM_CALL.search(line)
                if m:
                    uses_from = True

        # 3/4. migrations SQL
        if path.suffix == ".sql" or "migration" in rel.lower() or "/supabase/" in rel.replace("\\", "/").lower():
            sql_files.append(rel)
            for t in CREATE_TABLE.findall(text):
                tables_created.add(t.split(".")[-1])
            if ENABLE_RLS.search(text):
                defines_rls = True
                # rattacher grossièrement les tables ayant une activation RLS
                for t in re.findall(r"alter\s+table\s+[\"']?([a-zA-Z0-9_.]+)[\"']?\s+enable\s+row\s+level", text, re.I):
                    tables_with_rls.add(t.split(".")[-1])
            for line_no, line in enumerate(text.splitlines(), 1):
                if DISABLE_RLS.search(line):
                    ctx.add(Finding(
                        detector="supabase_rls",
                        title="RLS explicitement DÉSACTIVÉE dans une migration",
                        severity="critique",
                        category="CWE-284 / OWASP A01",
                        file=rel, line=line_no, evidence=line.strip()[:120],
                        impact="Table exposée en lecture/écriture publique via l'API Supabase. "
                               "Fuite ou altération de données par n'importe quel visiteur.",
                        remediation="ENABLE ROW LEVEL SECURITY sur la table + politiques "
                                    "restreignant l'accès à l'utilisateur propriétaire (auth.uid()).",
                        confidence="confirme", exposure="internet_no_auth",
                    ))

    # tables créées sans aucune RLS visible
    orphan = tables_created - tables_with_rls
    if sql_files and orphan and not defines_rls:
        ctx.add(Finding(
            detector="supabase_rls",
            title=f"{len(orphan)} table(s) Supabase créée(s) sans RLS visible",
            severity="critique",
            category="CWE-284 / OWASP A01",
            file=sql_files[0], line=0,
            evidence="Tables : " + ", ".join(sorted(orphan)[:8]) + ("…" if len(orphan) > 8 else ""),
            impact="Sans RLS, l'API REST publique de Supabase expose ces tables en "
                   "lecture/écriture à toute personne connaissant la clé anon (publique).",
            remediation="Pour chaque table : ENABLE ROW LEVEL SECURITY + politiques d'accès. "
                        "Vérifier dans le dashboard Supabase que RLS est ON partout. "
                        "Confirmer en dynamique avec vibehunt --live.",
            confidence="a_verifier", exposure="internet_no_auth",
        ))
    elif uses_from and not sql_files:
        ctx.add(Finding(
            detector="supabase_rls",
            title="Requêtes Supabase côté client sans migration RLS dans le repo",
            severity="elevee",
            category="CWE-284 / OWASP A01",
            file="", line=0,
            evidence="Appels .from('...') détectés côté client, aucune migration RLS trouvée.",
            impact="Impossible de confirmer que RLS protège les tables interrogées. "
                   "Si RLS est off (défaut fréquent), les données sont publiques.",
            remediation="Versionner les migrations, activer RLS sur chaque table, "
                        "confirmer en dynamique avec vibehunt --live <url>.",
            confidence="a_verifier", exposure="internet_no_auth",
        ))
