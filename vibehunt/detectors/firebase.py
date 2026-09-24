"""Détecteur : configuration Firebase à risque.

Firebase est, avec Supabase, l'autre back-end roi du vibe code. Deux problèmes
récurrents :
  1. Règles de sécurité ouvertes : `allow read, write: if true;` — équivalent
     Firebase du « RLS off », toute la base est publique.
  2. La config Firebase (apiKey, projectId...) est publique par design côté
     client ; ce n'est PAS un secret. On ne la signale donc pas comme tel —
     mais on rappelle que la sécurité repose entièrement sur les règles.
"""
from __future__ import annotations
import re
from ..model import Finding

OPEN_RULE = re.compile(r"allow\s+(read|write|read\s*,\s*write|create|update|delete)\s*:\s*if\s+true", re.I)
RULES_FILE = re.compile(r"(firestore\.rules|storage\.rules|database\.rules\.json|\.rules$)", re.I)
FIREBASE_USE = re.compile(r"(?i)(firebase|firestore|getFirestore|initializeApp)")


def run(ctx):
    firebase_seen = False
    rules_seen = False

    for path in ctx.iter_files():
        rel = ctx.rel(path)
        text = ctx.read(path)
        if not text:
            continue
        if FIREBASE_USE.search(text):
            firebase_seen = True

        is_rules = bool(RULES_FILE.search(path.name)) or "rules_version" in text or "service cloud.firestore" in text
        if is_rules:
            rules_seen = True
            for line_no, line in enumerate(text.splitlines(), 1):
                if OPEN_RULE.search(line):
                    ctx.add(Finding(
                        detector="firebase",
                        title="Règle Firebase ouverte à tous (allow ... : if true)",
                        severity="critique",
                        category="CWE-284 / OWASP A01",
                        file=rel, line=line_no, evidence=line.strip()[:120],
                        impact="La base/le stockage Firebase est accessible en lecture "
                               "et/ou écriture à n'importe qui : fuite ou altération "
                               "totale des données.",
                        remediation="Remplacer 'if true' par des règles basées sur "
                                    "request.auth (utilisateur authentifié) et la propriété "
                                    "du document. Tester avec l'émulateur de règles Firebase.",
                        confidence="confirme", exposure="internet_no_auth",
                    ))

    # Firebase utilisé mais aucune règle versionnée -> impossible de vérifier
    if firebase_seen and not rules_seen:
        ctx.add(Finding(
            detector="firebase",
            title="Firebase utilisé sans fichier de règles versionné",
            severity="moyenne",
            category="CWE-284 / OWASP A01",
            file="", line=0,
            evidence="SDK Firebase détecté, aucun firestore.rules / storage.rules trouvé",
            impact="La sécurité Firebase repose entièrement sur les règles. Sans elles "
                   "dans le dépôt, impossible de confirmer que la base n'est pas publique.",
            remediation="Versionner firestore.rules et storage.rules, les restreindre à "
                        "request.auth, et vérifier la configuration dans la console Firebase.",
            confidence="a_verifier", exposure="internet_no_auth",
        ))
