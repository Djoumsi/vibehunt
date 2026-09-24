"""Détecteur : SSRF (Server-Side Request Forgery) et absence de liste blanche d'URL.

On repère les appels sortants (fetch, axios, requests, http.get, urllib…) dont
l'URL provient d'une entrée utilisateur. En cloud, le risque majeur est
l'accès au service de métadonnées d'instance (169.254.169.254) qui rend les
identifiants IAM — d'où une sévérité élevée. C'est un détecteur par PUITS
(donnée variable → sink), donc plus fiable qu'une détection d'absence.
"""
from __future__ import annotations
import re
from ..model import Finding

# appels sortants
OUTBOUND = re.compile(
    r"(?ix)\b(fetch|axios(?:\.(get|post|put|delete|request))?|"
    r"got|superagent|http\.get|https\.get|request|requests\.(get|post)|"
    r"urllib\.request\.urlopen|urlopen|httpx\.(get|post)|node-fetch)\s*\("
)
# indices que l'URL est contrôlée par l'utilisateur
USER_INPUT = re.compile(
    r"(?i)(req\.(query|body|params)|request\.(args|form|json|GET|POST)|"
    r"\bparams\b|\bquery\b|searchParams|url\s*=\s*\w+|\$_(GET|POST|REQUEST)|"
    r"props\.|\.body\.|input\b|userUrl|targetUrl|req\.url)"
)
# une validation d'URL à proximité réduit le risque
GUARD = re.compile(
    r"(?i)(allowlist|allow_list|whitelist|new URL\(|URL\.parse|is_valid_url|"
    r"isValidUrl|allowedHosts|ALLOWED_|startswith\(|startsWith\(|hostname ===)"
)


def run(ctx):
    for path in ctx.iter_files():
        if path.suffix not in (".js", ".ts", ".jsx", ".tsx", ".py", ".php",
                               ".mjs", ".cjs", ".vue", ".svelte"):
            continue
        text = ctx.read(path)
        if not text or "169.254" not in text and not OUTBOUND.search(text):
            continue
        lines = text.splitlines()
        for i, line in enumerate(lines):
            if not OUTBOUND.search(line):
                continue
            window = "\n".join(lines[max(0, i - 1): i + 2])
            if USER_INPUT.search(window) and not GUARD.search("\n".join(lines[max(0, i - 4): i + 3])):
                ctx.add(Finding(
                    detector="ssrf",
                    title="Requête sortante vers une URL contrôlée par l'utilisateur (SSRF)",
                    severity="elevee",
                    category="CWE-918 / OWASP A10",
                    file=ctx.rel(path), line=i + 1, evidence=line.strip()[:120],
                    impact="Un attaquant peut faire émettre des requêtes par le serveur vers "
                           "des cibles internes — dont le service de métadonnées cloud "
                           "(169.254.169.254) qui expose les identifiants IAM.",
                    remediation="Valider l'URL contre une liste blanche de domaines autorisés, "
                                "bloquer les plages internes et le lien-local, refuser de "
                                "suivre les redirections vers l'interne.",
                    confidence="probable", exposure="internet",
                ))
