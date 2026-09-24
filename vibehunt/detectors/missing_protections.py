"""Détecteur : absence de protections (CSRF, rate limiting, signature de webhook).

Ces trois contrôles ont un point commun : on ne peut les vérifier qu'au niveau
du dépôt entier (une bibliothèque importée quelque part, des routes présentes
ailleurs). Les regrouper permet UN SEUL passage sur les fichiers plutôt que
trois — c'est un choix d'optimisation assumé.

Détecter une ABSENCE est intrinsèquement moins fiable que détecter une présence :
chaque règle est donc conditionnée à des prérequis stricts (le contrôle n'est
signalé manquant que s'il est réellement attendu) et marquée « à vérifier ».
Objectif : n'alerter que quand c'est pertinent, pour ne pas crier au loup.
"""
from __future__ import annotations
import re
from ..model import Finding

# --- signaux collectés en un passage ---
STATE_CHANGING = re.compile(r"(?i)\.(post|put|patch|delete)\s*\(|method\s*=\s*['\"]post['\"]|<form[^>]*method=['\"]?post")
COOKIE_SESSION = re.compile(r"(?i)(express-session|cookie-session|req\.session|connect\.sid|"
                            r"cookieParser|flask.*session|session\[|django.*session|set-cookie)")
JWT_HEADER = re.compile(r"(?i)(authorization:\s*bearer|Bearer \$|headers\.authorization|"
                        r"getToken|localStorage\.getItem\(['\"](token|jwt)|Authorization.*Bearer)")
# Usage RÉEL d'une protection CSRF (pas la simple mention du mot dans un commentaire)
CSRF_LIB = re.compile(r"(?i)(csurf|csrf-csrf|@fastify/csrf|\blusca\b|"
                      r"csrf_?token|csrfProtection|doubleCsrf|SameSite\s*=\s*['\"]?strict|"
                      r"require\(['\"]csrf|from\s+['\"]csrf|import.*\bcsrf\b)")

AUTH_ROUTE = re.compile(r"(?i)['\"/](login|signin|sign-in|register|signup|sign-up|"
                        r"auth|reset-password|forgot-password|token|session)['\"/ ]")
RATE_LIB = re.compile(r"(?i)(express-rate-limit|rate-limiter-flexible|@upstash/ratelimit|"
                      r"express-slow-down|fastify-rate-limit|flask-limiter|django-ratelimit|"
                      r"slowapi|rateLimit|RateLimiter|throttle)")

WEBHOOK_ROUTE = re.compile(r"(?i)['\"/](webhook|webhooks|hooks?|callback|stripe|payment-callback)['\"/ ]")
HMAC_VERIFY = re.compile(r"(?i)(createHmac|hmac|x-hub-signature|x-signature|stripe-signature|"
                         r"constructEvent|verifySignature|verify_signature|timingSafeEqual|"
                         r"hmac\.compare|signature.*verify|verify.*signature)")


def run(ctx):
    # agrégats sur tout le dépôt
    has_state_change = has_cookie = has_jwt = has_csrf = False
    has_auth_route = has_rate = False
    has_webhook = has_hmac = False
    example_csrf = example_rate = example_webhook = ""

    for path in ctx.iter_files():
        if path.suffix not in (".js", ".ts", ".jsx", ".tsx", ".py", ".php",
                               ".mjs", ".cjs", ".html", ".vue", ".svelte", ".json"):
            continue
        text = ctx.read(path)
        if not text:
            continue
        rel = ctx.rel(path)

        if STATE_CHANGING.search(text):
            has_state_change = True
            example_csrf = example_csrf or rel
        if COOKIE_SESSION.search(text):
            has_cookie = True
        if JWT_HEADER.search(text):
            has_jwt = True
        if CSRF_LIB.search(text):
            has_csrf = True
        if AUTH_ROUTE.search(text):
            has_auth_route = True
            example_rate = example_rate or rel
        if RATE_LIB.search(text):
            has_rate = True
        if WEBHOOK_ROUTE.search(text):
            has_webhook = True
            example_webhook = example_webhook or rel
        if HMAC_VERIFY.search(text):
            has_hmac = True

    # --- CSRF : sessions par cookie + routes mutatrices + pas de protection ---
    # (si l'app est purement JWT en en-tête, elle n'est pas exposée au CSRF classique)
    if has_cookie and has_state_change and not has_csrf and not (has_jwt and not has_cookie):
        ctx.add(Finding(
            detector="missing_protections",
            title="Protection CSRF absente (authentification par cookie détectée)",
            severity="moyenne",
            category="CWE-352 / OWASP A01",
            file=example_csrf, line=0,
            evidence="sessions par cookie + routes POST/PUT/DELETE, aucune protection CSRF trouvée",
            impact="Sans jeton anti-CSRF, un site tiers peut déclencher des actions "
                   "authentifiées à l'insu de l'utilisateur (le navigateur joint le cookie).",
            remediation="Activer une protection CSRF (jeton synchronizer ou double-submit) "
                        "et/ou cookies SameSite=Strict/Lax sur les routes mutatrices.",
            confidence="a_verifier", exposure="internet",
        ))

    # --- Rate limiting : routes d'auth + aucun limiteur nulle part ---
    if has_auth_route and not has_rate:
        ctx.add(Finding(
            detector="missing_protections",
            title="Rate limiting absent sur les routes d'authentification",
            severity="moyenne",
            category="CWE-307 / OWASP A07",
            file=example_rate, line=0,
            evidence="routes login/register/reset détectées, aucun limiteur de débit trouvé",
            impact="Sans limitation, les endpoints d'authentification sont exposés au "
                   "bruteforce de mots de passe et à l'énumération de comptes.",
            remediation="Ajouter un limiteur de débit (par IP et par compte) sur login, "
                        "register et reset ; verrouillage progressif après échecs répétés.",
            confidence="a_verifier", exposure="internet",
        ))

    # --- Webhook sans vérification de signature ---
    if has_webhook and not has_hmac:
        ctx.add(Finding(
            detector="missing_protections",
            title="Endpoint webhook sans vérification de signature (HMAC)",
            severity="elevee",
            category="CWE-345 / OWASP A08",
            file=example_webhook, line=0,
            evidence="route webhook/callback détectée, aucune vérification de signature trouvée",
            impact="Un attaquant peut forger des appels webhook (faux paiement confirmé, "
                   "fausse notification) que l'application traitera comme authentiques.",
            remediation="Vérifier la signature HMAC de chaque webhook (ex. stripe-signature, "
                        "x-hub-signature) avec comparaison à temps constant avant traitement.",
            confidence="probable", exposure="internet",
        ))
