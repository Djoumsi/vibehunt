"""Scan black-box d'une application déployée, à partir de sa seule URL.

Analyse passive et non destructive, destinée aux applications dont l'utilisateur
est propriétaire : on récupère la page et ses scripts, on lit les en-têtes, on
teste quelques chemins sensibles courants (une requête chacun, pas de fuzzing).

Point fort sur le vibe code : le bundle JavaScript servi contient très souvent
des secrets (clé API, URL + clé anon Supabase). Quand on y trouve les
identifiants Supabase, on enchaîne automatiquement le test de RLS.
"""
from __future__ import annotations
import re
import ssl
import urllib.request
import urllib.error
from urllib.parse import urljoin, urlparse
from .model import Finding, ScanContext
from .detectors import secrets as secrets_det

_UA = {"User-Agent": "vibehunt/0.6 (audit autorisé)"}
_TIMEOUT = 12

# en-têtes de sécurité attendus (nom -> (sévérité si absent, explication))
SECURITY_HEADERS = {
    "content-security-policy": ("moyenne", "Sans CSP, une XSS est bien plus facilement exploitable."),
    "strict-transport-security": ("moyenne", "Sans HSTS, un attaquant peut forcer une connexion HTTP en clair."),
    "x-content-type-options": ("faible", "Sans nosniff, le navigateur peut interpréter un type MIME à tort."),
    "x-frame-options": ("faible", "Sans protection, la page est encadrable (clickjacking)."),
}
# chemins sensibles à sonder (un GET chacun)
SENSITIVE_PATHS = [
    "/.env", "/.git/HEAD", "/.git/config", "/config.json", "/.env.local",
    "/backup.sql", "/dump.sql", "/phpinfo.php", "/server-status", "/.DS_Store",
]
SUPABASE_URL_RE = re.compile(r"https://[a-z0-9]{15,}\.supabase\.co")
SUPABASE_ANON_RE = re.compile(r"eyJ[A-Za-z0-9_-]{20,}\.eyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}")
SCRIPT_SRC_RE = re.compile(r'<script[^>]+src=["\']([^"\']+)["\']', re.I)


def _get(url, method="GET"):
    req = urllib.request.Request(url, headers=_UA, method=method)
    ctx = ssl.create_default_context()
    return urllib.request.urlopen(req, timeout=_TIMEOUT, context=ctx)


def _analyze_headers(url, findings):
    try:
        resp = _get(url)
        headers = {k.lower(): v for k, v in resp.getheaders()}
        final_url = resp.geturl()
        body = resp.read(400_000).decode(errors="ignore")
    except Exception as e:
        findings.append(Finding(detector="webscan", title=f"Cible injoignable : {e}",
                                severity="info", category="—", file=url, line=0,
                                impact="Impossible d'analyser l'URL.", remediation="Vérifier l'URL.",
                                confidence="confirme", exposure="internet"))
        return None, None
    # HTTPS forcé ?
    if urlparse(final_url).scheme != "https":
        findings.append(Finding(
            detector="webscan", title="Application servie en HTTP (non chiffré)",
            severity="elevee", category="CWE-319 / OWASP A02", file=final_url, line=0,
            evidence=final_url, impact="Le trafic (dont identifiants et sessions) circule en clair.",
            remediation="Forcer HTTPS et rediriger tout le trafic HTTP vers HTTPS.",
            confidence="confirme", exposure="internet"))
    # en-têtes manquants
    for h, (sev, why) in SECURITY_HEADERS.items():
        if h not in headers:
            findings.append(Finding(
                detector="webscan", title=f"En-tête de sécurité manquant : {h}",
                severity=sev, category="CWE-693 / OWASP A05", file=final_url, line=0,
                evidence=f"{h} absent", impact=why,
                remediation=f"Ajouter l'en-tête {h} côté serveur/CDN.",
                confidence="confirme", exposure="internet"))
    # CORS large
    aco = headers.get("access-control-allow-origin", "")
    if aco == "*" and headers.get("access-control-allow-credentials", "").lower() == "true":
        findings.append(Finding(
            detector="webscan", title="CORS ouvert à toutes les origines avec credentials",
            severity="elevee", category="CWE-942 / OWASP A05", file=final_url, line=0,
            evidence="Access-Control-Allow-Origin: * + credentials", impact="Vol de session inter-sites possible.",
            remediation="Restreindre l'origine à une liste blanche.", confidence="confirme", exposure="internet"))
    # cookies
    setck = headers.get("set-cookie", "")
    if setck:
        low = setck.lower()
        missing = [f for f in ("secure", "httponly") if f not in low]
        if missing:
            findings.append(Finding(
                detector="webscan", title=f"Cookie sans attribut(s) : {', '.join(missing)}",
                severity="moyenne", category="CWE-614 / OWASP A05", file=final_url, line=0,
                evidence=setck[:80], impact="Cookie de session exposé (interception ou accès JavaScript).",
                remediation="Ajouter Secure, HttpOnly et SameSite aux cookies de session.",
                confidence="probable", exposure="internet"))
    return final_url, body


def _scan_bundle(base_url, html_body, findings):
    """Récupère les scripts liés et y cherche des secrets. Retourne (url, anon)
    Supabase si trouvés, pour enchaîner le test RLS."""
    seen_url = seen_anon = None
    sources = SCRIPT_SRC_RE.findall(html_body)[:10]  # limite raisonnable
    blobs = [("page", html_body)]
    for src in sources:
        js_url = urljoin(base_url, src)
        try:
            blobs.append((js_url, _get(js_url).read(2_000_000).decode(errors="ignore")))
        except Exception:
            continue
    for where, blob in blobs:
        # secrets génériques (réutilise les motifs du détecteur statique)
        for name, pattern, base_sev, cat in secrets_det.PATTERNS:
            for m in re.finditer(pattern, blob):
                snip = m.group(0)
                if not secrets_det._looks_real(snip):
                    continue
                # la clé anon Supabase est publique par design : on ne la crie pas comme un secret
                if "anon" in blob[max(0, m.start()-60):m.start()].lower():
                    continue
                shown = snip if len(snip) <= 14 else snip[:8] + "…" + snip[-4:]
                findings.append(Finding(
                    detector="webscan", title=f"{name} exposé dans le code servi au navigateur",
                    severity="critique", category=f"{cat} / OWASP A05", file=where, line=0,
                    evidence=shown, impact="Secret lisible par tout visiteur dans le bundle : usage frauduleux.",
                    remediation="Retirer le secret du front, le déplacer côté serveur, puis le révoquer.",
                    confidence="confirme", exposure="internet_no_auth"))
        # identifiants Supabase pour enchaîner
        mu = SUPABASE_URL_RE.search(blob)
        if mu and not seen_url:
            seen_url = mu.group(0)
        ma = SUPABASE_ANON_RE.search(blob)
        if ma and not seen_anon:
            seen_anon = ma.group(0)
    return seen_url, seen_anon


def _probe_paths(base_url, findings):
    root = f"{urlparse(base_url).scheme}://{urlparse(base_url).netloc}"
    for path in SENSITIVE_PATHS:
        try:
            resp = _get(root + path)
            body = resp.read(400).decode(errors="ignore")
            if resp.status == 200 and body.strip() and "<html" not in body.lower()[:200]:
                findings.append(Finding(
                    detector="webscan", title=f"Chemin sensible accessible : {path}",
                    severity="elevee" if path in ("/.env", "/.git/config", "/.env.local") else "moyenne",
                    category="CWE-538 / OWASP A05", file=root + path, line=0,
                    evidence=body[:60].replace("\n", " "),
                    impact="Fichier interne exposé publiquement (config, secrets, code source).",
                    remediation="Bloquer l'accès à ce chemin au niveau du serveur/CDN.",
                    confidence="confirme", exposure="internet_no_auth"))
        except (urllib.error.HTTPError, urllib.error.URLError, Exception):
            continue  # 404/403 attendu = bon signe


def _live_supabase(url, anon, findings):
    import json
    for t in ("users", "profiles", "todos", "messages", "posts", "accounts"):
        api = f"{url.rstrip('/')}/rest/v1/{t}?select=*&limit=1"
        req = urllib.request.Request(api, headers={"apikey": anon, "Authorization": f"Bearer {anon}"})
        try:
            with urllib.request.urlopen(req, timeout=_TIMEOUT) as r:
                body = r.read(2000).decode(errors="ignore")
                data = json.loads(body) if body.strip().startswith("[") else None
                if isinstance(data, list) and data:
                    findings.append(Finding(
                        detector="webscan", title=f"Table Supabase '{t}' lisible sans authentification (RLS off)",
                        severity="critique", category="CWE-284 / OWASP A01", file=url, line=0,
                        evidence=f"GET /rest/v1/{t} → 200 avec données",
                        impact="Toute la table est accessible publiquement via l'API : fuite de données confirmée.",
                        remediation="Activer la Row Level Security sur cette table + politiques d'accès.",
                        confidence="confirme", exposure="internet_no_auth"))
        except Exception:
            continue


def scan_url(url: str) -> dict:
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    findings = []
    final_url, body = _analyze_headers(url, findings)
    supa_url = supa_anon = None
    if body is not None:
        supa_url, supa_anon = _scan_bundle(final_url, body, findings)
        _probe_paths(final_url, findings)
        if supa_url and supa_anon:
            findings.append(Finding(
                detector="webscan", title="Identifiants Supabase découverts dans le bundle",
                severity="info", category="—", file=final_url, line=0,
                evidence=supa_url, impact="Permet de tester la RLS (clé anon publique par design).",
                remediation="Normal côté client ; la sécurité repose sur la RLS — vérifiée ci-dessous.",
                confidence="confirme", exposure="internet"))
            _live_supabase(supa_url, supa_anon, findings)

    # scoring + tri via engine
    from .engine import risk_score
    from .model import severity_rank
    seen, uniq = set(), []
    for f in findings:
        fp = f.fingerprint()
        if fp not in seen:
            seen.add(fp); uniq.append(f)
    uniq.sort(key=lambda f: (severity_rank(f.severity), -risk_score(f)))
    return {"target": final_url or url, "platform": "app en ligne (black-box)",
            "uses_supabase": bool(supa_url),
            "findings": [dict(f.to_dict(), score=risk_score(f)) for f in uniq]}
