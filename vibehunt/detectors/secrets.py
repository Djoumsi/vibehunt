"""Détecteur : secrets exposés, avec une attention particulière au FRONT.

En vibe code, la faute la plus grave n'est pas seulement d'avoir un secret en
dur — c'est de le mettre dans du code qui part dans le navigateur. Un secret
côté serveur mal rangé est un problème ; le même secret côté client est
public de fait, car n'importe quel visiteur peut le lire dans le bundle.

D'où deux niveaux :
  - secret détecté            -> élevée
  - secret détecté CÔTÉ CLIENT -> critique
et un cas à part, le plus dangereux du vibe code Supabase :
  - clé service_role Supabase (droit d'admin, contourne RLS) -> critique absolu
"""
from __future__ import annotations
import math
import re
from ..model import Finding

# motifs (nom, regex, sévérité de base, catégorie)
PATTERNS = [
    ("Clé service_role Supabase", r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]*role[A-Za-z0-9_-]*\.[A-Za-z0-9_-]+", "critique", "CWE-798"),
    ("Clé d'accès AWS", r"\bAKIA[0-9A-Z]{16}\b", "critique", "CWE-798"),
    ("Jeton GitHub", r"\bgh[pousr]_[0-9A-Za-z]{36,}\b", "critique", "CWE-798"),
    ("Clé Stripe secrète", r"\bsk_live_[0-9a-zA-Z]{24,}\b", "critique", "CWE-798"),
    ("Clé OpenAI", r"\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}\b", "critique", "CWE-798"),
    ("Clé Anthropic", r"\bsk-ant-(?:api\d\d-)?[A-Za-z0-9_-]{20,}\b", "critique", "CWE-798"),
    ("Clé API Google", r"\bAIza[0-9A-Za-z_-]{35}\b", "elevee", "CWE-798"),
    ("Jeton Slack", r"\bxox[baprs]-[0-9A-Za-z-]{10,}\b", "elevee", "CWE-798"),
    ("Jeton Mapbox secret", r"\bsk\.eyJ[A-Za-z0-9_-]{20,}\b", "elevee", "CWE-798"),
    ("Clé privée (PEM)", r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----", "critique", "CWE-798"),
    ("Chaîne de connexion BD", r"(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?)://[^\s:@/]+:[^\s:@/]+@[^\s/]+", "elevee", "CWE-798"),
]

# Placeholders : ancrés en limites de mot pour ne PAS rejeter une vraie clé qui
# contiendrait par hasard une sous-chaîne du genre "123456".
PLACEHOLDER = re.compile(
    r"(?i)(\byour[_-]?\w*|\bexample\b|\bsample\b|\bplaceholder\b|\bchange[_-]?me\b|"
    r"x{4,}|<[^>]+>|\bdummy\b|\bfake\b|\btest[_-]?key\b|\bredacted\b|\*{4,}|"
    r"\bfoobar\b|\bici\b|\bvotre\w*|\btodo\b|\bto[_-]?fill\b|\bxxx+\b)"
)

# fichiers/chemins qui finissent dans le navigateur
CLIENT_HINTS = ("/src/", "/components/", "/app/", "/pages/", "/lib/", "/public/",
                "/client", "\\src\\", "index.html", ".jsx", ".tsx", ".vue", ".svelte")
# fichiers plutôt serveur / non embarqués
SERVER_HINTS = ("/api/", "/server", "/functions/", "/supabase/functions/",
                "/edge-functions/", "/backend/", ".env")

# préfixes qui EXPOSENT une variable au navigateur (donc secret = fuite publique)
PUBLIC_ENV_PREFIX = re.compile(r"(?i)\b(NEXT_PUBLIC_|VITE_|REACT_APP_|PUBLIC_|EXPO_PUBLIC_|NUXT_PUBLIC_)")


def _entropy(s: str) -> float:
    if not s:
        return 0.0
    return -sum((s.count(c) / len(s)) * math.log2(s.count(c) / len(s)) for c in set(s))


def _looks_real(text: str) -> bool:
    if PLACEHOLDER.search(text):
        return False
    tokens = re.findall(r"[A-Za-z0-9_\-./+]{16,}", text)
    return not tokens or max(_entropy(t) for t in tokens) >= 3.0


def _is_client_side(relpath: str) -> bool:
    r = relpath.replace("\\", "/").lower()
    if any(h in r for h in (s.lower() for s in SERVER_HINTS)):
        return False
    return any(h.lower() in r for h in CLIENT_HINTS)


def run(ctx):
    for path in ctx.iter_files():
        rel = ctx.rel(path)
        text = ctx.read(path)
        if not text:
            continue
        client = _is_client_side(rel)
        for line_no, line in enumerate(text.splitlines(), 1):
            if len(line) > 4000:
                continue
            # cas particulier : secret exposé par une variable PUBLIC_*
            public_env = bool(PUBLIC_ENV_PREFIX.search(line))
            for name, pattern, base_sev, cat in PATTERNS:
                for m in re.finditer(pattern, line):
                    snippet = m.group(0)
                    if not _looks_real(snippet):
                        continue
                    # la clé anon Supabase (role=anon) est publique par design :
                    # ne pas la crier comme un secret. Seule service_role compte.
                    if name == "Clé service_role Supabase" and "service_role" not in snippet and "service_role" not in line and "service" not in line.lower():
                        # heuristique : un JWT sans mention de service_role est
                        # probablement la clé anon (légitimement publique)
                        if "anon" in line.lower() or "publishable" in line.lower():
                            continue
                    sev = base_sev
                    where = "serveur"
                    if client or public_env:
                        sev = "critique"
                        where = "CLIENT (navigateur)"
                    shown = snippet if len(snippet) <= 14 else snippet[:8] + "…" + snippet[-4:]
                    ctx.add(Finding(
                        detector="secrets",
                        title=f"{name} en dur — exposé côté {where}",
                        severity=sev,
                        category=f"{cat} / OWASP A05",
                        file=rel, line=line_no, evidence=shown,
                        impact=("Clé lisible par tout visiteur dans le bundle client — "
                                "usage frauduleux, coûts, accès aux données."
                                if (client or public_env)
                                else "Identifiant en dur : fuite si le code est partagé, "
                                     "compromis dans l'historique Git."),
                        remediation=("Retirer la clé du code, la placer dans une variable "
                                     "d'environnement SERVEUR (jamais NEXT_PUBLIC_/VITE_ pour un secret), "
                                     "appeler l'API tierce depuis une fonction serveur/edge, "
                                     "puis RÉVOQUER et régénérer la clé (elle est déjà compromise)."),
                        confidence="confirme",
                        exposure="internet_no_auth" if (client or public_env) else "internet",
                    ))
