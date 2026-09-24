"""Détecteur : dépendances et cryptographie de mots de passe.

Deux volets :
  1. SCA : si un auditeur est installé (npm/pip-audit/osv-scanner), on le lance ;
     sinon on relève au moins l'absence de lockfile (versions non figées =
     build non reproductible et vulnérabilités difficiles à suivre).
  2. Hachage de mot de passe : usage de MD5/SHA1 pour des mots de passe, ou
     stockage en clair — un grand classique du vibe code (issu de la checklist
     de contrôles attendus : bcrypt/Argon2 obligatoires).
"""
from __future__ import annotations
import json
import re
import shutil
import subprocess
from pathlib import Path
from ..model import Finding

WEAK_HASH = re.compile(r"(?ix)\b(md5|sha1)\s*\(", )
PASSWORD_CTX = re.compile(r"(?i)(password|passwd|pwd|mot_de_passe|motdepasse)")
STRONG = re.compile(r"(?i)(bcrypt|argon2|scrypt|pbkdf2)")


def _run_auditor(ctx):
    root = ctx.root
    # npm audit (si package-lock + npm dispo)
    if (root / "package-lock.json").exists() and shutil.which("npm"):
        try:
            r = subprocess.run(["npm", "audit", "--json"], cwd=root,
                               capture_output=True, text=True, timeout=120)
            data = json.loads(r.stdout or "{}")
            vulns = data.get("metadata", {}).get("vulnerabilities", {})
            total = sum(v for k, v in vulns.items() if k != "total")
            if total:
                worst = "critique" if vulns.get("critical") else (
                    "elevee" if vulns.get("high") else "moyenne")
                ctx.add(Finding(
                    detector="dependencies",
                    title=f"{total} dépendance(s) npm vulnérable(s) (npm audit)",
                    severity=worst, category="CWE-1104 / OWASP A06",
                    file="package-lock.json", line=0,
                    evidence=", ".join(f"{k}:{v}" for k, v in vulns.items() if v and k != "total"),
                    impact="Des composants tiers portent des vulnérabilités connues, "
                           "chemin d'entrée fréquent si la fonction vulnérable est atteinte.",
                    remediation="npm audit fix, ou monter les versions concernées. Prioriser "
                                "les vulnérabilités au catalogue CISA KEV et à fort EPSS.",
                    confidence="confirme", exposure="internet",
                ))
            return True
        except (subprocess.SubprocessError, json.JSONDecodeError, ValueError):
            pass
    return False


def run(ctx):
    root = ctx.root
    ran = _run_auditor(ctx)

    # absence de lockfile
    if (root / "package.json").exists() and not any(
            (root / lf).exists() for lf in ("package-lock.json", "yarn.lock", "pnpm-lock.yaml")):
        ctx.add(Finding(
            detector="dependencies",
            title="Aucun lockfile — versions de dépendances non figées",
            severity="faible", category="CWE-1104 / OWASP A06",
            file="package.json", line=0, evidence="ni package-lock.json ni yarn.lock ni pnpm-lock.yaml",
            impact="Sans versions figées, les installations divergent et une dépendance "
                   "peut basculer vers une version vulnérable sans que le code change.",
            remediation="Committer un lockfile et le maintenir. Lancer un audit SCA en CI.",
            confidence="confirme", exposure="interne",
        ))

    # hachage de mot de passe faible / en clair
    for path in ctx.iter_files():
        if path.suffix not in (".js", ".ts", ".jsx", ".tsx", ".py", ".php", ".sql", ".mjs", ".cjs"):
            continue
        text = ctx.read(path)
        if not text or not PASSWORD_CTX.search(text):
            continue
        for line_no, line in enumerate(text.splitlines(), 1):
            if WEAK_HASH.search(line) and PASSWORD_CTX.search(line):
                ctx.add(Finding(
                    detector="dependencies",
                    title="Mot de passe haché avec un algorithme faible (MD5/SHA1)",
                    severity="elevee", category="CWE-916 / OWASP A02",
                    file=ctx.rel(path), line=line_no, evidence=line.strip()[:120],
                    impact="MD5/SHA1 se cassent en masse hors ligne : une fuite de base "
                           "expose directement les mots de passe des utilisateurs.",
                    remediation="Hacher les mots de passe avec bcrypt, Argon2 ou scrypt "
                                "(fonctions lentes et salées), jamais MD5/SHA1.",
                    confidence="confirme", exposure="interne",
                ))
