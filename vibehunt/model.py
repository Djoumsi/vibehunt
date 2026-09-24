"""Modèle de données partagé : Finding et ScanContext.

On garde volontairement des dataclasses simples : elles se sérialisent en JSON,
se stockent en SQLite et se lisent dans un rapport sans couche d'ORM.
"""
from __future__ import annotations
import hashlib
import os
from dataclasses import dataclass, field, asdict
from pathlib import Path

SEVERITIES = ["critique", "elevee", "moyenne", "faible", "info"]
_SEV_RANK = {s: i for i, s in enumerate(SEVERITIES)}


@dataclass
class Finding:
    detector: str            # nom du détecteur émetteur
    title: str               # titre factuel et spécifique
    severity: str            # une valeur de SEVERITIES
    category: str            # CWE / OWASP / classe de faille
    file: str = ""           # chemin relatif
    line: int = 0
    evidence: str = ""       # extrait minimal, tronqué/masqué
    impact: str = ""         # ce qu'un attaquant obtient, en clair
    remediation: str = ""    # correctif concret
    confidence: str = "confirme"   # confirme | probable | a_verifier
    exposure: str = "internet"     # sert au scoring (cf. triage)

    def fingerprint(self) -> str:
        """Identité stable d'un finding : sert à dédoublonner et à suivre
        un même défaut d'un scan à l'autre."""
        key = f"{self.detector}|{self.category}|{self.file}|{self.line}|{self.title}"
        return hashlib.sha1(key.encode()).hexdigest()[:12]

    def to_dict(self) -> dict:
        d = asdict(self)
        d["fingerprint"] = self.fingerprint()
        return d


@dataclass
class ScanContext:
    """Ce qu'un détecteur reçoit. Il lit les fichiers via cette classe pour
    profiter du filtrage (pas de node_modules, binaires, etc.) et du cache."""
    root: Path
    platform: str = "inconnue"     # rempli par platforms.detect()
    findings: list = field(default_factory=list)
    _cache: dict = field(default_factory=dict)

    SKIP_DIRS = {".git", "node_modules", "vendor", "dist", "build", ".next",
                 "__pycache__", ".venv", "venv", "coverage", ".turbo", "out"}
    # extensions pertinentes pour du vibe code web
    CODE_EXT = {".js", ".jsx", ".ts", ".tsx", ".vue", ".svelte", ".astro",
                ".json", ".env", ".html", ".py", ".php", ".mjs", ".cjs",
                ".toml", ".yaml", ".yml", ".sql", ".rules"}

    SKIP_FILE = (".min.js", ".min.css", ".bundle.js", ".chunk.js", "-min.js",
                 ".umd.min.js", ".production.min.js")

    def iter_files(self):
        for dirpath, dirnames, filenames in os.walk(self.root):
            dirnames[:] = [d for d in dirnames if d not in self.SKIP_DIRS]
            for fn in filenames:
                # ignorer les bundles/minifiés tiers (bruit, faux positifs)
                if any(fn.endswith(suf) for suf in self.SKIP_FILE):
                    continue
                p = Path(dirpath) / fn
                if p.suffix in self.CODE_EXT or fn.startswith(".env"):
                    yield p

    def read(self, path: Path) -> str:
        """Lecture avec cache et garde-fous (taille, binaire)."""
        key = str(path)
        if key in self._cache:
            return self._cache[key]
        try:
            if path.stat().st_size > 3_000_000:
                text = ""
            else:
                text = path.read_text(errors="ignore")
        except OSError:
            text = ""
        self._cache[key] = text
        return text

    def rel(self, path: Path) -> str:
        try:
            return str(Path(path).relative_to(self.root))
        except ValueError:
            return str(path)

    def add(self, finding: Finding):
        self.findings.append(finding)


def severity_rank(sev: str) -> int:
    return _SEV_RANK.get(sev, len(SEVERITIES))
