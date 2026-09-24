"""Orchestrateur : prépare le contexte, lance les détecteurs, score, dédoublonne."""
from __future__ import annotations
from pathlib import Path
from . import platforms
from .detectors import ALL
from .model import ScanContext, severity_rank

# score de risque 0..100 (aligné sur la logique du skill cybersec-agent)
_SEV_BASE = {"critique": 90, "elevee": 70, "moyenne": 45, "faible": 20, "info": 5}
_EXPO_BONUS = {"internet_no_auth": 8, "internet": 4, "interne": 0, "isole": -5}
_CONF_ADJ = {"confirme": 0, "probable": -5, "a_verifier": -12}


def risk_score(f) -> int:
    s = _SEV_BASE.get(f.severity, 30)
    s += _EXPO_BONUS.get(f.exposure, 0)
    s += _CONF_ADJ.get(f.confidence, 0)
    return max(0, min(100, s))


def scan(root: str) -> dict:
    root_path = Path(root).resolve()
    if not root_path.is_dir():
        raise NotADirectoryError(f"Dossier introuvable : {root_path}")

    ctx = ScanContext(root=root_path)
    ctx.platform = platforms.detect(root_path)

    for detector in ALL:
        try:
            detector.run(ctx)
        except Exception as e:  # un détecteur qui plante ne doit pas tout arrêter
            print(f"  [!] détecteur {getattr(detector, '__name__', '?')} en erreur : {e}")

    # dédoublonnage par empreinte
    seen, unique = set(), []
    for f in ctx.findings:
        fp = f.fingerprint()
        if fp not in seen:
            seen.add(fp)
            unique.append(f)

    # tri : sévérité puis score
    unique.sort(key=lambda f: (severity_rank(f.severity), -risk_score(f)))

    return {
        "target": str(root_path),
        "platform": ctx.platform,
        "uses_supabase": platforms.uses_supabase(ctx),
        "findings": [dict(f.to_dict(), score=risk_score(f)) for f in unique],
    }
