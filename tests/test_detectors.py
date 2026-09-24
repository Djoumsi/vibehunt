"""Tests de non-régression des détecteurs.

Principe : deux applications de référence dans tests/fixtures/
  - vuln_app   : truffée de failles typiques du vibe code -> doit les remonter ;
  - secure_app : bonnes pratiques -> ne doit RIEN remonter de critique/élevé.
Ces tests garantissent qu'on détecte les vraies failles sans crier au loup.
"""
import os
import pytest
from vibehunt import engine

HERE = os.path.dirname(__file__)
VULN = os.path.join(HERE, "fixtures", "vuln_app")
SECURE = os.path.join(HERE, "fixtures", "secure_app")


@pytest.fixture(scope="module")
def vuln():
    return engine.scan(VULN)


@pytest.fixture(scope="module")
def secure():
    return engine.scan(SECURE)


def titles(result):
    return [f["title"] for f in result["findings"]]


def test_detecte_secret_client(vuln):
    assert any("OpenAI" in t and "CLIENT" in t for t in titles(vuln)), \
        "la clé exposée via VITE_ doit être critique côté client"


def test_detecte_service_role_client(vuln):
    assert any("service_role" in t for t in titles(vuln))


def test_detecte_rls_manquant(vuln):
    assert any("RLS" in t for t in titles(vuln))


def test_detecte_authz_client(vuln):
    assert any("côté client" in t.lower() and "rôle" in t.lower() for t in titles(vuln))


def test_vuln_a_du_critique(vuln):
    assert any(f["severity"] == "critique" for f in vuln["findings"])


def test_secure_sans_critique_ni_eleve(secure):
    graves = [f for f in secure["findings"] if f["severity"] in ("critique", "elevee")]
    assert graves == [], f"faux positifs sur l'app saine : {[f['title'] for f in graves]}"


def test_plateforme_non_bloquante():
    # même une app sans indice de plateforme est scannée
    assert engine.scan(VULN)["findings"], "le scan doit fonctionner quelle que soit la plateforme"


def test_fingerprint_stable(vuln):
    fps = [f["fingerprint"] for f in vuln["findings"]]
    assert len(fps) == len(set(fps)), "les empreintes doivent être uniques (dédoublonnage)"


# --- v0.2 : nouveaux détecteurs ---

def test_detecte_cors_permissif(vuln):
    assert any("CORS" in t for t in titles(vuln))


def test_detecte_route_debug(vuln):
    assert any("debug" in t.lower() for t in titles(vuln))


def test_detecte_env_versionne(vuln):
    assert any(".env" in t for t in titles(vuln) if "Fichier sensible" in t)


def test_detecte_xss(vuln):
    assert any("XSS" in t for t in titles(vuln))


def test_detecte_injection_sql(vuln):
    assert any("SQL" in t for t in titles(vuln))


def test_detecte_hash_faible(vuln):
    assert any("MD5" in t or "faible" in t.lower() for t in titles(vuln))


def test_html_report_genere(vuln):
    from vibehunt import report
    h = report.to_html(vuln)
    assert h.startswith("<!DOCTYPE html>") and "vibehunt" in h and "CRITIQUE" in h
