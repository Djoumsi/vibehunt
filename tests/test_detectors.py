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


# --- v0.3 : SSRF + absence de protections ---

def test_detecte_ssrf(vuln):
    assert any("SSRF" in t for t in titles(vuln))


def test_detecte_webhook_sans_signature(vuln):
    assert any("webhook" in t.lower() for t in titles(vuln))


def test_detecte_rate_limiting_absent(vuln):
    assert any("rate limiting" in t.lower() for t in titles(vuln))


def test_detecte_csrf_absent(vuln):
    assert any("CSRF" in t for t in titles(vuln))


def test_absence_control_ne_matche_pas_un_commentaire():
    # une simple mention "csrf" en commentaire ne doit pas faire croire à une protection
    from vibehunt.detectors import missing_protections as mp
    assert not mp.CSRF_LIB.search("// TODO: penser au csrf plus tard")
    assert mp.CSRF_LIB.search("app.use(csrfProtection)")


# --- v0.4 : Firebase + SARIF ---

def test_detecte_firebase_ouvert(vuln):
    assert any("Firebase" in t and "true" in t for t in titles(vuln))


def test_export_sarif_valide(vuln):
    import json
    from vibehunt import sarif
    doc = json.loads(sarif.to_sarif(vuln))
    assert doc["version"] == "2.1.0"
    assert doc["runs"][0]["tool"]["driver"]["name"] == "vibehunt"
    assert len(doc["runs"][0]["results"]) == len(vuln["findings"])


# --- v0.5 : interface web ---

def test_webui_importe_et_rend(vuln):
    from vibehunt import webui, report
    # le rendu HTML du rapport doit s'intégrer dans la page (pas d'exception)
    inner = report.to_html(vuln)
    assert "<body>" in inner and "vibehunt" in inner
    # la page enveloppe se formate sans erreur
    page = webui._PAGE.format(body="x", **webui._tabs("scan"))
    assert "vibehunt" in page and "Scan statique" in page


# --- v0.6 : scan black-box (fonctions pures, sans réseau) ---

def test_webscan_headers_manquants():
    from vibehunt import webscan
    f = []
    # simuler l'analyse : on appelle la logique d'en-têtes via un faux résultat
    # (test de la table des en-têtes attendus)
    assert "content-security-policy" in webscan.SECURITY_HEADERS
    assert "strict-transport-security" in webscan.SECURITY_HEADERS


def test_webscan_regex_supabase():
    from vibehunt import webscan
    assert webscan.SUPABASE_URL_RE.search("const u='https://abcdef1234567890.supabase.co'")
    assert webscan.SCRIPT_SRC_RE.findall('<script src="/assets/index-abc.js"></script>') == ["/assets/index-abc.js"]
