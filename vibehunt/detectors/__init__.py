"""Détecteurs de failles. Chaque détecteur expose run(ctx) -> list[Finding]."""
from . import secrets, supabase_rls, client_authz

# Registre : ordre = ordre d'exécution. Ajoute un détecteur ici pour l'activer.
ALL = [secrets, supabase_rls, client_authz]
