"""Détecteurs de failles. Chaque détecteur expose run(ctx) -> ajoute des Finding."""
from . import (secrets, supabase_rls, client_authz, cors, exposed_files,
               input_validation, dependencies, ssrf, missing_protections)

# Registre : ordre = ordre d'exécution. Ajoute un détecteur ici pour l'activer.
ALL = [secrets, supabase_rls, client_authz, cors, exposed_files,
       input_validation, dependencies, ssrf, missing_protections]
