# vibehunt

**Scanner de sécurité pour applications « vibe codées ».**

vibehunt détecte et collecte les failles récurrentes des applications générées
par IA — quel que soit l'outil utilisé : **Lovable, Bolt, v0, Replit, Cursor,
Windsurf, Codex, Claude Code, Copilot**… ou aucun. La détection porte sur le
**code**, jamais sur la plateforme : une app d'origine inconnue est analysée
exactement comme les autres.

> ⚠️ **Usage autorisé uniquement.** vibehunt est un outil défensif, à utiliser
> sur **vos propres** applications (ou dans un cadre de test explicitement
> mandaté). Le mode dynamique interroge une cible en ligne : ne le pointez que
> sur une app qui vous appartient.

## Pourquoi un outil dédié au vibe code

Les générateurs d'apps par IA produisent des failles **caractéristiques et
répétitives**. Trois d'entre elles causent la majorité des fuites de données :

1. **Secrets exposés côté client** — une clé API (OpenAI, Stripe…) placée dans
   le code du navigateur ou une variable `VITE_`/`NEXT_PUBLIC_` : lisible par
   tout visiteur.
2. **RLS Supabase désactivée** — l'API REST de Supabase expose toutes les
   tables ; sans Row Level Security, n'importe qui lit et écrit la base.
3. **Autorisation côté client uniquement** — un contrôle « es-tu admin ? » en
   JavaScript, contournable en appelant l'API directement.

vibehunt cible ce catalogue plutôt que de faire du SAST généraliste — d'où sa
précision (peu de faux positifs) sur ces stacks.

## Installation

```bash
git clone https://github.com/Djoumsi/vibehunt
cd vibehunt
pip install -e .        # expose la commande `vibehunt`
```

Le scan statique n'utilise que la bibliothèque standard Python (≥ 3.9).
`pytest` n'est requis que pour les tests.

## Utilisation

```bash
# Analyse statique d'un dépôt local
vibehunt scan ./mon-app

# … ou directement depuis GitHub (clone temporaire)
vibehunt scan https://github.com/moi/mon-app

# Rapports dans un fichier (Markdown, HTML autonome) + sortie JSON
vibehunt scan ./mon-app --out rapport.md
vibehunt scan ./mon-app --html rapport.html
vibehunt scan ./mon-app --json

# Statistiques agrégées de toutes vos collectes
vibehunt stats

# Confirmation DYNAMIQUE que des tables Supabase répondent sans auth (VOS apps)
vibehunt live https://mon-app.com \
  --supabase-url https://xxxx.supabase.co \
  --anon-key <clé-anon-publique> \
  --tables profiles,todos,messages
```

Le code de sortie de `scan` vaut **1** si au moins une faille critique ou
élevée est trouvée (pratique en intégration continue).

## Architecture

```
vibehunt/
├── cli.py            # commandes scan / stats / live
├── engine.py         # orchestration, scoring, dédoublonnage
├── model.py          # Finding + ScanContext (lecture filtrée du dépôt)
├── platforms.py      # empreinte de plateforme (non bloquante)
├── collector.py      # collecte SQLite (historique multi-apps + stats)
├── report.py         # rapport Markdown + JSON
└── detectors/        # cœur extensible : un module = une famille de failles
    ├── secrets.py            # clés/API en dur, surpondérées côté client
    ├── supabase_rls.py       # service_role client, RLS off, tables non protégées
    ├── client_authz.py       # contrôle d'accès côté client uniquement
    ├── cors.py               # CORS permissif (origine * + credentials)
    ├── exposed_files.py      # .env versionné, routes de debug/seed exposées
    ├── input_validation.py   # XSS (dangerouslySetInnerHTML, v-html…) et injection SQL
    ├── dependencies.py       # SCA (npm audit), lockfile absent, hachage MD5/SHA1
    ├── ssrf.py               # requête sortante vers une URL contrôlée par l'utilisateur
    └── missing_protections.py # CSRF, rate limiting, signature de webhook (HMAC) absents
```

### Ajouter un détecteur

1. Créer `vibehunt/detectors/mon_detecteur.py` avec une fonction
   `run(ctx)` qui ajoute des `Finding` via `ctx.add(...)`.
2. L'enregistrer dans `vibehunt/detectors/__init__.py` (liste `ALL`).

Chaque `Finding` porte : localisation, catégorie (CWE/OWASP), preuve, impact
métier, correctif concret, niveau de confiance et exposition (qui alimentent le
score de risque 0–100).

## Feuille de route

- **v0.1** : secrets, RLS Supabase, autorisation client ; collecte SQLite ;
  rapport Markdown/JSON ; mode dynamique RLS.
- **v0.2** : CORS permissif, fichiers/endpoints exposés, validation d'entrée
  (XSS/injection SQL), dépendances (SCA + hachage faible), rapport HTML.
- **v0.3 (actuel)** : SSRF (URL contrôlée par l'utilisateur), et détection
  d'ABSENCE de protection — CSRF, rate limiting sur l'auth, signature de
  webhook (HMAC). Détecteurs d'absence conditionnés à des prérequis stricts
  et marqués « à vérifier » pour limiter les faux positifs.
- **v0.4** : Firebase (règles ouvertes), export CI/SARIF, rapport comparatif
  multi-apps depuis la base de collecte.

## Note de conception : présence vs absence

Détecter la PRÉSENCE d'un défaut (un secret, une requête SQL concaténée) est
fiable. Détecter l'ABSENCE d'un contrôle (pas de CSRF, pas de rate limiting)
l'est moins : c'est pourquoi ces règles ne se déclenchent que si le contrôle
est réellement attendu (ex. CSRF seulement si des sessions par cookie et des
routes mutatrices existent) et sont marquées « à vérifier ». Objectif : n'alerter
que quand c'est pertinent. Le mode `--live` sert à confirmer sur l'app réelle.

## Tests

```bash
pytest -q
```

Deux applications de référence servent de garde-fou : une vulnérable (doit
lever les failles) et une saine (ne doit lever aucune faille grave).

## Licence

MIT.
