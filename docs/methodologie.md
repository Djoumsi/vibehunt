# Conception et évaluation de vibehunt — chapitre méthodologique

> Chapitre rédigé pour le mémoire de master. Il décrit le problème traité,
> l'architecture de l'outil, la méthode de détection, l'évaluation empirique
> sur des applications réelles et les limites. Les résultats chiffrés
> proviennent de scans réels réalisés avec la version 0.4 de l'outil.

## 1. Problématique

L'essor des assistants de génération de code par IA (« vibe coding ») —
Lovable, Bolt, v0, Replit, Cursor, Windsurf, Codex, Claude Code, Copilot —
permet de produire des applications fonctionnelles sans expertise en
développement. Ce gain de productivité s'accompagne d'un angle mort : le code
généré embarque des vulnérabilités **caractéristiques et répétitives**, que
l'utilisateur non technicien ne sait ni repérer ni corriger.

L'objectif de ce travail est de concevoir un outil, **vibehunt**, capable de
**détecter et de collecter** automatiquement ces vulnérabilités, quel que soit
l'assistant ayant produit le code. L'outil se limite volontairement à la
sécurité **défensive** et à l'analyse d'applications dont l'utilisateur est
propriétaire.

## 2. Délimitation du périmètre

Une distinction structure tout le travail : il existe deux familles de risques
associées au vibe coding.

| | Vulnérabilités **dans le code produit** | Vulnérabilités **de l'assistant / plateforme** |
|---|---|---|
| Exemples | secret exposé, RLS désactivée, XSS, injection SQL, IAM trop large | prompt injection de l'IA, fuite de données d'entraînement, sandbox serveur défaillant, fuite de contexte entre sessions |
| Objet vulnérable | l'application livrée | l'outil de génération lui-même |
| Détectable par analyse de code ? | oui | non (recherche sur le modèle/la plateforme) |
| Traité par vibehunt | **oui — c'est le périmètre** | non — documenté comme contexte |

vibehunt traite exclusivement la première famille. La seconde (documentée dans
l'état de l'art à partir des incidents publics : exposition de secrets par
Copilot, exécution arbitraire signalée sur des interpréteurs de code,
défaillances de contrôle d'accès rapportées sur certaines plateformes) relève
d'un axe de recherche distinct qu'un scanner de code ne peut pas couvrir.

## 3. Modèle de menace propre au vibe code

L'analyse d'applications générées par IA fait ressortir un catalogue restreint
de vulnérabilités dominantes. Trois causent l'essentiel des fuites réelles :

1. **Secret exposé côté client.** L'assistant place une clé d'API dans le code
   du navigateur ou dans une variable préfixée `VITE_`/`NEXT_PUBLIC_`, la
   rendant lisible par tout visiteur.
2. **Row Level Security (RLS) Supabase désactivée.** L'API REST de Supabase
   expose toutes les tables ; sans RLS, la clé anonyme (publique par
   conception) donne accès à l'ensemble des données.
3. **Autorisation côté client uniquement.** Le contrôle d'accès est réalisé en
   JavaScript, contournable par appel direct à l'API.

Le choix d'un outil **spécialisé** sur ce catalogue, plutôt qu'un scanner SAST
généraliste, améliore la précision : les règles sont taillées pour les stacks
réellement produites par ces assistants (majoritairement React/Next.js +
Supabase/Firebase).

## 4. Architecture

vibehunt est une application en ligne de commande écrite en Python (bibliothèque
standard pour l'analyse statique). Elle est organisée en modules à
responsabilité unique :

- **`model`** — structures partagées : `Finding` (un défaut : localisation,
  catégorie CWE/OWASP, preuve, impact, correctif, confiance, exposition) et
  `ScanContext` (parcours filtré du dépôt, lecture avec cache).
- **`platforms`** — empreinte de l'assistant générateur. **Non bloquante** : la
  détection sert à étiqueter le rapport, jamais à conditionner l'analyse. Une
  plateforme inconnue est traitée comme les autres.
- **`detectors/`** — le cœur extensible : un module par famille de
  vulnérabilité, exposant une fonction `run(ctx)`.
- **`engine`** — orchestration, calcul du score de risque, dédoublonnage par
  empreinte, tri.
- **`collector`** — persistance SQLite des findings (volet « collecter » :
  historique multi-applications, statistiques, comparaison).
- **`report` / `sarif`** — restitution : Markdown, HTML autonome, SARIF 2.1.0.

Ajouter un détecteur consiste à écrire un module `run(ctx)` et à l'enregistrer :
l'architecture est pensée pour l'extension, condition d'un outil pérenne.

## 5. Méthode de détection

### 5.1 Détecter une présence vs une absence

Le principe directeur est la distinction entre deux natures de détection, aux
fiabilités très différentes :

- **Présence d'un défaut** (un secret, une requête SQL concaténée, une règle
  Firebase ouverte) : fiable, la preuve est dans le code.
- **Absence d'un contrôle** (pas de protection CSRF, pas de limitation de
  débit) : intrinsèquement moins fiable. Ces règles ne se déclenchent que si le
  contrôle est **réellement attendu** (la protection CSRF n'est signalée
  manquante que si des sessions par cookie et des routes mutatrices coexistent)
  et sont marquées « à vérifier ». Objectif : n'alerter que quand c'est
  pertinent, pour préserver la confiance de l'utilisateur.

### 5.2 Suivi de la donnée

Pour les injections (SQL, XSS, SSRF, exécution dynamique), la détection repose
sur l'identification de **puits dangereux** alimentés par une donnée variable,
plutôt que sur une simple correspondance de mots-clés. La confiance est ajustée
selon que le puits reçoit une constante ou une entrée variable.

### 5.3 Score de risque contextuel

Chaque finding reçoit un score 0–100 combinant la **sévérité**, l'**exposition**
(internet non authentifié > internet > interne > isolé) et la **confiance**.
Ce score contextuel, plutôt qu'une sévérité brute, permet de prioriser ce qui
compte réellement pour l'application analysée.

### 5.4 Confirmation dynamique

Un mode `--live` complète l'analyse statique : il interroge l'API Supabase
d'une application (dont l'utilisateur est propriétaire) pour **confirmer**
qu'une table répond sans authentification — preuve directe que la RLS est
désactivée. Le test se limite à la preuve minimale (une ligne), sans
extraction de données.

## 6. Évaluation empirique

L'outil a été exécuté sur des applications réelles de l'auteur, générées ou
assistées par IA. Résultats (version 0.4, dernier scan par application) :

| Application | Findings | Critique | Élevé | Moyen | Observation principale |
|---|---|---|---|---|---|
| erp-scolaire | 8 | 0 | 6 | 2 | XSS récurrents (insertion HTML non assainie) |
| plantdoc | 2 | 0 | 2 | 0 | défauts mineurs, code globalement propre |
| site-vitrine | 0 | 0 | 0 | 0 | aucune vulnérabilité détectée |

**Failles les plus répandues** sur l'échantillon : insertion HTML non assainie
(`innerHTML`) et, sur les applications concernées, absence de vérification de
signature de webhook.

Ce processus d'évaluation a été **itératif** : le test sur code réel a révélé
des faux positifs corrigés dans l'outil, chacun couvert ensuite par un test de
non-régression :

- une requête **préparée** avec arithmétique SQL (`colonne + 1`) prise à tort
  pour une concaténation → règle affinée pour exiger une variable et exclure les
  requêtes paramétrées ;
- un `->fetch()` PDO (PHP) confondu avec un `fetch()` HTTP → détection SSRF
  restreinte au `fetch(` global ;
- la comptabilisation de tables « sans RLS » sur une base MySQL classique →
  conditionnée à l'usage réel de Supabase ;
- l'analyse de fichiers **minifiés tiers** (bundles) → désormais ignorés.

Cette boucle « scanner du code réel → corriger la précision → tester » est au
cœur de la démarche : un outil de sécurité perd sa valeur dès qu'il produit du
bruit.

## 7. Validation

La qualité est garantie par une suite de **22 tests automatisés** s'appuyant sur
deux applications de référence :

- une application **vulnérable** rassemblant les défauts du catalogue — l'outil
  doit tous les remonter ;
- une application **saine** respectant les bonnes pratiques — l'outil ne doit
  produire **aucune** vulnérabilité grave (validation de l'absence de faux
  positifs).

## 8. Limites

- L'analyse statique ne suit pas le flux de données de bout en bout ; certains
  résultats sont marqués « à vérifier » et demandent une confirmation.
- Les détecteurs d'absence dépendent de la présence de signaux dans le dépôt
  (une protection appliquée par un service externe non versionné n'est pas
  visible).
- Le périmètre est celui du code : les vulnérabilités des plateformes de
  génération elles-mêmes ne sont pas couvertes (cf. §2).
- La confirmation dynamique se limite actuellement à Supabase.

## 9. Perspectives

Détection de licences et génération de SBOM, plugin d'intégration continue
prêt à l'emploi (l'export SARIF est déjà en place), extension de la
confirmation dynamique à Firebase, et enrichissement du catalogue de
détecteurs au fil des motifs observés sur de nouvelles applications.
