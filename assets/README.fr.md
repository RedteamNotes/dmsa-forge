# dMSA Forge

[![Release](https://img.shields.io/github/v/release/RedteamNotes/dmsa-forge?label=release)](https://github.com/RedteamNotes/dmsa-forge/releases/tag/v0.5.17)
[![Tests](https://github.com/RedteamNotes/dmsa-forge/actions/workflows/test.yml/badge.svg)](https://github.com/RedteamNotes/dmsa-forge/actions/workflows/test.yml)
[![License](https://img.shields.io/badge/license-Impacket%20Apache--1.1-blue)](https://github.com/RedteamNotes/dmsa-forge/blob/main/LICENSE)

**Langue :** [English](../README.md) | [简体中文](README.zh-CN.md) | Français

Version actuelle : `v0.5.17`

Forge [dMSA](https://learn.microsoft.com/fr-fr/windows-server/identity/ad-ds/manage/delegated-managed-service-accounts/delegated-managed-service-accounts-overview) pour les workflows LDAP [BadSuccessor](https://www.akamai.com/blog/security-research/abusing-dmsa-for-privilege-escalation-in-active-directory) autorisés : assess, add, verify et delete.

Conçu autour de LDAP 389 signé, de la création atomique de dMSA, de la vérification après ajout, d'une aide opérateur concise, des profils projet et du reporting structuré.

<p align="center">
  <img src="dMSAForge.png" alt="dMSA Forge by RedteamNotes" width="100%">
</p>

Ce projet est basé sur Impacket `examples/badsuccessor.py` et conserve l'attribution ainsi que le contexte de licence en amont. Cette version est largement remaniée par **RedteamNotes** afin de rendre explicites et reproductibles LDAP 389 avec signature, la création atomique de dMSA et la vérification après ajout.

À utiliser uniquement dans des environnements pour lesquels vous disposez d'une autorisation explicite.

## Changements principaux

- Utilise directement le `LDAPConnection` natif d'Impacket ; `ldap3` n'est plus une dépendance d'exécution.
- Prend en charge LDAP signé sur le port 389 pour les environnements qui imposent la signature LDAP et où LDAPS n'est pas utilisable.
- Écrit les attributs essentiels du dMSA dans l'AddRequest initiale, notamment `msDS-GroupMSAMembership`, `msDS-ManagedAccountPrecededByLink` et `msDS-DelegatedMSAState`.
- Vérifie l'objet en le relisant depuis le DC après l'ajout.
- Analyse `msDS-GroupMSAMembership` comme un descripteur de sécurité binaire et affiche un résumé lisible au lieu d'octets bruts.
- Ajoute `verify` comme action en lecture seule.
- Modernise l'expérience opérateur avec des commandes nommées par tâche, une aide contextuelle concise, des valeurs par défaut inférées, des suggestions de prochaines commandes et des rapports structurés.
- Ajoute des workflows de preflight et de reporting plus sûrs : plans dry-run, guardrails de périmètre, sortie structurée masquée, contrôles readiness et diagnostics d'échec plus clairs.
- Garde une sortie honnête : une vérification LDAP réussie ne signifie pas que le KDC est prêt.

## Installation

Depuis GitHub avec `pipx` :

```bash
pipx install git+https://github.com/RedteamNotes/dmsa-forge.git
```

Ou clonez le dépôt puis installez depuis une copie locale :

```bash
git clone https://github.com/RedteamNotes/dmsa-forge.git
python -m venv dmsa-forge/.venv
source dmsa-forge/.venv/bin/activate
python -m pip install ./dmsa-forge
```

Après installation, exécutez :

```bash
dmsaforge -h
```

Quand une nouvelle version est disponible, mettez à jour l'environnement actif :

```bash
dmsaforge update
```

`update` compare d'abord la version installée avec la version cible. Si elles correspondent, pip est ignoré ; si elles diffèrent, la mise à jour est lancée, que la version cible soit supérieure ou inférieure. Utilisez `dmsaforge update --force` seulement pour exécuter pip sans contrôle de version.

Entrées d'aide utiles :

```bash
dmsaforge add -h
dmsaforge update --dry-run
```

Pour une utilisation depuis une copie source sans installation, exécutez `./dmsaforge.py`.
Les exemples et les next steps générés utilisent les options longues par défaut. Les alias courts comme `-m`, `-p`, `-d`, `-o` et `-t` restent disponibles pour l'usage interactif.

## Démarrage Rapide

Prévisualisez un add avec le profil safe. Les commandes de ce README sont volontairement présentées sur une seule ligne, prêtes à copier ; si vous utilisez un wrapper local comme `proxychains -f chain1080.conf -q`, placez-le avant `dmsaforge`.

```bash
dmsaforge plan add redteamnotes.com/operator:'PASSWORD' --profile safe --ou 'OU=Dev,DC=redteamnotes,DC=com' --dmsa-name redpen --target-account 'Administrator' --principals-allowed '<SID_OR_NAME>'
```

Par défaut, `DOMAIN/user` infère `--scope-domain`, `--scope-base-dn` et `--base-dn` ; LDAP/389 est la méthode et le port par défaut ; `--dns-hostname` est inféré depuis `--dmsa-name` et le domaine du compte. Pour `add`, choisissez explicitement le compte predecessor avec `--target-account` et le lecteur du mot de passe géré avec `--principals-allowed`.

Les modèles utilisent `redpen` comme nom dMSA suggéré et `Administrator` comme exemple courant de predecessor account. Remplacez l'une ou l'autre valeur lorsque la chaîne autorisée cible un autre objet.

## Flux Opérateur

Ces modèles gardent chaque commande sur une seule ligne pour le copier-coller, l'historique du terminal et les runbooks reproductibles. Remplacez les placeholders avant utilisation.

Évaluer les droits OU :

```bash
dmsaforge assess redteamnotes.com/operator:'PASSWORD' --dc-host dc.redteamnotes.com
```

Vérification avant ajout :

```bash
dmsaforge verify redteamnotes.com/operator:'PASSWORD' --dc-host dc.redteamnotes.com --ou 'OU=Dev,DC=redteamnotes,DC=com' --dmsa-name redpen
```

Plan d'ajout :

```bash
dmsaforge plan add redteamnotes.com/operator:'PASSWORD' --dc-host dc.redteamnotes.com --ou 'OU=Dev,DC=redteamnotes,DC=com' --dmsa-name redpen --target-account 'Administrator' --principals-allowed '<SID_OR_NAME>'
```

Ajouter :

```bash
dmsaforge add redteamnotes.com/operator:'PASSWORD' --dc-host dc.redteamnotes.com --ou 'OU=Dev,DC=redteamnotes,DC=com' --dmsa-name redpen --target-account 'Administrator' --principals-allowed '<SID_OR_NAME>'
```

Vérification après ajout :

```bash
dmsaforge verify redteamnotes.com/operator:'PASSWORD' --dc-host dc.redteamnotes.com --ou 'OU=Dev,DC=redteamnotes,DC=com' --dmsa-name redpen
```

Supprimer après usage :

```bash
dmsaforge delete redteamnotes.com/operator:'PASSWORD' --dc-host dc.redteamnotes.com --ou 'OU=Dev,DC=redteamnotes,DC=com' --dmsa-name redpen --yes
```

Après un `add` ou `verify` validé, `Next steps` affiche directement les commandes Kerberos externes concrètes. Le flux généré commence par `Rubeus hash`, utilise ensuite la valeur AES256 affichée pour `asktgt`, puis lance la requête dMSA `asktgs`.

La résolution du compte cible repose sur une recherche LDAP. `--target-account` écrit `msDS-ManagedAccountPrecededByLink`; `--principals-allowed` écrit le SID utilisé dans `msDS-GroupMSAMembership`. Les next steps générés par assess peuvent remplir le SID principal découvert, mais le compte cible reste un choix explicite de l'opérateur.

Contrôles de sécurité :

- Utilisez `dmsaforge plan ACTION ...`, `--dry-run` ou `--plan` pour valider les options et afficher les opérations LDAP prévues sans ouvrir de connexion LDAP.
- Utilisez `--profile safe` pour un dry-run masqué, `--profile report` pour des rapports JSON, ou `--profile ci` pour une sortie quiet JSON/no-banner.
- `DOMAIN/user` infère `--scope-domain`, `--scope-base-dn` et `--base-dn` ; un `--scope-base-dn` valide peut aussi fournir le base DN par défaut. Remplacez-les explicitement lorsque le périmètre autorisé diffère.
- Quand `--method` et `--port` sont omis, LDAP/389 est tenté en premier. Si la connexion échoue, dMSA Forge peut essayer LDAPS/636 et consigne les candidats tentés dans la sortie terminale et les rapports JSON/texte. Un `--port 636` seul infère LDAPS ; définir à la fois method et port exige une paire exacte.
- Les opérations LDAP utilisent par défaut un timeout socket de 30 secondes. Remplacez-le avec `--timeout SECONDS` seulement lorsque le chemin réseau autorisé l'exige.
- `--dns-hostname` vaut par défaut `<dmsa-name>.<account-domain>` lorsque `--dmsa-name` est défini.
- Utilisez `--dc-host` pour un DC précis, et `--dc-ip` uniquement lorsque DNS ou le routage nécessite une adresse IP explicite. La résolution automatique de l'IP du DC ne sonde jamais le réseau ; les résultats multicast, loopback, link-local, unspecified, broadcast et reserved sont rejetés afin qu'un placeholder DNS de proxy comme `224.0.0.1` ne devienne pas une valeur Kerberos `/dc:`.
- Pour `assess`, `--ou` réduit la base d'évaluation OU. La vérification préalable du DC est best-effort ; en cas d'échec, l'évaluation OU continue et consigne un warning.
- La résolution du compte cible et de `--principals-allowed` préfère les correspondances exactes `sAMAccountName`, UPN ou CN. Les résultats LDAP ambigus échouent proprement avec une indication de fournir un DN complet ou un SID.
- `delete` exige `--yes`. L'ancien workflow `modify` a été supprimé ; utilisez `delete`, `add` et `verify`.
- La sortie locale est masquée par défaut. `--no-redact` exige `--debug`.
- Utilisez `--json` pour les rapports structurés et `--output FILE` pour écrire le rapport avec le mode `0600`.
- Utilisez `--output-only` pour une exécution ultra-discrète. Cela active automatiquement `--quiet` et `--no-banner`, et bascule sur `--json` par défaut si `--output` n'est pas fourni. Avec `--output`, le fichier de sortie reste au format JSON.
- Utilisez `--quiet` pour réduire la verbosité au niveau warning/error.
- Utilisez `--no-banner` pour intégrer l'outil dans des scripts locaux avec une sortie plus compacte.
- Utilisez `--lean` pour une sortie locale plus légère et des évaluations plus sobres (équivalent à `--minimal`, `--quiet`, `--skip-dc-prereq`, `--no-banner`).

Les rapports JSON structures incluent `schema_version` afin que l'automatisation puisse figer le comportement de parsing.

La sortie terminale humaine utilise des en-tetes compacts : `Run context:`, `Progress:`, `Findings:` et `Next steps:`. Les warnings et erreurs conservent leurs marqueurs de severite `[!]` / `[-]` et n'utilisent la couleur que lorsque le terminal la prend en charge ; les modes JSON, quiet et output-only restent propres pour les machines.

Modes d'évaluation :

- `assess` analyse par défaut les descripteurs de sécurité des OU.
- Les résultats d'évaluation listent les principals disposant de droits OU pertinents pour BadSuccessor, c'est-à-dire capables de créer des objets dMSA ou de contrôler les OU listées. L'outil compare aussi ces SID avec l'`objectSid` et les `tokenGroups` du compte lié et indique si chaque ligne s'applique au bind courant; si `tokenGroups` n'est pas disponible, les droits via groupe sont marqués `unknown`.
- Utilisez `--summary` pour une liste OU légère sans analyse de descripteur de sécurité. `--include-security-descriptor` sélectionne explicitement le mode d'analyse par défaut.
- Ajoutez `--resolve-names` pour résoudre les SID correspondants en noms.
- Utilisez `--minimal` pour éviter l'analyse large, la résolution de noms et les commandes Kerberos supplémentaires.
- Ajoutez `--skip-dc-prereq` pour sauter la vérification prérequise du DC dans `assess` et réduire le bruit LDAP.

Les détails avancés et de compatibilité sont dans [advanced.fr.md](advanced.fr.md).

Tests :

```bash
python -m unittest discover -s tests
```

## Limite Kerberos

Cet outil vérifie uniquement l'état de l'objet LDAP. Il ne vérifie pas que le KDC est prêt et n'exécute pas Rubeus.

Utilisez explicitement IPv4 pour les requêtes Kerberos dMSA suivantes, par exemple `/dc:<DC_IPV4>`, afin d'éviter une résolution accidentelle vers une adresse IPv6 link-local.

L'outil n'attend pas après add par défaut. Utilisez `--verify-attempts N` et `--verify-delay SECONDS` pour contrôler explicitement les reprises de vérification LDAP, et `--kdc-wait SECONDS` si vous voulez volontairement ajouter un délai.

## Attribution

Base amont :

- Impacket `examples/badsuccessor.py`
- Auteur original : Ilya Yatsenko (`@fulc2um`)
- Copyright Impacket : Fortra, LLC and affiliates

Modifications :

- RedteamNotes

Consultez [NOTICE.md](../NOTICE.md) pour les notes de source et de licence.

Licence : conditions modified Apache Software License 1.1 héritées d'Impacket ; voir [LICENSE](../LICENSE).
