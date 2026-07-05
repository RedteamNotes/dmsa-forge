# dMSA Forge

[![Release](https://img.shields.io/github/v/release/RedteamNotes/dmsa-forge?label=release)](https://github.com/RedteamNotes/dmsa-forge/releases/tag/v0.5.4)
[![Tests](https://github.com/RedteamNotes/dmsa-forge/actions/workflows/test.yml/badge.svg)](https://github.com/RedteamNotes/dmsa-forge/actions/workflows/test.yml)
[![License](https://img.shields.io/badge/license-Impacket%20Apache--1.1-blue)](https://github.com/RedteamNotes/dmsa-forge/blob/main/LICENSE)

**Langue :** [English](../README.md) | [简体中文](README.zh-CN.md) | Français

Version actuelle : `v0.5.4`

Forge [dMSA](https://learn.microsoft.com/fr-fr/windows-server/identity/ad-ds/manage/delegated-managed-service-accounts/delegated-managed-service-accounts-overview) pour les workflows LDAP [BadSuccessor](https://www.akamai.com/blog/security-research/abusing-dmsa-for-privilege-escalation-in-active-directory) autorisés : add, verify, delete et search.

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
- Modernise l'expérience opérateur avec des commandes nommées par tâche, une aide contextuelle plus courte, des profiles locaux, des valeurs par défaut inférées, des diagnostics, des suggestions de prochaines commandes et la completion shell.
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
dmsa-forge -h
```

`dmsaforge` est installé comme alias équivalent. Utilisez-le si votre shell se trouve dans un dossier qui contient aussi une copie `dmsa-forge/` et que `dmsa-forge` seul est intercepté par la navigation de répertoire du shell.

Quand une nouvelle version est disponible, mettez à jour l'environnement actif :

```bash
dmsa-forge update
```

`update` compare d'abord la version installée avec la version cible. Si elles correspondent, pip est ignoré ; si elles diffèrent, la mise à jour est lancée, que la version cible soit supérieure ou inférieure. Utilisez `dmsa-forge update --force` seulement pour exécuter pip sans contrôle de version.

Entrées d'aide locales utiles :

```bash
dmsa-forge actions
dmsa-forge examples
dmsa-forge add -h
dmsa-forge add --help-advanced
dmsa-forge update --dry-run
```

Pour une utilisation depuis une copie source sans installation, exécutez `./dmsa-forge.py`.
Les exemples ci-dessous utilisent des commandes nommées par tâche et les options modernes `--long-option`. L'ancien format `--action ...` et les options historiques à simple tiret de style Impacket, comme `-dc-host` et `-target-ou`, restent compatibles. Ne combinez pas les commandes nommées par tâche avec `--action`.

## Démarrage Rapide

Inspectez la préparation locale avant d'exécuter les flux LDAP :

```bash
dmsa-forge doctor eighteen.htb/adam.scott
```

Utilisez `dmsa-forge doctor --kerberos` pour exiger les verifications locales du cache Kerberos, notamment `KRB5CCNAME`, la lisibilite du cache, son analyse et l'alignement du realm. Cela ne contacte pas le KDC.

Prévisualisez un add avec le profil safe. Les commandes de ce README sont volontairement présentées sur une seule ligne, prêtes à copier ; si vous utilisez un wrapper local comme `proxychains -f chain1080.conf -q`, placez-le avant `dmsa-forge`.

```bash
dmsa-forge plan add eighteen.htb/adam.scott:'PASSWORD' --profile safe --target-ou 'OU=Staff,DC=eighteen,DC=htb' --dmsa-name redpen --target-account 'CN=Administrator,CN=Users,DC=eighteen,DC=htb'
```

Par défaut, `DOMAIN/user` infère `--scope-domain`, `--scope-base-dn` et `--base-dn` ; LDAP/389 est la méthode et le port par défaut ; `--dns-hostname` est inféré depuis `--dmsa-name` et le domaine du compte. Utilisez les options explicites uniquement pour remplacer ces valeurs.

## Flux Opérateur

Ces modèles gardent chaque commande sur une seule ligne pour le copier-coller, l'historique du terminal et les runbooks reproductibles. Remplacez les placeholders avant utilisation.

Vérification avant ajout :

```bash
dmsa-forge verify eighteen.htb/adam.scott:'PASSWORD' --dc-host dc01.eighteen.htb --target-ou 'OU=Staff,DC=eighteen,DC=htb' --dmsa-name redpen
```

Plan d'ajout :

```bash
dmsa-forge plan add eighteen.htb/adam.scott:'PASSWORD' --dc-host dc01.eighteen.htb --target-ou 'OU=Staff,DC=eighteen,DC=htb' --dmsa-name redpen --principals-allowed '<SID_OR_NAME>' --target-account 'CN=Administrator,CN=Users,DC=eighteen,DC=htb'
```

Ajouter :

```bash
dmsa-forge add eighteen.htb/adam.scott:'PASSWORD' --dc-host dc01.eighteen.htb --target-ou 'OU=Staff,DC=eighteen,DC=htb' --dmsa-name redpen --principals-allowed '<SID_OR_NAME>' --target-account 'CN=Administrator,CN=Users,DC=eighteen,DC=htb'
```

Vérification après ajout :

```bash
dmsa-forge verify eighteen.htb/adam.scott:'PASSWORD' --dc-host dc01.eighteen.htb --target-ou 'OU=Staff,DC=eighteen,DC=htb' --dmsa-name redpen
```

Supprimer après usage :

```bash
dmsa-forge delete eighteen.htb/adam.scott:'PASSWORD' --dc-host dc01.eighteen.htb --target-ou 'OU=Staff,DC=eighteen,DC=htb' --dmsa-name redpen --yes
```

Après un `add` ou `verify` validé, `Next steps` affiche directement les commandes Kerberos externes concrètes. Utilisez `--kerberos-guidance` uniquement si vous voulez imprimer les mêmes commandes dans le bloc de vérification.

La résolution du compte cible repose sur une recherche LDAP, et `--target-account` doit être fourni explicitement pour `add`. Pour le compte intégré `Administrator`, le DN complet est la forme la plus déterministe ; les noms courts sont résolus via des correspondances LDAP exactes et des candidats DN exacts consignés.

Contrôles de sécurité :

- Utilisez `dmsa-forge plan ACTION ...`, `--dry-run` ou `--plan` pour valider les options et afficher les opérations LDAP prévues sans ouvrir de connexion LDAP.
- Utilisez `dmsa-forge doctor` pour obtenir un rapport local concis ; la sortie texte n'affiche que les warning/error, tandis que JSON conserve l'ensemble des contrôles.
- Utilisez `--profile safe` pour un dry-run masqué, `--profile report` pour des rapports JSON, ou `--profile ci` pour une sortie quiet JSON/no-banner.
- `DOMAIN/user` infère `--scope-domain`, `--scope-base-dn` et `--base-dn` ; un `--scope-base-dn` valide peut aussi fournir le base DN par défaut. Remplacez-les explicitement lorsque le périmètre autorisé diffère.
- Quand `--method` et `--port` sont omis, LDAP/389 est tenté en premier. Si la connexion échoue, dMSA Forge peut essayer LDAPS/636 et consigne les candidats tentés dans la sortie terminale et les rapports JSON/texte. Un `--port 636` seul infère LDAPS ; définir à la fois `--method` et `--port` exige une paire exacte.
- `--dns-hostname` vaut par défaut `<dmsa-name>.<account-domain>` lorsque `--dmsa-name` est défini.
- Utilisez `--dc-host` pour un DC précis, et `--dc-ip` uniquement lorsque DNS ou le routage nécessite une adresse IP explicite.
- Pour `search`, `--target-ou` réduit la base de recherche OU. La vérification préalable du DC est best-effort ; en cas d'échec, la recherche OU continue et consigne un warning.
- La résolution du compte cible et de `--principals-allowed` préfère les correspondances exactes `sAMAccountName`, UPN ou CN. Les résultats LDAP ambigus échouent proprement avec une indication de fournir un DN complet ou un SID.
- `delete` exige `--yes`. L'ancien workflow `modify` a été supprimé ; utilisez `delete`, `add` et `verify`.
- La sortie locale est masquée par défaut. `--no-redact` exige `--debug`.
- Utilisez `--json` pour les rapports structurés et `--output FILE` pour écrire le rapport avec le mode `0600`.
- Utilisez `--output-only` pour une exécution ultra-discrète. Cela active automatiquement `--quiet` et `--no-banner`, et bascule sur `--json` par défaut si `--output` n'est pas fourni. Avec `--output`, le fichier de sortie reste au format JSON.
- Utilisez `--quiet` pour réduire la verbosité au niveau warning/error.
- Utilisez `--no-banner` pour intégrer l'outil dans des scripts locaux avec une sortie plus compacte.
- Utilisez `--lean` pour une sortie locale plus légère et des recherches plus sobres (équivalent à `--minimal`, `--quiet`, `--skip-dc-prereq`, `--no-banner`). `--low-noise` reste disponible comme alias de compatibilité.

Les rapports JSON structures incluent `schema_version` afin que l'automatisation puisse figer le comportement de parsing.

Modes de recherche :

- `search` analyse par défaut les descripteurs de sécurité des OU.
- Utilisez `--summary` pour une liste OU légère sans analyse de descripteur de sécurité. `--include-security-descriptor` et `--include-sd` restent acceptés comme alias explicites du mode d'analyse par défaut.
- Ajoutez `--resolve-names` pour résoudre les SID correspondants en noms.
- Utilisez `--minimal` pour éviter l'analyse large, la résolution de noms et le guidance Kerberos.
- Ajoutez `--skip-dc-prereq` pour sauter la vérification prérequise du DC dans `search` et réduire le bruit LDAP.

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
