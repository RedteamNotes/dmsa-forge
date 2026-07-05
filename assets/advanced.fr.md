# Utilisation Avancee

Cette page garde les details de compatibilite et d'automatisation hors du README principal.

## Aide Par Action

Utilisez l'aide par action pour obtenir une liste d'options plus courte et plus pertinente :

```bash
dmsa-forge add -h
dmsa-forge search -h
dmsa-forge add --help-advanced
```

L'aide par action reste volontairement courte. Utilisez `--help-advanced` sur une action pour afficher les options d'authentification, les alias de compatibilite, les controles de retry de verification et les options avancees de workflow.

## Valeurs Par Défaut Inférées

dMSA Forge garde l'état d'exécution visible dans la ligne de commande et ne charge pas de fichier de configuration projet. Les valeurs courantes sont inférées depuis les arguments explicites :

- `DOMAIN/user` infère `--scope-domain`, `--scope-base-dn` et `--base-dn`.
- Si `DOMAIN/user` n'est pas un FQDN DNS, un DN `--target-ou` valide peut inférer le périmètre de domaine et le base DN.
- Un `--scope-base-dn` explicite et valide fournit le `--base-dn` par défaut lorsqu'aucun base DN n'est fourni.
- `--method` vaut `LDAP` par défaut, et `--port` vaut `389`.
- Quand ni `--method` ni `--port` ne sont explicites, l'exécution tente d'abord LDAP/389 et peut tenter LDAPS/636 seulement si la première connexion échoue.
- Un `--port 636` seul infère `LDAPS` ; un `--port 389` seul infère `LDAP`.
- `--method LDAPS` utilise le port `636` par défaut ; définir explicitement l'une des options de connexion désactive l'essai method/port.
- Pour `add`, `--target-account` vaut `Administrator` par défaut ; fournissez un autre sAMAccountName ou DN si nécessaire.
- `--dns-hostname` vaut `<dmsa-name>.<account-domain>` lorsque `--dmsa-name` est défini.
- `--principals-allowed` utilise le nom d'utilisateur authentifié au moment de l'exécution s'il est omis.
- La résolution automatique de l'IP du DC utilise uniquement le DNS local. Elle ne lance ni ping ni sonde, et rejette les adresses à usage spécial avant de les utiliser dans les suggestions Kerberos.
- Pour `search`, `--target-ou` réduit la base de recherche OU, et la vérification préalable du DC est best-effort.

Les options explicites remplacent toujours les valeurs inférées. Utilisez `--dc-host` pour cibler un DC précis, et `--dc-ip` seulement lorsque DNS ou le routage exige une adresse IP explicite. Les décisions d'inférence et les candidats de connexion sont consignés dans la sortie terminale et les rapports structurés.

La résolution du compte cible et de `--principals-allowed` préfère les correspondances exactes `sAMAccountName`, UPN, CN ou name. Si LDAP retourne plusieurs candidats utilisables sans correspondance exacte, l'exécution échoue fermée et demande un DN complet ou un SID.

## Wrappers Locaux

Les commandes `next_steps` générées héritent du wrapper proxychains détecté : une exécution lancée avec `proxychains -f chain1080.conf -q dmsa-forge ...` suggère des commandes de suivi avec le même préfixe. Si le wrapper local ne peut pas être inféré, passez `--next-step-prefix 'proxychains -f chain1080.conf -q'`.

## Raccourci Plan

`dmsa-forge plan ACTION ...` est un raccourci pour `dmsa-forge ACTION ... --dry-run`.

```bash
dmsa-forge plan add eighteen.htb/user --target-ou 'OU=Staff,DC=eighteen,DC=htb' --dmsa-name redpen
```

Il utilise la meme validation et le meme format de rapport que le mode dry-run.

## Profiles

- `safe` : active un dry-run masque et derive le perimetre depuis le domaine du compte lorsque c'est possible.
- `report` : active les rapports JSON et supprime la banniere.
- `ci` : active JSON, la sortie quiet et no-banner.

Les options explicites en ligne de commande prennent le dessus sur les profiles. Les profiles sont de simples presets locaux, pas des fichiers de configuration.

## Schema De Rapport

Les rapports JSON structures incluent :

- `schema_version` : actuellement `1.0` ;
- `operation_id` : identifiant local de run pour la correlation ;
- `mode` : `dry_run` ou `execute` ;
- `connection`, `scope`, `inputs`, `controls` et `ldap_operations` ;
- `result` : details propres a la commande.

Utilisez `--output-only --output FILE` pour une sortie JSON uniquement fichier avec le mode `0600`.

## Depannage

Les echecs des actions LDAP conservent autant que possible le point de decision local dans la sortie structuree. Consultez `result.error_code`, `result.error` et, lorsqu'ils existent, `result.ldap_result` ou `result.verification_errors`.

Les erreurs locales courantes sont bloquees avant l'execution LDAP :

- `--dmsa-name` doit etre un label DNS-safe comme `redpen` ou `dMSA-REDPEN01` ;
- `--dns-hostname` doit etre un hostname DNS complet comme `redpen.eighteen.htb` ;
- pour les workflows d'execution, `--scope-domain` et `--scope-base-dn` doivent etre coherents.

## Compatibilite

`--lean` est le preset court recommande pour une sortie locale plus legere et des recherches plus sobres. `--low-noise` reste disponible comme alias de compatibilite.

L'ancien workflow `modify` a ete supprime. Utilisez `delete`, `add` et `verify` ; les anciennes commandes `modify` renvoient une erreur de migration au lieu d'atteindre LDAP.
