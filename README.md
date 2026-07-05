# dMSA Forge

[![Release](https://img.shields.io/github/v/release/RedteamNotes/dmsa-forge?label=release)](https://github.com/RedteamNotes/dmsa-forge/releases/tag/v0.5.4)
[![Tests](https://github.com/RedteamNotes/dmsa-forge/actions/workflows/test.yml/badge.svg)](https://github.com/RedteamNotes/dmsa-forge/actions/workflows/test.yml)
[![License](https://img.shields.io/badge/license-Impacket%20Apache--1.1-blue)](https://github.com/RedteamNotes/dmsa-forge/blob/main/LICENSE)

**Language:** English | [简体中文](assets/README.zh-CN.md) | [Français](assets/README.fr.md)

Current release: `v0.5.4`

A [dMSA](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/delegated-managed-service-accounts/delegated-managed-service-accounts-overview) forge for authorized [BadSuccessor](https://www.akamai.com/blog/security-research/abusing-dmsa-for-privilege-escalation-in-active-directory) LDAP workflows: add, verify, delete, and search.

Designed around signed LDAP 389, atomic dMSA creation, post-add verification, concise operator help, project profiles, and structured reporting.

<p align="center">
  <img src="assets/dMSAForge.png" alt="dMSA Forge by RedteamNotes" width="100%">
</p>

This project is based on Impacket `examples/badsuccessor.py` and keeps the upstream attribution and licensing context. This version is heavily refactored by **RedteamNotes** to make LDAP 389 with signing, atomic dMSA creation, and post-add verification explicit and reproducible.

Use only in environments where you have explicit authorization.

## What Changed

- Uses Impacket native `LDAPConnection` directly; `ldap3` is not a runtime dependency.
- Supports signed LDAP on port 389 for environments that enforce LDAP signing and have unusable LDAPS.
- Writes dMSA core attributes in the initial AddRequest, including `msDS-GroupMSAMembership`, `msDS-ManagedAccountPrecededByLink`, and `msDS-DelegatedMSAState`.
- Verifies the object by reading it back from the DC after add.
- Parses `msDS-GroupMSAMembership` as a binary security descriptor and prints a readable summary instead of raw bytes.
- Adds `verify` as a read-only action.
- Modernizes the operator experience with task-named commands, shorter contextual help, local profiles, inferred defaults, diagnostics, next-step suggestions, and shell completion.
- Adds safer preflight and reporting workflows: dry-run plans, scope guardrails, redacted structured output, readiness checks, and clearer failure diagnostics.
- Keeps output honest: LDAP verification success does not mean KDC readiness.

## Install

From GitHub with `pipx`:

```bash
pipx install git+https://github.com/RedteamNotes/dmsa-forge.git
```

Or clone and install from a local checkout:

```bash
git clone https://github.com/RedteamNotes/dmsa-forge.git
python -m venv dmsa-forge/.venv
source dmsa-forge/.venv/bin/activate
python -m pip install ./dmsa-forge
```

After installation, run:

```bash
dmsa-forge -h
```

`dmsaforge` is installed as an equivalent alias. Use it when your shell is in a directory that also contains a `dmsa-forge/` checkout and bare `dmsa-forge` is intercepted by shell directory navigation.

Update the active environment when a new release is available:

```bash
dmsa-forge update
```

`update` compares the installed version with the target release first. If the versions match, it skips pip; if they differ, it updates regardless of whether the target version is higher or lower. Use `dmsa-forge update --force` only when you deliberately want to run pip without the version check.

Helpful local help entry points:

```bash
dmsa-forge actions
dmsa-forge examples
dmsa-forge add -h
dmsa-forge add --help-advanced
dmsa-forge update --dry-run
```

For source-checkout use without installation, run `./dmsa-forge.py`.
Task-named commands and modern `--long-option` flags are shown below. Legacy `--action ...` and original Impacket-style single-dash options, such as `-dc-host` and `-target-ou`, are still supported for compatibility. Do not combine task-named commands with `--action`.

## Quick Start

Inspect local readiness before running LDAP workflows:

```bash
dmsa-forge doctor eighteen.htb/adam.scott
```

Use `dmsa-forge doctor --kerberos` to require local Kerberos cache checks, including `KRB5CCNAME`, cache readability, cache parsing, and realm alignment. It does not contact the KDC.

Preview an add with the safe profile. Commands in this README are intentionally shown as one-line, copy-ready examples; if you use a local wrapper such as `proxychains -f chain1080.conf -q`, place it before `dmsa-forge`.

```bash
dmsa-forge plan add eighteen.htb/adam.scott:'PASSWORD' --profile safe --target-ou 'OU=Staff,DC=eighteen,DC=htb' --dmsa-name redpen --target-account 'CN=Administrator,CN=Users,DC=eighteen,DC=htb'
```

By default, `DOMAIN/user` infers `--scope-domain`, `--scope-base-dn`, and `--base-dn`; LDAP/389 is the default method and port; `--dns-hostname` is inferred from `--dmsa-name` and the account domain. Use explicit flags when you need to override these values.

## Operator Flow

These templates keep each command on one line for paste, terminal history, and repeatable runbooks. Replace placeholders before use.

Pre-add verify:

```bash
dmsa-forge verify eighteen.htb/adam.scott:'PASSWORD' --dc-host dc01.eighteen.htb --target-ou 'OU=Staff,DC=eighteen,DC=htb' --dmsa-name redpen
```

Plan add:

```bash
dmsa-forge plan add eighteen.htb/adam.scott:'PASSWORD' --dc-host dc01.eighteen.htb --target-ou 'OU=Staff,DC=eighteen,DC=htb' --dmsa-name redpen --principals-allowed '<SID_OR_NAME>' --target-account 'CN=Administrator,CN=Users,DC=eighteen,DC=htb'
```

Add:

```bash
dmsa-forge add eighteen.htb/adam.scott:'PASSWORD' --dc-host dc01.eighteen.htb --target-ou 'OU=Staff,DC=eighteen,DC=htb' --dmsa-name redpen --principals-allowed '<SID_OR_NAME>' --target-account 'CN=Administrator,CN=Users,DC=eighteen,DC=htb'
```

Post-add verify:

```bash
dmsa-forge verify eighteen.htb/adam.scott:'PASSWORD' --dc-host dc01.eighteen.htb --target-ou 'OU=Staff,DC=eighteen,DC=htb' --dmsa-name redpen
```

Delete when finished:

```bash
dmsa-forge delete eighteen.htb/adam.scott:'PASSWORD' --dc-host dc01.eighteen.htb --target-ou 'OU=Staff,DC=eighteen,DC=htb' --dmsa-name redpen --yes
```

After a verified `add` or `verify`, `Next steps` includes concrete external Kerberos commands. Use `--kerberos-guidance` only when you want the same commands printed inline with the verification block.

Target account resolution is LDAP-search based and `--target-account` is explicit for `add`. For the built-in `Administrator` account, the full DN is the most deterministic form; short names are resolved through exact LDAP matches and logged exact-DN candidates.

Safety controls:

- Use `dmsa-forge plan ACTION ...`, `--dry-run`, or `--plan` to validate options and print the planned LDAP operations without opening an LDAP connection.
- Use `dmsa-forge doctor` for a concise local readiness report; text output shows only warnings/errors while JSON keeps the full check set.
- Use `--profile safe` for a redacted dry-run preset, `--profile report` for JSON reports, or `--profile ci` for quiet JSON/no-banner output.
- `DOMAIN/user` infers `--scope-domain`, `--scope-base-dn`, and `--base-dn`; a valid `--scope-base-dn` can also supply the default base DN. Override with explicit flags when the authorized scope differs.
- LDAP/389 is tried first when `--method` and `--port` are omitted. If that connection fails, dMSA Forge can try LDAPS/636 and records the attempted candidates in terminal output and JSON/text reports. A lone `--port 636` infers LDAPS; pin both `--method` and `--port` to require an exact pair.
- `--dns-hostname` defaults to `<dmsa-name>.<account-domain>` when `--dmsa-name` is set.
- Use `--dc-host` for a specific DC hostname and `--dc-ip` only when DNS or routing requires an IP override.
- For `search`, `--target-ou` narrows the OU search base. The Domain Controller prerequisite check is best-effort; if it fails, the OU search continues and records a warning.
- Target account and `--principals-allowed` name resolution prefer exact `sAMAccountName`/UPN/CN matches. Ambiguous LDAP results fail closed with a prompt to pass a full DN or SID.
- `delete` requires `--yes`. The old `modify` workflow has been removed; use `delete`, `add`, and `verify` instead.
- Local output is redacted by default. `--no-redact` requires `--debug`.
- Use `--json` for structured reports and `--output FILE` to write the report with file mode `0600`.
- Use `--output-only` for ultra-quiet operation. It enables `--quiet`, `--no-banner`, and defaults to `--json` unless `--output` is provided. When `--output` is used, the output file is written as JSON.
- Use `--quiet` for warning/error-only terminal output.
- Use `--no-banner` when embedding the tool in local scripts.
- Use `--lean` for reduced local output and lighter search defaults (`--minimal`, `--quiet`, `--skip-dc-prereq`, `--no-banner`). `--low-noise` remains as a compatibility alias.

Structured JSON reports include `schema_version` so automation can pin parsing behavior.

Search modes:

- `search` defaults to OU security descriptor analysis.
- Use `--summary` for a lightweight OU-only listing. `--include-security-descriptor` and `--include-sd` remain accepted explicit aliases for the default analysis mode.
- Add `--resolve-names` to resolve matching SIDs to names.
- Use `--minimal` to avoid broad search analysis, name resolution, and Kerberos guidance.
- Add `--skip-dc-prereq` for `search` to skip the prerequisite Domain Controller OS check.

Advanced and compatibility details live in [assets/advanced.md](assets/advanced.md).

Tests:

```bash
python -m unittest discover -s tests
```

## Kerberos Boundary

This tool verifies the LDAP object state only. It does not verify KDC readiness and does not execute Rubeus.

Use IPv4 explicitly for downstream Kerberos dMSA requests, for example `/dc:<DC_IPV4>`, to avoid accidental IPv6 link-local resolution.

The tool does not sleep after add by default. Use `--verify-attempts N` and `--verify-delay SECONDS` for explicit LDAP verification retries, and `--kdc-wait SECONDS` when you intentionally want a delay.

## Attribution

Upstream basis:

- Impacket `examples/badsuccessor.py`
- Original author: Ilya Yatsenko (`@fulc2um`)
- Impacket copyright: Fortra, LLC and affiliates

Modifications:

- RedteamNotes

See [NOTICE.md](NOTICE.md) for source and licensing notes.

License: modified Apache Software License 1.1 terms inherited from Impacket; see [LICENSE](LICENSE).
