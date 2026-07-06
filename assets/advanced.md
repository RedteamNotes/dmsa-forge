# Advanced Usage

This page keeps compatibility and automation details out of the main README.

## Action Help

Use action-specific help for the shortest useful option list:

```bash
dmsa-forge add -h
dmsa-forge assess -h
```

Action help is intentionally short. Keep detailed authentication, reporting, retry, and compatibility behavior in this document instead of expanding terminal help.

## Inferred Defaults

dMSA Forge keeps runtime state visible in the command line and does not load project configuration files. Common values are inferred from explicit command arguments:

- `DOMAIN/user` infers `--scope-domain`, `--scope-base-dn`, and `--base-dn`.
- If `DOMAIN/user` is not a DNS FQDN, a valid `--target-ou` DN can infer the domain scope and base DN.
- A valid explicit `--scope-base-dn` supplies the default `--base-dn` when no base DN is provided.
- `--method` defaults to `LDAP`, and `--port` defaults to `389`.
- When neither `--method` nor `--port` is explicit, execution tries LDAP/389 first and can try LDAPS/636 only if the first connection fails.
- A lone `--port 636` infers `LDAPS`; a lone `--port 389` infers `LDAP`.
- `--method LDAPS` defaults to port `636`; explicitly setting either connection option disables method/port trial.
- For `add` execution, `--target-account` is required and defines the account DN written to `msDS-ManagedAccountPrecededByLink`.
- `--dns-hostname` defaults to `<dmsa-name>.<account-domain>` when `--dmsa-name` is set.
- For `add` execution, `--principals-allowed` is required and defines the SID written to `msDS-GroupMSAMembership`.
- Automatic DC IP resolution is local DNS only. It does not ping or probe, and it rejects special-use results before using them for Kerberos command guidance.
- For `assess`, `--target-ou` narrows the OU assessment base, and the Domain Controller prerequisite check is best-effort.

Explicit flags always override inferred values. Use `--dc-host` for a specific DC hostname and `--dc-ip` only when DNS or routing requires an IP override. Inference decisions and connection candidates are recorded in terminal output and structured reports.

Target account and `--principals-allowed` name resolution prefer exact `sAMAccountName`, UPN, CN, or name matches. If LDAP returns multiple usable candidates without an exact match, execution fails closed and asks for a full DN or SID.

## Local Wrappers

Generated `next_steps` commands inherit a detected proxychains wrapper, so a run started as `proxychains -f chain1080.conf -q dmsa-forge ...` suggests follow-up commands with the same prefix. If a local wrapper cannot be inferred, pass `--next-step-prefix 'proxychains -f chain1080.conf -q'`.

## Plan Shorthand

`dmsa-forge plan ACTION ...` is shorthand for `dmsa-forge ACTION ... --dry-run`.

```bash
dmsa-forge plan add redteamnotes.com/operator --target-ou 'OU=Dev,DC=redteamnotes,DC=com' --dmsa-name redpen --target-account Administrator --principals-allowed SID_OR_NAME
```

It uses the same validation and report format as normal dry-run mode.

## Profiles

- `safe`: turns on redacted dry-run mode and derives scope from the account domain when possible.
- `report`: turns on JSON reports and suppresses the banner.
- `ci`: turns on JSON, quiet output, and no banner.

Explicit command-line flags override profile defaults. Profiles are lightweight local presets, not configuration files.

## Report Schema

Structured JSON reports include:

- `schema_version`: currently `1.0`;
- `operation_id`: local run identifier for correlation;
- `mode`: `dry_run` or `execute`;
- `connection`, `scope`, `inputs`, `controls`, and `ldap_operations`;
- `result`: command-specific details.

Use `--output-only --output FILE` for file-only JSON output with mode `0600`.

## Terminal Output

Normal terminal output is intentionally light and grouped by purpose:

- `Run context:` parsed command values, inferred defaults, target DC, LDAP method, auth mode, and base DN;
- `Progress:` connection and LDAP workflow events;
- `Findings:` results that matter to the operator, including OU rights, dMSA verification, and cleanup status;
- `Next steps:` concrete follow-up commands when the run succeeded or can continue.

Warnings and errors use severity markers and color when stderr is a TTY. The same data remains available in JSON reports without terminal formatting.

## Troubleshooting

LDAP action failures try to preserve the local decision point in structured output. Look at `result.error_code`, `result.error`, and, when present, `result.ldap_result` or `result.verification_errors`.

Common local validation failures are intentionally caught before LDAP execution:

- `--dmsa-name` must be a DNS-safe label such as `redpen` or `dMSA-REDPEN01`;
- `--dns-hostname` must be a fully qualified DNS hostname such as `redpen.redteamnotes.com`;
- `--scope-domain` and `--scope-base-dn` must agree for execution workflows.

## Compatibility

`--lean` is the short preset for lighter local output and assessment defaults.

The old `modify` workflow has been removed. Use `delete`, `add`, and `verify`; old `modify` commands return a migration error instead of reaching LDAP.
