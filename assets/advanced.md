# Advanced Usage

This page keeps compatibility and automation details out of the main README.

## Action Help

Use action-specific help for the shortest useful option list:

```bash
dmsa-forge add -h
dmsa-forge search -h
dmsa-forge doctor -h
dmsa-forge add --help-advanced
```

Default action help is intentionally short. Use `--help-advanced` on an action to show authentication, compatibility aliases, verification retry controls, and advanced workflow flags.

The legacy form remains supported:

```bash
dmsa-forge eighteen.htb/user:'PASSWORD' --action add --target-account 'CN=Administrator,CN=Users,DC=eighteen,DC=htb'
```

## Inferred Defaults

dMSA Forge keeps runtime state visible in the command line and does not load project configuration files. Common values are inferred from explicit command arguments:

- `DOMAIN/user` infers `--scope-domain`, `--scope-base-dn`, and `--base-dn`.
- If `DOMAIN/user` is not a DNS FQDN, a valid `--target-ou` DN can infer the domain scope and base DN.
- A valid explicit `--scope-base-dn` supplies the default `--base-dn` when no base DN is provided.
- `--method` defaults to `LDAP`, and `--port` defaults to `389`.
- When neither `--method` nor `--port` is explicit, execution tries LDAP/389 first and can try LDAPS/636 only if the first connection fails.
- A lone `--port 636` infers `LDAPS`; a lone `--port 389` infers `LDAP`.
- `--method LDAPS` defaults to port `636`; explicitly setting either connection option disables method/port trial.
- `--dns-hostname` defaults to `<dmsa-name>.<account-domain>` when `--dmsa-name` is set.
- `--principals-allowed` defaults to the authenticated username at execution time.
- For `search`, `--target-ou` narrows the OU search base, and the Domain Controller prerequisite check is best-effort.

Explicit flags always override inferred values. Use `--dc-host` for a specific DC hostname and `--dc-ip` only when DNS or routing requires an IP override. Inference decisions and connection candidates are recorded in terminal output and structured reports.

Target account and `--principals-allowed` name resolution prefer exact `sAMAccountName`, UPN, CN, or name matches. If LDAP returns multiple usable candidates without an exact match, execution fails closed and asks for a full DN or SID.

## Local Wrappers

Generated `next_steps` commands inherit a detected proxychains wrapper, so a run started as `proxychains -f chain1080.conf -q dmsa-forge ...` suggests follow-up commands with the same prefix. If a local wrapper cannot be inferred, pass `--next-step-prefix 'proxychains -f chain1080.conf -q'`.

## Plan Shorthand

`dmsa-forge plan ACTION ...` is shorthand for `dmsa-forge ACTION ... --dry-run`.

```bash
dmsa-forge plan add eighteen.htb/user --target-account 'CN=Administrator,CN=Users,DC=eighteen,DC=htb' --target-ou 'OU=Staff,DC=eighteen,DC=htb'
```

It uses the same validation and report format as normal dry-run mode.

## Profiles

- `safe`: turns on redacted dry-run mode and derives scope from the account domain when possible.
- `report`: turns on JSON reports and suppresses the banner.
- `ci`: turns on JSON, quiet output, and no banner.

Explicit command-line flags override profile defaults. Profiles are lightweight local presets, not configuration files.

## Kerberos Doctor

`dmsa-forge doctor --kerberos` requires local Kerberos cache readiness checks to pass. It checks:

- whether `KRB5CCNAME` is set;
- whether the cache backend is a single `FILE:` cache that Impacket can read;
- whether the cache file exists, is a regular file, is readable, and is not broadly readable;
- whether Impacket can parse the ccache and extract a default principal;
- whether the ccache realm matches the account, scope, or base DN domain;
- whether `--dc-host` is present for Kerberos execution.

This is a local readiness check only. It does not contact the KDC and does not prove that a future Kerberos request will succeed.

Doctor also accepts workflow hints such as `--target-ou`, `--target-account`, `--principals-allowed`, and `--dmsa-name` so DN/SID values, inferred defaults, and scope checks can be reviewed before execution.

Doctor reports include a readiness value:

- `ready`: no errors or warnings;
- `warning`: usable, but at least one recommended guardrail or local hygiene item is missing;
- `blocked`: at least one error should be fixed before execution.

Each warning/error includes a remediation string in JSON and text output.

## Report Schema

Structured JSON reports include:

- `schema_version`: currently `1.0`;
- `operation_id`: local run identifier for correlation;
- `mode`: `dry_run`, `execute`, or `doctor`;
- `connection`, `scope`, `inputs`, `controls`, and `ldap_operations`;
- `result`: command-specific details.

Use `--output-only --output FILE` for file-only JSON output with mode `0600`.

## Troubleshooting

LDAP action failures try to preserve the local decision point in structured output. Look at `result.error_code`, `result.error`, and, when present, `result.ldap_result` or `result.verification_errors`.

Common local validation failures are intentionally caught before LDAP execution:

- `--dmsa-name` must be a DNS-safe label such as `redpen` or `dMSA-REDPEN01`;
- `--dns-hostname` must be a fully qualified DNS hostname such as `redpen.eighteen.htb`;
- `--scope-domain` and `--scope-base-dn` must agree for execution workflows.

Diagnostic commands such as `doctor` report these as `blocked` readiness items instead of making LDAP calls.

## Shell Completion

Enable zsh completion for the current shell without writing files:

```bash
eval "$(dmsa-forge --completion-script zsh)"
```

For bash, use:

```bash
eval "$(dmsa-forge --completion-script bash)"
```

The old `completion` action has been removed; `--completion-script` is intentionally hidden so normal help stays focused on LDAP workflows. Add one of the `eval` lines to your shell profile only if you want persistent completion.

The output is intentionally static and local; it does not inspect LDAP or read credentials.

## Compatibility

`--lean` is the preferred short preset for lighter local output and search defaults. `--low-noise` remains as a compatibility alias.

The old `modify` workflow has been removed. Use `delete`, `add`, and `verify`; legacy `modify` commands return a migration error instead of reaching LDAP.
