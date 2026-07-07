"""CLI action and option metadata shared by parser and completion."""


VISIBLE_ACTION_CHOICES = ('assess', 'add', 'verify', 'delete')
ASSESS_ACTIONS = ('assess',)
ACTION_CHOICES = VISIBLE_ACTION_CHOICES
DESTRUCTIVE_ACTIONS = ('delete',)
UTILITY_COMMANDS = ('plan', 'update')
SUBCOMMAND_CHOICES = VISIBLE_ACTION_CHOICES + UTILITY_COMMANDS
PROFILE_CHOICES = ('safe', 'report', 'ci')

ACTION_SUMMARY = {
    'assess': 'Assess OU security descriptors for BadSuccessor-relevant rights.',
    'add': 'Create and verify a dMSA object for an authorized target account.',
    'verify': 'Read and validate an existing dMSA object without LDAP writes.',
    'delete': 'Delete a dMSA object, with explicit --yes confirmation required.',
}

ACTION_USAGE = {
    'assess': '%(prog)s [domain/]username[:password] [options]',
    'add': '%(prog)s [domain/]username[:password] --ou OU_DN [options]',
    'verify': '%(prog)s [domain/]username[:password] --ou OU_DN --dmsa-name NAME [options]',
    'delete': '%(prog)s [domain/]username[:password] --ou OU_DN --dmsa-name NAME --yes [options]',
}

ACTION_REQUIREMENTS = {
    'add': (('target_ou', '--ou'),),
    'delete': (('dmsa_name', '--dmsa-name'), ('target_ou', '--ou')),
    'verify': (('dmsa_name', '--dmsa-name'), ('target_ou', '--ou')),
}

ACTION_HELP = {
    'assess': 'assess - evaluate BadSuccessor OU feasibility by reading OU security descriptors, identifying relevant rights, and checking whether the bound account matches any listed effective SID.',
    'add': 'add - create and verify a dMSA object, with target OU, predecessor account, and managed-password reader validated before LDAP writes.',
    'verify': 'verify - read and validate an existing dMSA object, with target OU and dMSA name validated before LDAP reads.',
    'delete': 'delete - remove a dMSA object, requiring target OU, dMSA name, and explicit --yes confirmation before LDAP deletion.',
}

UPDATE_HELP = (
    'Update dmsaforge in the Python environment that is running this command. '
    'This works for a venv or a pipx-managed app environment.'
)

OPTION_ALIASES = {
    'allow_admin_fallback': ('--allow-admin-fallback',),
    'base_dn': ('--base-dn',),
    'dc_host': ('--dc-host',),
    'dc_ip': ('--dc-ip',),
    'debug': ('--debug',),
    'dmsa_name': ('--dmsa-name', '-d'),
    'dns_hostname': ('--dns-hostname',),
    'dry_run': ('--dry-run', '--plan'),
    'include_sd': ('--include-security-descriptor',),
    'json': ('--json',),
    'k': ('--kerberos', '-k'),
    'kdc_wait': ('--kdc-wait',),
    'kerberos_guidance': ('--kerberos-guidance',),
    'low_noise': ('--lean',),
    'method': ('--method', '-m'),
    'minimal': ('--minimal',),
    'next_step_prefix': ('--next-step-prefix', '--command-prefix'),
    'no_banner': ('--no-banner',),
    'output': ('--output',),
    'output_only': ('--output-only', '--minimal-output'),
    'port': ('--port', '-p'),
    'principals_allowed': ('--principals-allowed',),
    'profile': ('--profile',),
    'quiet': ('--quiet',),
    'redact': ('--redact', '--no-redact'),
    'resolve_names': ('--resolve-names',),
    'scope_base_dn': ('--scope-base-dn',),
    'scope_domain': ('--scope-domain',),
    'search_summary': ('--summary',),
    'skip_dc_prereq': ('--skip-dc-prereq',),
    'target_account': ('--target-account', '-t'),
    'target_ou': ('--target-ou', '--ou', '-o'),
    'timeout': ('--timeout',),
    'verify_attempts': ('--verify-attempts',),
    'verify_delay': ('--verify-delay',),
    'yes': ('--yes',),
}


ROOT_COMPLETION_OPTIONS = ('--help', '-h', '--version', '-v')
PLAN_COMPLETION_OPTIONS = ('--help', '-h')
UPDATE_COMPLETION_OPTIONS = ('--help', '-h', '--dry-run', '--source', '--force', '--quiet')

COMMON_ACTION_COMPLETION_KEYS = (
    'profile',
    'dry_run',
    'json',
    'output',
    'output_only',
    'quiet',
    'no_banner',
    'redact',
    'scope_domain',
    'scope_base_dn',
    'dc_host',
    'dc_ip',
    'method',
    'port',
    'timeout',
)

ACTION_COMPLETION_KEYS = {
    'assess': COMMON_ACTION_COMPLETION_KEYS + (
        'target_ou',
        'search_summary',
        'include_sd',
        'resolve_names',
        'skip_dc_prereq',
    ),
    'add': COMMON_ACTION_COMPLETION_KEYS + (
        'dmsa_name',
        'target_ou',
        'target_account',
        'principals_allowed',
        'dns_hostname',
    ),
    'verify': COMMON_ACTION_COMPLETION_KEYS + (
        'dmsa_name',
        'target_ou',
        'principals_allowed',
    ),
    'delete': COMMON_ACTION_COMPLETION_KEYS + (
        'dmsa_name',
        'target_ou',
        'yes',
    ),
}

def option_tokens_for_keys(keys):
    tokens = []
    for key in keys:
        tokens.extend(OPTION_ALIASES[key])
    return tuple(tokens)


def completion_options_by_action():
    return {
        action: ('--help', '-h') + option_tokens_for_keys(keys)
        for action, keys in ACTION_COMPLETION_KEYS.items()
    }
