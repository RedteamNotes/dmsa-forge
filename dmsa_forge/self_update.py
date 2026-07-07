"""Self-update workflow helpers."""

import json
import os
import re
import shlex
import subprocess
import sys
import urllib.request


DEFAULT_UPDATE_SOURCE = 'git+https://github.com/RedteamNotes/dmsa-forge.git'
DEFAULT_UPDATE_VERSION_URL = 'https://api.github.com/repos/RedteamNotes/dmsa-forge/releases/latest'
VERSION_REF_RE = re.compile(r'^v?\d+(?:\.\d+)+(?:[-._+A-Za-z0-9]*)?$')


def command_to_text(parts):
    return ' '.join(shlex.quote(str(part)) for part in parts)


def normalize_version_for_update(version):
    version = str(version or '').strip()
    if version.lower().startswith('v'):
        version = version[1:]
    return version


def update_versions_match(current_version, target_version):
    return normalize_version_for_update(current_version) == normalize_version_for_update(target_version)


def explicit_version_from_update_source(source):
    source = str(source or '').strip()
    if '.git@' not in source:
        return None
    ref = source.rsplit('.git@', 1)[1].split('#', 1)[0].strip()
    if VERSION_REF_RE.match(ref):
        return ref
    return None


def latest_release_version(timeout=10, version_url=DEFAULT_UPDATE_VERSION_URL, tool_name='dmsaforge'):
    request = urllib.request.Request(
        version_url,
        headers={'Accept': 'application/vnd.github+json', 'User-Agent': tool_name},
    )
    with urllib.request.urlopen(request, timeout=timeout) as response:
        payload = json.loads(response.read().decode('utf-8'))
    version = payload.get('tag_name')
    if not version:
        raise ValueError('latest release response did not include tag_name')
    return version


def resolve_update_target_version(source, default_source=DEFAULT_UPDATE_SOURCE, version_url=DEFAULT_UPDATE_VERSION_URL, tool_name='dmsaforge'):
    explicit_version = explicit_version_from_update_source(source)
    if explicit_version:
        return explicit_version, 'source ref'
    if (source or default_source) == default_source:
        return latest_release_version(version_url=version_url, tool_name=tool_name), 'latest GitHub release'
    return None, 'custom source without version ref'


def update_source_for_command(source, target_version=None, version_source=None, default_source=DEFAULT_UPDATE_SOURCE):
    source = source or default_source
    if (
        source == default_source
        and target_version
        and version_source == 'latest GitHub release'
        and explicit_version_from_update_source(source) is None
    ):
        return '%s@%s' % (source, target_version)
    return source


def build_update_command(options, target_version=None, version_source=None, default_source=DEFAULT_UPDATE_SOURCE):
    command = [sys.executable, '-m', 'pip', 'install', '--upgrade']
    if options.quiet:
        command.append('-q')
    command.append(update_source_for_command(options.update_source, target_version, version_source, default_source=default_source))
    return command


def run_update_workflow(
    options,
    current_version,
    package_version,
    tool_name='dmsaforge',
    default_source=DEFAULT_UPDATE_SOURCE,
    version_url=DEFAULT_UPDATE_VERSION_URL,
    should_show_banner=None,
    print_banner=None,
    runner=None,
):
    if should_show_banner and should_show_banner(options) and print_banner:
        print_banner()

    runner = runner or subprocess.run
    target_version = None
    version_source = None
    if not options.force:
        try:
            target_version, version_source = resolve_update_target_version(
                options.update_source,
                default_source=default_source,
                version_url=version_url,
                tool_name=tool_name,
            )
        except Exception as e:
            sys.stderr.write('Could not determine update target version: %s\n' % e)
            sys.stderr.write('Use "dmsaforge update --force" to run pip anyway.\n')
            return 1

        if target_version is None:
            sys.stderr.write('Could not determine update target version from %s.\n' % version_source)
            sys.stderr.write('Use a versioned source such as "%s@v%s", or run "dmsaforge update --force".\n' % (default_source, package_version))
            return 1

        if not options.quiet:
            sys.stdout.write('Current version: %s\n' % current_version)
            sys.stdout.write('Target version:  %s\n' % target_version)
            sys.stdout.write('Version source:  %s\n' % version_source)

        if update_versions_match(current_version, target_version):
            if not options.quiet:
                sys.stdout.write('No update required; versions match.\n')
            return 0

    command = build_update_command(options, target_version, version_source, default_source=default_source)
    command_text = command_to_text(command)

    if options.dry_run:
        if not options.quiet:
            sys.stdout.write('Update dry-run: no changes will be made.\n')
        sys.stdout.write('Update command: %s\n' % command_text)
        return 0

    if not options.quiet:
        sys.stdout.write('Updating %s in the current Python environment.\n' % tool_name)
        sys.stdout.write('Python: %s\n' % sys.executable)
        sys.stdout.write('Command: %s\n' % command_text)
        sys.stdout.write('\n')

    start_cwd = os.getcwd()
    try:
        completed = runner(command, cwd=start_cwd)
    except OSError as e:
        sys.stderr.write('Could not start update command: %s\n' % e)
        return 1
    finally:
        try:
            os.chdir(start_cwd)
        except OSError:
            pass

    if completed.returncode == 0:
        if not options.quiet:
            sys.stdout.write('\nUpdate completed. Run "dmsaforge -v" to confirm the installed version.\n')
        return 0

    sys.stderr.write('\nUpdate failed with exit code %s.\n' % completed.returncode)
    return completed.returncode
