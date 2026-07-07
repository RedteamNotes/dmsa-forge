"""Operation report redaction and output helpers."""

import json
import os
import sys

from .ad_utils import display_base_dn, format_dn_for_display, looks_like_dn, validate_dn_syntax


def redact_report(value, options):
    if not options.redact:
        return value
    base_dn = display_base_dn(options)
    if isinstance(value, dict):
        return {key: redact_report(item, options) for key, item in value.items()}
    if isinstance(value, list):
        return [redact_report(item, options) for item in value]
    if isinstance(value, str):
        if looks_like_dn(value) and validate_dn_syntax(value):
            return format_dn_for_display(value, base_dn=base_dn, redact=True)
        return value
    return value


def report_to_text(report):
    lines = [
        'operation_id: %s' % report.get('operation_id'),
        'tool: %s %s' % (report.get('tool'), report.get('version')),
        'mode: %s' % report.get('mode'),
        'success: %s' % report.get('success'),
        'action: %s' % report.get('action'),
    ]
    connection = report.get('connection', {})
    lines.append('connection: %s:%s %s auth=%s base_dn=%s' % (
        connection.get('dc_host'),
        connection.get('port'),
        connection.get('method'),
        connection.get('auth'),
        connection.get('base_dn'),
    ))
    scope = report.get('scope', {})
    lines.append('scope: domain=%s base_dn=%s' % (scope.get('domain'), scope.get('base_dn')))
    result = report.get('result') or {}
    if result:
        lines.append('result:')
        for key in sorted(result):
            lines.append('  %s: %s' % (key, result[key]))
    inference = report.get('inference') or []
    if inference:
        lines.append('inference:')
        for event in inference:
            lines.append('  - %s: %s - %s' % (event.get('kind'), event.get('status'), event.get('detail')))
    operations = report.get('ldap_operations') or []
    if operations:
        lines.append('ldap_operations:')
        for idx, operation in enumerate(operations, 1):
            lines.append('  %d. %s' % (idx, json.dumps(operation, sort_keys=True)))
    return '\n'.join(lines) + '\n'


def write_output_file(path, text):
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
    if hasattr(os, 'O_NOFOLLOW'):
        flags |= os.O_NOFOLLOW
    fd = os.open(path, flags, 0o600)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, 'w') as handle:
            fd = None
            handle.write(text)
    finally:
        if fd is not None:
            os.close(fd)


def emit_report(options, report):
    if report is None:
        return True

    def write_report_file(text):
        try:
            write_output_file(options.output, text)
            return True
        except Exception as e:
            sys.stderr.write('Could not write output file %s: %s\n' % (options.output, e))
            return False

    if options.output_only:
        if options.output:
            return write_report_file(json.dumps(report, indent=2, sort_keys=True) + '\n')
        else:
            sys.stdout.write(json.dumps(report, indent=2, sort_keys=True) + '\n')
        return True

    if options.json:
        text = json.dumps(report, indent=2, sort_keys=True) + '\n'
        sys.stdout.write(text)
        if options.output:
            return write_report_file(text)
        return True

    if options.output:
        return write_report_file(report_to_text(report))
    return True
