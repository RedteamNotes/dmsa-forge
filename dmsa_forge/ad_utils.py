"""Active Directory string, DN, SID, and address helpers."""

import ipaddress
import re
import socket


SID_RE = re.compile(r'^S-\d-\d+(?:-\d+)+$')
DOMAIN_RE = re.compile(r'^(?=.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}$')
DNS_HOSTNAME_RE = re.compile(r'^(?=.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])$')
DMSA_NAME_RE = re.compile(r'^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$')
DN_ATTR_RE = re.compile(r'^[A-Za-z][A-Za-z0-9-]*$')
DN_OID_ATTR_RE = re.compile(r'^\d+(?:\.\d+)+$')
IPV4_RE = re.compile(r'^\d{1,3}(?:\.\d{1,3}){3}$')
IPV4_LIMITED_BROADCAST = '255.255.255.255'


def escape_filter_chars(value):
    value = str(value)
    return (
        value
        .replace('\\', r'\5c')
        .replace('*', r'\2a')
        .replace('(', r'\28')
        .replace(')', r'\29')
        .replace('\x00', r'\00')
    )


def looks_like_dn(value):
    value = str(value)
    return '=' in value and ',' in value


def domain_to_base_dn(domain):
    domain = str(domain).strip().strip('.')
    if not domain:
        return None
    return ','.join('DC=%s' % part for part in domain.split('.') if part)


def domain_from_base_dn(base_dn):
    parsed = parse_dn(base_dn)
    if not parsed:
        return None
    labels = []
    for rdn in parsed:
        if len(rdn) != 1:
            continue
        attr, value = rdn[0]
        if attr.lower() != 'dc':
            continue
        labels.append(value.replace(r'\.', '.'))
    if not labels:
        return None
    return '.'.join(labels)


def base_dn_from_dn_context(dn):
    domain = domain_from_base_dn(dn)
    if not domain:
        return None
    return domain_to_base_dn(domain)


def parent_ou_from_dn(dn):
    if not dn or not validate_dn_syntax(dn):
        return None
    rdns = split_unescaped(str(dn), {',', ';'})
    if not rdns or len(rdns) < 2:
        return None
    parent_rdns = [part.strip() for part in rdns[1:] if part.strip()]
    if not parent_rdns:
        return None
    sep = find_unescaped(parent_rdns[0], '=')
    if sep <= 0 or parent_rdns[0][:sep].strip().lower() != 'ou':
        return None
    parent = ','.join(parent_rdns)
    return parent if validate_dn_syntax(parent) else None


def domain_from_account_hint(account):
    account = str(account)
    if '/' in account:
        domain = account.split('/', 1)[0].strip()
        return domain or None
    return None


def escape_dn_value(value):
    value = str(value)
    escaped = []
    for idx, char in enumerate(value):
        if char == ' ' and (idx == 0 or idx == len(value) - 1):
            escaped.append('\\ ')
        elif char == '#' and idx == 0:
            escaped.append('\\#')
        elif char in {',', '+', '"', '\\', '<', '>', ';', '='}:
            escaped.append('\\%s' % char)
        elif ord(char) < 32:
            escaped.append('\\%02X' % ord(char))
        else:
            escaped.append(char)
    return ''.join(escaped)


def split_unescaped(value, separators):
    parts = []
    current = []
    escaped = False
    for char in str(value):
        if escaped:
            current.append(char)
            escaped = False
            continue
        if char == '\\':
            current.append(char)
            escaped = True
            continue
        if char in separators:
            parts.append(''.join(current))
            current = []
            continue
        current.append(char)
    if escaped:
        return None
    parts.append(''.join(current))
    return parts


def find_unescaped(value, needle):
    escaped = False
    for idx, char in enumerate(str(value)):
        if escaped:
            escaped = False
            continue
        if char == '\\':
            escaped = True
            continue
        if char == needle:
            return idx
    return -1


def is_escaped_at(value, idx):
    backslashes = 0
    pos = idx - 1
    while pos >= 0 and value[pos] == '\\':
        backslashes += 1
        pos -= 1
    return bool(backslashes % 2)


def validate_dn_value(value):
    if value == '':
        return False

    if value[0] == ' ' or value[-1] == ' ':
        if (value[0] == ' ' and not is_escaped_at(value, 0)) or (value[-1] == ' ' and not is_escaped_at(value, len(value) - 1)):
            return False

    if value[0] == '#' and not is_escaped_at(value, 0):
        return False

    idx = 0
    hex_digits = set('0123456789abcdefABCDEF')
    escaped_chars = set(' "#+,;<>\\=')
    while idx < len(value):
        char = value[idx]
        if char == '\\':
            if idx + 1 >= len(value):
                return False
            if idx + 2 < len(value) and value[idx + 1] in hex_digits and value[idx + 2] in hex_digits:
                idx += 3
                continue
            if value[idx + 1] in escaped_chars:
                idx += 2
                continue
            return False
        if ord(char) < 32:
            return False
        if char in ',+"\\<>;=':
            return False
        idx += 1
    return True


def has_unescaped_boundary_space(value):
    if value == '':
        return False
    if value[0] == ' ' and not is_escaped_at(value, 0):
        return True
    if value[-1] == ' ' and not is_escaped_at(value, len(value) - 1):
        return True
    return False


def validate_dn_component_boundary(value):
    if not value:
        return False
    if has_unescaped_boundary_space(value):
        return False
    return True


def parse_dn(value):
    if value in (None, ''):
        return None

    value = str(value)
    if has_unescaped_boundary_space(value):
        return None

    rdns = split_unescaped(value, {',', ';'})
    if rdns is None or not rdns:
        return None

    parsed = []
    for rdn in rdns:
        if not validate_dn_component_boundary(rdn):
            return None
        avas = split_unescaped(rdn, {'+'})
        if avas is None or not avas:
            return None

        parsed_rdn = []
        for ava in avas:
            if not validate_dn_component_boundary(ava):
                return None
            sep = find_unescaped(ava, '=')
            if sep <= 0:
                return None
            attr = ava[:sep]
            val = ava[sep + 1:]
            if not attr or not (DN_ATTR_RE.match(attr) or DN_OID_ATTR_RE.match(attr)):
                return None
            if not validate_dn_value(val):
                return None
            parsed_rdn.append((attr, val))
        parsed.append(parsed_rdn)
    return parsed


def normalize_dn(value):
    parsed = parse_dn(value)
    if not parsed:
        return ','.join(part.strip().lower() for part in str(value).split(',') if part.strip())
    return ','.join(
        '+'.join('%s=%s' % (attr.lower(), val.lower()) for attr, val in rdn)
        for rdn in parsed
    )


def dn_in_scope(dn, scope_base_dn):
    dn = normalize_dn(dn)
    scope_base_dn = normalize_dn(scope_base_dn)
    return dn == scope_base_dn or dn.endswith(',' + scope_base_dn)


def validate_domain_name(value):
    return bool(value and DOMAIN_RE.match(str(value).strip()))


def validate_dns_hostname(value):
    value = str(value or '').strip().rstrip('.')
    return bool(value and DNS_HOSTNAME_RE.match(value))


def is_ipv4_address(value):
    value = str(value or '').strip()
    if not IPV4_RE.match(value):
        return False
    try:
        socket.inet_aton(value)
    except OSError:
        return False
    return all(0 <= int(part) <= 255 for part in value.split('.'))


def auto_dc_ip_rejection_reason(value):
    value = str(value or '').strip()
    if not is_ipv4_address(value):
        return 'not an IPv4 address'
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return 'not an IPv4 address'
    if address.is_multicast:
        return 'multicast address'
    if address.is_loopback:
        return 'loopback'
    if address.is_link_local:
        return 'link-local'
    if address.is_unspecified:
        return 'unspecified'
    if value == IPV4_LIMITED_BROADCAST:
        return 'limited broadcast'
    if address.is_reserved:
        return 'reserved'
    return ''


def is_usable_auto_dc_ip(value):
    return not auto_dc_ip_rejection_reason(value)


def resolve_ipv4_address(host, usable_only=False):
    host = str(host or '').strip()
    if not host:
        return None
    if is_ipv4_address(host):
        return host if not usable_only or is_usable_auto_dc_ip(host) else None
    try:
        infos = socket.getaddrinfo(host, None, socket.AF_INET, socket.SOCK_STREAM)
    except OSError:
        return None
    for info in infos:
        address = info[4][0]
        if is_ipv4_address(address) and (not usable_only or is_usable_auto_dc_ip(address)):
            return address
    return None


def parse_account_hint(account):
    account = str(account or '')
    domain = ''
    username = ''
    password = ''
    if '/' in account:
        domain, rest = account.split('/', 1)
    else:
        rest = account
    if ':' in rest:
        username, password = rest.split(':', 1)
    else:
        username = rest
    if '@' in username and not domain:
        username, domain = username.split('@', 1)
    return domain, username, password


def normalized_dmsa_name(value):
    return str(value or '').strip().rstrip('$').strip()


def validate_dmsa_name(value):
    value = normalized_dmsa_name(value)
    return bool(value and DMSA_NAME_RE.match(value))


def validate_dn_syntax(value):
    if not value or not looks_like_dn(value):
        return False
    return parse_dn(value) is not None


def validate_sid_syntax(value):
    return bool(value and SID_RE.match(str(value).strip()))


def redact_account(account):
    account = str(account)
    colon = account.find(':')
    if colon < 0:
        return account

    at_after_secret = account.find('@', colon)
    if at_after_secret >= 0:
        return account[:colon + 1] + '<redacted>' + account[at_after_secret:]
    return account[:colon + 1] + '<redacted>'


def account_has_inline_secret(account):
    account = str(account or '')
    if not account:
        return False
    principal = account.split('@', 1)[0]
    if '/' in principal:
        principal = principal.split('/', 1)[1]
    if ':' not in principal:
        return False
    username, secret = principal.split(':', 1)
    return bool(username and secret)


def format_dn_for_display(dn, base_dn=None, redact=True):
    if dn in (None, ''):
        return dn

    return str(dn)


def format_value_for_display(value, base_dn=None, redact=True):
    if value in (None, ''):
        return value
    if looks_like_dn(value):
        return format_dn_for_display(value, base_dn=base_dn, redact=redact)
    return str(value)


def dn_rdns_for_display(dn):
    parts = split_unescaped(dn, {',', ';'})
    if not parts:
        return []
    return [part.strip() for part in parts if part.strip()]


def derived_base_dn_from_account(account):
    account = str(account)
    if '/' not in account:
        return None
    domain = account.split('/', 1)[0]
    if not domain or '.' not in domain:
        return None
    return ','.join('DC=%s' % part for part in domain.split('.') if part)


def effective_port(options):
    if options.port is not None:
        return options.port
    return 389 if options.method == 'LDAP' else 636


def planned_dmsa_dn(options):
    if not options.dmsa_name or not options.target_ou:
        return None
    return 'CN=%s,%s' % (options.dmsa_name.rstrip('$'), options.target_ou)


def current_base_dn(options):
    return options.base_dn or derived_base_dn_from_account(options.account)


def display_base_dn(options):
    return options.scope_base_dn or current_base_dn(options)


def effective_dns_hostname(options):
    if options.dns_hostname:
        return options.dns_hostname
    if not options.dmsa_name:
        return None
    domain = options.scope_domain or domain_from_account_hint(options.account)
    if not domain or not validate_domain_name(domain):
        return None
    return '%s.%s' % (options.dmsa_name.rstrip('$').lower(), domain.lower())
