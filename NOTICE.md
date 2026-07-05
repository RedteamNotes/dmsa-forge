# Notices

## Upstream Basis

This repository contains a modified derivative of Impacket `examples/badsuccessor.py`.

Original project:

- Impacket: https://github.com/fortra/impacket
- Upstream license: https://github.com/fortra/impacket/blob/master/LICENSE
- Original `badsuccessor.py` author: Ilya Yatsenko (`@fulc2um`)

Impacket notice:

> This product includes software developed by SecureAuth Corporation (https://www.secureauth.com/) and Fortra (https://www.fortra.com).

## Modifications

The `dmsa_forge` package and `dmsa-forge.py` compatibility launcher in this repository were modified by **RedteamNotes**.

Notable changes include signed LDAP 389 support, Impacket-native LDAP compatibility wrappers, atomic dMSA AddRequest construction, post-add verification, readable security descriptor summaries, and stricter exit-code behavior.

## License Handling

Keep the upstream Impacket copyright and license notice in source distributions.
This repository includes a local `LICENSE` file with the Impacket main license terms and links to the full upstream license above.
