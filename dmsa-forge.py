#!/usr/bin/env python3
"""Compatibility launcher for running dMSA Forge from a source checkout."""

import sys

from dmsa_forge.cli import main


if __name__ == "__main__":
    sys.exit(main())
