#!/usr/bin/env python3
"""
Vantic CLI - Red Team Penetration Testing Toolkit
"""

import sys
import os

# Add the vantic package to path
script_dir = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, script_dir)

from vantic.cli import main

if __name__ == '__main__':
    main()
