#!/usr/bin/env python
"""
Backward compatibility wrapper for enumerate-iam CLI.
This file maintains compatibility with the old ./enumerate-iam.py usage.
For uv-managed installations, use: enumerate-iam (without .py extension)
"""
from enumerate_iam.cli import main

if __name__ == '__main__':
    main()
