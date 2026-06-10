#!/usr/bin/env python3
"""
Backward-compatibility shim. Use: stackraider scan <path>
"""
import sys
import warnings

warnings.warn(
    "scanner.py is deprecated. Use: stackraider scan <path>  or  python -m stackraider.cli scan <path>",
    DeprecationWarning,
    stacklevel=1,
)

from stackraider.core.scanner import main

if __name__ == "__main__":
    sys.exit(main())
