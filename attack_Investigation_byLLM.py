"""Thin CLI entrypoint for Themis attack investigation.

Delegates to ``themis.investigation`` (the real implementation now lives in the
``themis/`` package). This file is preserved verbatim as the invocation target
so existing scripts and ``supplementary/run_themis_investigation.py`` (which
runs it as a subprocess with ``--log_file --alert --collection --output``)
keep working unchanged.
"""
import os
import sys

# Ensure the repo root is importable when invoked from any cwd.
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from themis.investigation import main

if __name__ == "__main__":
    main()
