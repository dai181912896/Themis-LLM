import argparse
import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from themis.story import generate_story

if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="Attack Story Generation")
    ap.add_argument("--cache", required=True, help="reasoning_cache.jsonl from investigation")
    ap.add_argument("--out", required=True, help="Output report file (.md)")
    ap.add_argument("--kill-chain", default=None, help="Optional Kill Chain KB JSON for context")
    a = ap.parse_args()
    generate_story(a.cache, a.out, a.kill_chain)
