#!/usr/bin/env python3
"""
Threat Hunt Report generator with CTA section validation.

Exit codes:
  1 - invalid CLI usage / missing required args
  2 - missing GEMINI_API_KEY
  3 - system prompt file missing/unreadable
  4 - generation error (API call failed)
  5 - model returned empty / too small content
  6 - write failure (unable to write output file)
  7 - section validation failed (missing/short sections or ATT&CK IDs not propagated)

Usage:
  python app/main_ai_studio.py \
    --system-file prompts/hunt_system_prompt.txt \
    --prompt "malicious use of workload identities (T1578)" \
    --attach output/logs.txt output/findings.json \
    --no-stream \
    --output output/threat_hunt_report.md \
    --min-section-words 80 \
    --strict-sections
"""

import argparse
import os
import sys
import time
import json
import re
import traceback
from datetime import datetime
from typing import List, Optional, Dict, Tuple

from google import genai
from google.genai import types

# -------- Utilities -------- #

def log(msg: str) -> None:
    ts = datetime.utcnow().isoformat(timespec="seconds") + "Z"
    sys.stderr.write(f"[{ts}] {msg}\n")
