#!/usr/bin/env python3
"""
Generate a Threat Hunt Report from a system prompt + idea + optional attachments,
using the Google GenAI (Gemini) SDK.

Exit codes:
  1 - invalid CLI usage / missing required args
  2 - missing GEMINI_API_KEY
  3 - system prompt file missing/unreadable
  4 - generation error (API call failed)
  5 - model returned empty content
  6 - write failure (unable to write output file)

Usage example:
  python app/main_ai_studio.py \
    --system-file prompts/hunt_system_prompt.txt \
    --prompt "malicious use of workload identities" \
    --attach output/logs.txt output/findings.json \
    --no-stream \
    --output output/threat_hunt_report.md
"""

import argparse
import os
import sys
import time
import json
import traceback
from datetime import datetime
from typing import List, Optional

# SDK: google-genai >= 1.62.0
# pip install google-genai>=1.62.0
from google import genai
from google.genai import types

# -------- Utilities -------- #

def log(msg: str) -> None:
    """Structured stderr logging with timestamp."""
    ts = datetime.utcnow().isoformat(timespec="seconds") + "Z"
    sys.stderr.write(f"[{ts}] {msg}\n")
    sys.stderr.flush()

def read_text_file(path: str, max_bytes: int = 2_000_000) -> Optional[str]:
    """Read text file safely; returns None if missing/unreadable."""
    try:
        if not os.path.isfile(path):
            log(f"WARNING: attachment not found: {path}")
            return None
        size = os.path.getsize(path)
        if size > max_bytes:
            log(f"WARNING: attachment too large ({size} bytes), truncating to {max_bytes}: {path}")
        with open(path, "rb") as f:
            data = f.read(max_bytes)
        # Try to decode as utf-8; fallback with replace.
        return data.decode("utf-8", errors="replace")
    except Exception as e:
        log(f"WARNING: failed to read attachment {path}: {e}")
        return None

def ensure_parent_dir(path: str) -> None:
    parent = os.path.dirname(os.path.abspath(path))
    if parent and not os.path.exists(parent):
        os.makedirs(parent, exist_ok=True)

# -------- Prompt Assembly -------- #

def assemble_user_prompt(idea: str, attachments: List[str]) -> str:
    """
    Builds the user content that goes with the system prompt.
    Includes the idea and formatted attachments.
    """
    lines = []
    lines.append(f"THREAT HUNT IDEA:\n{idea.strip()}\n")
    if attachments:
        lines.append("ATTACHMENTS:")
        for idx, apath in enumerate(attachments, start=1):
            content = read_text_file(apath)
            if content is None:
                # Skip missing/unreadable files
                continue
            size = len(content.encode("utf-8"))
            ext = os.path.splitext(apath)[1].lower()
            lines.append(f"\n--- Attachment {idx} ---")
            lines.append(f"Path: {apath}")
            lines.append(f"Type: {ext or 'text'} | Size: {size} bytes")
            # Provide a fenced block for clarity
            lines.append("```")
            lines.append(content)
            lines.append("```")
    return "\n".join(lines).strip()

# -------- Model Call -------- #

def generate_report(
    api_key: str,
    system_prompt: str,
    user_prompt: str,
    model_name: str = "gemini-1.5-pro",
    stream: bool = True,
    temperature: float = 0.2,
    top_p: float = 0.9,
    max_output_tokens: int = 8192,
    safety: Optional[List[types.SafetySetting]] = None,
) -> str:
    """
    Calls Gemini to generate the report. Returns markdown string (non-empty),
    or raises RuntimeError on failure.
    """
    client = genai.Client(api_key=api_key)

    # Build the content parts
    system_part = types.Part.from_text(system_prompt)
    user_part = types.Part.from_text(user_prompt)

    # Configure generation
    config = types.GenerateContentConfig(
        temperature=temperature,
        top_p=top_p,
        max_output_tokens=max_output_tokens,
        safety_settings=safety or [],
        response_mime_type="text/markdown",  # ask for markdown
    )

    # Request
    start = time.time()
    try:
      # Use multi-part with system+user roles (SDK supports role-based content)
      req = types.GenerateContentRequest(
          model=model_name,
          config=config,
          contents=[
              types.Content(role="system", parts=[system_part]),
              types.Content(role="user", parts=[user_part]),
          ],
      )
      if stream:
          log(f"Invoking model (streaming): {model_name}")
          chunks = []
          for evt in client.models.generate_content_stream(req):
              if evt.type == "content":
                  # Each event carries parts; extract text from MIME-markdown parts
                  for part in evt.content.parts:
                      if part.inline_data and part.inline_data.mime_type == "text/markdown":
                          chunks.append(part.inline_data.data.decode("utf-8", errors="replace"))
                      elif part.text:
                          chunks.append(part.text)
              elif evt.type == "error":
                  raise RuntimeError(f"Model stream error: {evt.error.message}")
          output = "".join(chunks).strip()
      else:
          log(f"Invoking model (non-stream): {model_name}")
          resp = client.models.generate_content(req)
          # Prefer inline_data markdown; fallback to text
          output = ""
          for part in resp.candidates[0].content.parts:
              if part.inline_data and part.inline_data.mime_type == "text/markdown":
                  output += part.inline_data.data.decode("utf-8", errors="replace")
              elif part.text:
                  output += part.text
          output = (output or "").strip()
    except Exception as e:
        raise RuntimeError(f"Generation failed: {e}") from e
    finally:
        log(f"Model call duration: {time.time() - start:.2f}s")

    if not output:
        raise RuntimeError("Model returned empty content")
    return output

# -------- Main -------- #

def main(argv: List[str]) -> int:
    parser = argparse.ArgumentParser(description="Threat Hunt Report generator")
    parser.add_argument("--system-file", required=True, help="Path to system prompt file (text)")
    parser.add_argument("--prompt", required=True, help="Idea / user prompt text")
    parser.add_argument("--attach", nargs="*", default=[], help="Paths to attachment files")
    parser.add_argument("--output", required=True, help="Output markdown path")
    parser.add_argument("--model", default="gemini-1.5-pro", help="Model name")
    parser.add_argument("--no-stream", action="store_true", help="Disable streaming")
    parser.add_argument("--temperature", type=float, default=0.2)
    parser.add_argument("--top-p", type=float, default=0.9)
    parser.add_argument("--max-output-tokens", type=int, default=8192)

    args = parser.parse_args(argv)

    api_key = os.environ.get("GEMINI_API_KEY", "").strip()
    if not api_key:
        log("ERROR: GEMINI_API_KEY not set")
        return 2

    # Read system prompt
    try:
        with open(args.system_file, "r", encoding="utf-8") as f:
            system_prompt = f.read()
    except Exception as e:
        log(f"ERROR: Failed to read system prompt file {args.system_file}: {e}")
        return 3

    if not system_prompt.strip():
        log(f"ERROR: System prompt file {args.system_file} is empty")
        return 3

    idea = (args.prompt or "").strip()
    if not idea:
        log("ERROR: --prompt (idea) is required and cannot be empty")
        return 1

    user_prompt = assemble_user_prompt(idea, args.attach)

    # Generate
    try:
        output_md = generate_report(
            api_key=api_key,
            system_prompt=system_prompt,
            user_prompt=user_prompt,
            model_name=args.model,
            stream=not args.no_stream,
            temperature=args.temperature,
            top_p=args.top_p,
            max_output_tokens=args.max_output_tokens,
            safety=[
                # Add safety settings appropriate for your environment
                types.SafetySetting(category="HARM_CATEGORY_DANGEROUS_CONTENT", threshold="BLOCK_MEDIUM_AND_ABOVE"),
            ],
        )
    except Exception as e:
        log(f"ERROR: {e}")
        traceback.print_exc(file=sys.stderr)
        return 4

    # Fail if the content is suspiciously tiny (header-only)
    if len(output_md.encode("utf-8")) < 256:
        log("ERROR: Generated report is too small (<256 bytes); treating as empty")
        return 5

    # Write output
    try:
        ensure_parent_dir(args.output)
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(output_md)
    except Exception as e:
        log(f"ERROR: Failed to write output to {args.output}: {e}")
        return 6

    # Emit short summary to STDOUT for CI logs
    print(json.dumps({
        "status": "ok",
        "output_path": args.output,
        "size_bytes": len(output_md.encode("utf-8")),
        "model": args.model,
        "streaming": not args.no_stream,
    }, indent=2))

    log(f"SUCCESS: Wrote report to {args.output}")
    return 0


if __name__ == "__main__":
    try:
        code = main(sys.argv[1:])
        sys.exit(code)
    except KeyboardInterrupt:
        log("Interrupted by user")
