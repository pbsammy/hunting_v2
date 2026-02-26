#!/usr/bin/env python3
"""
CTA Threat Hunt Report Generator
Clean, CI-safe, google-genai compatible
"""

import argparse
import os
import sys
import json
import traceback
from datetime import datetime
from typing import List, Optional

from google import genai


# ----------------------------
# Logging
# ----------------------------

def log(msg: str) -> None:
    ts = datetime.utcnow().isoformat(timespec="seconds") + "Z"
    sys.stderr.write(f"[{ts}] {msg}\n")
    sys.stderr.flush()


# ----------------------------
# File helpers
# ----------------------------

def read_text_file(path: str, max_bytes: int = 2_000_000) -> str:
    if not os.path.isfile(path):
        log(f"WARNING: file not found: {path}")
        return ""

    size = os.path.getsize(path)
    if size > max_bytes:
        log(f"WARNING: file too large ({size} bytes), truncating to {max_bytes}: {path}")

    with open(path, "rb") as f:
        data = f.read(max_bytes)

    return data.decode("utf-8", errors="replace")


def ensure_parent_dir(path: str) -> None:
    parent = os.path.dirname(os.path.abspath(path))
    if parent and not os.path.exists(parent):
        os.makedirs(parent, exist_ok=True)


# ----------------------------
# Prompt assembly
# ----------------------------

def assemble_user_prompt(
    idea: str,
    attachments: List[str],
    template_content: str
) -> str:
    parts = []

    parts.append("THREAT HUNT IDEA:")
    parts.append(idea.strip())
    parts.append("")

    if template_content:
        parts.append("TEMPLATE:")
        parts.append(template_content)
        parts.append("")

    if attachments:
        parts.append("ATTACHMENTS:")
        for idx, apath in enumerate(attachments, start=1):
            content = read_text_file(apath)
            if not content:
                continue

            ext = os.path.splitext(apath)[1].lower()
            parts.append(f"\n--- Attachment {idx} ---")
            parts.append(f"Path: {apath}")
            parts.append(f"Type: {ext or 'text'}")
            parts.append("```")
            parts.append(content)
            parts.append("```")

    parts.append("""
REQUIREMENTS:
- Generate a professional cyber threat hunt report in markdown.
- Use the provided template structure.
- Populate all sections with real content.
- Background: 6 to 10 paragraphs.
- Hypothesis: concise and clear.
- Analysis: 3 to 6 paragraphs with technical depth.
- Findings, Recommendations, Additional Research, Appendix, Resources must all be populated.
- Use authoritative enterprise/DoD tone.
- Include technical details, detection logic, and operational context.
- No placeholders.
- No skeleton text.
- No meta commentary.
""")

    return "\n".join(parts).strip()


# ----------------------------
# AI Generation
# ----------------------------

def generate_report(
    api_key: str,
    system_prompt: str,
    user_prompt: str,
    model_name: str,
    temperature: float,
    top_p: float,
    max_output_tokens: int
) -> str:
    client = genai.Client(api_key=api_key)

    contents = [
        {
            "role": "user",
            "parts": [
                {"text": f"SYSTEM INSTRUCTION:\n{system_prompt.strip()}"},
                {"text": user_prompt}
            ]
        }
    ]

    try:
        response = client.models.generate_content(
            model=model_name,
            contents=contents,
            config={
                "temperature": temperature,
                "top_p": top_p,
                "max_output_tokens": max_output_tokens
            }
        )
    except Exception as e:
        raise RuntimeError(f"Generation failed: {e}")

    if not response or not getattr(response, "text", None):
        raise RuntimeError("Model returned empty response")

    return response.text.strip()


# ----------------------------
# Main
# ----------------------------

def main(argv: List[str]) -> int:
    parser = argparse.ArgumentParser(description="CTA Threat Hunt Report Generator")

    parser.add_argument("--system-file", required=True)
    parser.add_argument("--template", required=True)
    parser.add_argument("--prompt", required=True)
    parser.add_argument("--attach", nargs="*", default=[])
    parser.add_argument("--output", required=True)
    parser.add_argument("--model", default="gemini-2.5-flash")
    parser.add_argument("--temperature", type=float, default=0.2)
    parser.add_argument("--top-p", type=float, default=0.9)
    parser.add_argument("--max-output-tokens", type=int, default=8192)

    args = parser.parse_args(argv)

    api_key = os.environ.get("GEMINI_API_KEY", "").strip()
    if not api_key:
        log("ERROR: GEMINI_API_KEY not set")
        return 2

    try:
        system_prompt = read_text_file(args.system_file)
        if not system_prompt.strip():
            log("ERROR: system prompt file empty or unreadable")
            return 3
    except Exception as e:
        log(f"ERROR reading system file: {e}")
        return 3

    try:
        template_content = read_text_file(args.template)
        if not template_content.strip():
            log("ERROR: template file empty or unreadable")
            return 3
    except Exception as e:
        log(f"ERROR reading template: {e}")
        return 3

    idea = args.prompt.strip()
    if not idea:
        log("ERROR: prompt cannot be empty")
        return 1

    user_prompt = assemble_user_prompt(
        idea=idea,
        attachments=args.attach,
        template_content=template_content
    )

    try:
        output_md = generate_report(
            api_key=api_key,
            system_prompt=system_prompt,
            user_prompt=user_prompt,
            model_name=args.model,
            temperature=args.temperature,
            top_p=args.top_p,
            max_output_tokens=args.max_output_tokens
        )
    except Exception as e:
        log(str(e))
        traceback.print_exc(file=sys.stderr)
        return 4

    if len(output_md.encode("utf-8")) < 256:
        log("ERROR: generated output too small")
        return 5

    try:
        ensure_parent_dir(args.output)
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(output_md)
    except Exception as e:
        log(f"ERROR writing output: {e}")
        return 6

    print(json.dumps({
        "status": "ok",
        "output_path": args.output,
        "bytes": len(output_md.encode("utf-8")),
        "model": args.model
    }, indent=2))

    log(f"SUCCESS: report written to {args.output}")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main(sys.argv[1:]))
    except KeyboardInterrupt:
        log("Interrupted by user")
        sys.exit(130)
