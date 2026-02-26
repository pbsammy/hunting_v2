#!/usr/bin/env python3
"""
CTA Threat Hunt Report generator — resilient to google-genai SDK changes.

Exit codes:
  1 - invalid CLI usage / missing required args
  2 - missing GEMINI_API_KEY
  3 - system prompt file or template missing/unreadable
  4 - generation error (API call failed)
  5 - model returned empty / too small content
  6 - write failure (unable to write output file)
  7 - section validation failed (missing/short sections or ATT&CK IDs not propagated)
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
from google.genai.errors import ClientError

# ---------- Utilities ---------- #

def log(msg: str) -> None:
    ts = datetime.utcnow().isoformat(timespec="seconds") + "Z"
    sys.stderr.write(f"[{ts}] {msg}\n")
    sys.stderr.flush()

def read_text_file(path: str, max_bytes: int = 2_000_000) -> Optional[str]:
    try:
        if not os.path.isfile(path):
            log(f"WARNING: file not found: {path}")
            return None
        size = os.path.getsize(path)
        if size > max_bytes:
            log(f"WARNING: file too large ({size} bytes), truncating to {max_bytes}: {path}")
        with open(path, "rb") as f:
            data = f.read(max_bytes)
        return data.decode("utf-8", errors="replace")
    except Exception as e:
        log(f"WARNING: failed to read file {path}: {e}")
        return None

def ensure_parent_dir(path: str) -> None:
    parent = os.path.dirname(os.path.abspath(path))
    if parent and not os.path.exists(parent):
        os.makedirs(parent, exist_ok=True)

def log_sdk_versions() -> None:
    try:
        import importlib.metadata as importlib_metadata
        ver = importlib_metadata.version("google-genai")
        log(f"google-genai version: {ver}")
    except Exception:
        pass

# ---------- CTA Section Rules & Validation ---------- #

RE_HEADING = re.compile(r"^\s{0,3}#{1,6}\s+(.+?)\s*$", re.MULTILINE)
SECTION_ALIASES = {
    "Suspicious Activity Hits": {"Suspicious Activity Hits", "Suspicious Activity", "Findings"},
    "Findings": {"Findings", "Suspicious Activity Hits", "Suspicious Activity"},
    "Resources": {"Resources", "References", "Further Reading"},
}

def find_headings(md: str) -> List[Tuple[str, int]]:
    return [(m.group(1).strip(), m.start()) for m in RE_HEADING.finditer(md)]

def section_spans(md: str) -> Dict[str, str]:
    hits = find_headings(md)
    sections = {}
    for i, (h_text, start_idx) in enumerate(hits):
        end_idx = hits[i + 1][1] if i + 1 < len(hits) else len(md)
        body = md[start_idx:end_idx]
        body = re.sub(r"^\s{0,3}#{1,6}\s+.*?\n", "", body, count=1, flags=re.MULTILINE).strip()
        sections[h_text] = body
    return sections

def match_required_sections(found: Dict[str, str]) -> Dict[str, Optional[str]]:
    present_map: Dict[str, Optional[str]] = {}
    for canonical in ["Background", "Hypothesis", "Analysis", "Recommendations", "Additional Research", "Appendix", "Resources"]:
        if canonical in found:
            present_map[canonical] = canonical
            continue
        if canonical == "Resources":
            variants = SECTION_ALIASES["Resources"]
            matched = next((v for v in variants if v in found), None)
            present_map[canonical] = matched
            continue
        present_map[canonical] = None
    findings_present = None
    for variant in SECTION_ALIASES["Findings"]:
        if variant in found:
            findings_present = variant
            break
    present_map["Suspicious Activity Hits"] = findings_present
    present_map["Findings"] = findings_present
    return present_map

def count_words(text: str) -> int:
    return len([w for w in re.findall(r"\b\w+\b", text or "")])

def extract_attack_ids(s: str) -> List[str]:
    return sorted(set(re.findall(r"\bT\d{4}\b", s)))

def validate_cta(md: str, idea: str, min_words: int = 80, require_attack_ids: bool = True) -> Tuple[bool, List[str], Dict[str, int]]:
    sections = section_spans(md)
    present_map = match_required_sections(sections)
    errors = []
    word_counts = {}
    if present_map["Findings"] is None and present_map["Suspicious Activity Hits"] is None:
        errors.append("Missing required section: Findings or Suspicious Activity Hits")
    required = ["Background", "Hypothesis", "Analysis", "Recommendations", "Additional Research", "Resources"]
    for sec in required:
        matched = present_map.get(sec)
        if not matched:
            errors.append(f"Missing required section: {sec}")
        else:
            body = sections.get(matched, "")
            wc = count_words(body)
            word_counts[sec] = wc
            if wc < min_words:
                errors.append(f"Section '{sec}' is too short ({wc} words < {min_words}).")
    if present_map.get("Appendix"):
        body = sections.get(present_map["Appendix"], "")
        word_counts["Appendix"] = count_words(body)
    if require_attack_ids:
        idea_ids = extract_attack_ids(idea)
        if idea_ids:
            found_ids = extract_attack_ids(md)
            if not any(i in found_ids for i in idea_ids):
                errors.append(f"ATT&CK IDs from idea not reflected in output: expected one of {idea_ids}")
    return (len(errors) == 0), errors, word_counts

def synthesize_skeleton(sec_name: str, idea: str) -> str:
    return (
        f"### {sec_name}\n"
        f"_This section could not be auto-synthesized. Use the hunt idea_ **{idea}** "
        f"_to expand this section with behaviors, analytics (KQL/pseudo‑KQL), telemetry hints, ATT&CK mappings, and recommendations._\n"
    )

def add_missing_sections(md: str, idea: str, missing_sections: List[str]) -> str:
    additions = []
    for sec in missing_sections:
        additions.append(synthesize_skeleton(sec, idea))
    if additions:
        md = md.rstrip() + "\n\n" + "\n\n".join(additions) + "\n"
    return md

# ---------- Prompt Assembly ---------- #

def assemble_user_prompt(idea: str, attachments: List[str], template_content: str = "") -> str:
    lines = []
    lines.append(f"THREAT HUNT IDEA:\n{idea.strip()}\n")
    if template_content:
        lines.append("\nTEMPLATE:\n")
        lines.append(template_content)
    if attachments:
        lines.append("\nATTACHMENTS:")
        for idx, apath in enumerate(attachments, start=1):
            content = read_text_file(apath)
            if content is None:
                log(f"WARNING: skipping missing attachment: {apath}")
                continue
            size = len(content.encode("utf-8"))
            ext = os.path.splitext(apath)[1].lower()
            lines.append(f"\n--- Attachment {idx} ---")
            lines.append(f"Path: {apath}")
            lines.append(f"Type: {ext or 'text'} | Size: {size} bytes")
            lines.append("```")
            lines.append(content)
            lines.append("```")
    lines.append(
        "\nREQUIREMENTS:\n"
        "- Produce markdown with explicit H2/H3 headings for: Background, Hypothesis, Analysis, Findings (or Suspicious Activity Hits), Recommendations, Additional Research, Resources. Appendix optional.\n"
        "- Include technical detail (behaviors, analytics/detection logic, example timelines, telemetry hints, ATT&CK mappings). Use authoritative tone suitable for DoD/enterprise audiences.\n"
        "- Do NOT include title pages, signature blocks, or CUI markings unless explicitly requested.\n"
    )
    return "\n".join(lines).strip()

# ---------- Model Call (generate_report) ---------- #

def generate_report(
    api_key: str,
    system_prompt: str,
    user_prompt: str,
    model_name: str = "gemini-2.5-flash",
    stream: bool = True,
    temperature: float = 0.2,
    top_p: float = 0.9,
    max_output_tokens: int = 8192,
    safety=None,
) -> str:
    """
    Call Google GenAI to generate a threat hunt report.
    Returns the generated markdown as a string.
    """
    client = genai.Client(api_key=api_key)
    messages = [
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": user_prompt},
    ]
    try:
        if stream:
            output = []
            for resp in client.chat.stream(
                model=model_name,
                messages=messages,
                temperature=temperature,
                top_p=top_p,
                max_output_tokens=max_output_tokens,
            ):
                if hasattr(resp, "content") and resp.content:
                    output.append(resp.content)
            return "".join(output)
        else:
            resp = client.chat.create(
                model=model_name,
                messages=messages,
                temperature=temperature,
                top_p=top_p,
                max_output_tokens=max_output_tokens,
            )
            if resp.choices:
                return resp.choices[0].content
            return ""
    except ClientError as e:
        raise RuntimeError(f"GenAI client error: {e}")

# ---------- Main ---------- #

def main(argv: List[str]) -> int:
    parser = argparse.ArgumentParser(description="CTA Threat Hunt Report generator")
    parser.add_argument("--system-file", required=True, help="Path to system prompt file (text)")
    parser.add_argument("--template", default="templates/threat_hunt_template.md", help="Path to markdown template file")
    parser.add_argument("--prompt", required=True, help="Idea / user prompt text")
    parser.add_argument("--attach", nargs="*", default=[], help="Paths to attachment files")
    parser.add_argument("--output", required=True, help="Output markdown path")
    parser.add_argument("--model", default="gemini-2.5-flash", help="Model name (e.g., gemini-2.5-flash)")
    parser.add_argument("--no-stream", action="store_true", help="Disable streaming")
    parser.add_argument("--temperature", type=float, default=0.2)
    parser.add_argument("--top-p", type=float, default=0.9)
    parser.add_argument("--max-output-tokens", type=int, default=8192)
    parser.add_argument("--min-section-words", type=int, default=80)
    parser.add_argument("--strict-sections", action="store_true")
    parser.add_argument("--skeleton-fallback", action="store_true")
    parser.add_argument("--require-attack-ids", action="store_true")

    args = parser.parse_args(argv)
    api_key = os.environ.get("GEMINI_API_KEY", "").strip()
    if not api_key:
        log("ERROR: GEMINI_API_KEY not set")
        return 2

    log_sdk_versions()

    try:
        with open(args.system_file, "r", encoding="utf-8") as f:
            system_prompt = f.read()
        if not system_prompt.strip():
            log(f"ERROR: System prompt file {args.system_file} is empty")
            return 3
    except Exception as e:
        log(f"ERROR: Failed to read system prompt file {args.system_file}: {e}")
        return 3

    template_content = ""
    if args.template:
        try:
            with open(args.template, "r", encoding="utf-8") as f:
                template_content = f.read()
        except Exception as e:
            log(f"ERROR: Failed to read template file {args.template}: {e}")
            return 3

    idea = (args.prompt or "").strip()
    if not idea:
        log("ERROR: --prompt (idea) is required and cannot be empty")
        return 1

    user_prompt = assemble_user_prompt(idea, args.attach, template_content=template_content)

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
            safety=None,
        )
    except Exception as e:
        log(f"ERROR: {e}")
        traceback.print_exc(file=sys.stderr)
        return 4

    if len(output_md.encode("utf-8")) < 256:
        log("ERROR: Generated report is too small (<256 bytes); treating as empty")
        return 5

    valid, errors, word_counts = validate_cta(
        md=output_md,
        idea=idea,
        min_words=args.min_section_words,
        require_attack_ids=args.require_attack_ids,
    )

    if not valid:
        log("CTA section validation failed:")
        for e in errors:
            log(f"  - {e}")
        if args.skeleton_fallback:
            missing = [msg.replace("Missing required section: ", "") for msg in errors if msg.startswith("Missing required section: ")]
            output_md = add_missing_sections(output_md, idea, missing)
            log("Applied skeleton fallback for missing sections.")
        elif args.strict_sections:
            return 7
        else:
            log("Continuing without strict enforcement.")

    try:
        ensure_parent_dir(args.output)
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(output_md)
    except Exception as e:
        log(f"ERROR: Failed to write output to {args.output}: {e}")
        return 6

    print(json.dumps({
        "status": "ok",
        "output_path": args.output,
        "size_bytes": len(output_md.encode("utf-8")),
        "model": args.model,
        "streaming": not args.no_stream,
        "min_section_words": args.min_section_words,
        "word_counts": word_counts,
    }, indent=2))

    log(f"SUCCESS: Wrote report to {args.output}")
    return 0

if __name__ == "__main__":
    try:
        code = main(sys.argv[1:])
        sys.exit(code)
    except KeyboardInterrupt:
        log("Interrupted by user")
