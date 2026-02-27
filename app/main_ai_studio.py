#!/usr/bin/env python3
"""
CTA Threat Hunt Report generator — template-driven and resilient to google-genai SDK changes.

Pipeline:
1) Request structured JSON from Gemini (sections + metadata)
2) Validate & normalize sections
3) Render Jinja2 CTA markdown template
4) Workflow converts markdown to DOCX via Pandoc reference doc (CTA Word file)

Exit codes:
  1 - invalid CLI usage / missing required args
  2 - missing GEMINI_API_KEY
  3 - system prompt file missing/unreadable
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

# Third-party (installed by workflow)
from google import genai
from google.genai.errors import ClientError
from jinja2 import Template

# ---------- Utilities ---------- #

def log(msg: str) -> None:
    ts = datetime.utcnow().isoformat(timespec="seconds") + "Z"
    sys.stderr.write(f"[{ts}] {msg}\n")
    sys.stderr.flush()

def read_text_file(path: str, max_bytes: int = 2_000_000) -> Optional[str]:
    """Read up to max_bytes from a text file; return None if missing."""
    try:
        if not os.path.isfile(path):
            log(f"WARNING: attachment not found: {path}")
            return None
        size = os.path.getsize(path)
        if size > max_bytes:
            log(f"WARNING: attachment too large ({size} bytes), truncating to {max_bytes}: {path}")
        with open(path, "rb") as f:
            data = f.read(max_bytes)
        return data.decode("utf-8", errors="replace")
    except Exception as e:
        log(f"WARNING: failed to read attachment {path}: {e}")
        return None

def ensure_parent_dir(path: str) -> None:
    parent = os.path.dirname(os.path.abspath(path))
    if parent and not os.path.exists(parent):
        os.makedirs(parent, exist_ok=True)

def log_sdk_versions() -> None:
    """Log SDK versions so CI runs are diagnosable."""
    try:
        import importlib.metadata as importlib_metadata
        ver = importlib_metadata.version("google-genai")
        log(f"google-genai version: {ver}")
    except Exception:
        pass

# ---------- CTA Validation ---------- #

RE_HEADING = re.compile(r"^\s{0,3}#{1,6}\s+(.+?)\s*$", re.MULTILINE)

def find_headings(md: str) -> List[Tuple[str, int]]:
    return [(m.group(1).strip(), m.start()) for m in RE_HEADING.finditer(md)]

def count_words(text: str) -> int:
    return len([w for w in re.findall(r"\b\w+\b", text or "")])

def extract_attack_ids(s: str) -> List[str]:
    return sorted(set(re.findall(r"\bT\d{4}\b", s)))

def validate_cta(sections: Dict[str, str], idea: str, min_words: int = 80, require_attack_ids: bool = True) -> Tuple[bool, List[str], Dict[str, int]]:
    """
    sections: keys (lowercased + space) => body text
    required: Background, Hypothesis, Analysis, Recommendations, Additional Research, Resources
    Findings OR Suspicious Activity Hits must exist
    """
    errors = []
    word_counts: Dict[str, int] = {}

    # Check Findings or Suspicious Activity Hits
    findings_ok = sections.get("findings") or sections.get("suspicious activity hits")
    if not findings_ok:
        errors.append("Missing required section: Findings or Suspicious Activity Hits")

    required = ["background", "hypothesis", "analysis", "recommendations", "additional research", "resources"]
    for key in required:
        body = sections.get(key, "")
        if not body.strip():
            errors.append(f"Missing required section: {key.title()}")
        else:
            wc = count_words(body)
            word_counts[key.title()] = wc
            if wc < min_words:
                errors.append(f"Section '{key.title()}' is too short ({wc} words < {min_words}).")

    # Optional appendix
    if sections.get("appendix", ""):
        word_counts["Appendix"] = count_words(sections["appendix"])

    # ATT&CK propagation (if idea contains IDs)
    if require_attack_ids:
        idea_ids = extract_attack_ids(idea)
        if idea_ids:
            found_ids = extract_attack_ids("\n".join(sections.values()))
            if not any(i in found_ids for i in idea_ids):
                errors.append(f"ATT&CK IDs from idea not reflected in output: expected one of {idea_ids}")

    return (len(errors) == 0), errors, word_counts

# ---------- Prompt Assembly ---------- #

def assemble_json_prompt(idea: str, attachments: List[str]) -> str:
    """
    Request STRICT JSON (no prose) with two top-level keys:
      - metadata: HUNT_TITLE, ATTACK_ID, ATTACK_NAME, AUTHOR, CYCLE_NUMBER, DATE, ENVIRONMENT, CLASSIFICATION, REVISION, CUI_CATEGORY, DISSEMINATION, POC
      - sections: BACKGROUND, HYPOTHESIS, ANALYSIS, FINDINGS, RECOMMENDATIONS, ADDITIONAL_RESEARCH, APPENDIX, RESOURCES
    """
    lines = []
    lines.append("You are a DoD Cyber Threat Analytics report generator.")
    lines.append("Return ONLY JSON (no markdown, no prose).")
    lines.append("Top-level keys MUST be exactly: 'metadata' and 'sections'.")
    lines.append("metadata keys: HUNT_TITLE, ATTACK_ID, ATTACK_NAME, AUTHOR, CYCLE_NUMBER, DATE, ENVIRONMENT, CLASSIFICATION, REVISION, CUI_CATEGORY, DISSEMINATION, POC.")
    lines.append("sections keys: BACKGROUND, HYPOTHESIS, ANALYSIS, FINDINGS, RECOMMENDATIONS, ADDITIONAL_RESEARCH, APPENDIX, RESOURCES.")
    lines.append("Each section MUST be >=80 words; authoritative DoD tone; include ATT&CK mappings where relevant.")
    lines.append("Do NOT include title pages or signature blocks unless in metadata.")
    lines.append(f"\nTHREAT HUNT IDEA:\n{idea.strip()}\n")

    if attachments:
        lines.append("ATTACHMENTS:")
        for idx, apath in enumerate(attachments, start=1):
            content = read_text_file(apath)
            if content is None:
                continue
            lines.append(f"\n--- Attachment {idx} ---\nPath: {apath}\n```\n{content}\n```")

    lines.append("\nReturn a single JSON object EXACTLY with 'metadata' and 'sections'.")
    return "\n".join(lines)

# ---------- Model Call Helpers (SDK drift-tolerant) ---------- #

def _call_generate_content(client, model: str, contents: List[Dict], cfg: Dict, safety):
    """
    Try multiple signatures to survive SDK drift across versions.
    Prefer config=..., fallback to generation_config=...
    """
    last_err = None
    try:
        return client.models.generate_content(model=model, contents=contents, config=cfg, safety_settings=safety)
    except TypeError as e:
        last_err = e
    try:
        return client.models.generate_content(model=model, contents=contents, config=cfg)
    except TypeError as e:
        last_err = e
    try:
        return client.models.generate_content(model=model, contents=contents, generation_config=cfg, safety_settings=safety)
    except TypeError as e:
        last_err = e
    try:
        return client.models.generate_content(model=model, contents=contents, generation_config=cfg)
    except TypeError as e:
        last_err = e
    raise last_err or TypeError("No compatible signature for generate_content")

def _is_mime_error(err: Exception) -> bool:
    msg = str(err)
    return "response_mime_type" in msg and "INVALID_ARGUMENT" in msg

def _is_not_found(err: Exception) -> bool:
    msg = str(err)
    return "NOT_FOUND" in msg or "404" in msg

def _discover_model_names(client) -> List[str]:
    names: List[str] = []
    try:
        for m in client.models.list():
            name = getattr(m, "name", None) or getattr(m, "model", None)
            if name:
                names.append(str(name))
    except Exception as e:
        log(f"WARNING: Failed to list models: {e}")
    if names:
        log("Available models for this key:")
        for n in names:
            log(f"  - {n}")
    else:
        log("WARNING: No models discovered via client.models.list(); will try static fallbacks.")
    return names

def _candidate_models(client, preferred: Optional[str]) -> List[str]:
    discovered = _discover_model_names(client)  # e.g., 'models/gemini-1.5-flash'
    seen = set(discovered)
    order = list(discovered)
    if preferred and preferred.strip():
        pm = preferred.strip()
        if pm not in seen:
            order.append(pm)
        prefixed = f"models/{pm}"
        if prefixed not in seen:
            order.append(prefixed)
    for m in ["gemini-1.5-pro-latest", "gemini-1.5-flash", "gemini-1.5-flash-8b", "gemini-1.5-pro", "gemini-1.0-pro"]:
        if m not in seen:
            order.append(m)
        prefixed = f"models/{m}"
        if prefixed not in seen:
            order.append(prefixed)
    return order

def request_structured_json(
    api_key: str,
    system_prompt: str,
    user_prompt: str,
    model_name: str,
) -> Dict:
    """Ask Gemini for JSON; parse and return a dict."""
    client = genai.Client(api_key=api_key)

    cfg_json = {
        "temperature": 0.2,
        "top_p": 0.9,
        "max_output_tokens": 8192,
        "response_mime_type": "application/json",
    }
    cfg_plain = {
        "temperature": 0.2,
        "top_p": 0.9,
        "max_output_tokens": 8192,
    }
    safety = [{"category": "HARM_CATEGORY_DANGEROUS_CONTENT", "threshold": "BLOCK_MEDIUM_AND_ABOVE"}]

    contents = [
        {"role": "user", "parts": [{"text": f"SYSTEM INSTRUCTION:\n{system_prompt.strip()}"}]},
        {"role": "user", "parts": [{"text": user_prompt}]},
    ]

    models = _candidate_models(client, model_name)
    last_err: Optional[Exception] = None
    for m in models:
        try:
            log(f"Invoking model (JSON): {m}")
            try:
                resp = _call_generate_content(client, m, contents, cfg_json, safety)
            except Exception as e:
                if _is_mime_error(e):
                    resp = _call_generate_content(client, m, contents, cfg_plain, safety)
                else:
                    raise
            # Prefer unified .text; else parts text
            text = (getattr(resp, "text", "") or "").strip()
            if not text and getattr(resp, "candidates", None):
                parts = getattr(resp.candidates[0].content, "parts", []) or []
                buf: List[str] = []
                for part in parts:
                    if getattr(part, "text", None):
                        buf.append(part.text)
                text = "".join(buf).strip()

            if not text:
                last_err = RuntimeError("Empty model response")
                continue

            # Parse JSON
            try:
                return json.loads(text)
            except json.JSONDecodeError:
                # Attempt to extract {...} block
                mobj = re.search(r"\{.*\}", text, flags=re.DOTALL)
                if mobj:
                    return json.loads(mobj.group(0))
                last_err = RuntimeError("Model did not return valid JSON")
                continue

        except ClientError as ce:
            if _is_not_found(ce):
                log(f"Model '{m}' not available; trying next candidate...")
                last_err = ce
                continue
            last_err = ce
            break
        except Exception as e:
            last_err = e
            break

    raise RuntimeError(f"Generation failed: {last_err}")

# ---------- Rendering ---------- #

def render_template(template_path: str, metadata: Dict[str, str], sections: Dict[str, str]) -> str:
    """Render the Jinja2 CTA markdown template."""
    with open(template_path, "r", encoding="utf-8") as f:
        tmpl_src = f.read()
    tmpl = Template(tmpl_src)

    # Normalize resources into plain list text if needed
    resources = sections.get("RESOURCES", "").strip()
    if resources and not resources.startswith("-"):
        lines = [l.strip() for l in resources.splitlines() if l.strip()]
        resources = "\n".join(lines)

    md = tmpl.render(
        HUNT_TITLE=metadata.get("HUNT_TITLE", "Untitled Hunt"),
        ATTACK_ID=metadata.get("ATTACK_ID", ""),
        ATTACK_NAME=metadata.get("ATTACK_NAME", ""),
        AUTHOR=metadata.get("AUTHOR", ""),
        CYCLE_NUMBER=metadata.get("CYCLE_NUMBER", ""),
        DATE=metadata.get("DATE", ""),
        ENVIRONMENT=metadata.get("ENVIRONMENT", ""),
        CLASSIFICATION=metadata.get("CLASSIFICATION", "CUI"),
        REVISION=metadata.get("REVISION", "Version 1.0"),
        CUI_CATEGORY=metadata.get("CUI_CATEGORY", "General Proprietary Business Information"),
        DISSEMINATION=metadata.get("DISSEMINATION", "FEDCON"),
        POC=metadata.get("POC", ""),

        BACKGROUND=sections.get("BACKGROUND", ""),
        HYPOTHESIS=sections.get("HYPOTHESIS", ""),
        ANALYSIS=sections.get("ANALYSIS", ""),
        FINDINGS=sections.get("FINDINGS", ""),
        RECOMMENDATIONS=sections.get("RECOMMENDATIONS", ""),
        ADDITIONAL_RESEARCH=sections.get("ADDITIONAL_RESEARCH", ""),
        APPENDIX=sections.get("APPENDIX", ""),
        RESOURCES=resources,
    )
    return md

# ---------- Main ---------- #

def main(argv: List[str]) -> int:
    parser = argparse.ArgumentParser(description="CTA Threat Hunt Report generator (template-driven)")
    parser.add_argument("--system-file", required=True, help="Path to system prompt file (text)")
    parser.add_argument("--prompt", required=True, help="Idea / user prompt text")
    parser.add_argument("--attach", nargs="*", default=[], help="Paths to attachment files")
    parser.add_argument("--template", default="templates/cta_hunt_report_template.md", help="CTA markdown template path")
    parser.add_argument("--output", required=True, help="Output markdown path")
    parser.add_argument("--model", default="gemini-1.5-pro-latest", help="Model name")
    parser.add_argument("--no-stream", action="store_true", help="(unused) kept for CLI compatibility")
    parser.add_argument("--temperature", type=float, default=0.2)
    parser.add_argument("--top-p", type=float, default=0.9)
    parser.add_argument("--max-output-tokens", type=int, default=8192)
    parser.add_argument("--min-section-words", type=int, default=80)
    parser.add_argument("--strict-sections", action="store_true", help="Fail if required sections missing/short")
    parser.add_argument("--require-attack-ids", action="store_true", help="Require ATT&CK IDs if present in idea")

    args = parser.parse_args(argv)

    api_key = os.environ.get("GEMINI_API_KEY", "").strip()
    if not api_key:
        log("ERROR: GEMINI_API_KEY not set")
        return 2

    log_sdk_versions()

    # System prompt
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

    # Build JSON-focused user prompt
    user_prompt = assemble_json_prompt(idea, args.attach)

    # Generate structured content
    try:
        data = request_structured_json(
            api_key=api_key,
            system_prompt=system_prompt,
            user_prompt=user_prompt,
            model_name=args.model,
        )
    except Exception as e:
        log(f"ERROR: {e}")
        traceback.print_exc(file=sys.stderr)
        return 4

    # Validate structure
    metadata = data.get("metadata", {})
    sections_raw = data.get("sections", {})

    # Normalize keys to template expectations (UPPERCASE for rendering)
    norm_sections = {k.upper().strip(): (v or "").strip() for k, v in sections_raw.items()}

    # Build lower-case view for validator
    lower_sections = {k.lower().replace("_", " "): v for k, v in norm_sections.items()}
    valid, errors, word_counts = validate_cta(
        sections=lower_sections,
        idea=idea,
        min_words=args.min_section_words,
        require_attack_ids=args.require_attack_ids,
    )

    if not valid:
        log("CTA section validation failed:")
        for e in errors:
            log(f"  - {e}")
        if args.strict_sections:
            return 7
        else:
            log("Continuing; template will render with current sections.")

    # Render template → markdown
    try:
        ensure_parent_dir(args.output)
        md = render_template(args.template, metadata, norm_sections)
        if len(md.encode("utf-8")) < 256:
            log("ERROR: Rendered report is too small (<256 bytes)")
            return 5
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(md)
    except Exception as e:
        log(f"ERROR: Failed to write output to {args.output}: {e}")
        return 6

    print(json.dumps({
        "status": "ok",
        "output_path": args.output,
        "size_bytes": len(md.encode("utf-8")),
        "model": args.model,
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
