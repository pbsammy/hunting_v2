#!/usr/bin/env python3
"""
Threat Hunt Report generator using the Google Gen AI SDK (google.genai).

Key features:
- Single-turn generation with a structured prompt (no chat message dicts).
- Persona/behavior instruction via top-level `system_instruction` (REST v1 expects snake_case).
- Optional attachments via client.files.upload() (e.g., logs or artifacts).
- Streaming and non-streamed generation supported.
- API version pinned to v1 for stability.
"""

from __future__ import annotations

import argparse
import logging
import mimetypes
import os
import sys
import time
from typing import List, Optional

# Google Gen AI SDK (new, supported)
from google import genai
from google.genai import types

# -------- Defaults --------
DEFAULT_MODEL = os.environ.get("GEMINI_MODEL", "gemini-2.5-flash")
DEFAULT_API_KEY_ENV = "GEMINI_API_KEY"
DEFAULT_MAX_RETRIES = 3
DEFAULT_RETRY_BACKOFF_SEC = 2.0
PIN_API_V1 = True  # pin to stable v1 to avoid v1beta model mismatch
INLINE_SYSTEM = os.environ.get("GEMINI_INLINE_SYSTEM", "0") == "1"  # set to "1" to inline system prompt

LOG = logging.getLogger("main_ai_studio")
logging.basicConfig(
    level=os.environ.get("LOG_LEVEL", "INFO"),
    format="%(asctime)s %(levelname)s %(message)s",
)

# -------- Helpers --------
def read_text(path: str) -> str:
    with open(path, "r", encoding="utf-8") as f:
        return f.read()

def ensure_api_key(env_var: str = DEFAULT_API_KEY_ENV) -> str:
    api_key = os.environ.get(env_var, "").strip()
    if not api_key:
        raise RuntimeError(
            f"Missing API key. Set environment variable {env_var} with your Gemini API key."
        )
    return api_key

def build_client(api_key_env: str = DEFAULT_API_KEY_ENV) -> genai.Client:
    """
    Create a GenAI client. Pins API to v1 unless PIN_API_V1 is False.
    """
    api_key = ensure_api_key(api_key_env)
    http_opts = None
    if PIN_API_V1:
        http_opts = types.HttpOptions(api_version="v1")
    client = genai.Client(api_key=api_key, http_options=http_opts)
    return client

def guess_mime(path: str) -> str:
    mt, _ = mimetypes.guess_type(path)
    return mt or "application/octet-stream"

def upload_attachments(client: genai.Client, paths: List[str]) -> List[types.Part]:
    """
    Upload files and return Parts that can be included in the user Content.
    """
    parts: List[types.Part] = []
    for p in paths:
        if not os.path.exists(p):
            raise FileNotFoundError(f"Attachment not found: {p}")
        LOG.info("Uploading attachment: %s", p)

        # OPEN THE FILE AND PASS IT AS 'file=' (NOT 'path=')
        with open(p, "rb") as fh:
            uploaded = client.files.upload(file=fh, mime_type=guess_mime(p))

        # Wrap the uploaded file as a Part for the contents payload
        parts.append(types.Part.from_file(uploaded))

    return parts

def do_generate(
    client: genai.Client,
    model_name: str,
    contents: List[object] | object,
    system_instruction: Optional[str],
    generation_config: Optional[dict],
    stream: bool,
    max_retries: int = DEFAULT_MAX_RETRIES,
    backoff_sec: float = DEFAULT_RETRY_BACKOFF_SEC,
):
    attempt = 0
    last_exc = None

    gen_cfg = None
    if generation_config:
        gen_cfg = types.GenerationConfig(**generation_config)

    # Inline fallback: remove system_instruction and prefix user text
    if INLINE_SYSTEM and system_instruction:
        LOG.info("Inline system instruction is ENABLED (GEMINI_INLINE_SYSTEM=1).")
        # contents is a list of Content; first message is user
        if isinstance(contents, list) and contents and hasattr(contents[0], "parts"):
            # Prepend the system instruction text to the first user part
            system_text = f"System instruction:\n{system_instruction}\n\n"
            first_parts = contents[0].parts
            if first_parts and hasattr(first_parts[0], "text") and first_parts[0].text:
                first_parts[0].text = system_text + first_parts[0].text
            else:
                first_parts.insert(0, types.Part.from_text(system_text))
        # Clear system_instruction so it's not sent to the API
        system_instruction = None

    while attempt < max_retries:
        try:
            if stream:
                LOG.info("Starting streamed generation...")
                resp_iter = client.models.generate_content_stream(
                    model=model_name,
                    contents=contents,
                    system_instruction=system_instruction,
                    generation_config=gen_cfg,
                )
                return resp_iter
            else:
                LOG.info("Starting non-streamed generation...")
                resp = client.models.generate_content(
                    model=model_name,
                    contents=contents,
                    system_instruction=system_instruction,
                    generation_config=gen_cfg,
                )
                return resp
        except Exception as e:
            last_exc = e
            attempt += 1
            wait = backoff_sec * (2 ** (attempt - 1))
            LOG.warning("Generation attempt %d failed: %s", attempt, repr(e))
            if attempt < max_retries:
                LOG.info("Retrying in %.1f seconds...", wait)
                time.sleep(wait)
            else:
                LOG.error("Max retries reached.")
                raise last_exc

def accumulate_stream(stream_resp) -> str:
    full_text = []
    try:
        for chunk in stream_resp:
            if hasattr(chunk, "text") and chunk.text:
                print(chunk.text, end="", flush=True)
                full_text.append(chunk.text)
        print()
    except Exception as e:
        LOG.error("Error while streaming: %s", repr(e))
        raise
    return "".join(full_text)

# -------- CLI --------
def make_argparser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Generate a threat hunt report using Google Gen AI (single-turn)."
    )
    p.add_argument("--model", default=DEFAULT_MODEL, help=f"Model name (default: {DEFAULT_MODEL})")
    p.add_argument("--system", help="Persona/behavior instruction text.")
    p.add_argument("--system-file", help="Path to a file containing the instruction text.")
    prompt_group = p.add_mutually_exclusive_group(required=True)
    prompt_group.add_argument("--prompt", help="User prompt as a single string.")
    prompt_group.add_argument("--prompt-file", help="Path to a file containing the prompt.")
    p.add_argument("--attach", nargs="*", default=[], help="Paths to files to upload and include.")
    p.add_argument("--no-stream", action="store_true", help="Disable streaming; return full response.")
    p.add_argument("--output", help="Write final text to this file.")
    p.add_argument("--api-key-env", default=DEFAULT_API_KEY_ENV, help=f"Env var for API key (default: {DEFAULT_API_KEY_ENV}).")

    # Optional generation parameters
    p.add_argument("--temperature", type=float, help="Optional temperature.")
    p.add_argument("--top-p", type=float, help="Optional top_p.")
    p.add_argument("--top-k", type=int, help="Optional top_k.")
    p.add_argument("--max-output-tokens", type=int, help="Optional max_output_tokens.")

    # Quick smoke test
    p.add_argument("--smoke-test", action="store_true", help="Quick test to verify SDK.")
    return p

def resolve_text_arg(arg_value: Optional[str], file_path: Optional[str]) -> Optional[str]:
    if arg_value:
        return arg_value
    if file_path:
        return read_text(file_path)
    return None

def run_smoke_test() -> None:
    LOG.info("Running smoke test...")
    client = build_client()
    resp = client.models.generate_content(
        model=DEFAULT_MODEL,
        contents=[types.Content(role="user", parts=[types.Part.from_text("Say hello in one sentence.")])],
        system_instruction="Respond concisely.",
    )
    txt = getattr(resp, "text", "")
    assert txt, "Smoke test failed: empty response.text"
    print("Smoke test output:", txt)
    LOG.info("Smoke test passed.")

def main() -> int:
    args = make_argparser().parse_args()

    if args.smoke_test:
        run_smoke_test()
        return 0

    # Build client
    try:
        client = build_client(args.api_key_env)
    except Exception as e:
        LOG.error("Client configuration error: %s", repr(e))
        return 2

    # Resolve instruction & prompt
    system_instruction = resolve_text_arg(args.system, args.system_file)
    user_prompt = resolve_text_arg(args.prompt, args.prompt_file)
    if not user_prompt:
        LOG.error("No user prompt provided.")
        return 2

    # Generation config
    generation_config = {}
    if args.temperature is not None:
        generation_config["temperature"] = args.temperature
    if args.top_p is not None:
        generation_config["top_p"] = args.top_p
    if args.top_k is not None:
        generation_config["top_k"] = args.top_k
    if args.max_output_tokens is not None:
        generation_config["max_output_tokens"] = args.max_output_tokens
    if not generation_config:
        generation_config = None

