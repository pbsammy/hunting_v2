# Hunt Automation Framework

This repository automates cyber threat hunt documentation using the Google Gen AI SDK and Gemini models. It standardizes outputs, accelerates reporting, and supports repeatable workflows for analysts and investigators.

## Overview
The framework performs single-turn generation using the stable v1 API. The user prompt and optional system instruction are passed to the model using the google-genai package. Optional file attachments are supported for log analysis or structured input.

## Features
- Uses the google-genai SDK (current, supported Google Gen AI package)
- Single-turn text generation
- Optional system instruction
- Optional file attachments (logs, JSON, text, PDF)
- Supports streaming or non-streamed output
- CI-friendly formatting (no deprecated modules, no legacy code patterns)

## Requirements
- Python 3.11 or newer
- google-genai SDK

Install the SDK:
pip install google-genai

## Set API Key

macOS / Linux:
export GEMINI_API_KEY="your_key_here"

Windows PowerShell:
setx GEMINI_API_KEY "your_key_here"

## Usage Examples

### Basic example
python app/main_ai_studio.py --prompt "Generate a threat hunt."

### With a system instruction
python app/main_ai_studio.py --system "You are a cyber threat hunter." --prompt "Analyze suspicious activity."

### With an attachment
python app/main_ai_studio.py --prompt "Analyze the attached log." --attach examples/sample_log.json

### Disable streaming
python app/main_ai_studio.py --prompt "Summaries." --no-stream

### Write output to a file
python app/main_ai_studio.py --prompt "Create a hunt report." --output output/hunt.md

### Smoke test
python app/main_ai_studio.py --smoke-test

## GitHub Actions CI Example

Use the following to install the Google Gen AI SDK inside your workflow:

- name: Install Google Gen AI SDK
  run: pip install google-genai

Provide the API key through GitHub secrets:

env:
  GEMINI_API_KEY: ${{ secrets.GEMINI_API_KEY }}

## Troubleshooting
- Ensure the google-genai package is installed
- Ensure the GEMINI_API_KEY environment variable is set
- Check that attachment paths point to existing files
- Pin the API to v1 in your client configuration if needed
- Ensure your model name is supported, for example: gemini-2.5-flash

## Suggested Project Structure
app/
  main_ai_studio.py
templates/
  hunt.md
  prompt_template.txt
docs/
  usage.md
  config.md
examples/
  sample_log.json
  sample_output.md

## Contributing
Contributions are welcome. Keep formatting clean and avoid deprecated references.

## License
Add your preferred license such as MIT or Apache 2.0.

## Support
For questions or help, open an issue in this repository.
