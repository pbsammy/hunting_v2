# CTA DOCX Threat Hunt Pipeline

This workflow generates a **CTA-styled Word document** directly from your hunt prompt using Gemini—no Markdown, no Pandoc. Output matches CTA formatting used in internal hunts (header: `TRUST IN DISA – MISSION FIRST, PEOPLE ALWAYS`, `CUI//FEDCON`, DISA/DEOS footer lines, CTA metadata, and standard sections).

## Prerequisites
- **Secret**: `GEMINI_API_KEY` (Repo → Settings → Secrets and variables → Actions → Secrets)
- **Template**: `templates/cta/CTA_THREAT_HUNT_Integrated.docx` (CTA-styled base template)

## Run the workflow
1. Go to **Actions → Generate Threat Hunt Report (CTA DOCX)** → **Run workflow**.
2. Provide:
   - **Threat hunt prompt** (your idea or topic)
   - **Prepared by** (optional; defaults to `Shawn McWhirter`)
   - **Model** (optional; defaults to `gemini-2.5-flash`)
3. Download the artifact:
   - `CTA_THREAT_HUNT_DOCX` → the generated Word report

## What the script does
- Calls Gemini to **return JSON** with CTA sections:
  - `background`, `hypothesis`, `analysis`, `findings`, `recommendations`, `additional_research`, `appendix`, `resources[]`
- Writes sections into the CTA Word template.
- Stamps CTA **header/footer** and **metadata**.

## Troubleshooting
If the job fails with `Model did not return valid JSON`:

1. Download **model_debug** artifact:
   - `output/model_raw.txt` → raw model output
   - `output/sections.json` → parsed/partial JSON if any
2. Inspect `model_raw.txt`:
   - If you see prose or Markdown, ensure your prompt is concise and avoids asking for prose outside JSON.
   - The generator already tries to extract JSON from ```json fenced blocks or the first `{...}` object.

Other common causes:
- **`GEMINI_API_KEY` missing** → set the secret.
- **Template path invalid** → verify `templates/cta/CTA_THREAT_HUNT_Integrated.docx` exists.
- **Library versions**: If you see `response_mime_type` issues, try:
  ```bash
  pip install --upgrade google-genai
