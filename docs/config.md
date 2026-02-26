# Configuration Guide

## 🔑 GitHub Secrets

This action requires:

- `GEMINI_API_KEY` — Your API key for the Google AI SDK (Gemini).  
  Add it under: **Settings → Secrets and variables → Actions**

## ⚙️ Workflow Parameters

The GitHub Action workflow (e.g., `generate-report-ai-studio.yml`) supports these inputs:

| Parameter         | Required | Description |
|------------------|----------|-------------|
| `threat_name`     | yes      | The name of the threat |
| `mitre_attack_id` | yes      | MITRE ATT&CK ID for the threat |
| `threat_description` | yes  | A detailed description |
| `attack_vector`   | yes      | Method/attack route |
| `detection_hypothesis` | yes | How you plan to detect it |
| `resources`       | no       | URLs for the resources section (comma-separated) |
| `output_filename` | no       | Name of the generated report MD file (default: `threat_hunt_report.md`) |

## 🧠 Model Configuration

- The script uses `gemini-pro` by default (in `main_ai_studio.py`)
- You may switch to a different model string if desired
