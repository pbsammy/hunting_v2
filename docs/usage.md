# Usage Guide: Generate Threat Hunt Report

This guide explains how to use the "Generate Threat Hunt Report" GitHub Action.

## 🧠 Prerequisites

1. **Repository Setup**  
   Ensure all required files (workflow YAML, main script) are committed in your repo.

2. **API Key Secret**  
   Add your Google AI Studio API key as a repo secret:
   - Secret Name: `GEMINI_API_KEY`
   - Value: (your key)

## ▶️ Steps to Run

1. Go to the **Actions** tab of this repo.
2. Under **Workflows**, locate **Generate Threat Hunt Report**.
3. Click **Run workflow**.
4. Fill in these fields in the form:
   - `threat_name`: Name of the threat
   - `mitre_attack_id`: The MITRE ATT&CK ID
   - `threat_description`: Detailed summary
   - `attack_vector`: How the attack occurs
   - `detection_hypothesis`: Your approach to detect it
   - `resources`: Comma-separated resource URLs
   - `output_filename`: Name of the report file (optional)

5. Hit **Run workflow**.

## ☁️ After Completion

- A workflow artifact named `threat-hunt-report` will be generated.
- Download the artifact to get your threat report in Markdown.
