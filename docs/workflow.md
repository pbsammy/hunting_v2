## Example Workflow: `.github/workflows/generate-report-ai-studio.yml`

```yaml
name: Generate Threat Hunt Report

on:
  workflow_dispatch:
    inputs:
      threat_name:
        description: 'Name of the threat'
        required: true
      mitre_attack_id:
        required: true
      threat_description:
        required: true
      attack_vector:
        required: true
      detection_hypothesis:
        required: true
      resources:
        required: false
      output_filename:
        required: false

jobs:
  generate:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - name: Set up Python
        uses: actions/setup-python@v4
        with:
          python-version: 3.11
      - name: Install dependencies
        run: pip install -r requirements.txt
      - name: Run report generator
        run: python app/main_ai_studio.py \
          --prompt "Generate threat hunt report..." \
          --output output/${{ github.event.inputs.output_filename }}
      - name: Upload report
        uses: actions/upload-artifact@v3
        with:
          name: threat-hunt-report
          path: output/
