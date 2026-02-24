# Configuration Guide

This document outlines the necessary configuration for the "Generate Threat Hunt Report" GitHub Action.

## GitHub Secrets

The action requires a Google AI Studio API key to be stored as a secret in your GitHub repository.

*   `GEMINI_API_KEY`: Your API key for the Google AI SDK.

To add this secret:
1.  Go to your repository's **Settings**.
2.  Navigate to **Secrets and variables > Actions**.
3.  Click **New repository secret**.
4.  Enter `GEMINI_API_KEY` as the name and your API key as the value.

## Workflow Parameters

The `generate-report-ai-studio.yml` workflow accepts the following input parameter:

*   `output_filename`: (Optional) The name for the generated Markdown report file. The default is `threat_hunt_report.md`.

## Model Configuration

The AI model is configured in `main_ai_studio.py`. By default, it uses `gemini-pro`. You can modify the script to use a different model or adjust generation parameters if needed.
