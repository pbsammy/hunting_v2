# Usage Guide: Generate Threat Hunt Report

This guide explains how to use the "Generate Threat Hunt Report" GitHub Action.

## Prerequisites

1.  **Repository Setup:** Ensure all required files are in your GitHub repository.
2.  **API Key:** Add your Google AI Studio API key as a repository secret named `GEMINI_API_KEY`.

## Steps to Run the Action

1.  **Trigger the Workflow:**
    *   Go to the **Actions** tab in your repository.
    *   Under "Workflows," select **Generate Threat Hunt Report**.
    *   Click the **Run workflow** dropdown on the right.

2.  **Fill in the Threat Details:**
    *   You will see a form with several input fields. Fill them out with the details of the vulnerability or threat you are reporting on:
        *   **`threat_name`**: The name of the threat.
        *   **`mitre_attack_id`**: The corresponding MITRE ATT&CK ID.
        *   **`threat_description`**: A detailed summary of the threat.
        *   **`attack_vector`**: How the attack is executed.
        *   **`detection_hypothesis`**: Your theory on how to detect it.
        *   **`resources`**: A comma-separated list of URLs for the resources section.
        *   **`output_filename`**: The desired name for the report file.

3.  **Run the Workflow:**
    *   Click the green **Run workflow** button.

4.  **Download the Report:**
    *   Once the workflow is complete, an artifact named "threat-hunt-report" will be available.
    *   Download the artifact to get your generated Markdown report.
