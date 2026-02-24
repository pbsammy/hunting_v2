import os
import argparse
import pathlib
import google.generativeai as genai

def generate_report(args):
    """
    Generates a generic threat hunt report using the Google AI SDK.
    """
    # --- Configuration ---
    api_key = os.getenv("GEMINI_API_KEY")
    if not api_key:
        raise ValueError("GEMINI_API_KEY environment variable not set.")
    genai.configure(api_key=api_key)

    model = genai.GenerativeModel('gemini-pro')

    # --- Load Prompts and Template ---
    try:
        system_prompt = pathlib.Path("hunt_system_prompt.txt").read_text()
        user_prompt_template = pathlib.Path("hunt_user_prompt.md").read_text()
        report_template = pathlib.Path("report_template.md").read_text()
    except FileNotFoundError as e:
        print(f"Error: Missing required file - {e.filename}")
        return

    # --- Populate User Prompt ---
    user_prompt = user_prompt_template.replace("{{THREAT_NAME}}", args.threat_name)
    user_prompt = user_prompt.replace("{{MITRE_ATTACK_ID}}", args.mitre_attack_id)
    user_prompt = user_prompt.replace("{{THREAT_DESCRIPTION}}", args.threat_description)
    user_prompt = user_prompt.replace("{{ATTACK_VECTOR}}", args.attack_vector)
    user_prompt = user_prompt.replace("{{DETECTION_HYPOTHESIS}}", args.detection_hypothesis)
    
    # Format resources into a bulleted list
    resource_list = ""
    if args.resources:
        urls = [url.strip() for url in args.resources.split(',')]
        resource_list = "\n".join([f"*   {url}" for url in urls])
    user_prompt = user_prompt.replace("{{RESOURCES}}", resource_list)
    
    # --- Generate Content ---
    print("Generating report content with Google AI Studio...")
    full_prompt = f"{system_prompt}\n\n{user_prompt}"
    response = model.generate_content(full_prompt)

    ai_content = response.text

    # --- Populate Report Template ---
    final_report = report_template.replace("{{AI_GENERATED_CONTENT}}", ai_content)
    final_report = final_report.replace("{{MITRE_ATTACK_ID}}", args.mitre_attack_id)
    final_report = final_report.replace("{{THREAT_NAME}}", args.threat_name)

    # --- Save Report ---
    with open(args.output, "w") as f:
        f.write(final_report)
    print(f"Successfully generated report: {args.output}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Generate a generic Threat Hunt Report.")
    parser.add_argument("--threat-name", type=str, required=True, help="Name of the threat.")
    parser.add_argument("--mitre-attack-id", type=str, required=True, help="MITRE ATT&CK ID.")
    parser.add_argument("--threat-description", type=str, required=True, help="Description of the threat.")
    parser.add_argument("--attack-vector", type=str, required=True, help="Attack vector.")
    parser.add_action("--detection-hypothesis", type=str, required=True, help="Detection hypothesis.")
    parser.add_argument("--resources", type=str, help="Comma-separated list of resource URLs.")
    parser.add_argument("--output", type=str, required=True, help="Output filename for the report.")
    
    args = parser.parse_args()
    generate_report(args)
