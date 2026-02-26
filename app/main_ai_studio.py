import argparse

Rules:
- Background: 6–10 paragraphs
- Hypothesis: 1 paragraph
- Analysis: 3–6 paragraphs
- Findings: realistic hunt results
- Recommendations: actionable bullets
- Additional research: forward-looking
- Resources: URLs
"""

    resp = client.models.generate_content(
        model=model,
        contents=prompt
    )

    text = resp.text
    blocks = {}
    current = None
    for line in text.splitlines():
        line = line.strip()
        if line.endswith(":") and line.replace(":", "").isupper():
            current = line.replace(":", "")
            blocks[current] = []
        elif current:
            blocks[current].append(line)

    return {k: "\n".join(v).strip() for k, v in blocks.items()}



def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--system-file", required=True)
    ap.add_argument("--template", required=True)
    ap.add_argument("--prompt", required=True)
    ap.add_argument("--output", required=True)
    ap.add_argument("--model", required=True)
    ap.add_argument("--min-section-words", type=int, default=80)
    args = ap.parse_args()

    system_prompt = load_file(args.system_file)
    template_md = load_file(args.template)

    client = genai.Client(api_key=os.getenv("GEMINI_API_KEY"))

    sections = generate_sections(client, args.prompt, system_prompt, args.model)

    data = {
        "DATE": datetime.utcnow().strftime("%Y-%m-%d"),
        "MITRE_ATTACK_ID": "AUTO-GENERATED",
        "THREAT_NAME": args.prompt,
        "BACKGROUND": sections.get("BACKGROUND", ""),
        "HYPOTHESIS": sections.get("HYPOTHESIS", ""),
        "ANALYSIS": sections.get("ANALYSIS", ""),
        "FINDINGS": sections.get("FINDINGS", ""),
        "RECOMMENDATIONS": sections.get("RECOMMENDATIONS", ""),
        "ADDITIONAL_RESEARCH": sections.get("ADDITIONAL_RESEARCH", ""),
        "RESOURCES": sections.get("RESOURCES", ""),
        "KQL_QUERY": sections.get("KQL_QUERY", "// AI-generated analytic")
    }

    tpl = Template(template_md)
    output = tpl.render(**data)

    with open(args.output, "w", encoding="utf-8") as f:
        f.write(output)

    print(f"Report generated: {args.output}")


if __name__ == "__main__":
    main()
