#!/usr/bin/env python3
"""
CTA DOCX Threat Hunt Report Generator
- Uses Google Gemini to generate section content
- Writes directly into a CTA-styled Word template (DOCX)
- No markdown, no pandoc
"""

import argparse, os, sys, json
from datetime import datetime
from typing import Dict, Any
from docx import Document
from docx.shared import Pt, Inches
from docx.enum.text import WD_ALIGN_PARAGRAPH
from google import genai

def log(msg: str) -> None:
    ts = datetime.utcnow().isoformat(timespec="seconds") + "Z"
    sys.stderr.write(f"[{ts}] {msg}\n")
    sys.stderr.flush()

def read_text(path: str) -> str:
    with open(path, "r", encoding="utf-8") as f:
        return f.read()

def call_model(api_key: str, system_prompt: str, user_prompt: str, model: str) -> Dict[str, Any]:
    client = genai.Client(api_key=api_key)
    # Ask the model to return JSON with CTA sections
    contents = [{
        "role": "user",
        "parts": [
            {"text": f"SYSTEM INSTRUCTION:\n{system_prompt.strip()}"},
            {"text": f"""
You are a cyber threat hunt report generator. Produce JSON with these keys:
sections.background, sections.hypothesis, sections.analysis, sections.findings,
sections.recommendations, sections.additional_research, sections.appendix, sections.resources (array).

Requirements:
- Tone: DISA/DEOS CTA report style (authoritative).
- Populate each section with substantive content (no placeholders).
- Resources: return as a JSON array of strings.
- Keep content under ~5k words total.

THREAT HUNT IDEA:
{user_prompt.strip()}
"""}
        ]
    }]
    response = client.models.generate_content(
        model=model,
        contents=contents,
        config={"temperature": 0.2, "top_p": 0.9, "max_output_tokens": 8192}
    )
    if not response or not getattr(response, "text", None):
        raise RuntimeError("Model returned empty response")
    try:
        data = json.loads(response.text)
    except Exception:
        raise RuntimeError("Model did not return valid JSON")
    return data

def stamp_header_footer(doc: Document):
    # Match CTA hunts (header/footer lines). [1](https://boozallen.sharepoint.us/teams/Thunderdome-F-35Execution/_layouts/15/Doc.aspx?sourcedoc=%7B5C10BCE0-25D4-4FED-BA91-6DC876060EA0%7D&file=CUI-CDI%20Rules%20of%20Behavior%20Thunderdome_Lewis_Julien_12112025.docx&action=default&mobileredirect=true&DefaultItemOpen=1)[2](https://boozallen.sharepoint.us/teams/Thunderdome-F-35Execution/_layouts/15/Doc.aspx?sourcedoc=%7B34F09DB0-4577-4CD6-B423-425D6021144C%7D&file=CUI-CDI%20Rules%20of%20Behavior%20Thunderdome_Venturino_12312025.docx&action=default&mobileredirect=true&DefaultItemOpen=1)
    section = doc.sections[0]
    for h in section.header.paragraphs:
        h.clear()

    hp1 = section.header.add_paragraph()
    r1 = hp1.add_run("TRUST IN DISA – MISSION FIRST, PEOPLE ALWAYS")
    r1.bold = True
    hp1.alignment = WD_ALIGN_PARAGRAPH.LEFT

    hp2 = section.header.add_paragraph()
    r2 = hp2.add_run("CUI//FEDCON")
    r2.bold = True
    hp2.alignment = WD_ALIGN_PARAGRAPH.RIGHT

    for f in section.footer.paragraphs:
        f.clear()

    fp1 = section.footer.add_paragraph("Controlled By: Defense Information Systems Agency (DISA) | DEOS Program Management Office (PMO) (DISA SD3)")
    fp1.alignment = WD_ALIGN_PARAGRAPH.CENTER
    fp2 = section.footer.add_paragraph("CUI Category: General Proprietary Business Information | Limited Dissemination Control: Federal Employees and Contractors Only (FEDCON)")
    fp2.alignment = WD_ALIGN_PARAGRAPH.CENTER

def set_styles(doc: Document):
    # CTA-like styles (Calibri 11 body, H1/H2 sizes)
    normal = doc.styles["Normal"]
    normal.font.name = "Calibri"
    normal.font.size = Pt(11)
    h1 = doc.styles["Heading 1"]
    h1.font.name = "Calibri"
    h1.font.size = Pt(16)
    h1.font.bold = True
    h2 = doc.styles["Heading 2"]
    h2.font.name = "Calibri"
    h2.font.size = Pt(13)
    h2.font.bold = True
    # Margins
    section = doc.sections[0]
    section.top_margin = Inches(1)
    section.bottom_margin = Inches(1)
    section.left_margin = Inches(1)
    section.right_margin = Inches(1)

def add_cover(doc: Document, prepared_by: str):
    p = doc.add_paragraph(style="Title")
    p.alignment = WD_ALIGN_PARAGRAPH.CENTER
    p.add_run("Threat Hunt Report").bold = True

    meta = doc.add_paragraph()
    meta.add_run("Controlled Unclassified Information (CUI)\n").bold = True
    doc.add_paragraph(f"Prepared by: {prepared_by}")
    doc.add_paragraph("Document Owner: DEOS Program Management Office")
    doc.add_paragraph("OPR: DISA SD3")
    doc.add_paragraph("CUI DESIGNATION INDICATOR: CUI Category: General Proprietary Business Information | Dissemination: FEDCON")

    disclaimer = doc.add_paragraph()
    disclaimer.add_run(
        "DISCLAIMER\nThe contents of this document are not to be construed as an official Defense Information Systems Agency document unless so designated by other authorized documents. The use of trade names in this document does not constitute an official endorsement or approval. Do not cite this document for the purpose of advertisement."
    )

def add_section(doc: Document, title: str, body):
    doc.add_paragraph(title, style="Heading 1")
    if isinstance(body, list):
        for item in body:
            doc.add_paragraph(str(item))
    else:
        doc.add_paragraph(str(body) if body else "[Insert content]")

def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--system-file", required=True)
    ap.add_argument("--template", required=True)
    ap.add_argument("--prompt", required=True)
    ap.add_argument("--prepared-by", default="Shawn McWhirter")
    ap.add_argument("--model", default="gemini-2.5-flash")
    ap.add_argument("--output", required=True)
    args = ap.parse_args(argv)

    api_key = os.environ.get("GEMINI_API_KEY", "").strip()
    if not api_key:
        log("ERROR: GEMINI_API_KEY not set")
        return 2

    system_prompt = read_text(args.system_file)

    # Call model to get structured section content
    data = call_model(api_key, system_prompt, args.prompt, args.model)
    sections = data.get("sections", {})

    # Load CTA template (preserves layout). [3](https://boozallen.sharepoint.us/teams/PowerBITigerTeam/SitePages/AI-Builder.aspx?web=1)
    doc = Document(args.template)

    # Ensure CTA styling & banners (double-safety). [1](https://boozallen.sharepoint.us/teams/Thunderdome-F-35Execution/_layouts/15/Doc.aspx?sourcedoc=%7B5C10BCE0-25D4-4FED-BA91-6DC876060EA0%7D&file=CUI-CDI%20Rules%20of%20Behavior%20Thunderdome_Lewis_Julien_12112025.docx&action=default&mobileredirect=true&DefaultItemOpen=1)[2](https://boozallen.sharepoint.us/teams/Thunderdome-F-35Execution/_layouts/15/Doc.aspx?sourcedoc=%7B34F09DB0-4577-4CD6-B423-425D6021144C%7D&file=CUI-CDI%20Rules%20of%20Behavior%20Thunderdome_Venturino_12312025.docx&action=default&mobileredirect=true&DefaultItemOpen=1)
    set_styles(doc)
    stamp_header_footer(doc)

    # Cover + Prepared by
    add_cover(doc, args.prepared_by)

    # Standard CTA sections
    order = [
        ("Background", sections.get("background")),
        ("Hypothesis", sections.get("hypothesis")),
        ("Analysis", sections.get("analysis")),
        ("Findings", sections.get("findings")),
        ("Recommendations", sections.get("recommendations")),
        ("Additional Research", sections.get("additional_research")),
        ("Appendix", sections.get("appendix")),
        ("Resources", sections.get("resources", [])),
    ]
    for title, body in order:
        add_section(doc, title, body)

    doc.save(args.output)
    log(f"SUCCESS: wrote CTA DOCX to {args.output}")
    print(json.dumps({"status": "ok", "docx": args.output}, indent=2))
    return 0

if __name__ == "__main__":
    sys.exit(main())
