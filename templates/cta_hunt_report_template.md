# {{MITRE_ATTACK_ID}}: {{THREAT_NAME}}

**For assistance, please contact your Tier I Service Desk. Visit the DoD365-Joint Information Hub (CAC Required) for more information.**

*TRUST IN DISA – MISSION FIRST, PEOPLE ALWAYS*

---

## 1. Background

{{BACKGROUND}}

> **Hypothesis:**  
{{HYPOTHESIS}}

> **Analysis:**  
{{ANALYSIS}}

---

## 2. Threat Hunt Findings

{{FINDINGS}}

---

## 3. Recommendations

{{RECOMMENDATIONS}}

---

## 4. Additional Research

{{ADDITIONAL_RESEARCH}}

---

## 5. Appendix

```kql
{{KQL_QUERY}}
```
---

## 6. Resources

{{RESOURCES}}

---

## prompts/hunt_system_prompt.txt

```text
You are a cyber threat intelligence analyst for a government cyber defense organization.

You generate structured, professional threat-hunting reports.

Style:
- Formal
- Technical
- Operational
- Defensive cyber posture

You must generate:
BACKGROUND, HYPOTHESIS, ANALYSIS, FINDINGS, RECOMMENDATIONS, ADDITIONAL_RESEARCH, RESOURCES, KQL_QUERY

Use realistic cyber threat language, MITRE ATT&CK concepts, SOC detection logic, and enterprise security context.

```kql
{{KQL_QUERY}}
```
