import json
import os
import sys

with open("qa_report.json", encoding="utf-8") as f:
    data = json.load(f)

markdown = "# 🧠 AI-Enriched Edge Case Security Report\n\n"
markdown += "This report compiles the Gemini AI's contextual analysis of the engine's edge case findings.\n\n"

for i, report in enumerate(data):
    file_name = report.get('analyzed_file')
    markdown += f"## File: `{os.path.basename(file_name)}`\n\n"
    
    if "ai_risk_narrative" in report:
        markdown += f"**AI Risk Narrative:**\n> {report['ai_risk_narrative']}\n\n"
    elif "summary" in report:
        markdown += f"**Engine Summary:**\n> {report['summary']}\n\n"
    
    for fng in report.get('findings', []):
        markdown += f"### [{fng['id']}] {fng['title']}\n"
        markdown += f"- **Severity**: {fng['severity'].upper()}\n"
        markdown += f"- **Confidence**: {fng['confidence']}\n\n"
        
        if "ai_explanation" in fng:
            markdown += f"**Gemini AI Explanation:**\n{fng['ai_explanation']}\n\n"
        if "attack_scenario" in fng:
            markdown += f"**Attack Scenario:**\n{fng['attack_scenario']}\n\n"
        if "fixed_code_example" in fng:
            markdown += "**AI Suggested Fix:**\n```pact\n" + fng['fixed_code_example'] + "\n```\n\n"
            
        markdown += "---\n\n"

out_path = r"C:\Users\kumar\.gemini\antigravity\brain\3d385ece-5d7d-449b-85d5-580cc1287669\edge_case_report.md"
with open(out_path, "w", encoding='utf-8') as f:
    f.write(markdown)
print(f"Report generated successfully to {out_path}")
