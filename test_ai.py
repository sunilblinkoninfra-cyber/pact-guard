import os
import json
from src.ai.gemini_analyzer import AIAnalyzer, ENRICHMENT_PROMPT
from src.rules.rule_engine import Finding, Severity, Location

api_key = os.environ.get("GEMINI_API_KEY", "AIzaSyDKtZiiyP-g2w0z5s6qncBFr8e9aXi1mEY")
analyzer = AIAnalyzer(api_key=api_key)

with open(r"tests/contracts/edge_cases/engine-limits.pact", "r") as f:
    source = f.read()

f1 = Finding(rule_id="R-005", title="Test", severity=Severity.CRITICAL, location=Location("m", "f", 1), issue="issue", risk="risk", recommendation="rec")

findings_json = json.dumps([{"rule_id": f1.rule_id, "title": f1.title, "severity": f1.severity.value, "location": f1.location.to_dict(), "issue": f1.issue, "risk": f1.risk}], indent=2)

prompt = ENRICHMENT_PROMPT.format(contract_code=source, findings_json=findings_json)
print("Sending prompt...")
raw = analyzer._call(prompt, 120)

with open("raw_out.txt", "w", encoding="utf-8") as f:
    f.write(raw)

res = analyzer._parse(raw)
with open("parse_res.txt", "w", encoding="utf-8") as f:
    f.write(str(res))
print("Done. Check parse_res.txt and raw_out.txt")
