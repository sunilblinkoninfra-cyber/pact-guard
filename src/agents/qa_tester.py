#!/usr/bin/env python3
"""
QA Tester Agent
Runs the PactGuard core analysis engine on contracts and produces a structured
JSON report designed for the DevOps Agent to consume and automatically patch.
"""
import sys
import os
import json
from pathlib import Path

# Add project root to path so we can import src.core.analyzer
project_root = Path(__file__).parent.parent.parent
sys.path.insert(0, str(project_root))

try:
    from src.core.analyzer import PactGuard
except ImportError:
    print("Error: Could not import PactGuard. Are you running this from the project root?")
    sys.exit(1)

def main():
    if len(sys.argv) < 2:
        print("QA Tester Help:")
        print("Usage: python src/agents/qa_tester.py <path_to_file_or_directory>")
        sys.exit(1)
        
    target_path = sys.argv[1]
    
    # We require the Gemini API key to generate actionable fix metrics
    api_key = os.environ.get("GEMINI_API_KEY")
    if not api_key:
        print("\n[QA Tester WARNING]: GEMINI_API_KEY environment variable is missing.")
        print("AI enrichment (and thus auto-fix snippets) will be disabled in the report.\n")
        
    print(f"[QA Tester] Initializing Sentinel engine for target: {target_path} ...")
    
    sentinel = PactGuard(
        api_key=api_key,
        use_ai=bool(api_key),
        confidence_threshold=0.5
    )
    
    if os.path.isdir(target_path):
        results = sentinel.analyze_directory(target_path)
    else:
        results = [sentinel.analyze_file(target_path)]
        
    qa_report = []
    total_findings = 0
    critical_findings = 0
    high_findings = 0
    
    for r in results:
        # Extract dictionary payload
        report_data = r.report
        qa_report.append(report_data)
        
        findings = report_data.get('findings', [])
        total_findings += len(findings)
        
        for f in findings:
            if f['severity'] == "critical":
                critical_findings += 1
            elif f['severity'] == "high":
                high_findings += 1
                
    report_output_path = "qa_report.json"
    try:
        with open(report_output_path, "w", encoding="utf-8") as f:
            json.dump(qa_report, f, indent=2)
    except Exception as e:
        print(f"[QA Tester] Error writing report: {e}")
        sys.exit(1)
        
    print("-" * 50)
    print("QA TESTER REPORT SUMMARY")
    print("-" * 50)
    print(f"Total Files Analyzed : {len(results)}")
    print(f"Total Issues Found   : {total_findings}")
    print(f"  Critical           : {critical_findings}")
    print(f"  High               : {high_findings}")
    print("-" * 50)
    print(f"[QA Tester] Full findings saved to: {report_output_path}")
    
    if critical_findings > 0 or high_findings > 0:
        print("[QA Tester] High/Critical vulnerabilities found. Action is required.")
        # Exit code 1 signals a failure condition to CI/CD workflows
        sys.exit(1)
    else:
        print("[QA Tester] All contracts pass security policy. Ready for deployment!")
        sys.exit(0)

if __name__ == "__main__":
    main()
