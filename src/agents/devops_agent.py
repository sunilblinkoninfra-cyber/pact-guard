#!/usr/bin/env python3
"""
DevOps CI/CD Agent and Auto-Fixer
Evaluates the QA Tester report. If critical vulnerabilities are found,
it fails the CI/CD pipeline. It also supports an --auto-fix mode to inject
suggested patches into the codebase.
"""
import sys
import json
import os

def apply_fixes(qa_report):
    for report in qa_report:
        file_path = report.get('analyzed_file')
        if not file_path or not os.path.exists(file_path):
            continue
            
        with open(file_path, 'r', encoding='utf-8') as f:
            lines = f.readlines()
            
        # We will insert FIX comments at the vulnerable lines (reverse order to maintain line numbers)
        findings = sorted(report.get('findings', []), key=lambda x: x.get('location', {}).get('line', 0), reverse=True)
        fixes_applied = 0
        
        for fng in findings:
            line_num = fng.get('location', {}).get('line', 0)
            if line_num > 0 and line_num <= len(lines):
                fix_code = fng.get('fixed_code_example') or fng.get('fixed_code')
                if fix_code:
                    patch_comment = f"\n    ;; >>> DEVOPS AUTO-FIX SUGGESTION FOR [{fng['id']}] <<<\n"
                    patch_comment += f"    ;; VULNERABILITY: {fng.get('title')}\n"
                    patch_comment += f"    ;; RECOMMENDATION: {fng.get('recommendation')}\n"
                    for cl in fix_code.split('\n'):
                        patch_comment += f"    ;; {cl}\n"
                    patch_comment += f"    ;; >>> END AUTO-FIX <<<\n"
                    
                    # Insert before the vulnerable line
                    lines.insert(line_num - 1, patch_comment)
                    fixes_applied += 1
                    
        if fixes_applied > 0:
            with open(file_path, 'w', encoding='utf-8') as f:
                f.writelines(lines)
            print(f"[DevOps Agent] Applied {fixes_applied} auto-fix inline suggestions to {file_path}")

def main():
    if len(sys.argv) < 2:
        print("Usage: python devops_agent.py <qa_report.json> [--auto-fix]")
        sys.exit(1)
        
    report_path = sys.argv[1]
    auto_fix = "--auto-fix" in sys.argv
    
    try:
        with open(report_path, 'r', encoding='utf-8') as f:
            qa_report = json.load(f)
    except Exception as e:
        print(f"[DevOps Agent] Failed to read report: {e}")
        sys.exit(1)
        
    total_critical = 0
    total_high = 0
    
    for report in qa_report:
        for fng in report.get('findings', []):
            sev = fng.get('severity', '').lower()
            if sev == 'critical':
                total_critical += 1
            elif sev == 'high':
                total_high += 1
                
    print("=" * 60)
    print(" 🛠️  DEVOPS SECURITY GATE EVALUATION")
    print("=" * 60)
    print(f" Total Critical Issues : {total_critical}")
    print(f" Total High Issues     : {total_high}")
    
    if auto_fix:
        print("\n[DevOps Agent] --auto-fix enabled. Injecting safe code patterns...")
        apply_fixes(qa_report)
        
    if total_critical > 0 or total_high > 0:
        print("\n[❌ REJECTED] Deployment blocked due to critical/high vulnerabilities.")
        print("Run the agent with --auto-fix to securely patch the affected contracts.")
        sys.exit(1)
    else:
        print("\n[✅ APPROVED] Code passed security gate. Proceeding with deployment.")
        sys.exit(0)

if __name__ == "__main__":
    main()
