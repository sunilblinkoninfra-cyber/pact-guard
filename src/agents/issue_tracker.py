#!/usr/bin/env python3
"""
Deployment Issue Tracker Agent
Parses the QA Tester report and automatically opens GitHub Issues
for newly discovered vulnerabilities.
"""
import sys
import json
import os
import urllib.request
import urllib.error

GITHUB_API_URL = "https://api.github.com/repos/{owner}/{repo}/issues"

def create_github_issue(token, owner, repo, issue_data):
    url = GITHUB_API_URL.format(owner=owner, repo=repo)
    req = urllib.request.Request(
        url,
        data=json.dumps(issue_data).encode(),
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github.v3+json",
            "Content-Type": "application/json"
        },
        method="POST"
    )
    try:
        with urllib.request.urlopen(req) as r:
            return json.loads(r.read())
    except urllib.error.HTTPError as e:
        print(f"[Issue Tracker] Error creating issue: {e}")
        try:
            print(e.read().decode())
        except Exception:
            pass
        return None

def main():
    if len(sys.argv) < 2:
        print("Usage: python src/agents/issue_tracker.py <qa_report.json>")
        sys.exit(1)
        
    report_path = sys.argv[1]
    
    try:
        with open(report_path, 'r', encoding='utf-8') as f:
            qa_report = json.load(f)
    except Exception as e:
        print(f"[Issue Tracker] Failed to read report {report_path}: {e}")
        sys.exit(1)
        
    github_token = os.environ.get("GITHUB_TOKEN")
    repo_slug = os.environ.get("GITHUB_REPOSITORY")  # e.g., "owner/repo"
    
    print("=" * 60)
    print(" 🐛 DEPLOYMENT ISSUE TRACKER")
    print("=" * 60)
    
    if not github_token or not repo_slug:
        print("[Issue Tracker] WARNING: GITHUB_TOKEN or GITHUB_REPOSITORY not found.")
        print("Running in DRY-RUN mode. Issues will only be printed, not created.\n")
        
    owner = repo_slug.split('/')[0] if repo_slug and '/' in repo_slug else "local-owner"
    repo = repo_slug.split('/')[1] if repo_slug and '/' in repo_slug else "local-repo"
    
    issues_created = 0
    
    for report in qa_report:
        file_path = report.get('analyzed_file', 'Unknown File')
        findings = report.get('findings', [])
        
        for fng in findings:
            sev = fng.get('severity', '').lower()
            if sev not in ['critical', 'high']:
                continue
                
            title = f"[{sev.upper()}] {fng.get('title')} in {os.path.basename(file_path)}"
            body = (
                f"### Vulnerability Profile\n"
                f"- **Rule ID:** {fng.get('rule_id')}\n"
                f"- **Severity:** {sev.upper()}\n"
                f"- **Location:** `{file_path}` : Line {fng.get('location', {}).get('line')}\n\n"
                f"### Issue Description\n"
                f"{fng.get('issue')}\n\n"
                f"### AI Risk Analysis\n"
                f"{fng.get('risk')}\n\n"
                f"### Recommendation\n"
                f"{fng.get('recommendation')}\n\n"
            )
            
            # Use 'fixed_code' or 'fixed_code_example' whichever is present from Gemini report
            auto_fix = fng.get('fixed_code_example') or fng.get('fixed_code')
            if auto_fix:
                body += f"### Gemini AI Auto-Fix Suggestion\n```pact\n{auto_fix}\n```\n"
                
            if github_token and repo_slug:
                issue_data = {
                    "title": title,
                    "body": body,
                    "labels": ["security", "bug", f"severity:{sev}"]
                }
                res = create_github_issue(github_token, owner, repo, issue_data)
                if res:
                    print(f"✅ Created Issue: {res.get('html_url')}")
                    issues_created += 1
            else:
                print(f"[DRY RUN] Issue Formulated: {title}")
                issues_created += 1

    print(f"\n[Issue Tracker] Processed {issues_created} actionable vulnerability reports.")

if __name__ == "__main__":
    main()
