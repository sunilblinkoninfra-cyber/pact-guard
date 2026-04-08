import os
import json
import time
from src.core.analyzer import PactGuard

contracts = {
    "1. Missing Capability + Missing Enforce": """(module basic-vuln 'admin-keyset
  (defschema account
    balance:decimal)
  (deftable accounts:{account})
  (defun transfer (from:string to:string amount:decimal)
    (update accounts from { "balance": (- (at 'balance (read accounts from)) amount) })
    (update accounts to { "balance": (+ (at 'balance (read accounts to)) amount) })
  )
)""",

    "2. Incorrect Authorization Order": """(module bad-sequence 'admin-keyset
  (deftable accounts:{balance:decimal})
  (defun withdraw (user:string amount:decimal)
    (update accounts user { "balance": 0.0 })
    (enforce (> amount 0.0) "Invalid amount")
  )
)""",

    "3. Weak Guard": """(module weak-guard 'admin-keyset
  (defun secure-action ()
    (let ((guard (read-keyset "admin")))
      "No enforcement applied"
    )
  )
)""",

    "4. Hardcoded Admin Key": """(module hardcoded-key 'admin-keyset
  (defconst ADMIN "admin-key")
  (defun upgrade ()
    (if (= ADMIN "admin-key")
        (write config "version" "2.0")
    )
  )
)""",

    "5. Capability Misuse": """(module cap-misuse 'admin-keyset
  (defcap ADMIN ()
    true
  )
  (defun dangerous ()
    (with-capability (ADMIN)
      (write system "mode" "unsafe")
    )
  )
)""",

    "6. Public Critical Function": """(module public-critical 'admin-keyset
  (deftable config:{value:string})
  (defun set-config (key:string value:string)
    (write config key value)
  )
)""",

    "7. Multi-Step Pact Vulnerability": """(module multi-step 'admin-keyset
  (defpact transfer-pact (from to amount)
    (step
      (update accounts from { "balance": 0.0 })
    )
    (step
      (update accounts to { "balance": amount })
    )
  )
)""",

    "8. Conditional Logic Without Enforcement": """(module conditional-bug 'admin-keyset
  (defun risky (x:integer)
    (if (> x 10)
        (write logs "event" "high")
        (write logs "event" "low")
    )
  )
)""",

    "9. Partial Security": """(module partial-secure 'admin-keyset
  (defun semi-safe (user:string)
    (enforce (!= user "") "User required")
    (write accounts user { "balance": 100.0 })
  )
)""",

    "10. Safe Contract": """(module safe-contract 'admin-keyset
  (defcap ADMIN ()
    (enforce-keyset "admin-keyset")
  )
  (deftable accounts:{balance:decimal})
  (defun secure-transfer (from:string to:string amount:decimal)
    (with-capability (ADMIN)
      (enforce (> amount 0.0) "Invalid amount")
      (update accounts from { "balance": 0.0 })
      (update accounts to { "balance": amount })
    )
  )
)"""
}

def run_demo():
    print("Initializing PactGuard...")
    # Run with AI analysis to provide the best output
    sentinel = PactGuard(use_ai=True, gemini_key=os.environ.get("GEMINI_API_KEY"))
    
    artifact_path = r"C:\\Users\\kumar\\.gemini\\antigravity\\brain\\3d385ece-5d7d-449b-85d5-580cc1287669\\demo_results.md"
    
    with open(artifact_path, "w", encoding="utf-8") as out:
        out.write("# PactGuard Analysis on 10 Demo Contracts\\n\\n")
        
        for name, code in contracts.items():
            print(f"\\nAnalyzing '{name}'...")
            result = sentinel.analyze_source(code, filename=name)
            report = result.report
            
            score = report.get("overall_risk_score", 0)
            findings = report.get("findings", [])
            narrative = report.get("risk_narrative", "")
            
            critCount = sum(1 for f in findings if f.get("severity") == "critical")
            highCount = sum(1 for f in findings if f.get("severity") == "high")
            
            out.write(f"## {name}\\n")
            out.write(f"**Security Score:** {score}/100 | **Findings:** {len(findings)} ({critCount} C, {highCount} H)\\n\\n")
            if narrative:
                out.write(f"> **AI Risk Narrative:** {narrative}\\n\\n")
                
            if not findings:
                out.write("🏁 No vulnerabilities found.\\n\\n")
                out.write("---\\n\\n")
                continue
                
            for idx, f in enumerate(findings, 1):
                rule = f.get("rule_id", "Unknown")
                title = f.get("title", "Issue")
                sev = f.get("severity", "LOW").upper()
                issue = f.get("issue", "")
                rec = f.get("recommendation", "")
                ai_exp = f.get("ai_explanation", "")
                ai_fix = f.get("fixed_code_example", "")
                
                out.write(f"### [F-{idx:03d}] {title}\\n")
                out.write(f"- **Severity:** {sev}\\n")
                out.write(f"- **Rule ID:** {rule}\\n\\n")
                out.write(f"**Issue:** {issue}\\n\\n")
                if ai_exp:
                    out.write(f"**AI Context:** {ai_exp}\\n\\n")
                out.write(f"**Recommendation:** {rec}\\n\\n")
                if ai_fix:
                    out.write("**AI Suggested Fix:**\\n```pact\\n")
                    out.write(ai_fix.strip())
                    out.write("\\n```\\n\\n")
                    
            out.write("---\\n\\n")
            # Rate limiting for Gemini API stability
            time.sleep(3)

    print(f"Demo complete! View results at: {artifact_path}")

if __name__ == "__main__":
    run_demo()
