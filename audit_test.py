import sys, os, json
from src.core.analyzer import PactGuard

contract = """
(module vulnerable-defi 'admin-keyset

  (defschema account
    balance:decimal
    guard:guard)

  (deftable accounts:{account})

  (defcap GOVERNANCE ()
    (enforce-guard (read-keyset "admin")))

  (defcap INTERNAL () true)

  (defun init (admin:guard)
    (insert accounts "admin" { "balance": 1000000.0, "guard": admin }))

  (defun transfer (from:string to:string amount:decimal)
    (let ((b (at 'balance (read accounts from))))
      (update accounts from { "balance": (- b amount) })
      (update accounts to { "balance": (+ (at 'balance (read accounts to)) amount) })
      (enforce (>= b amount) "Insufficient balance")
    )
  )

  (defun withdraw (user:string amount:decimal)
    (with-capability (INTERNAL)
      (update accounts user { "balance": 0.0 })
      (enforce (> amount 0.0) "Invalid")
    )
  )

  (defun upgrade ()
    "Success"
  )
)
"""

# Initialize PactGuard (auto-detects keys)
sentinel = PactGuard(use_ai=True)

if not sentinel.ai.available:
    print("AI not available. Please set GEMINI_API_KEY.")
    sys.exit(1)

print("Starting expert security analysis...")
result = sentinel.analyze_source(contract)

print("\n--- EXECUTIVE SUMMARY ---\n")
print(result.summary)

print("\n--- ENRICHED FINDINGS ---\n")
print(json.dumps(result.report, indent=2))
