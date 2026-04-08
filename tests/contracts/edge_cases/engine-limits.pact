(module engine-limits GOVERNANCE
  "Testing Sentinel's control-flow and cross-module tracking boundaries."

  (defcap GOVERNANCE ()
    @doc "Valid capability structure to prevent initial flagged errors"
    (enforce-keyset "admin-keyset"))

  (defschema secure-ledger
    balance:decimal)
  (deftable ledger:{secure-ledger})

  ;; ---------------------------------------------------------
  ;; LIMIT TEST 1: Control-Flow Deception (False Negative)
  ;; The developer placed `enforce-guard` inside an unreachable `if`.
  ;; Will Sentinel flag this as protected just because the token exists
  ;; structurally in the AST, even though it's logically dead code?
  ;; ---------------------------------------------------------
  (defcap DEAD-CODE-CAP (account:string)
    @doc "Guard is present in AST but unreachable at runtime"
    (if false
        (enforce-guard (at 'guard (read accounts account)))
        true)
  )

  (defun deceive-control-flow (acc:string)
    "Should trigger R-001 (Mutation without capability) but might not if DEAD-CODE-CAP tricks it"
    (with-capability (DEAD-CODE-CAP acc)
      (update ledger acc { 'balance: 99999.0 }))
  )

  ;; ---------------------------------------------------------
  ;; LIMIT TEST 2: Cross-Module Reentrancy / Blindness
  ;; Sentinel works on a per-file basis. If we call an external 
  ;; module that has an unsafe state mutation, will Sentinel catch it?
  ;; ---------------------------------------------------------
  (defun call-external-module (user:string)
    "Sentinel cannot see into `free.other-module`. This is a strict limitation."
    (free.other-module.unsafe-write user 100.0)
  )

  ;; ---------------------------------------------------------
  ;; LIMIT TEST 3: Aliased Let-bindings (False Warning Bypass)
  ;; Directly updating a table is caught (R-001). What if we store the 
  ;; table reference in a `let` block or alias it?
  ;; ---------------------------------------------------------
  (defun let-alias-mutation (acc:string)
    "Testing if Sentinel tracks variable reassignment before mutation"
    (let ((target-table ledger))
      ;; If Sentinel only looks for explicit `(update ledger ...)`, 
      ;; this dynamic alias might bypass the R-001 rule!
      (update target-table acc { 'balance: 0.0 }))
  )

)
