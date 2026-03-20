;;  =============================================================
;;  vulnerable-defi.pact
;;  A deliberately vulnerable DeFi token contract.
;;  DO NOT DEPLOY — For security testing purposes only.
;;  Contains: 8 intentional vulnerabilities.
;;  =============================================================

(define-keyset 'admin "admin")  ;; VULN: hardcoded admin string

(module vulnerable-defi-token 'admin
  "A vulnerable DeFi token with multiple security issues."

  (defschema account-schema
    balance:decimal
    guard:guard)

  (defschema config-schema
    total-supply:decimal
    paused:bool)

  (deftable accounts:{account-schema})
  (deftable config:{config-schema})

  ;; VULN R-005: Empty capability — grants nothing meaningful
  (defcap TRANSFER (sender:string receiver:string amount:decimal)
    "Transfer capability — completely unprotected!"
  )

  ;; VULN R-012: Transfer cap with no @managed annotation
  ;; allows same authorization used multiple times = double-spend
  (defcap DEBIT (sender:string amount:decimal)
    (enforce (> amount 0.0) "Amount must be positive")
    ;; Missing: (enforce-guard (at 'guard (read accounts sender)))
    ;; Missing: @managed amount DEBIT-mgr
  )

  (defcap CREDIT (receiver:string amount:decimal)
    ;; Intentionally empty — any account can be credited
  )

  ;; VULN R-007: Admin init with NO protection at all
  (defun init (initial-supply:decimal)
    "Initialize the token — callable by ANYONE"
    (insert config "global"
      { 'total-supply: initial-supply
      , 'paused: false })
  )

  ;; VULN R-001 + R-006: Public transfer with:
  ;;   (a) no capability guard
  ;;   (b) state mutation before auth check (CEI violation)
  (defun transfer (sender:string receiver:string amount:decimal)
    "Transfer tokens — completely unguarded"
    ;; WRONG: state mutations happen BEFORE any checks
    (with-read accounts sender { 'balance := old-sender-bal }
      (with-read accounts receiver { 'balance := old-receiver-bal }
        ;; MUTATION BEFORE CHECK!
        (update accounts sender { 'balance: (- old-sender-bal amount) })
        (update accounts receiver { 'balance: (+ old-receiver-bal amount) })
        ;; Auth check comes AFTER state change — too late!
        (enforce (>= old-sender-bal amount) "Insufficient funds")
        (enforce (!= sender receiver) "Cannot transfer to self")
      ))
  )

  ;; VULN R-004: Public function directly mutating balance table
  ;; with no capability protection
  (defun mint (account:string amount:decimal)
    "Mint new tokens — anyone can call this!"
    (with-read accounts account { 'balance := current }
      (update accounts account { 'balance: (+ current amount) }))
    (with-read config "global" { 'total-supply := supply }
      (update config "global" { 'total-supply: (+ supply amount) }))
  )

  ;; VULN R-007: Admin function with zero protection
  (defun pause ()
    "Pause the contract — no auth check!"
    (update config "global" { 'paused: true })
  )

  (defun unpause ()
    "Unpause — also no auth check"
    (update config "global" { 'paused: false })
  )

  ;; VULN R-010: Unguarded account creation
  (defun create-account (account:string guard:guard initial:decimal)
    "Create an account — no governance check on initial balance"
    (insert accounts account
      { 'balance: initial  ;; can be seeded with arbitrary amount!
      , 'guard: guard })
  )

  ;; VULN R-009: Weak guard — accepts user-supplied guard function directly
  (defun update-guard (account:string new-guard:guard)
    "Update account guard — no old guard verification!"
    ;; Missing: (enforce-guard (at 'guard (read accounts account)))
    (update accounts account { 'guard: new-guard })
  )

  ;; Reads — not vulnerable but included for context
  (defun get-balance (account:string)
    (at 'balance (read accounts account)))

  (defun get-supply ()
    (at 'total-supply (read config "global")))
)
