;;; ============================================================
;;; DEMO: Vulnerable Pact Contract
;;; This contract is INTENTIONALLY BROKEN for testing purposes.
;;; It violates multiple Pact security best-practices.
;;; DO NOT deploy this to any network.
;;; ============================================================

(define-keyset 'admin-keyset
  { "keys": ["aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899"]
  , "pred": "keys-any" })

(module vuln-token GOVERNANCE

  ;;-------------------------------------------------------------
  ;; GOVERNANCE — should use a proper capability, not a raw keyset
  ;;-------------------------------------------------------------
  (defcap GOVERNANCE ()
    ;; BUG R002: No enforce / enforce-guard inside this capability.
    ;; Anyone can call (with-capability (GOVERNANCE) ...) and it succeeds.
    true)

  ;;-------------------------------------------------------------
  ;; Schemas & tables
  ;;-------------------------------------------------------------
  (defschema account-schema
    balance:decimal
    guard:guard)

  (deftable accounts:{account-schema})

  (defschema config-schema
    paused:bool
    admin:string)

  (deftable config-table:{config-schema})

  ;;-------------------------------------------------------------
  ;; TRANSFER capability — weak, no enforce
  ;;-------------------------------------------------------------
  (defcap TRANSFER (sender:string receiver:string amount:decimal)
    ;; BUG R002: This cap checks nothing!
    (enforce (> amount 0.0) "Amount must be positive"))

  ;;-------------------------------------------------------------
  ;; ADMIN capability — empty body
  ;;-------------------------------------------------------------
  (defcap ADMIN ()
    ;; BUG R002: Completely empty — no guard check.
    )

  ;;-------------------------------------------------------------
  ;; init — public, no auth, writes to config-table
  ;;-------------------------------------------------------------
  (defun init (admin:string)
    "Initialise the token contract."
    ;; BUG R001 + R004: state mutation without any capability guard.
    (insert config-table "config"
      { 'paused: false
      , 'admin: admin }))

  ;;-------------------------------------------------------------
  ;; create-account — sensitive name, no auth at all
  ;;-------------------------------------------------------------
  (defun create-account (account:string guard:guard)
    "Create a new account."
    ;; BUG R005: function named 'create-account' but no enforce/guard.
    ;; BUG R001: direct insert with zero protection.
    (insert accounts account
      { 'balance: 0.0
      , 'guard: guard }))

  ;;-------------------------------------------------------------
  ;; transfer — state mutation BEFORE auth check (ordering bug)
  ;;-------------------------------------------------------------
  (defun transfer (sender:string receiver:string amount:decimal)
    "Transfer tokens between accounts."
    ;; BUG R006: update (state mutation) happens BEFORE the capability check.
    (update accounts sender
      { 'balance: (- (at 'balance (read accounts sender)) amount) })
    ;; Auth check comes TOO LATE — after the state has already changed.
    (with-capability (TRANSFER sender receiver amount)
      (update accounts receiver
        { 'balance: (+ (at 'balance (read accounts receiver)) amount) })))

  ;;-------------------------------------------------------------
  ;; admin-pause — sensitive admin function, entire body in with-capability
  ;;-------------------------------------------------------------
  (defun admin-pause ()
    "Pause the contract."
    ;; BUG R007: with-capability wraps the ENTIRE function body.
    (with-capability (ADMIN)
      (let ((cfg (read config-table "config")))
        (update config-table "config"
          { 'paused: true }))))

  ;;-------------------------------------------------------------
  ;; withdraw — public, calls a mutating function, no outer guard
  ;;-------------------------------------------------------------
  (defun do-withdraw (account:string amount:decimal)
    "Internal withdraw helper."
    (update accounts account
      { 'balance: (- (at 'balance (read accounts account)) amount) }))

  (defun withdraw (account:string amount:decimal)
    "Anyone can call this to withdraw from any account."
    ;; BUG R004: withdraw calls do-withdraw (mutating) with no auth.
    (do-withdraw account amount))

  ;;-------------------------------------------------------------
  ;; rotate-admin — sensitive but completely unguarded
  ;;-------------------------------------------------------------
  (defun rotate-admin (new-admin:string)
    "Rotate the admin key."
    ;; BUG R005: 'rotate' is a sensitive name with zero enforcement.
    (update config-table "config"
      { 'admin: new-admin }))

  ;;-------------------------------------------------------------
  ;; cross-chain pact — no rollback handlers
  ;;-------------------------------------------------------------
  (defpact cross-chain-transfer (sender:string target-chain:string amount:decimal)
    "Cross-chain token transfer via pact."
    ;; BUG R009: step has no rollback — if step 2 fails, debit is permanent.
    (step
      (update accounts sender
        { 'balance: (- (at 'balance (read accounts sender)) amount) }))
    (step
      (let ((receiver (read-msg 'receiver)))
        (insert accounts receiver
          { 'balance: amount
          , 'guard: (read-keyset 'receiver-guard) }))))
)
