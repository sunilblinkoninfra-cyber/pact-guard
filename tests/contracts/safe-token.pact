;;  =============================================================
;;  safe-token.pact — Secure reference implementation
;;  Demonstrates correct Pact security patterns.
;;  All capability guards, @managed, enforce ordering are correct.
;;  Expected result: 0 findings, Grade A+
;;  =============================================================

(namespace 'free)
(define-keyset 'free.admin-ks (read-keyset "admin-keyset"))

(module safe-token GOVERNANCE
  @doc "Secure fungible token following all Pact best practices."

  ;; ── Governance ──────────────────────────────────────────────
  (defcap GOVERNANCE ()
    @doc "Module governance — requires admin keyset to upgrade"
    (enforce-guard (keyset-ref-guard 'free.admin-ks)))

  ;; ── Managed transfer capability ─────────────────────────────
  (defcap TRANSFER (sender:string receiver:string amount:decimal)
    @doc "Transfer capability — managed to prevent double-spend"
    @managed amount TRANSFER-mgr
    (enforce-guard (at 'guard (read accounts sender)))
    (enforce (> amount 0.0) "Amount must be positive")
    (enforce (!= sender receiver) "Cannot self-transfer"))

  (defun TRANSFER-mgr:decimal (managed:decimal requested:decimal)
    @doc "Manager function — enforces amount constraint"
    (enforce (>= managed requested) "Exceeds authorized transfer amount")
    (- managed requested))

  ;; ── DEBIT / CREDIT capabilities ─────────────────────────────
  (defcap DEBIT (sender:string amount:decimal)
    @doc "Debit capability for internal accounting"
    @managed amount DEBIT-mgr
    (enforce-guard (at 'guard (read accounts sender))))

  (defun DEBIT-mgr:decimal (m:decimal r:decimal)
    (enforce (>= m r) "Exceeds debit authorization")
    (- m r))

  (defcap CREDIT (receiver:string amount:decimal)
    @doc "Credit capability — @event for auditability"
    @event
    (enforce (!= receiver "") "Receiver cannot be empty"))

  ;; ── Schema ──────────────────────────────────────────────────
  (defschema account-schema
    @doc "Account record with balance and ownership guard"
    balance:decimal
    guard:guard)

  (deftable accounts:{account-schema})

  ;; ── Account management ──────────────────────────────────────
  (defun create-account:string (account:string guard:guard)
    @doc "Create a new zero-balance account"
    (enforce (!= account "") "Account name cannot be empty")
    (enforce (= (typeof guard) "guard") "Invalid guard type")
    (insert accounts account
      { 'balance: 0.0
      , 'guard:   guard })
    (format "Account {} created" [account]))

  (defun fund-account (account:string amount:decimal)
    @doc "Fund an existing account — governance protected"
    ;; CHECKS first
    (enforce (> amount 0.0) "Amount must be positive")
    ;; EFFECTS under capability
    (with-capability (GOVERNANCE)
      (with-read accounts account { 'balance := current }
        (update accounts account { 'balance: (+ current amount) }))))

  ;; ── Transfer ────────────────────────────────────────────────
  (defun transfer:string (sender:string receiver:string amount:decimal)
    @doc "Transfer tokens between accounts with full protection"
    ;; 1. CHECKS — all validation before any state change
    (enforce (!= sender receiver) "Cannot self-transfer")
    (enforce (> amount 0.0) "Amount must be positive")
    ;; 2. EFFECTS — all mutations inside capability scope
    (with-capability (TRANSFER sender receiver amount)
      (with-read accounts sender { 'balance := sender-bal }
        (enforce (>= sender-bal amount) "Insufficient balance")
        (update accounts sender { 'balance: (- sender-bal amount) }))
      (with-read accounts receiver { 'balance := receiver-bal }
        (update accounts receiver { 'balance: (+ receiver-bal amount) })))
    (format "Transferred {}{} from {} to {}" [amount, " tokens", sender, receiver]))

  (defun transfer-create:string
    ( sender:string
      receiver:string
      receiver-guard:guard
      amount:decimal )
    @doc "Transfer to a new account, creating it if necessary"
    (enforce (!= sender receiver) "Cannot self-transfer")
    (enforce (> amount 0.0) "Amount must be positive")
    (with-capability (TRANSFER sender receiver amount)
      (with-read accounts sender { 'balance := sender-bal }
        (enforce (>= sender-bal amount) "Insufficient balance")
        (update accounts sender { 'balance: (- sender-bal amount) }))
      ;; Create receiver if needed
      (with-default-read accounts receiver
        { 'balance: -1.0, 'guard: receiver-guard }
        { 'balance := recv-bal, 'guard := _ }
        (if (= recv-bal -1.0)
          (insert accounts receiver { 'balance: amount, 'guard: receiver-guard })
          (update accounts receiver { 'balance: (+ recv-bal amount) })))))

  ;; ── Read functions ──────────────────────────────────────────
  (defun get-balance:decimal (account:string)
    @doc "Read account balance — public"
    (at 'balance (read accounts account)))

  (defun get-details:object{account-schema} (account:string)
    @doc "Read full account details"
    (read accounts account))

  (defun account-exists:bool (account:string)
    @doc "Check if account exists"
    (with-default-read accounts account
      { 'balance: -1.0, 'guard: (keyset-ref-guard 'free.admin-ks) }
      { 'balance := bal }
      (!= bal -1.0)))
)
