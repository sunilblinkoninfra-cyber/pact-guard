(module edge-cases GOVERNANCE
  (defcap GOVERNANCE ()
    (enforce-keyset "admin-keyset"))

  (defschema state-schema val:integer)
  (deftable state-table:{state-schema})

  ;; ---------------------------------------------------------
  ;; EDGE CASE 1: Indirect Table Mutation via Call Graph
  ;; A public function with no capability calls a private 
  ;; helper function that mutates state. Does Sentinel map this?
  ;; ---------------------------------------------------------
  (defun public-indirect-mutator (id:string new-val:integer)
    "Should trigger R-004 (Public Function Modifies State)"
    (private-mutator id new-val)
  )

  (defun private-mutator (id:string new-val:integer)
    (require-capability (GOVERNANCE)) ;; Developer thought this protected it
    (update state-table id { 'val: new-val })
  )

  ;; ---------------------------------------------------------
  ;; EDGE CASE 2: Multi-step Defpact with missing 'rollback'
  ;; Complex cross-chain logic without failure safety.
  ;; ---------------------------------------------------------
  (defpact unsafe-cross-chain-swap (sender:string receiver:string amount:decimal)
    "Should trigger R-008 (Unsafe Multi-Step Pact Logic)"
    (step
      (with-capability (GOVERNANCE)
        (update state-table sender { 'val: 0 })
      )
      ;; MISSING 'rollback' block! If step 2 fails, state is trapped.
    )
    (step
      (update state-table receiver { 'val: 100 })
    )
  )

  ;; ---------------------------------------------------------
  ;; EDGE CASE 3: Capability Composition Reentrancy
  ;; Capability composition allows acquiring one cap to automatically 
  ;; acquire another, but what if the inner cap is empty?
  ;; ---------------------------------------------------------
  (defcap OUTER-CAP ()
    @doc "Outer capability"
    (compose-capability (INNER-CAP))
  )

  (defcap INNER-CAP ()
    @doc "Inner empty capability"
    ;; Should trigger R-005 (Empty capability) and R-011 (Composition Reentrancy)
  )

  ;; ---------------------------------------------------------
  ;; EDGE CASE 4: Weak Guard logic
  ;; Creating a guard that always returns true
  ;; ---------------------------------------------------------
  (defun create-dummy-guard ()
    "Should trigger R-009 (Weak or Bypassable Guard)"
    (create-user-guard (constantly-true))
  )

  (defun constantly-true () true)

)
