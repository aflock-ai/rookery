import CilockCi.Proofs
import CilockCi.Review
import CilockCi.Trust

/-! Axiom audit: every headline theorem must depend only on Lean's core
axioms (propext, Quot.sound, Classical.choice). No `sorry`, no
`native_decide`. `lake build` prints these; `jade check formal-cilock-ci`
fails when any of them names another axiom or when a theorem listed here
disappears. -/

open CilockCi

#print axioms select_sound
#print axioms forwarded_aud_exact
#print axioms forwarded_this_job
#print axioms explicit_respected
#print axioms keyless_needs_job_token
#print axioms keyless_job_has_token
#print axioms gitlab_github_parity
#print axioms route_kind_vendor_blind
#print axioms upload_aud_exact
#print axioms login_only_via_match
#print axioms gitlab_login_never_browser
#print axioms ci_login_never_browser
#print axioms held_uploads_unless_opted_out
#print axioms held_never_silent
#print axioms gate_refuses_silent_loss
#print axioms foreign_archivista_not_held
#print axioms gitlab_held_needs_archivista_token
#print axioms provider_is_ci
#print axioms gitlab_login_aud
#print axioms automode_ci_parity

-- jctl's reading of the platform's answer
#print axioms jctl_refuses_no_match
#print axioms jctl_session_only_via_match

-- gitlab-review exact-sha binding
#print axioms Review.counts_only_bound_sha
#print axioms Review.other_sha_not_counted
#print axioms Review.late_approval_not_counted
#print axioms Review.parent_sha_approval_fails
#print axioms Review.tie_unbound
