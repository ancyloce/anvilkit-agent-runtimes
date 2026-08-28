package runtime

import "regexp"

// DelegationFailedError reports that the Specialist a Manager delegated to did
// not produce its outcome: the delegated attempt failed, under the governed
// reason the control plane recorded against it. It is a failure of the
// Manager's turn, not a refusal — the pinned policy did not decline the work,
// the work did not get done — so the host reports it with the failed status
// and the Specialist's own reason, which is what lets the control plane decide
// whether the work is tried again.
type DelegationFailedError struct{ ReasonCode string }

func (e *DelegationFailedError) Error() string {
	return "delegation failed: " + e.ReasonCode
}

// governedReasonPattern is the shape every governed reason code has. A reason
// that does not fit it is not one the control plane can branch on.
var governedReasonPattern = regexp.MustCompile(`^[A-Z][A-Z0-9_]{2,63}$`)

// governedReason returns the reason as recorded when it is a governed code,
// and the internal-error reason otherwise: a result must never carry a reason
// outside the governed vocabulary, whatever was written into a brief.
func governedReason(reason string) string {
	if governedReasonPattern.MatchString(reason) {
		return reason
	}
	return "RUNTIME_INTERNAL_ERROR"
}
