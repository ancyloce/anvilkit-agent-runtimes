package runtime

import (
	"net/http"
	"time"
)

// boundedClient is the HTTP client every controlled exchange leaves the
// process through: bounded in time, and never following a redirect.
//
// A unit's outbound requests carry the task-scoped credential and, on the
// artifact path, the candidate it produced. A client that followed a 307 or
// 308 would deliver both, body intact, wherever the control plane's answer
// pointed — and the only destination a unit may reach is the origin it was
// released with, resolved before any request is made. A redirect is therefore
// not followed; it is read as a status, and every caller treats a status that
// is not the one it expects as a refusal.
func boundedClient(timeout time.Duration) *http.Client {
	return &http.Client{
		Timeout: timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}
