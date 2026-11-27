package approval

import "context"

// Identity names an authenticated caller: the id of the token it used and
// the agent that token acts as. It carries no secret.
type Identity struct {
	TokenID string
	Agent   string
}

// IsZero reports whether the identity names nobody (no token, no agent).
func (i Identity) IsZero() bool { return i.TokenID == "" && i.Agent == "" }

type requesterKey struct{}

// WithRequester returns ctx carrying the identity of the caller that is
// about to ask for an approval. The server stores the authenticated
// principal here for every request, so Broker.Consult can pin the request
// to the token that made it (separation of duties: that same token can
// never approve it).
func WithRequester(ctx context.Context, id Identity) context.Context {
	return context.WithValue(ctx, requesterKey{}, id)
}

// RequesterFrom returns the identity stored by WithRequester.
func RequesterFrom(ctx context.Context) (Identity, bool) {
	id, ok := ctx.Value(requesterKey{}).(Identity)
	return id, ok
}

// Approver is the operator side of an Approve call: a display name plus the
// authenticated identity the decision is attributed to.
type Approver struct {
	// Name is the label recorded as Decision.DecidedBy (default "operator").
	Name string
	// Identity is the authenticated token the approval came with. Without
	// it the broker cannot prove separation of duties and refuses to
	// approve a request that has a known requester.
	Identity
}
