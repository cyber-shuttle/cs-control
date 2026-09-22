// Principal is the identity the OAuth boundary resolves and every subsystem scopes state by. It travels in the
// request context rather than in request or state structs. Shared name predicates also live here because callers
// validate identities and protected path segments without owning a common feature vocabulary.
package security

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"regexp"
)

var (
	safeNamePattern      = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]*$`)
	identityValuePattern = regexp.MustCompile(`^[A-Za-z0-9._:@/,-]{1,256}$`)
)

type Principal struct {
	Subject string `json:"subject"`
	Tenant  string `json:"tenant"`
}

type principalContextKey struct{}

func SafeName(value string, max int) bool {
	return len(value) > 0 && len(value) <= max && safeNamePattern.MatchString(value)
}

func ValidIdentityValue(value string) bool { return identityValuePattern.MatchString(value) }

func PrincipalDirName(principal Principal) string {
	sum := sha256.Sum256([]byte(principal.Subject + "\x00" + principal.Tenant))
	return hex.EncodeToString(sum[:16])
}

func WithPrincipal(ctx context.Context, principal Principal) context.Context {
	return context.WithValue(ctx, principalContextKey{}, principal)
}

func PrincipalFromContext(ctx context.Context) (Principal, error) {
	principal, ok := ctx.Value(principalContextKey{}).(Principal)
	if !ok || !ValidIdentityValue(principal.Subject) || !ValidIdentityValue(principal.Tenant) {
		return Principal{}, New("unauthorized", "an authenticated principal is required", http.StatusUnauthorized)
	}
	return principal, nil
}
