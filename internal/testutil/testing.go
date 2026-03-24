package testutil

import (
	"time"

	"github.com/ArmanAvanesyan/accessgate/pkg/token"
)

// NewTestPrincipal creates a minimal Principal for use in tests.
func NewTestPrincipal(subject string) *token.Principal {
	return &token.Principal{
		Subject:   subject,
		Scopes:    []string{},
		Roles:     []string{},
		Claims:    map[string]any{},
		ExpiresAt: time.Now().Add(time.Hour),
	}
}

// NewTestJWT returns a placeholder JWT string for tests.
func NewTestJWT(subject string) string {
	return "test-jwt-for-" + subject
}
