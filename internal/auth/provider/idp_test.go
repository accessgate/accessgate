package provider

import (
	"testing"

	"github.com/accessgate/accessgate/pkg/oidc"
)

func TestOIDCClientImplementsIdP(t *testing.T) {
	var _ IdP = (*oidc.Client)(nil)
}
