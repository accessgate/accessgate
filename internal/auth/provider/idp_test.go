package provider

import (
	"testing"

	"github.com/ArmanAvanesyan/accessgate/pkg/oidc"
)

func TestOIDCClientImplementsIdP(t *testing.T) {
	var _ IdP = (*oidc.Client)(nil)
}
