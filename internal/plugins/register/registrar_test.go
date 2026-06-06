package register

import (
	"context"
	"testing"

	"github.com/accessgate/accessgate/internal/plugin"
)

func TestRegistrarRegisterBuiltins(t *testing.T) {
	reg := plugin.New()
	var r Registrar
	if err := r.RegisterBuiltins(context.Background(), reg); err != nil {
		t.Fatal(err)
	}
	if _, ok := reg.RegistrationFor(plugin.PluginID("provider:oidc")); !ok {
		t.Fatal("expected OIDC provider registered")
	}
}
