package register

import (
	"context"

	"github.com/ArmanAvanesyan/accessgate/internal/plugin"
	provideroidc "github.com/ArmanAvanesyan/accessgate/internal/plugins/oidcprovider"
	"github.com/ArmanAvanesyan/accessgate/internal/plugins/ratelimit"
)

// Registrar registers built-in plugins that are compiled into the binary.
// It is used by cmd/* before manifest discovery and before runtime execution.
type Registrar struct{}

var _ plugin.BuiltinRegistrar = (*Registrar)(nil)

func (r *Registrar) RegisterBuiltins(ctx context.Context, reg *plugin.Registry) error {
	// Pipeline: rate limit
	p := ratelimit.New()
	desc := p.Descriptor()
	if err := reg.Register(desc, func(ctx context.Context, _ plugin.PluginDescriptor) (plugin.Plugin, error) {
		return ratelimit.New(), nil
	}); err != nil {
		return err
	}

	// Provider: OIDC
	po := provideroidc.New()
	pdesc := po.Descriptor()
	return reg.Register(pdesc, func(ctx context.Context, _ plugin.PluginDescriptor) (plugin.Plugin, error) {
		return provideroidc.New(), nil
	})
}
