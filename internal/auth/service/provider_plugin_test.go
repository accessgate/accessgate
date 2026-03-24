package service

import (
	"github.com/ArmanAvanesyan/accessgate/internal/plugin"
)

// mockProvider is defined in service_test.go; it must satisfy the provider plugin contract.
var _ plugin.ProviderPlugin = (*mockProvider)(nil)
