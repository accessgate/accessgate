package plugin

import (
	"context"
	"errors"
	"fmt"
)

// Factory constructs a plugin instance for the given descriptor.
type Factory func(ctx context.Context, descriptor PluginDescriptor) (Plugin, error)

// Registration represents a registered plugin implementation and its runtime state.
type Registration struct {
	Descriptor PluginDescriptor
	Factory    Factory

	Enabled bool

	State PluginState
	Error error
}

// Registry holds registered plugins and provides resolution and lifecycle helpers.
type Registry struct {
	byID          map[PluginID]*Registration
	byCapability  map[Capability][]*Registration
	dependencies  map[PluginID][]Capability
	dependents    map[PluginID][]PluginID
	sortedStartup []PluginID
}

// New creates an empty Registry.
func New() *Registry {
	return &Registry{
		byID:         make(map[PluginID]*Registration),
		byCapability: make(map[Capability][]*Registration),
		dependencies: make(map[PluginID][]Capability),
		dependents:   make(map[PluginID][]PluginID),
	}
}

var (
	// ErrAlreadyRegistered is returned when attempting to register a plugin with a duplicate ID.
	ErrAlreadyRegistered = errors.New("plugin: already registered")
	// ErrUnknownPlugin is returned when a referenced plugin is not known to the registry.
	ErrUnknownPlugin = errors.New("plugin: unknown plugin")
	// ErrDependencyCycle is returned when plugin dependencies contain a cycle.
	ErrDependencyCycle = errors.New("plugin: dependency cycle")
)

// Register adds a plugin descriptor and factory to the registry.
// Call BuildDependencyGraph after all registrations are complete.
func (r *Registry) Register(descriptor PluginDescriptor, factory Factory) error {
	if _, ok := r.byID[descriptor.ID]; ok {
		return fmt.Errorf("%w: %s", ErrAlreadyRegistered, descriptor.ID)
	}
	reg := &Registration{
		Descriptor: descriptor,
		Factory:    factory,
		Enabled:    true,
		State:      PluginStateRegistered,
	}
	r.byID[descriptor.ID] = reg
	for _, cap := range descriptor.Capabilities {
		r.byCapability[cap] = append(r.byCapability[cap], reg)
	}
	if len(descriptor.DependsOn) > 0 {
		r.dependencies[descriptor.ID] = append([]Capability(nil), descriptor.DependsOn...)
	}
	return nil
}

// Enable marks the plugin with the given ID as enabled.
func (r *Registry) Enable(id PluginID) error {
	reg, ok := r.byID[id]
	if !ok {
		return fmt.Errorf("%w: %s", ErrUnknownPlugin, id)
	}
	reg.Enabled = true
	return nil
}

// Disable marks the plugin with the given ID as disabled.
func (r *Registry) Disable(id PluginID) error {
	reg, ok := r.byID[id]
	if !ok {
		return fmt.Errorf("%w: %s", ErrUnknownPlugin, id)
	}
	reg.Enabled = false
	return nil
}

// ResolveByCapability returns all enabled plugins that provide the given capability.
func (r *Registry) ResolveByCapability(cap Capability) []PluginDescriptor {
	regs := r.byCapability[cap]
	out := make([]PluginDescriptor, 0, len(regs))
	for _, reg := range regs {
		if reg.Enabled {
			out = append(out, reg.Descriptor)
		}
	}
	return out
}

// ResolveAllByKind returns all enabled plugins for the given kind.
func (r *Registry) ResolveAllByKind(kind PluginKind) []PluginDescriptor {
	out := make([]PluginDescriptor, 0, len(r.byID))
	for _, reg := range r.byID {
		if reg.Enabled && reg.Descriptor.Kind == kind {
			out = append(out, reg.Descriptor)
		}
	}
	return out
}

// BuildDependencyGraph validates plugin dependencies and computes an ordered startup list.
// Dependencies are expressed in terms of capabilities; this resolves them to concrete plugins.
func (r *Registry) BuildDependencyGraph() error {
	// Build dependents mapping by resolving capability dependencies to concrete plugin IDs.
	for id, caps := range r.dependencies {
		for _, cap := range caps {
			deps := r.byCapability[cap]
			if len(deps) == 0 {
				return fmt.Errorf("plugin: plugin %s depends on capability %s with no providers", id, cap)
			}
			for _, reg := range deps {
				r.dependents[reg.Descriptor.ID] = append(r.dependents[reg.Descriptor.ID], id)
			}
		}
	}

	// Kahn's algorithm: inDegree[id] = number of providers (edges) that id depends on.
	inDegree := make(map[PluginID]int)
	for id := range r.byID {
		inDegree[id] = 0
	}
	for id, caps := range r.dependencies {
		for _, cap := range caps {
			inDegree[id] += len(r.byCapability[cap])
		}
	}

	queue := make([]PluginID, 0, len(inDegree))
	for id, deg := range inDegree {
		if deg == 0 {
			queue = append(queue, id)
		}
	}

	var order []PluginID
	for len(queue) > 0 {
		id := queue[0]
		queue = queue[1:]
		order = append(order, id)
		for _, depID := range r.dependents[id] {
			inDegree[depID]--
			if inDegree[depID] == 0 {
				queue = append(queue, depID)
			}
		}
	}

	if len(order) != len(r.byID) {
		return ErrDependencyCycle
	}
	r.sortedStartup = order
	return nil
}

// StartupOrder returns the plugin IDs in dependency-respecting startup order.
// Call BuildDependencyGraph first. Returns empty if BuildDependencyGraph was not called.
func (r *Registry) StartupOrder() []PluginID {
	out := make([]PluginID, len(r.sortedStartup))
	copy(out, r.sortedStartup)
	return out
}

// AllPluginIDs returns all registered plugin IDs in no particular order.
func (r *Registry) AllPluginIDs() []PluginID {
	ids := make([]PluginID, 0, len(r.byID))
	for id := range r.byID {
		ids = append(ids, id)
	}
	return ids
}

// RegistrationFor returns the registration for a given ID, if present.
func (r *Registry) RegistrationFor(id PluginID) (*Registration, bool) {
	reg, ok := r.byID[id]
	return reg, ok
}
