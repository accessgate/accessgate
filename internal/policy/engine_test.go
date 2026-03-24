package policy

// Compile-time: concrete engines satisfy Engine.
var _ Engine = (*WASMRuntime)(nil)
var _ Engine = (*RegoEngine)(nil)
