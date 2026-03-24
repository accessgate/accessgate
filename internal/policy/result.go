package policy

// Decision is the result of evaluating a policy against an input.
type Decision struct {
	Allow       bool
	StatusCode  int
	Headers     map[string]string
	Reason      string
	Obligations map[string]any // Optional obligations (e.g. "set_header_X": "value") from policy.
}
