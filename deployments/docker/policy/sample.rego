# Sample AccessGate policy for the local docker-compose quickstart.
#
# Contract (see internal/policy/rego.go):
#   - Must declare `package accessgate`.
#   - The proxy evaluates the query `data.accessgate.decision`.
#   - `decision` must be an object shaped like:
#       { "allow": bool, "status_code": number, "reason": string,
#         "headers": {string: string}, "obligations": {…} }
#
# The policy input is the normalized request. Field names are the Go struct
# field names from internal/policy.Input (note: capitalized, no json tags), so
# you reference `input.Path`, `input.Method`, `input.Principal`, etc.
#
# The proxy serves requests under PROXY_PATH_PREFIX (=/anything in the
# quickstart compose) and forwards the FULL request path to the upstream
# (httpbin), which echoes any /anything/* path with 200. This sample
# demonstrates BOTH an allow and a deny by path so the quickstart shows a 200
# and a 403 through the proxy with no IdP login required:
#
#   GET /anything/allow  -> ALLOW (proxied to httpbin, returns 200)
#   GET /anything/deny   -> DENY  (proxy short-circuits with 403)
#   anything else        -> DENY  (deny-by-default; safe posture)
package accessgate

import rego.v1

# Deny by default; only explicitly-allowed paths pass. Everything not matched
# below (including /anything/deny and any other path) is denied with 403.
default allow := false

# Allow exactly the demo "allow" path.
allow if input.Path == "/anything/allow"

# decision is what the proxy reads. Build it from `allow`.
decision := {
	"allow": true,
	"status_code": 200,
	"reason": "",
	"headers": {},
	"obligations": {},
} if {
	allow
} else := {
	"allow": false,
	"status_code": 403,
	"reason": "denied by sample policy",
	"headers": {},
	"obligations": {},
}
