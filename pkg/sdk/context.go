package sdk

import (
	"strings"
	"time"

	"github.com/ArmanAvanesyan/accessgate/pkg/auth"
	pkgsession "github.com/ArmanAvanesyan/accessgate/pkg/session"
	"github.com/ArmanAvanesyan/accessgate/pkg/token"
	sdkv1 "github.com/ArmanAvanesyan/accessgate/proto/gen/go/accessgate/sdk/v1"
	"google.golang.org/protobuf/types/known/structpb"
)

// AuthContextFromSession builds the shared SDK auth context from a persisted session.
func AuthContextFromSession(sess *pkgsession.Session) (*sdkv1.AuthContext, error) {
	return AuthContextFromPrincipalAndSession(nil, sess)
}

// AuthContextFromPrincipalAndSession builds the shared SDK auth context from an explicit principal and session.
//
// If principal is nil and session is present, a principal is derived from the session claims.
func AuthContextFromPrincipalAndSession(principal *token.Principal, sess *pkgsession.Session) (*sdkv1.AuthContext, error) {
	if principal == nil && sess != nil {
		principal = principalFromSession(sess)
	}

	protoPrincipal, err := principalToProto(principal)
	if err != nil {
		return nil, err
	}
	protoSession, err := sessionToProto(sess)
	if err != nil {
		return nil, err
	}
	return &sdkv1.AuthContext{Principal: protoPrincipal, Session: protoSession}, nil
}

// SessionResponseFromAuthContext converts a shared SDK auth context into the JSON session response shape
// used by the auth runtime and server-side integrations.
func SessionResponseFromAuthContext(ctx *sdkv1.AuthContext) *auth.SessionResponse {
	if ctx == nil || (ctx.Principal == nil && ctx.Session == nil) {
		return &auth.SessionResponse{IsAuthenticated: false}
	}
	user := sessionUserFromAuthContext(ctx)
	if user == nil {
		return &auth.SessionResponse{IsAuthenticated: false}
	}
	return &auth.SessionResponse{IsAuthenticated: true, User: user}
}

// SessionUserFromSession exposes the auth runtime's session-user shape as a reusable SDK helper.
func SessionUserFromSession(sess *pkgsession.Session) *auth.SessionUser {
	if sess == nil {
		return nil
	}
	ctx, err := AuthContextFromSession(sess)
	if err != nil {
		return nil
	}
	resp := SessionResponseFromAuthContext(ctx)
	if resp == nil {
		return nil
	}
	return resp.User
}

func sessionUserFromAuthContext(ctx *sdkv1.AuthContext) *auth.SessionUser {
	if ctx == nil {
		return nil
	}
	principal := ctx.GetPrincipal()
	sess := ctx.GetSession()
	claims := structMap(principal.GetClaims())
	if len(claims) == 0 {
		claims = structMapFromSession(sess)
	}
	tenantContext := structMap(principal.GetTenantContext())
	if len(tenantContext) == 0 {
		tenantContext = structMapFromSessionTenant(sess)
	}
	roles := stringsFromAny(principal.GetRoles())
	if len(roles) == 0 {
		roles = rolesFromClaims(claims)
	}
	groups := groupsFromClaims(claims)
	user := &auth.SessionUser{
		Sub:               principal.GetSubject(),
		Email:             stringFromMap(claims, "email"),
		PreferredUsername: stringFromMap(claims, "preferred_username"),
		Name:              stringFromMap(claims, "name"),
		Roles:             roles,
		Groups:            groups,
		Claims:            cloneMap(claims),
	}
	if user.Sub == "" {
		user.Sub = stringFromMap(claims, "sub")
	}
	if len(tenantContext) > 0 {
		user.TenantContext = cloneMap(tenantContext)
	}
	for _, role := range user.Roles {
		if role == "admin" || role == "administrator" {
			user.IsAdmin = true
			break
		}
	}
	if user.Sub == "" && len(user.Claims) == 0 && len(user.Roles) == 0 && len(user.Groups) == 0 {
		return nil
	}
	return user
}

func principalFromSession(sess *pkgsession.Session) *token.Principal {
	if sess == nil {
		return nil
	}
	claims := cloneMap(sess.Claims)
	return &token.Principal{
		Subject:       stringFromMap(claims, "sub"),
		Scopes:        scopesFromClaims(claims),
		Roles:         rolesFromClaims(claims),
		Claims:        claims,
		ExpiresAt:     time.Unix(sess.ExpiresAt, 0),
		AccessToken:   sess.AccessToken,
		TenantContext: tenantContextToMap(sess.TenantContext),
	}
}

func principalToProto(principal *token.Principal) (*sdkv1.Principal, error) {
	if principal == nil {
		return nil, nil
	}
	claims, err := structpb.NewStruct(cloneMap(principal.Claims))
	if err != nil {
		return nil, err
	}
	tenantContext, err := structpb.NewStruct(cloneMap(principal.TenantContext))
	if err != nil {
		return nil, err
	}
	return &sdkv1.Principal{
		Subject:       principal.Subject,
		Scopes:        append([]string(nil), principal.Scopes...),
		Roles:         append([]string(nil), principal.Roles...),
		Claims:        claims,
		TenantContext: tenantContext,
		AccessToken:   principal.AccessToken,
		ExpiresAt:     principal.ExpiresAt.Unix(),
	}, nil
}

func sessionToProto(sess *pkgsession.Session) (*sdkv1.Session, error) {
	if sess == nil {
		return nil, nil
	}
	claims, err := structpb.NewStruct(cloneMap(sess.Claims))
	if err != nil {
		return nil, err
	}
	tenantContext, err := structpb.NewStruct(tenantContextToMap(sess.TenantContext))
	if err != nil {
		return nil, err
	}
	return &sdkv1.Session{
		Id:            sess.ID,
		AccessToken:   sess.AccessToken,
		RefreshToken:  sess.RefreshToken,
		IdToken:       sess.IDToken,
		ExpiresAt:     sess.ExpiresAt,
		Claims:        claims,
		TenantContext: tenantContext,
	}, nil
}

func cloneMap(in map[string]any) map[string]any {
	if len(in) == 0 {
		return map[string]any{}
	}
	out := make(map[string]any, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

func tenantContextToMap(tc *pkgsession.TenantContext) map[string]any {
	if tc == nil {
		return map[string]any{}
	}
	out := map[string]any{}
	if tc.TenantID != "" {
		out["tenant_id"] = tc.TenantID
	}
	if tc.TenantSlug != "" {
		out["tenant_slug"] = tc.TenantSlug
	}
	if tc.Status != "" {
		out["status"] = tc.Status
	}
	if tc.Locale != "" {
		out["locale"] = tc.Locale
	}
	if tc.Timezone != "" {
		out["timezone"] = tc.Timezone
	}
	return out
}

func structMap(v *structpb.Struct) map[string]any {
	if v == nil {
		return nil
	}
	return v.AsMap()
}

func structMapFromSession(sess *sdkv1.Session) map[string]any {
	if sess == nil {
		return nil
	}
	return structMap(sess.GetClaims())
}

func structMapFromSessionTenant(sess *sdkv1.Session) map[string]any {
	if sess == nil {
		return nil
	}
	return structMap(sess.GetTenantContext())
}

func stringFromMap(m map[string]any, key string) string {
	if m == nil {
		return ""
	}
	if s, ok := m[key].(string); ok {
		return s
	}
	return ""
}

func stringsFromAny(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	out := make([]string, 0, len(values))
	for _, v := range values {
		if v != "" {
			out = append(out, v)
		}
	}
	return out
}

func scopesFromClaims(claims map[string]any) []string {
	if claims == nil {
		return nil
	}
	if raw, ok := claims["scope"].(string); ok {
		parts := strings.Fields(raw)
		if len(parts) > 0 {
			return parts
		}
	}
	return stringSliceFromValue(claims["scopes"])
}

func rolesFromClaims(claims map[string]any) []string {
	if claims == nil {
		return nil
	}
	if realmAccess, ok := claims["realm_access"].(map[string]any); ok {
		if roles := stringSliceFromValue(realmAccess["roles"]); len(roles) > 0 {
			return roles
		}
	}
	return stringSliceFromValue(claims["roles"])
}

func groupsFromClaims(claims map[string]any) []string {
	if claims == nil {
		return nil
	}
	return stringSliceFromValue(claims["groups"])
}

func stringSliceFromValue(v any) []string {
	switch values := v.(type) {
	case []string:
		return append([]string(nil), values...)
	case []any:
		out := make([]string, 0, len(values))
		for _, item := range values {
			if s, ok := item.(string); ok && s != "" {
				out = append(out, s)
			}
		}
		return out
	default:
		return nil
	}
}
