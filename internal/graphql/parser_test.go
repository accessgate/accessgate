package graphql

import "testing"

func TestExtractOperationName(t *testing.T) {
	cases := []struct {
		name string
		body string
		want string
	}{
		{"raw query", `query MyQuery { field }`, "MyQuery"},
		{"raw mutation", `mutation CreateThing { create { id } }`, "CreateThing"},
		{"raw subscription", `subscription OnEvent { event }`, "OnEvent"},
		{"raw query with variables", `query GetUser($id: ID!) { user(id: $id) { name } }`, "GetUser"},
		{"raw query with directives", `query GetUser @cached { user { name } }`, "GetUser"},
		{"anonymous shorthand", `{ field }`, ""},
		{"anonymous query keyword", `query { field }`, ""},
		{"anonymous query with vars", `query ($id: ID!) { user(id: $id) { name } }`, ""},
		{"leading comment", "# fetch the user\nquery GetUser { user }", "GetUser"},
		{"leading whitespace", "\n\t  query Spaced { x }", "Spaced"},
		{"leading BOM", "\ufeffquery WithBOM { x }", "WithBOM"},
		{"json with operationName", `{"operationName":"FromJSON","query":"query FromJSON { x }"}`, "FromJSON"},
		{"json operationName precedence", `{"operationName":"Override","query":"query Other { x }"}`, "Override"},
		{"json query only", `{"query":"query OnlyQuery { x }"}`, "OnlyQuery"},
		{"json query only anonymous", `{"query":"{ x }"}`, ""},
		{"json empty", `{}`, ""},
		{"empty body", ``, ""},
		{"whitespace only", "   \n\t ", ""},
		{"garbage", `not a graphql document`, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := ExtractOperationName([]byte(tc.body))
			if got != tc.want {
				t.Fatalf("ExtractOperationName(%q) = %q, want %q", tc.body, got, tc.want)
			}
		})
	}
}

func TestExtractOperationType(t *testing.T) {
	cases := []struct {
		name     string
		body     string
		wantName string
		wantType string
	}{
		{"query", `query Q { x }`, "Q", "query"},
		{"mutation", `mutation M { x }`, "M", "mutation"},
		{"subscription", `subscription S { x }`, "S", "subscription"},
		{"shorthand", `{ x }`, "", "query"},
		{"json", `{"query":"mutation M { x }"}`, "M", "mutation"},
		{"json name precedence keeps type", `{"operationName":"M","query":"mutation M { x }"}`, "M", "mutation"},
		{"garbage", `nonsense`, "", ""},
		{"empty", ``, "", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			name, opType := ExtractOperation([]byte(tc.body))
			if name != tc.wantName || opType != tc.wantType {
				t.Fatalf("ExtractOperation(%q) = (%q, %q), want (%q, %q)", tc.body, name, opType, tc.wantName, tc.wantType)
			}
		})
	}
}
