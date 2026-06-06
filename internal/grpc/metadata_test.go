package grpc

import "testing"

func TestExtractMethod(t *testing.T) {
	cases := []struct {
		name       string
		fullMethod string
		wantSvc    string
		wantMethod string
	}{
		{
			name:       "canonical",
			fullMethod: "/package.Service/Method",
			wantSvc:    "package.Service",
			wantMethod: "Method",
		},
		{
			name:       "nested package",
			fullMethod: "/foo.bar.baz.Greeter/SayHello",
			wantSvc:    "foo.bar.baz.Greeter",
			wantMethod: "SayHello",
		},
		{
			name:       "no leading slash tolerated",
			fullMethod: "svc.Foo/Bar",
			wantSvc:    "svc.Foo",
			wantMethod: "Bar",
		},
		{
			name:       "empty input",
			fullMethod: "",
			wantSvc:    "",
			wantMethod: "",
		},
		{
			name:       "no method separator",
			fullMethod: "/svc.Foo",
			wantSvc:    "svc.Foo",
			wantMethod: "",
		},
		{
			name:       "trailing slash empty method",
			fullMethod: "/svc.Foo/",
			wantSvc:    "svc.Foo",
			wantMethod: "",
		},
		{
			name:       "leading slash only",
			fullMethod: "/",
			wantSvc:    "",
			wantMethod: "",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			svc, method := ExtractMethod(tc.fullMethod)
			if svc != tc.wantSvc || method != tc.wantMethod {
				t.Fatalf("ExtractMethod(%q) = (%q, %q), want (%q, %q)",
					tc.fullMethod, svc, method, tc.wantSvc, tc.wantMethod)
			}
		})
	}
}
