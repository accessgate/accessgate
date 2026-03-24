package main

import "testing"

func TestEnvOrDefault(t *testing.T) {
	t.Setenv("MOCKIDP_TEST_X", "")
	if got := envOrDefault("MOCKIDP_TEST_X", "d"); got != "d" {
		t.Fatal(got)
	}
	t.Setenv("MOCKIDP_TEST_X", "  v  ")
	if got := envOrDefault("MOCKIDP_TEST_X", "d"); got != "v" {
		t.Fatal(got)
	}
}

func TestEnvOrDefaultInt(t *testing.T) {
	t.Setenv("MOCKIDP_TEST_N", "")
	if got := envOrDefaultInt("MOCKIDP_TEST_N", 7); got != 7 {
		t.Fatal(got)
	}
	t.Setenv("MOCKIDP_TEST_N", "42")
	if got := envOrDefaultInt("MOCKIDP_TEST_N", 7); got != 42 {
		t.Fatal(got)
	}
}

func TestS256ChallengeDeterministic(t *testing.T) {
	a := s256Challenge("verifier")
	b := s256Challenge("verifier")
	if a != b || a == "" {
		t.Fatal(a, b)
	}
}

func TestRandomCodeLength(t *testing.T) {
	c := randomCode()
	if len(c) < 10 {
		t.Fatal(c)
	}
}
