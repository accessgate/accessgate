package session

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/ArmanAvanesyan/accessgate/pkg/cookie"
	pkgsession "github.com/ArmanAvanesyan/accessgate/pkg/session"
)

type stubCodec struct{}

func (stubCodec) Encode(sessionID string) (string, error) { return "e:" + sessionID, nil }

func (stubCodec) Decode(raw string) (string, error) {
	if len(raw) < 2 || raw[0:2] != "e:" {
		return "", errors.New("bad")
	}
	return raw[2:], nil
}

type memSessionStore struct {
	data map[string]*pkgsession.Session
}

func newMemSessionStore() *memSessionStore {
	return &memSessionStore{data: make(map[string]*pkgsession.Session)}
}

func (m *memSessionStore) Get(ctx context.Context, sessionID string) (*pkgsession.Session, error) {
	return m.data[sessionID], nil
}

func (m *memSessionStore) Set(ctx context.Context, sessionID string, s *pkgsession.Session, ttlSeconds int) error {
	m.data[sessionID] = s
	return nil
}

func (m *memSessionStore) Delete(ctx context.Context, sessionID string) error {
	delete(m.data, sessionID)
	return nil
}

func TestSessionFromCookieEmpty(t *testing.T) {
	st := newMemSessionStore()
	got, err := SessionFromCookie(context.Background(), st, "", func(string) (string, error) {
		t.Fatal("decode should not run")
		return "", nil
	})
	if err != nil || got != nil {
		t.Fatalf("got %v err %v", got, err)
	}
}

func TestSessionFromCookieDecodeError(t *testing.T) {
	st := newMemSessionStore()
	_, err := SessionFromCookie(context.Background(), st, "x", func(string) (string, error) {
		return "", errors.New("nope")
	})
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestBrowserSessionManagerStartResolveEnd(t *testing.T) {
	st := newMemSessionStore()
	cfg := cookie.DefaultSessionCookieConfig("sid")
	m := NewBrowserSessionManager(st, stubCodec{}, cfg, pkgsession.DefaultKeyLayout())

	sess := &pkgsession.Session{ID: "abc", AccessToken: "t", ExpiresAt: 9, Claims: map[string]any{}}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	if err := m.StartSession(context.Background(), w, r, sess, 60); err != nil {
		t.Fatal(err)
	}
	cookies := w.Result().Cookies()
	if len(cookies) != 1 || cookies[0].Name != "sid" {
		t.Fatalf("cookies: %+v", cookies)
	}

	r2 := httptest.NewRequest(http.MethodGet, "/", nil)
	r2.AddCookie(&http.Cookie{Name: "sid", Value: "e:abc"})
	got, err := m.ResolveSession(context.Background(), r2)
	if err != nil || got == nil || got.ID != "abc" {
		t.Fatalf("ResolveSession: %v %#v", err, got)
	}

	w2 := httptest.NewRecorder()
	if err := m.EndSession(context.Background(), w2, r2); err != nil {
		t.Fatal(err)
	}
	if st.data["abc"] != nil {
		t.Fatal("expected session deleted")
	}
}

func TestStartSessionNoOpNilOrEmptyID(t *testing.T) {
	m := NewBrowserSessionManager(newMemSessionStore(), stubCodec{}, cookie.DefaultSessionCookieConfig("sid"), pkgsession.DefaultKeyLayout())
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	if err := m.StartSession(context.Background(), w, r, nil, 60); err != nil {
		t.Fatal(err)
	}
	if len(w.Result().Cookies()) != 0 {
		t.Fatal("expected no cookie")
	}
	if err := m.StartSession(context.Background(), w, r, &pkgsession.Session{ID: ""}, 60); err != nil {
		t.Fatal(err)
	}
}
