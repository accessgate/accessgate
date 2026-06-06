package session

import (
	"context"
	"net/http"

	"github.com/accessgate/accessgate/pkg/cookie"
	pkgsession "github.com/accessgate/accessgate/pkg/session"
)

// BrowserSessionManager coordinates cookie and store operations for browser sessions.
type BrowserSessionManager struct {
	store        pkgsession.SessionStore
	codec        cookie.Codec
	cookieConfig cookie.SessionCookieConfig
	keyLayout    pkgsession.KeyLayout
}

// NewBrowserSessionManager constructs a BrowserSessionManager.
func NewBrowserSessionManager(store pkgsession.SessionStore, codec cookie.Codec, cfg cookie.SessionCookieConfig, layout pkgsession.KeyLayout) *BrowserSessionManager {
	return &BrowserSessionManager{
		store:        store,
		codec:        codec,
		cookieConfig: cfg,
		keyLayout:    layout,
	}
}

// StartSession persists sess in the store and issues a session cookie on the response.
func (m *BrowserSessionManager) StartSession(ctx context.Context, w http.ResponseWriter, r *http.Request, sess *pkgsession.Session, ttlSeconds int) error {
	if sess == nil || sess.ID == "" {
		return nil
	}
	if err := m.store.Set(ctx, sess.ID, sess, ttlSeconds); err != nil {
		return err
	}
	value, err := m.codec.Encode(sess.ID)
	if err != nil {
		return err
	}
	opts := m.cookieConfig.Options()
	cookie.WriteOutCookie(w, cookie.OutCookie{
		Name:    m.cookieConfig.Name,
		Value:   value,
		Options: opts,
	})
	return nil
}

// ResolveSession decodes the browser cookie and loads the corresponding session from the store.
func (m *BrowserSessionManager) ResolveSession(ctx context.Context, r *http.Request) (*pkgsession.Session, error) {
	c, err := r.Cookie(m.cookieConfig.Name)
	if err != nil || c == nil || c.Value == "" {
		return nil, nil
	}
	id, err := m.codec.Decode(c.Value)
	if err != nil || id == "" {
		return nil, nil
	}
	return m.store.Get(ctx, id)
}

// EndSession deletes the session from the store and clears the browser cookie.
func (m *BrowserSessionManager) EndSession(ctx context.Context, w http.ResponseWriter, r *http.Request) error {
	c, err := r.Cookie(m.cookieConfig.Name)
	if err == nil && c != nil && c.Value != "" {
		id, err := m.codec.Decode(c.Value)
		if err == nil && id != "" {
			_ = m.store.Delete(ctx, id)
		}
	}
	opts := m.cookieConfig.Options()
	opts.MaxAge = -1
	cookie.WriteOutCookie(w, cookie.OutCookie{
		Name:    m.cookieConfig.Name,
		Value:   "",
		Options: opts,
	})
	return nil
}

// SessionFromCookie decodes the cookie value to a session ID (e.g. via signed decode) and loads
// the session from the store. decodeCookie should return the session ID or an error if invalid.
// Session body lives in the store; the cookie typically holds only the session ID.
func SessionFromCookie(ctx context.Context, store pkgsession.SessionStore, cookieValue string, decodeCookie func(string) (string, error)) (*pkgsession.Session, error) {
	if cookieValue == "" {
		return nil, nil
	}
	sessionID, err := decodeCookie(cookieValue)
	if err != nil {
		return nil, err
	}
	return store.Get(ctx, sessionID)
}
