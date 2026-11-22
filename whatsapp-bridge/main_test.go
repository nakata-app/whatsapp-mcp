package main

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestBridgeAuthRejectsUnauthenticatedAndWrongToken(t *testing.T) {
	t.Setenv("WHATSAPP_BRIDGE_TOKEN", "test-secret-token-123456")
	mux := newRESTMux(nil, nil)

	for _, ep := range []string{"/api/send", "/api/revoke", "/api/download"} {
		// Missing token -> 401
		req := httptest.NewRequest(http.MethodPost, ep, bytes.NewBufferString(`{}`))
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("%s without token: got %d, want 401", ep, rec.Code)
		}

		// Wrong token -> 401
		req2 := httptest.NewRequest(http.MethodPost, ep, bytes.NewBufferString(`{}`))
		req2.Header.Set("Authorization", "Bearer wrong-token")
		rec2 := httptest.NewRecorder()
		mux.ServeHTTP(rec2, req2)
		if rec2.Code != http.StatusUnauthorized {
			t.Fatalf("%s with wrong token: got %d, want 401", ep, rec2.Code)
		}
	}
}

func TestBridgeAuthFailClosedWhenTokenMissing(t *testing.T) {
	t.Setenv("WHATSAPP_BRIDGE_TOKEN", "")
	t.Setenv("WHATSAPP_BRIDGE_TOKEN_FILE", filepath.Join(t.TempDir(), "missing.token"))
	mux := newRESTMux(nil, nil)

	req := httptest.NewRequest(http.MethodPost, "/api/send", bytes.NewBufferString(`{}`))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("missing token file: got %d, want 503", rec.Code)
	}
}

func TestBridgeAuthAcceptsValidBearerAndHeaderFromFile(t *testing.T) {
	tokFile := filepath.Join(t.TempDir(), "bridge.token")
	if err := os.WriteFile(tokFile, []byte("file-token-abcdef\n"), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("WHATSAPP_BRIDGE_TOKEN", "")
	t.Setenv("WHATSAPP_BRIDGE_TOKEN_FILE", tokFile)
	mux := newRESTMux(nil, nil)

	// Valid Bearer passes auth -> hits request validation (400 empty recipient)
	req := httptest.NewRequest(http.MethodPost, "/api/send", bytes.NewBufferString(`{}`))
	req.Header.Set("Authorization", "Bearer file-token-abcdef")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("valid Bearer token: got %d, want 400 (passed auth)", rec.Code)
	}

	// Valid X-Bridge-Token passes auth -> hits request validation (400 missing chat_jid)
	req2 := httptest.NewRequest(http.MethodPost, "/api/revoke", bytes.NewBufferString(`{}`))
	req2.Header.Set("X-Bridge-Token", "file-token-abcdef")
	rec2 := httptest.NewRecorder()
	mux.ServeHTTP(rec2, req2)
	if rec2.Code != http.StatusBadRequest {
		t.Fatalf("valid X-Bridge-Token: got %d, want 400 (passed auth)", rec2.Code)
	}
}

func TestRecipientAllowedBlocksDisallowedGroupAndNumber(t *testing.T) {
	if recipientAllowed("120363040489136513@g.us") {
		t.Fatal("expected arbitrary group JID to be blocked")
	}
	if recipientAllowed("905000000000") {
		t.Fatal("expected arbitrary phone number to be blocked")
	}
}
