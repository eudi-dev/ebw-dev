package demo

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestReadWalletResponseRefusesALargeBody(t *testing.T) {
	body := "vp_token=" + strings.Repeat("a", maxResponseBytes)
	request := httptest.NewRequest(http.MethodPost, "/response", strings.NewReader(body))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	recorder := httptest.NewRecorder()
	if readWalletResponse(recorder, request) {
		t.Fatal("the body over the limit was read")
	}
	if recorder.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status %d, want 413", recorder.Code)
	}
	if !strings.Contains(recorder.Body.String(), "limit of 65536 bytes") {
		t.Fatalf("body %s does not name the limit", recorder.Body)
	}
}
