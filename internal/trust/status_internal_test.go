package trust

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestCheckStatusRefusesRedirect(t *testing.T) {
	var targetRequests atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		targetRequests.Add(1)
	}))
	defer target.Close()
	wallet := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL+"/status", http.StatusFound)
	}))
	defer wallet.Close()

	store := &Store{current: &snapshot{origins: []string{wallet.URL}, statusClient: statusClient(nil)}}
	check := store.CheckStatus(context.Background(), nil, time.Now())
	err := check(map[string]any{"status": map[string]any{
		"status_list": map[string]any{"uri": wallet.URL + "/status", "idx": float64(0)},
	}})
	if err == nil || !strings.Contains(err.Error(), "redirect") {
		t.Fatalf("CheckStatus = %v, want a redirect error", err)
	}
	if got := targetRequests.Load(); got != 0 {
		t.Fatalf("the redirect target got %d requests", got)
	}
}
