package demo

import (
	"testing"
	"time"
)

func TestWalletCredentialValid(t *testing.T) {
	now := time.Date(2027, 3, 1, 12, 0, 0, 0, time.UTC)
	tests := []struct {
		name       string
		credential walletCredential
		want       bool
	}{
		{"active", walletCredential{ExpiresAt: now.Add(time.Hour), Status: &walletStatus{}}, true},
		{"without expires_at", walletCredential{Status: &walletStatus{}}, true},
		{"without status", walletCredential{ExpiresAt: now.Add(time.Hour)}, true},
		{"expired", walletCredential{ExpiresAt: now.Add(-time.Second), Status: &walletStatus{}}, false},
		{"expires now", walletCredential{ExpiresAt: now, Status: &walletStatus{}}, false},
		{"revoked", walletCredential{ExpiresAt: now.Add(time.Hour), Status: &walletStatus{Status: 1}}, false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := test.credential.valid(now); got != test.want {
				t.Errorf("valid = %v, want %v", got, test.want)
			}
		})
	}
}
