package trust_test

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/eudi-dev/ebw-dev/internal/trust"
	"github.com/eudi-dev/ebw-dev/internal/wallettest"
)

const credentialType = "urn:test:authority:1"

func jwtPart(t *testing.T, token string, part int) map[string]any {
	t.Helper()
	jwt, _, _ := strings.Cut(token, "~")
	data, err := base64.RawURLEncoding.DecodeString(strings.Split(jwt, ".")[part])
	if err != nil {
		t.Fatal(err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatal(err)
	}
	return decoded
}

func setup(t *testing.T) (*wallettest.Wallet, *trust.Store) {
	t.Helper()
	wallet := wallettest.New()
	t.Cleanup(wallet.Close)
	store := trust.NewStore(wallet.URL)
	if err := store.Reload(context.Background()); err != nil {
		t.Fatal(err)
	}
	return wallet, store
}

func TestResolveIssuer(t *testing.T) {
	wallet, store := setup(t)
	wallet.Issue("pub-eaa", credentialType, map[string]any{"name": "Acme Logistics GmbH"})
	header := jwtPart(t, wallet.Credentials()[0].IssuerJWT, 0)

	issuer, err := store.ResolveIssuer([]string{"pub-eaa"}, time.Now())(header, nil)
	if err != nil || issuer.TrustError != nil {
		t.Fatalf("issuer on the list: err %v, trust error %v", err, issuer.TrustError)
	}
	if issuer.Name != "Test pub-eaa Provider" || issuer.Key == nil {
		t.Errorf("issuer = %q with key %v", issuer.Name, issuer.Key)
	}

	issuer, err = store.ResolveIssuer([]string{"eaa"}, time.Now())(header, nil)
	if err != nil || issuer.TrustError == nil {
		t.Errorf("issuer of another list: err %v, trust error %v", err, issuer.TrustError)
	}
}

func TestCheckStatus(t *testing.T) {
	wallet, store := setup(t)
	index := wallet.Issue("eaa", credentialType, map[string]any{"name": "Bob"})
	claims := jwtPart(t, wallet.Credentials()[0].IssuerJWT, 1)
	check := store.CheckStatus(context.Background(), []string{"eaa"}, time.Now())

	if err := check(claims); err != nil {
		t.Fatalf("valid credential: %v", err)
	}
	wallet.Revoke(index)
	if err := check(claims); err == nil || !strings.Contains(err.Error(), "status 1") {
		t.Errorf("revoked credential: %v", err)
	}

	foreign := map[string]any{"status": map[string]any{"status_list": map[string]any{"idx": 0, "uri": "https://other.example/list"}}}
	foreign = roundTrip(t, foreign)
	if err := check(foreign); err == nil || !strings.Contains(err.Error(), "outside the wallet") {
		t.Errorf("status list on another host: %v", err)
	}

	// draft-ietf-oauth-status-list-21 §6.2 makes idx a non-negative integer.
	fractional := roundTrip(t, map[string]any{"status": map[string]any{"status_list": map[string]any{"idx": 1.5, "uri": "https://other.example/list"}}})
	if err := check(fractional); err == nil || !strings.Contains(err.Error(), "whole number idx") {
		t.Errorf("fractional idx: %v", err)
	}
}

func roundTrip(t *testing.T, value map[string]any) map[string]any {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatal(err)
	}
	return decoded
}

func TestSummary(t *testing.T) {
	_, store := setup(t)
	summary, err := store.Summary()
	if err != nil {
		t.Fatal(err)
	}
	if len(summary.Lists) != 2 || summary.Lists[0].ID != "eaa" || summary.Lists[0].Issuers[0] != "Test eaa CA" {
		t.Errorf("summary = %+v", summary)
	}
}

func TestReloadRejectsForeignListSigner(t *testing.T) {
	wallet, _ := setup(t)
	other := wallettest.New()
	t.Cleanup(other.Close)
	wallet.ServeListsOf(other)
	err := trust.NewStore(wallet.URL).Reload(context.Background())
	var unknownCA x509.UnknownAuthorityError
	if !errors.As(err, &unknownCA) {
		t.Errorf("list signed under another CA: %v", err)
	}
}
