//go:build e2e

// Package e2e runs the showcase against a running wallet and demo server.
package e2e

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"slices"
	"testing"

	"github.com/eudi-dev/ebw-dev/internal/demo"
	"github.com/eudi-dev/ebw-dev/internal/dsdjwt"
	"github.com/eudi-dev/ebw-dev/internal/dsdjwt/dsdtest"
)

func env(name, fallback string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return fallback
}

var (
	demoURL   = env("EBW_DEV_PUBLIC_URL", "http://localhost:28090")
	walletURL = env("EBW_DEV_WALLET_URL", "http://localhost:28085")
)

func call(t *testing.T, method, target string, body, into any) int {
	t.Helper()
	encoded, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	request, err := http.NewRequest(method, target, bytes.NewReader(encoded))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", "application/json")
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatalf("%s %s: %v. Start the setup with scripts/run-local.sh.", method, target, err)
	}
	defer response.Body.Close()
	data, _ := io.ReadAll(response.Body)
	if response.StatusCode >= 300 {
		t.Fatalf("%s %s = %d: %s", method, target, response.StatusCode, data)
	}
	if into != nil {
		if err := json.Unmarshal(data, into); err != nil {
			t.Fatalf("%s %s: %v in %s", method, target, err, data)
		}
	}
	return response.StatusCode
}

// granted asks for a mandate and has the wallet answer without a consent
// dialog. It fails unless the wallet grants the delegation.
func granted(t *testing.T, caseID string) demo.Mandate {
	t.Helper()
	var mandate demo.Mandate
	call(t, http.MethodPost, demoURL+"/api/mandates", map[string]string{"case": caseID}, &mandate)
	t.Logf("mandate request: %s", mandate.Request.URI)

	var answer map[string]any
	call(t, http.MethodPost, walletURL+"/api/presentations", map[string]any{"uri": mandate.Request.URI, "auto_accept": true}, &answer)
	t.Logf("the wallet answered with the status %v", answer["status"])

	call(t, http.MethodGet, demoURL+"/api/mandates/"+mandate.ID, nil, &mandate)
	if mandate.Error == demo.ErrorNoDelegation {
		t.Fatalf("The wallet returned no dSD-JWT. %s Set WALLET_BIN to a wallet with the transaction data type delegate.", mandate.ErrorDescription)
	}
	if mandate.Status != demo.MandateGranted {
		t.Fatalf("mandate status %q (%s): %s", mandate.Status, mandate.Error, mandate.ErrorDescription)
	}
	return mandate
}

func run(t *testing.T, mandate demo.Mandate, variant string) demo.Run {
	t.Helper()
	var result demo.Run
	call(t, http.MethodPost, demoURL+"/api/mandates/"+mandate.ID+"/runs", map[string]string{"variant": variant}, &result)
	if result.Report == nil && !(variant == demo.VariantRevoked && result.Outcome == "stopped") {
		t.Fatalf("run without report: %q %v", result.Outcome, result.Reasons)
	}
	return result
}

func TestDelegation(t *testing.T) {
	cases := []struct{ id, credentialType string }{
		{"supplier", demo.TypePowerOfAttorney},
		{"internal", demo.TypeEmployeeAuthorisation},
	}
	variants := []struct{ variant, failed string }{
		{demo.VariantOK, ""},
		{demo.VariantOverLimit, dsdjwt.CheckPolicyLimit},
		{demo.VariantExpired, dsdjwt.CheckMandateValid},
		{demo.VariantWrongVerifier, dsdjwt.CheckPolicyAudience},
		{demo.VariantTampered, dsdjwt.CheckOnePayload},
	}
	for _, c := range cases {
		t.Run(c.id, func(t *testing.T) {
			mandate := granted(t, c.id)
			if got := mandate.Report.Credential["vct"]; got != c.credentialType {
				t.Fatalf("the mandate rests on %v, want %s", got, c.credentialType)
			}
			for _, v := range variants {
				t.Run(v.variant, func(t *testing.T) {
					result := run(t, mandate, v.variant)
					failed := dsdtest.Failed(result.Report)
					if v.failed == "" {
						if result.Outcome != "accepted" {
							t.Fatalf("outcome %q, failed checks %v, reasons %v", result.Outcome, failed, result.Reasons)
						}
						return
					}
					if result.Outcome != "refused" || !slices.Equal(failed, []string{v.failed}) {
						t.Fatalf("outcome %q, failed checks %v, want only %s", result.Outcome, failed, v.failed)
					}
					t.Logf("refused: %v", result.Reasons)
				})
			}
		})
	}
}

// The demo revokes the credential under the mandate. The verifier refuses at
// the status check, and a new mandate rests on a fresh credential. A wallet
// started with --demo protects its file credentials. The demo then stops the
// first run and issues a credential it can revoke.
func TestRevokedCredential(t *testing.T) {
	for _, caseID := range []string{"supplier", "internal"} {
		t.Run(caseID, func(t *testing.T) {
			result := run(t, granted(t, caseID), demo.VariantRevoked)
			if result.Outcome == "stopped" {
				t.Logf("stopped: %v", result.Reasons)
				result = run(t, granted(t, caseID), demo.VariantRevoked)
			}
			if failed := dsdtest.Failed(result.Report); result.Outcome != "refused" || !slices.Equal(failed, []string{dsdjwt.CheckStatus}) {
				t.Fatalf("outcome %q, failed checks %v, want only %s", result.Outcome, failed, dsdjwt.CheckStatus)
			}
			t.Logf("refused: %v", result.Reasons)
			if result := run(t, granted(t, caseID), demo.VariantOK); result.Outcome != "accepted" {
				t.Fatalf("run on the fresh credential: %q %v", result.Outcome, result.Reasons)
			}
		})
	}
}

// scenario asks the wallet for the scenario variant and has the wallet answer
// without a consent dialog.
func scenario(t *testing.T, id, variant string) demo.ScenarioRequest {
	t.Helper()
	var request demo.ScenarioRequest
	call(t, http.MethodPost, demoURL+"/api/scenarios/"+id+"/requests", map[string]string{"variant": variant}, &request)
	t.Logf("request: %s", request.Request.URI)
	call(t, http.MethodPost, walletURL+"/api/presentations", map[string]any{"uri": request.Request.URI, "auto_accept": true}, nil)
	call(t, http.MethodGet, demoURL+"/api/scenarios/"+id+"/requests/"+request.ID, nil, &request)
	return request
}

func TestScenarios(t *testing.T) {
	tests := []struct {
		name, scenario, variant, status, failed string
	}{
		{"poa", "poa", demo.VariantOK, demo.ScenarioAccepted, ""},
		{"poa wrong scope", "poa", demo.VariantWrongScope, demo.ScenarioRefused, demo.CheckPolicyScope},
		{"poa expired", "poa", demo.VariantExpired, demo.ScenarioRefused, demo.CheckPolicyValidity},
		{"poa revoked", "poa", demo.VariantRevoked, demo.ScenarioRefused, dsdjwt.CheckStatus},
		{"poa after the revocation", "poa", demo.VariantOK, demo.ScenarioAccepted, ""},
		{"kyb", "kyb", demo.VariantOK, demo.ScenarioAccepted, ""},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request := scenario(t, test.scenario, test.variant)
			var failed []string
			for _, presentation := range request.Presentations {
				failed = append(failed, dsdtest.Failed(presentation.Report)...)
			}
			var want []string
			if test.failed != "" {
				want = []string{test.failed}
			}
			if request.Status != test.status || !slices.Equal(failed, want) {
				t.Fatalf("status %q, failed checks %v, reasons %v", request.Status, failed, request.Reasons)
			}
			t.Logf("%s: %v %v", request.Status, request.Reasons, request.Notes)
		})
	}
}

// The wallet takes each offer of the business issuer page without a consent
// dialog and stores a new credential of the type.
func TestIssuerOffers(t *testing.T) {
	for _, before := range holdings(t) {
		t.Run(before.Configuration, func(t *testing.T) {
			var offer demo.IssuerOffer
			call(t, http.MethodPost, demoURL+"/api/offers", map[string]string{"configuration": before.Configuration}, &offer)
			call(t, http.MethodPost, walletURL+"/api/offers", map[string]string{"uri": offer.SchemeURI}, nil)
			after := holdings(t)
			index := slices.IndexFunc(after, func(h demo.Holding) bool { return h.Configuration == before.Configuration })
			if got, want := len(after[index].Credentials), len(before.Credentials)+1; got != want {
				t.Fatalf("the wallet holds %d credentials of %s, want %d", got, before.Configuration, want)
			}
		})
	}
}

func holdings(t *testing.T) []demo.Holding {
	t.Helper()
	var holdings []demo.Holding
	call(t, http.MethodGet, demoURL+"/api/wallet/credentials", nil, &holdings)
	return holdings
}

func TestWalletHoldsTheCredentials(t *testing.T) {
	all := holdings(t)
	if len(all) != 3 {
		t.Fatalf("%d holdings, want 3", len(all))
	}
	for _, holding := range all {
		valid := slices.IndexFunc(holding.Credentials, func(held demo.HeldCredential) bool { return held.Valid })
		if valid < 0 {
			t.Errorf("%s: no valid credential", holding.Configuration)
			continue
		}
		if held := holding.Credentials[valid]; !held.ExpiresAt.After(held.IssuedAt) {
			t.Errorf("%s: expires at %v, issued at %v", holding.Configuration, held.ExpiresAt, held.IssuedAt)
		}
	}
}
