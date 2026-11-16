package demo_test

import (
	"encoding/base64"
	"encoding/json"
	"maps"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"testing"

	"github.com/eudi-dev/ebw-dev/internal/demo"
	"github.com/eudi-dev/ebw-dev/internal/dsdjwt"
	"github.com/eudi-dev/ebw-dev/internal/dsdjwt/dsdtest"
)

var owner = map[string]any{
	"id":                "DETEST.00000471",
	"name":              "Acme Logistics GmbH",
	"issuing_authority": "Test Business Register Hamburg",
	"issuing_country":   "DE",
	"date_of_expiry":    "2099-11-12",
}

func startScenarios(t *testing.T, prefix string) *setup {
	t.Helper()
	s := start(t, prefix)
	s.wallet.Issue("pub-eaa", demo.TypeEBWOID, owner)
	s.wallet.SetTemplate("ebwoid", "pub-eaa", demo.TypeEBWOID, owner)
	return s
}

// scenario asks the wallet with the variant and returns the checked answer.
func (s *setup) scenario(id, variant string) demo.ScenarioRequest {
	s.t.Helper()
	var created demo.ScenarioRequest
	s.call(http.MethodPost, "/api/scenarios/"+id+"/requests", `{"variant":"`+variant+`"}`, http.StatusCreated, &created)
	if created.Status != demo.ScenarioPending {
		s.t.Fatalf("new request has the status %q", created.Status)
	}
	redirect, err := s.wallet.Present(http.DefaultClient, created.Request.WalletURL)
	if err != nil {
		s.t.Fatal(err)
	}
	if want := s.base + "/scenarios/" + id + "?request=" + created.ID; redirect != want {
		s.t.Errorf("redirect_uri = %q, want %q", redirect, want)
	}
	var answered demo.ScenarioRequest
	s.call(http.MethodGet, "/api/scenarios/"+id+"/requests/"+created.ID, "", http.StatusOK, &answered)
	return answered
}

func failedChecks(request demo.ScenarioRequest) []string {
	var failed []string
	for _, presentation := range request.Presentations {
		failed = append(failed, dsdtest.Failed(presentation.Report)...)
	}
	return failed
}

func TestPowerOfAttorneyScenario(t *testing.T) {
	variants := []struct {
		variant, status, failed string
	}{
		{demo.VariantOK, demo.ScenarioAccepted, ""},
		{demo.VariantWrongScope, demo.ScenarioRefused, demo.CheckPolicyScope},
		{demo.VariantExpired, demo.ScenarioRefused, demo.CheckPolicyValidity},
		{demo.VariantRevoked, demo.ScenarioRefused, dsdjwt.CheckStatus},
	}
	for _, prefix := range []string{"", "/agents"} {
		s := startScenarios(t, prefix)
		for _, v := range variants {
			t.Run(prefix+"/"+v.variant, func(t *testing.T) {
				answer := s.scenario("poa", v.variant)
				if answer.Status != v.status {
					t.Fatalf("status %q, reasons %v", answer.Status, answer.Reasons)
				}
				var want []string
				if v.failed != "" {
					want = []string{v.failed}
				}
				if failed := failedChecks(answer); !slices.Equal(failed, want) {
					t.Errorf("failed checks %v, want %v", failed, want)
				}
				if v.status == demo.ScenarioRefused && len(answer.Reasons) != 1 {
					t.Errorf("reasons %v", answer.Reasons)
				}
				if len(answer.Presentations) != 1 || answer.Presentations[0].Token == "" {
					t.Fatalf("presentations %+v", answer.Presentations)
				}
				decoder := answer.Presentations[0].DecoderURL
				if _, fragment, _ := strings.Cut(decoder, "#credential="); fragment != url.QueryEscape(answer.Presentations[0].Token) {
					t.Errorf("decoder link %q", decoder)
				}
			})
		}
		// The revoked variant leaves a valid power of attorney for the next request.
		if answer := s.scenario("poa", demo.VariantOK); answer.Status != demo.ScenarioAccepted {
			t.Errorf("%s: request after the revoked variant: %q %v", prefix, answer.Status, answer.Reasons)
		}
	}
}

func TestRevokedVariantRevokesOnlyThePresentedPowerOfAttorney(t *testing.T) {
	s := startScenarios(t, "")
	other := s.wallet.Credentials()[len(s.wallet.Credentials())-1]
	presented := s.wallet.Issue("pub-eaa", demo.TypePowerOfAttorney, map[string]any{
		"company_statutory_full_name":    "Acme Logistics GmbH",
		"scope_of_representation_powers": []any{"Registration and closure of branches of the Company"},
		"validity_period_valid_from":     "2026-10-01",
		"validity_period_valid_until":    "2099-09-30",
	})
	if answer := s.scenario("poa", demo.VariantRevoked); answer.Status != demo.ScenarioRefused {
		t.Fatalf("status %q, reasons %v", answer.Status, answer.Reasons)
	}
	if !s.wallet.Revoked(presented) {
		t.Error("the presented power of attorney is still valid")
	}
	if other.Type != demo.TypePowerOfAttorney || s.wallet.Revoked(other.Index) {
		t.Errorf("the demo revoked the %s at index %d, which was not presented", other.Type, other.Index)
	}
}

// The issuer cannot revoke a protected power of attorney. The demo issues a new
// one, and the wallet presents the newest.
func TestRevokedVariantOnAProtectedPowerOfAttorney(t *testing.T) {
	s := startScenarios(t, "")
	s.wallet.Protect()
	protected := s.wallet.Credentials()
	answer := s.scenario("poa", demo.VariantRevoked)
	if answer.Status != demo.ScenarioRefused || !slices.ContainsFunc(answer.Notes, func(note string) bool { return strings.Contains(note, "are protected") }) {
		t.Fatalf("status %q, reasons %v, notes %v", answer.Status, answer.Reasons, answer.Notes)
	}
	issued := s.wallet.Credentials()[0]
	if issued.Type != demo.TypePowerOfAttorney || !s.wallet.Revoked(issued.Index) {
		t.Errorf("the demo revoked no new power of attorney: %s at index %d", issued.Type, issued.Index)
	}
	for _, credential := range protected {
		if s.wallet.Revoked(credential.Index) {
			t.Errorf("the demo revoked the protected %s at index %d", credential.Type, credential.Index)
		}
	}
}

// A visitor revoked the new power of attorney before the wallet answered. The
// wallet then presents a protected one, which the issuer cannot revoke.
func TestRevokedVariantStopsOnAPresentedProtectedCredential(t *testing.T) {
	s := startScenarios(t, "")
	s.wallet.Protect()
	var created demo.ScenarioRequest
	s.call(http.MethodPost, "/api/scenarios/poa/requests", `{"variant":"`+demo.VariantRevoked+`"}`, http.StatusCreated, &created)
	s.wallet.Revoke(s.wallet.Credentials()[0].Index)
	if _, err := s.wallet.Present(http.DefaultClient, created.Request.WalletURL); err != nil {
		t.Fatal(err)
	}
	var answer demo.ScenarioRequest
	s.call(http.MethodGet, "/api/scenarios/poa/requests/"+created.ID, "", http.StatusOK, &answer)
	if answer.Status != demo.ScenarioStopped || len(answer.Reasons) != 1 || !strings.Contains(answer.Reasons[0], "protected") || len(failedChecks(answer)) != 0 {
		t.Fatalf("status %q, reasons %v, failed checks %v", answer.Status, answer.Reasons, failedChecks(answer))
	}
	for _, credential := range s.wallet.Credentials() {
		if credential.Protected && s.wallet.Revoked(credential.Index) {
			t.Errorf("the demo revoked the protected %s at index %d", credential.Type, credential.Index)
		}
	}
}

func TestExpiredVariantActsAfterTheEndDate(t *testing.T) {
	s := startScenarios(t, "")
	answer := s.scenario("poa", demo.VariantExpired)
	if answer.TaskDate != "2099-10-01" {
		t.Errorf("task date %q", answer.TaskDate)
	}
}

func TestPowerOfAttorneyWithoutEndDate(t *testing.T) {
	s := start(t, "")
	indefinite := map[string]any{
		"company_statutory_full_name":    "Acme Logistics GmbH",
		"scope_of_representation_powers": []any{"Registration and closure of branches of the Company"},
		"validity_period_valid_from":     "2026-10-01",
	}
	s.wallet.Issue("pub-eaa", demo.TypePowerOfAttorney, indefinite)
	if answer := s.scenario("poa", demo.VariantOK); answer.Status != demo.ScenarioAccepted {
		t.Errorf("status %q, reasons %v", answer.Status, answer.Reasons)
	}
}

func TestKnowYourBusinessScenario(t *testing.T) {
	s := startScenarios(t, "")
	answer := s.scenario("kyb", demo.VariantOK)
	if answer.Status != demo.ScenarioAccepted {
		t.Fatalf("status %q, reasons %v", answer.Status, answer.Reasons)
	}
	queries := []string{}
	for _, presentation := range answer.Presentations {
		queries = append(queries, presentation.Query)
		if !presentation.Report.Valid {
			t.Errorf("%s: failed checks %v", presentation.Query, dsdtest.Failed(presentation.Report))
		}
	}
	if !slices.Equal(queries, []string{"ebwoid", "poa"}) {
		t.Errorf("presentations for %v", queries)
	}
	learned := map[string]string{}
	for _, fact := range answer.Learned {
		learned[fact.Name] = fact.Value
	}
	if learned["Identifier"] != "DETEST.00000471" || learned["Representative"] != "Alice" {
		t.Errorf("learned %v", learned)
	}
}

func TestKnowYourBusinessOfAnotherCompany(t *testing.T) {
	s := startScenarios(t, "")
	other := map[string]any{"id": "DETEST.00000999", "name": "Delta Notaries B.V.", "date_of_expiry": "2099-11-12"}
	s.wallet.Issue("pub-eaa", demo.TypeEBWOID, other)
	answer := s.scenario("kyb", demo.VariantOK)
	if answer.Status != demo.ScenarioRefused {
		t.Fatalf("status %q", answer.Status)
	}
	if failed := failedChecks(answer); !slices.Equal(failed, []string{demo.CheckPolicyIdentifier, demo.CheckPolicyName}) {
		t.Errorf("failed checks %v", failed)
	}
}

func TestKnowYourBusinessWithoutOwnerData(t *testing.T) {
	s := start(t, "")
	// The template issues another type. The wallet then holds no owner
	// identification data and answers only the query for the power of attorney.
	s.wallet.SetTemplate("ebwoid", "pub-eaa", "urn:example:other", owner)
	answer := s.scenario("kyb", demo.VariantOK)
	if answer.Status != demo.ScenarioRefused || len(answer.Reasons) != 1 || !strings.Contains(answer.Reasons[0], "owner identification data") {
		t.Errorf("status %q, reasons %v", answer.Status, answer.Reasons)
	}
}

func TestScenarioRequestIsSigned(t *testing.T) {
	s := startScenarios(t, "")
	var created demo.ScenarioRequest
	s.call(http.MethodPost, "/api/scenarios/kyb/requests", `{}`, http.StatusCreated, &created)
	parts := strings.Split(created.Request.RequestObject, ".")
	if len(parts) != 3 {
		t.Fatalf("request object %q", created.Request.RequestObject)
	}
	raw, _ := base64.RawURLEncoding.DecodeString(parts[0])
	var header struct {
		Typ string   `json:"typ"`
		X5C []string `json:"x5c"`
	}
	if err := json.Unmarshal(raw, &header); err != nil || header.Typ != "oauth-authz-req+jwt" || len(header.X5C) != 1 {
		t.Errorf("header %s", raw)
	}
	clientID, _ := created.Request.Decoded["client_id"].(string)
	if !strings.HasPrefix(clientID, "x509_hash:") || created.Request.Decoded["verifier_info"] == nil {
		t.Errorf("client_id %q, verifier_info %v", clientID, created.Request.Decoded["verifier_info"])
	}
}

func TestScenarioAnswerIsSingleUse(t *testing.T) {
	s := startScenarios(t, "")
	var created demo.ScenarioRequest
	s.call(http.MethodPost, "/api/scenarios/poa/requests", `{}`, http.StatusCreated, &created)
	if _, err := s.wallet.Present(http.DefaultClient, created.Request.WalletURL); err != nil {
		t.Fatal(err)
	}
	if _, err := s.wallet.Present(http.DefaultClient, created.Request.WalletURL); err == nil {
		t.Error("the second answer was accepted")
	}
}

func TestScenarioRequestErrors(t *testing.T) {
	s := startScenarios(t, "")
	s.call(http.MethodPost, "/api/scenarios/unknown/requests", `{}`, http.StatusNotFound, nil)
	s.call(http.MethodPost, "/api/scenarios/kyb/requests", `{"variant":"expired"}`, http.StatusBadRequest, nil)
	s.call(http.MethodGet, "/api/scenarios/poa/requests/unknown", "", http.StatusNotFound, nil)
	var created demo.ScenarioRequest
	s.call(http.MethodPost, "/api/scenarios/poa/requests", `{}`, http.StatusCreated, &created)
	s.call(http.MethodGet, "/api/scenarios/kyb/requests/"+created.ID, "", http.StatusNotFound, nil)
}

func TestIssuerOffers(t *testing.T) {
	s := startScenarios(t, "")
	configurations := []string{"ebwoid", "eu-poa", "employee-authorisation"}
	for _, configuration := range configurations {
		var offer demo.IssuerOffer
		s.call(http.MethodPost, "/api/offers", `{"configuration":"`+configuration+`"}`, http.StatusCreated, &offer)
		if !strings.HasPrefix(offer.WalletURL, walletPublicURL+"/credential-offer?credential_offer_uri=") {
			t.Errorf("%s: wallet URL %q", configuration, offer.WalletURL)
		}
		if ids, _ := offer.Offer["credential_configuration_ids"].([]any); len(ids) != 1 || ids[0] != configuration {
			t.Errorf("%s: offer %v", configuration, offer.Offer)
		}
		if !strings.HasPrefix(offer.SchemeURI, "openid-credential-offer://") || !strings.Contains(offer.DecoderURL, "/decoder/#credential=") {
			t.Errorf("%s: scheme %q, decoder %q", configuration, offer.SchemeURI, offer.DecoderURL)
		}
	}
	if offers := s.wallet.Offers(); !slices.Equal(offers, configurations) {
		t.Errorf("the wallet made offers for %v", offers)
	}
	s.call(http.MethodPost, "/api/offers", `{"configuration":"pid"}`, http.StatusBadRequest, nil)
}

func TestWalletCredentials(t *testing.T) {
	s := startScenarios(t, "")
	for _, stored := range s.wallet.Credentials() {
		if stored.Type == demo.TypePowerOfAttorney {
			s.wallet.Revoke(stored.Index)
		}
	}
	var holdings []demo.Holding
	s.call(http.MethodGet, "/api/wallet/credentials", "", http.StatusOK, &holdings)
	valid := map[string]bool{}
	for _, holding := range holdings {
		if len(holding.Credentials) != 1 {
			t.Fatalf("%s: %d credentials, want 1", holding.Configuration, len(holding.Credentials))
		}
		held := holding.Credentials[0]
		if !held.ExpiresAt.After(held.IssuedAt) {
			t.Errorf("%s: expires at %v, issued at %v", holding.Configuration, held.ExpiresAt, held.IssuedAt)
		}
		valid[holding.Configuration] = held.Valid
	}
	if want := map[string]bool{"ebwoid": true, "eu-poa": false, "employee-authorisation": true}; !maps.Equal(valid, want) {
		t.Errorf("valid = %v, want %v", valid, want)
	}
}

func TestWalletCredentialsWithoutWallet(t *testing.T) {
	s := startScenarios(t, "")
	s.wallet.Close()
	s.call(http.MethodGet, "/api/wallet/credentials", "", http.StatusBadGateway, nil)
}

func TestUnknownScenarioPage(t *testing.T) {
	s := startScenarios(t, "")
	response, err := http.Get(s.base + "/scenarios/unknown")
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusNotFound {
		t.Errorf("status %d", response.StatusCode)
	}
}
