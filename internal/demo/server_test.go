package demo_test

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/eudi-dev/ebw-dev/internal/demo"
	"github.com/eudi-dev/ebw-dev/internal/dsdjwt"
	"github.com/eudi-dev/ebw-dev/internal/dsdjwt/dsdtest"
	"github.com/eudi-dev/ebw-dev/internal/wallettest"
)

type setup struct {
	t      *testing.T
	wallet *wallettest.Wallet
	base   string
}

func start(t *testing.T, prefix string) *setup {
	t.Helper()
	wallet := wallettest.New()
	t.Cleanup(wallet.Close)
	powerOfAttorney := map[string]any{
		"euid_reference":              "DETEST.00000471",
		"company_statutory_full_name": "Acme Logistics GmbH",
		"attorney_full_name":          "Alice",
		"scope_of_representation_powers": []any{
			"Registration and closure of branches of the Company",
			"Purchase orders for operating supplies up to EUR 5000 per order",
		},
		"validity_period_valid_from":  "2026-10-01",
		"validity_period_valid_until": "2099-09-30",
	}
	employeeAuthorisation := map[string]any{"proxy": map[string]any{"full_name": "Bob"}}
	wallet.Issue("pub-eaa", demo.TypePowerOfAttorney, powerOfAttorney)
	wallet.Issue("eaa", demo.TypeEmployeeAuthorisation, employeeAuthorisation)
	wallet.SetTemplate("eu-poa", "pub-eaa", demo.TypePowerOfAttorney, powerOfAttorney)
	wallet.SetTemplate("employee-authorisation", "eaa", demo.TypeEmployeeAuthorisation, employeeAuthorisation)

	listener := httptest.NewUnstartedServer(nil)
	base := "http://" + listener.Listener.Addr().String() + prefix
	server, err := demo.NewServer(demo.Config{PublicURL: base, WalletURL: wallet.URL})
	if err != nil {
		t.Fatal(err)
	}
	listener.Config.Handler = server
	listener.Start()
	t.Cleanup(listener.Close)
	return &setup{t: t, wallet: wallet, base: base}
}

func (s *setup) call(method, path, body string, want int, into any) {
	s.t.Helper()
	request, err := http.NewRequest(method, s.base+path, strings.NewReader(body))
	if err != nil {
		s.t.Fatal(err)
	}
	request.Header.Set("Content-Type", "application/json")
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		s.t.Fatal(err)
	}
	defer response.Body.Close()
	data, _ := io.ReadAll(response.Body)
	if response.StatusCode != want {
		s.t.Fatalf("%s %s = %d, want %d: %s", method, path, response.StatusCode, want, data)
	}
	if into != nil {
		if err := json.Unmarshal(data, into); err != nil {
			s.t.Fatalf("%s %s: %v in %s", method, path, err, data)
		}
	}
}

// mandate runs step 1: the agent service asks and the wallet answers.
func (s *setup) mandate(caseID string) demo.Mandate {
	s.t.Helper()
	var created demo.Mandate
	s.call(http.MethodPost, "/api/mandates", `{"case":"`+caseID+`"}`, http.StatusCreated, &created)
	if created.Status != demo.MandatePending {
		s.t.Fatalf("new mandate has the status %q", created.Status)
	}
	redirect, err := s.wallet.Present(http.DefaultClient, created.Request.WalletURL)
	if err != nil {
		s.t.Fatal(err)
	}
	if want := s.base + "/cases/" + caseID + "?mandate=" + created.ID; redirect != want {
		s.t.Errorf("redirect_uri = %q, want %q", redirect, want)
	}
	var answered demo.Mandate
	s.call(http.MethodGet, "/api/mandates/"+created.ID, "", http.StatusOK, &answered)
	return answered
}

func (s *setup) run(mandate demo.Mandate, variant string) demo.Run {
	s.t.Helper()
	var run demo.Run
	s.call(http.MethodPost, "/api/mandates/"+mandate.ID+"/runs", `{"variant":"`+variant+`"}`, http.StatusCreated, &run)
	var stored demo.Run
	s.call(http.MethodGet, "/api/runs/"+run.ID, "", http.StatusOK, &stored)
	if stored.Outcome != run.Outcome {
		s.t.Errorf("stored run has the outcome %q, the answer had %q", stored.Outcome, run.Outcome)
	}
	return run
}

func TestCases(t *testing.T) {
	cases := []struct{ id, verifier, credentialType string }{
		{"supplier", "bolt", demo.TypePowerOfAttorney},
		{"internal", "procurement", demo.TypeEmployeeAuthorisation},
	}
	variants := []struct {
		variant string
		failed  string
	}{
		{demo.VariantOK, ""},
		{demo.VariantOverLimit, dsdjwt.CheckPolicyLimit},
		{demo.VariantExpired, dsdjwt.CheckMandateValid},
		{demo.VariantWrongVerifier, dsdjwt.CheckPolicyAudience},
		{demo.VariantTampered, dsdjwt.CheckOnePayload},
	}
	for _, prefix := range []string{"", "/agents"} {
		s := start(t, prefix)
		for _, c := range cases {
			mandate := s.mandate(c.id)
			if mandate.Status != demo.MandateGranted || mandate.Report == nil || !mandate.Report.Valid {
				t.Fatalf("%s: mandate status %q, message %q", c.id, mandate.Status, mandate.ErrorDescription)
			}
			if got := mandate.Report.Credential["vct"]; got != c.credentialType {
				t.Errorf("%s: mandate rests on %v", c.id, got)
			}
			for _, v := range variants {
				t.Run(strings.Join([]string{prefix, c.id, v.variant}, "/"), func(t *testing.T) {
					run := s.run(mandate, v.variant)
					if run.Report == nil {
						t.Fatalf("run without report: %q %v", run.Outcome, run.Reasons)
					}
					if v.failed == "" {
						if run.Outcome != "accepted" || !run.Report.Valid || len(run.Report.Links) != 3 {
							t.Fatalf("outcome %q, reasons %v", run.Outcome, run.Reasons)
						}
						if run.Verifier.ID != c.verifier {
							t.Errorf("verifier = %q", run.Verifier.ID)
						}
						if audiences := run.Report.Mandate.Audiences; len(audiences) != 1 {
							t.Errorf("the verifier saw the audiences %v", audiences)
						}
						return
					}
					if run.Outcome != "refused" || run.Report.Valid {
						t.Fatalf("outcome %q, reasons %v", run.Outcome, run.Reasons)
					}
					if failed := dsdtest.Failed(run.Report); !slices.Equal(failed, []string{v.failed}) {
						t.Errorf("failed checks = %v, want only %s", failed, v.failed)
					}
					if len(run.Reasons) == 0 {
						t.Error("refusal without a reason")
					}
				})
			}
		}
	}
}

func TestWalletWithoutDelegation(t *testing.T) {
	s := start(t, "")
	s.wallet.SetPlain(true)
	mandate := s.mandate("supplier")
	if mandate.Status != demo.MandateRefused || mandate.Error != demo.ErrorNoDelegation {
		t.Fatalf("status %q, error %q", mandate.Status, mandate.Error)
	}
	if !strings.Contains(mandate.ErrorDescription, "does not support delegation") {
		t.Errorf("message = %q", mandate.ErrorDescription)
	}
	s.call(http.MethodPost, "/api/mandates/"+mandate.ID+"/runs", `{}`, http.StatusConflict, nil)
}

func TestRevokedCredential(t *testing.T) {
	s := start(t, "")
	mandate := s.mandate("supplier")
	s.wallet.Revoke(0)
	run := s.run(mandate, demo.VariantOK)
	if failed := dsdtest.Failed(run.Report); run.Outcome != "refused" || !slices.Equal(failed, []string{dsdjwt.CheckStatus}) {
		t.Errorf("outcome %q, failed checks %v", run.Outcome, failed)
	}
}

// The demo revokes the credential in the wallet and leaves a valid one.
func TestRevokedVariant(t *testing.T) {
	s := start(t, "")
	for _, c := range []struct{ id, credentialType string }{
		{"supplier", demo.TypePowerOfAttorney},
		{"internal", demo.TypeEmployeeAuthorisation},
	} {
		mandate := s.mandate(c.id)
		run := s.run(mandate, demo.VariantRevoked)
		if run.Report == nil {
			t.Fatalf("%s: run without report: %q %v", c.id, run.Outcome, run.Reasons)
		}
		if failed := dsdtest.Failed(run.Report); run.Outcome != "refused" || !slices.Equal(failed, []string{dsdjwt.CheckStatus}) {
			t.Errorf("%s: outcome %q, failed checks %v", c.id, run.Outcome, failed)
		}
		if run := s.run(mandate, demo.VariantOK); run.Outcome != "refused" {
			t.Errorf("%s: the revoked mandate still works: %q", c.id, run.Outcome)
		}
		fresh := s.mandate(c.id)
		if fresh.Status != demo.MandateGranted {
			t.Fatalf("%s: mandate after the fresh credential: %q %s", c.id, fresh.Status, fresh.ErrorDescription)
		}
		if run := s.run(fresh, demo.VariantOK); run.Outcome != "accepted" {
			t.Errorf("%s: run on the fresh credential: %q %v", c.id, run.Outcome, run.Reasons)
		}
	}
	if count := len(s.wallet.Credentials()); count != 4 {
		t.Errorf("the wallet holds %d credentials, want 4", count)
	}
}

func TestConfigNamesTheAgentClient(t *testing.T) {
	s := start(t, "")
	var config struct {
		AgentClientID string `json:"agent_client_id"`
	}
	s.call(http.MethodGet, "/api/config", "", http.StatusOK, &config)
	if !strings.HasPrefix(config.AgentClientID, "x509_hash:") {
		t.Errorf("agent_client_id = %q", config.AgentClientID)
	}
}

// The request is a signed request object of the registered agent service.
func TestMandateRequestIsSigned(t *testing.T) {
	s := start(t, "")
	var created demo.Mandate
	s.call(http.MethodPost, "/api/mandates", `{"case":"supplier"}`, http.StatusCreated, &created)
	clientID, _ := created.Request.Decoded["client_id"].(string)
	if !strings.HasPrefix(clientID, "x509_hash:") {
		t.Errorf("client_id = %q", clientID)
	}
	if created.Request.Decoded["verifier_info"] == nil {
		t.Error("the request carries no verifier_info")
	}
	if !strings.HasPrefix(created.Request.URI, "openid4vp://authorize?client_id=x509_hash%3A") || !strings.Contains(created.Request.URI, "&request="+created.Request.RequestObject) {
		t.Errorf("openid4vp_uri = %s", created.Request.URI)
	}
	other := wallettest.New()
	t.Cleanup(other.Close)
	if _, err := other.Present(http.DefaultClient, created.Request.URI); err == nil {
		t.Error("a wallet with another access CA took the request")
	}
}

func TestIssuerOfAnotherList(t *testing.T) {
	s := start(t, "")
	s.wallet.Issue("eaa", demo.TypePowerOfAttorney, map[string]any{"attorney_full_name": "Alice"})
	mandate := s.mandate("supplier")
	if mandate.Status != demo.MandateGranted {
		t.Fatalf("mandate status %q: %s", mandate.Status, mandate.ErrorDescription)
	}
	run := s.run(mandate, demo.VariantOK)
	if failed := dsdtest.Failed(run.Report); run.Outcome != "refused" || !slices.Contains(failed, dsdjwt.CheckIssuerTrusted) {
		t.Errorf("outcome %q, failed checks %v", run.Outcome, failed)
	}
}

func TestMandateAnswerIsSingleUse(t *testing.T) {
	s := start(t, "")
	var created demo.Mandate
	s.call(http.MethodPost, "/api/mandates", `{"case":"internal"}`, http.StatusCreated, &created)
	if _, err := s.wallet.Present(http.DefaultClient, created.Request.WalletURL); err != nil {
		t.Fatal(err)
	}
	if _, err := s.wallet.Present(http.DefaultClient, created.Request.WalletURL); err == nil {
		t.Error("the agent service took a second answer for the same request")
	}
}

func TestPagesUnderPrefix(t *testing.T) {
	s := start(t, "/agents")
	for _, path := range []string{"/", "/cases/supplier", "/cases/internal", "/scenarios/poa", "/scenarios/kyb", "/issuer"} {
		response, err := http.Get(s.base + path)
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(response.Body)
		response.Body.Close()
		if response.StatusCode != http.StatusOK || !strings.Contains(string(body), `<base href="/agents/">`) {
			t.Errorf("%s: status %d, base element missing", path, response.StatusCode)
		}
		for _, absolute := range []string{`href="/`, `src="/`, `action="/`} {
			if strings.Contains(strings.ReplaceAll(string(body), `<base href="/agents/">`, ""), absolute) {
				t.Errorf("%s holds an absolute path (%s)", path, absolute)
			}
		}
	}
	// A reverse proxy may strip the prefix.
	response, err := http.Get(strings.TrimSuffix(s.base, "/agents") + "/static/app.js")
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Errorf("static file without the prefix: %d", response.StatusCode)
	}
}

func TestPagesLinkToTheWallet(t *testing.T) {
	server, err := demo.NewServer(demo.Config{
		PublicURL:       "http://localhost:28090",
		WalletURL:       "http://wallet.internal:8085",
		WalletPublicURL: "https://wallet.example/",
	})
	if err != nil {
		t.Fatal(err)
	}
	links := map[string]string{
		"/":               `<a class="node wallet" href="https://wallet.example">`,
		"/cases/supplier": `<a class="to-wallet" href="https://wallet.example">`,
		"/scenarios/poa":  `<a class="to-wallet" href="https://wallet.example">`,
		"/issuer":         `<a class="to-wallet" href="https://wallet.example">`,
	}
	for path, link := range links {
		recorder := httptest.NewRecorder()
		server.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, path, nil))
		body := recorder.Body.String()
		if !strings.Contains(body, link) {
			t.Errorf("%s: no link to the public wallet URL", path)
		}
		if path == "/" && strings.Contains(body, `class="to-wallet"`) {
			t.Errorf("/: the header links to the wallet as well")
		}
	}
}

func TestFooterShowsTheEbwDevVersion(t *testing.T) {
	wallet := wallettest.New()
	t.Cleanup(wallet.Close)
	server, err := demo.NewServer(demo.Config{PublicURL: "http://localhost:28090", WalletURL: wallet.URL, Version: "0.0.1"})
	if err != nil {
		t.Fatal(err)
	}
	recorder := httptest.NewRecorder()
	server.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/", nil))
	if !strings.Contains(recorder.Body.String(), "<p>ebw-dev 0.0.1</p>") {
		t.Error("the footer does not show the version")
	}
}

func TestVerifierTakesOneResponsePerRequest(t *testing.T) {
	s := start(t, "")
	var created struct {
		Request string `json:"authorization_request"`
	}
	s.call(http.MethodPost, "/verifier/procurement/requests", `{"action":"invoice.approve","amount":"10","currency":"EUR"}`, http.StatusCreated, &created)
	request, err := url.Parse(created.Request)
	if err != nil {
		t.Fatal(err)
	}
	form := url.Values{"state": {request.Query().Get("state")}, "vp_token": {`{"authority":["not a token"]}`}}
	var accepted atomic.Int32
	var posting sync.WaitGroup
	for range 10 {
		posting.Go(func() {
			response, err := http.PostForm(s.base+"/verifier/procurement/response", form)
			if err != nil {
				t.Error(err)
				return
			}
			response.Body.Close()
			if response.StatusCode == http.StatusOK {
				accepted.Add(1)
			}
		})
	}
	posting.Wait()
	if got := accepted.Load(); got != 1 {
		t.Errorf("the verifier took %d responses for one request, want 1", got)
	}
}
