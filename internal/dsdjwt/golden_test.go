package dsdjwt_test

import (
	"encoding/json"
	"os"
	"reflect"
	"testing"
	"time"

	"github.com/eudi-dev/ebw-dev/internal/dsdjwt"
	"github.com/eudi-dev/ebw-dev/internal/dsdjwt/dsdtest"
)

const goldenPath = "../../testdata/golden-chain.json"

type goldenVector struct {
	Description string `json:"description"`
	Token       string `json:"token"`
	Keys        struct {
		Issuer dsdjwt.JWK `json:"issuer"`
		Holder dsdjwt.JWK `json:"holder"`
		Agent  dsdjwt.JWK `json:"agent"`
	} `json:"keys"`
	Verifier struct {
		Audience string `json:"audience"`
		Nonce    string `json:"nonce"`
		Time     int64  `json:"time"`
	} `json:"verifier"`
	Expected goldenResult `json:"expected"`
}

type goldenResult struct {
	Valid      bool            `json:"valid"`
	Links      []goldenLink    `json:"links"`
	Credential map[string]any  `json:"credential"`
	Mandate    *dsdjwt.Mandate `json:"mandate"`
}

type goldenLink struct {
	Kind          string            `json:"kind"`
	KeyThumbprint string            `json:"key_thumbprint"`
	Checks        map[string]string `json:"checks"`
}

func verifyGolden(t *testing.T, vector goldenVector) goldenResult {
	t.Helper()
	issuerKey, err := vector.Keys.Issuer.PublicKey()
	if err != nil {
		t.Fatal(err)
	}
	report, err := dsdjwt.VerifyPresentation(vector.Token,
		dsdjwt.PresentationExpectation{Audience: vector.Verifier.Audience, Nonce: vector.Verifier.Nonce},
		dsdjwt.Options{
			Now: time.Unix(vector.Verifier.Time, 0),
			ResolveIssuer: func(_, _ map[string]any) (dsdjwt.Issuer, error) {
				return dsdjwt.Issuer{Name: "Issuer", Key: issuerKey}, nil
			},
		})
	if err != nil {
		t.Fatal(err)
	}
	result := goldenResult{Valid: report.Valid, Credential: report.Credential, Mandate: report.Mandate}
	for _, link := range report.Links {
		checks := map[string]string{}
		for _, check := range link.Checks {
			checks[check.Name] = check.Result
		}
		result.Links = append(result.Links, goldenLink{Kind: link.Kind, KeyThumbprint: link.KeyThumbprint, Checks: checks})
	}
	// A JSON round trip gives the same value types as the committed file.
	data, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	var normalised goldenResult
	if err := json.Unmarshal(data, &normalised); err != nil {
		t.Fatal(err)
	}
	return normalised
}

func TestGoldenVector(t *testing.T) {
	if os.Getenv("UPDATE_GOLDEN") != "" {
		writeGolden(t)
	}
	data, err := os.ReadFile(goldenPath)
	if err != nil {
		t.Fatal(err)
	}
	var vector goldenVector
	if err := json.Unmarshal(data, &vector); err != nil {
		t.Fatal(err)
	}
	got := verifyGolden(t, vector)
	if !reflect.DeepEqual(got, vector.Expected) {
		gotJSON, _ := json.MarshalIndent(got, "", "  ")
		t.Fatalf("the result differs from the expected result of the vector:\n%s", gotJSON)
	}
	if !got.Valid || len(got.Links) != 3 {
		t.Fatalf("the vector must be a valid chain of 3 links, got valid=%v links=%d", got.Valid, len(got.Links))
	}
	for i, key := range []dsdjwt.JWK{vector.Keys.Issuer, vector.Keys.Holder, vector.Keys.Agent} {
		if got.Links[i].KeyThumbprint != key.Thumbprint() {
			t.Errorf("link %d is not signed with the published key", i+1)
		}
	}
}

// writeGolden creates a new vector with fresh keys. The private keys are
// dropped after signing.
func writeGolden(t *testing.T) {
	t.Helper()
	issuer, holder, agent := dsdtest.NewKey(), dsdtest.NewKey(), dsdtest.NewKey()
	const agentService = "redirect_uri:https://business.example/agents/agent/response/golden"
	const verifier = "redirect_uri:https://business.example/agents/verifier/supplier/response"

	issuerJWT, disclosures := dsdtest.Issue(dsdtest.Credential{
		IssuerKey: issuer,
		Issuer:    "https://wallet.example",
		Type:      "uri:eu.eudi.eu-poa.1",
		IssuedAt:  t0.Add(-24 * time.Hour),
		Expires:   t0.Add(365 * 24 * time.Hour),
		Holder:    dsdtest.JWK(holder),
		Claims: map[string]any{
			"company_statutory_full_name": "Acme Logistics GmbH",
			"euid_reference":              "DETEST.HRB900001",
			"attorney_full_name":          "Bob",
			"scope_of_representation_powers": []any{
				"Registration and closure of branches of the Company",
				"Purchase orders for operating supplies up to EUR 5000 per order",
			},
		},
	})
	sent, err := dsdjwt.NewTransactionData(dsdjwt.Mandate{
		IssuedAt:  t0,
		Expires:   t0.Add(time.Hour),
		AgentKey:  dsdtest.JWK(agent),
		Agent:     dsdjwt.Agent{ID: "urn:eudi-test:agent:procurement-1", Name: "Procurement agent", Operator: "Acme Logistics GmbH"},
		Purpose:   "Order packaging material",
		Actions:   []string{"order.create"},
		Limit:     dsdjwt.Limit{Amount: "5000.00", Currency: "EUR"},
		Audiences: []string{verifier, "redirect_uri:https://second-supplier.example/openid4vp/response"},
	}, []string{"authority"})
	if err != nil {
		t.Fatal(err)
	}
	mandate := dsdtest.Delegate(dsdtest.Delegation{
		HolderKey: holder, IssuerJWT: issuerJWT, Disclosures: disclosures,
		Audience: agentService, Nonce: "bWFuZGF0ZS1ub25jZQ", IssuedAt: t0, Sent: sent,
	})
	var vector goldenVector
	vector.Description = "dSD-JWT+KB in the format of docs/chain-format.md. The agent shows a mandate to the supplier portal."
	vector.Keys.Issuer, vector.Keys.Holder, vector.Keys.Agent = dsdtest.JWK(issuer), dsdtest.JWK(holder), dsdtest.JWK(agent)
	vector.Verifier.Audience = verifier
	vector.Verifier.Nonce = "dmVyaWZpZXItbm9uY2U"
	vector.Verifier.Time = t0.Add(100 * time.Second).Unix()
	vector.Token, err = dsdjwt.Present(mandate, dsdjwt.Presentation{
		Audience: verifier, Nonce: vector.Verifier.Nonce, IssuedAt: t0.Add(100 * time.Second), AgentKey: agent,
	})
	if err != nil {
		t.Fatal(err)
	}
	vector.Expected = verifyGolden(t, vector)
	data, err := json.MarshalIndent(vector, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(goldenPath, append(data, '\n'), 0o644); err != nil {
		t.Fatal(err)
	}
}
