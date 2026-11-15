package dsdjwt_test

import (
	"crypto/ecdsa"
	"errors"
	"maps"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/eudi-dev/eudi-dev/v3/pkg/sdjwt/delegate"

	"github.com/eudi-dev/ebw-dev/internal/dsdjwt"
	"github.com/eudi-dev/ebw-dev/internal/dsdjwt/dsdtest"
)

const (
	agentService = "redirect_uri:https://agents.example/agent/response/1"
	supplier     = "redirect_uri:https://supplier.example/response"
	otherBuyer   = "redirect_uri:https://other.example/response"
	poaType      = "uri:eu.eudi.eu-poa.1"
)

var t0 = time.Unix(1794571200, 0).UTC()

type parties struct {
	issuer, holder, agent *ecdsa.PrivateKey
	issuerJWT             string
	disclosures           []string
	sent                  dsdjwt.TransactionData
	mandate               string
}

func newParties(t *testing.T) *parties {
	t.Helper()
	p := &parties{issuer: dsdtest.NewKey(), holder: dsdtest.NewKey(), agent: dsdtest.NewKey()}
	p.sent = p.transactionData(t, t0.Add(time.Hour), dsdtest.JWK(p.agent))
	p.issue(t, nil)
	return p
}

// issue signs the credential with extra selectively disclosable claims and
// delegates it. The holder leaves out the disclosures of the withheld claims.
func (p *parties) issue(t *testing.T, extra map[string]any, withheld ...string) {
	t.Helper()
	claims := map[string]any{
		"company_statutory_full_name":    "Acme Logistics GmbH",
		"scope_of_representation_powers": []any{"Registration and closure of branches of the Company", "Purchase orders"},
	}
	maps.Copy(claims, extra)
	issuerJWT, disclosures := dsdtest.Issue(dsdtest.Credential{
		IssuerKey: p.issuer,
		Issuer:    "https://issuer.example",
		Type:      poaType,
		IssuedAt:  t0.Add(-24 * time.Hour),
		Expires:   t0.Add(24 * time.Hour),
		Holder:    dsdtest.JWK(p.holder),
		Claims:    claims,
	})
	p.issuerJWT = issuerJWT
	p.disclosures = slices.DeleteFunc(disclosures, func(raw string) bool {
		disclosure, err := dsdjwt.ParseDisclosure(raw)
		if err != nil {
			t.Fatal(err)
		}
		return slices.Contains(withheld, disclosure.Name)
	})
	p.mandate = p.delegate(p.sent)
}

func (p *parties) transactionData(t *testing.T, expires time.Time, agentKey dsdjwt.JWK) dsdjwt.TransactionData {
	t.Helper()
	sent, err := dsdjwt.NewTransactionData(dsdjwt.Mandate{
		IssuedAt:  t0,
		Expires:   expires,
		AgentKey:  agentKey,
		Agent:     dsdjwt.Agent{ID: "urn:eudi-test:agent:procurement-1", Name: "Procurement agent", Operator: "Acme Logistics GmbH"},
		Purpose:   "Order packaging material",
		Actions:   []string{"order.create"},
		Limit:     dsdjwt.Limit{Amount: "5000.00", Currency: "EUR"},
		Audiences: []string{supplier, otherBuyer},
	}, []string{"authority"})
	if err != nil {
		t.Fatal(err)
	}
	return sent
}

// withPayload signs a delegation whose delegate payload has the changes of change.
func (p *parties) withPayload(t *testing.T, change func(payload map[string]any)) string {
	t.Helper()
	disclosure, err := dsdjwt.ParseDisclosure(p.sent.PayloadDisclosure)
	if err != nil {
		t.Fatal(err)
	}
	payload, _ := disclosure.Value.(map[string]any)
	change(payload)
	changed, err := dsdjwt.NewDisclosure(payload)
	if err != nil {
		t.Fatal(err)
	}
	p.sent.PayloadDisclosure = changed.Raw
	return p.delegate(p.sent)
}

func (p *parties) delegate(sent dsdjwt.TransactionData) string {
	return dsdtest.Delegate(dsdtest.Delegation{
		HolderKey: p.holder, IssuerJWT: p.issuerJWT, Disclosures: p.disclosures,
		Audience: agentService, Nonce: "mandate-nonce", IssuedAt: t0, Sent: sent,
	})
}

func (p *parties) present(t *testing.T, mandate string) string {
	t.Helper()
	token, err := dsdjwt.Present(mandate, dsdjwt.Presentation{
		Audience: supplier, Nonce: "verifier-nonce", IssuedAt: t0.Add(time.Minute), AgentKey: p.agent,
	})
	if err != nil {
		t.Fatal(err)
	}
	return token
}

func (p *parties) options() dsdjwt.Options {
	return dsdjwt.Options{
		Now: t0.Add(2 * time.Minute),
		ResolveIssuer: func(_, _ map[string]any) (dsdjwt.Issuer, error) {
			return dsdjwt.Issuer{Name: "Test issuer", Key: &p.issuer.PublicKey}, nil
		},
	}
}

func (p *parties) kbSDJWT(t *testing.T, key *ecdsa.PrivateKey, change func(header, payload map[string]any)) string {
	t.Helper()
	sdJWT := strings.Join(append([]string{p.issuerJWT}, p.disclosures...), "~") + "~"
	header := map[string]any{"typ": "kb-sd-jwt+kb", "alg": "ES256"}
	payload := map[string]any{
		"iat": t0.Unix(), "aud": agentService, "nonce": "mandate-nonce",
		"sd_hash": dsdtest.Hash(sdJWT), "_sd_alg": "sha-256",
		"delegate_payload":        []any{map[string]any{"...": dsdtest.Hash(p.sent.PayloadDisclosure)}},
		"transaction_data_hashes": []any{dsdtest.Hash(p.sent.Encoded)},
	}
	change(header, payload)
	token, err := dsdjwt.SignES256(key, header, payload)
	if err != nil {
		t.Fatal(err)
	}
	return token
}

func (p *parties) withKBSDJWT(t *testing.T, kbSDJWT string, extraDisclosures ...string) string {
	t.Helper()
	chain, err := dsdjwt.Split(p.mandate)
	if err != nil {
		t.Fatal(err)
	}
	chain.KBSDJWT = kbSDJWT
	chain.DelegateDisclosures = append(chain.DelegateDisclosures, extraDisclosures...)
	return chain.String()
}

func TestVerifyPresentation(t *testing.T) {
	tests := []struct {
		name   string
		build  func(t *testing.T, p *parties) string
		expect func(*dsdjwt.PresentationExpectation, *dsdjwt.Options)
		failed []string
		// ownChoice marks a failure that draft 00 allows. It comes from a choice
		// of this project in docs/chain-format.md or from
		// draft-ietf-oauth-sd-jwt-vc-19, which eudi-dev delegate.Verify does not
		// apply.
		ownChoice bool
	}{
		{
			name:  "valid chain",
			build: func(t *testing.T, p *parties) string { return p.present(t, p.mandate) },
		},
		{
			name: "KB-SD-JWT of another credential",
			build: func(t *testing.T, p *parties) string {
				other := newParties(t)
				return p.present(t, p.withKBSDJWT(t, other.kbSDJWT(t, other.holder, func(_, payload map[string]any) {
					payload["delegate_payload"] = []any{map[string]any{"...": dsdtest.Hash(p.sent.PayloadDisclosure)}}
				})))
			},
			failed: []string{dsdjwt.CheckHolderSignature, dsdjwt.CheckMandateHash},
		},
		{
			name: "wrong sd_hash in the KB-SD-JWT",
			build: func(t *testing.T, p *parties) string {
				return p.present(t, p.withKBSDJWT(t, p.kbSDJWT(t, p.holder, func(_, payload map[string]any) {
					payload["sd_hash"] = dsdtest.Hash("something else")
				})))
			},
			failed: []string{dsdjwt.CheckMandateHash},
		},
		{
			name: "issuer disclosure removed after the mandate",
			build: func(t *testing.T, p *parties) string {
				chain, _ := dsdjwt.Split(p.mandate)
				chain.Disclosures = chain.Disclosures[1:]
				return p.present(t, chain.String())
			},
			failed: []string{dsdjwt.CheckMandateHash},
		},
		{
			name: "KB-SD-JWT with the typ of a plain key binding",
			build: func(t *testing.T, p *parties) string {
				return p.present(t, p.withKBSDJWT(t, p.kbSDJWT(t, p.holder, func(header, _ map[string]any) {
					header["typ"] = "kb+jwt"
				})))
			},
			failed: []string{dsdjwt.CheckMandateType},
		},
		{
			name: "KB-SD-JWT signed with another key",
			build: func(t *testing.T, p *parties) string {
				return p.present(t, p.withKBSDJWT(t, p.kbSDJWT(t, dsdtest.NewKey(), func(_, _ map[string]any) {})))
			},
			failed: []string{dsdjwt.CheckHolderSignature},
		},
		{
			name: "2 disclosed delegate payloads",
			build: func(t *testing.T, p *parties) string {
				second := p.transactionData(t, t0.Add(time.Hour), dsdtest.JWK(p.agent))
				kbSDJWT := p.kbSDJWT(t, p.holder, func(_, payload map[string]any) {
					payload["delegate_payload"] = []any{
						map[string]any{"...": dsdtest.Hash(p.sent.PayloadDisclosure)},
						map[string]any{"...": dsdtest.Hash(second.PayloadDisclosure)},
					}
				})
				return p.present(t, p.withKBSDJWT(t, kbSDJWT, second.PayloadDisclosure))
			},
			failed: []string{dsdjwt.CheckOnePayload},
		},
		{
			name: "delegate payload changed by the agent",
			build: func(t *testing.T, p *parties) string {
				changed := p.transactionData(t, t0.Add(100*time.Hour), dsdtest.JWK(p.agent))
				chain, _ := dsdjwt.Split(p.mandate)
				chain.DelegateDisclosures = append([]string{changed.PayloadDisclosure}, changed.Disclosures...)
				return p.present(t, chain.String())
			},
			failed: []string{dsdjwt.CheckOnePayload},
		},
		{
			name: "delegate disclosure without a digest in the payload",
			build: func(t *testing.T, p *parties) string {
				extra, _ := dsdjwt.NewDisclosure(supplier)
				chain, _ := dsdjwt.Split(p.mandate)
				chain.DelegateDisclosures = append(chain.DelegateDisclosures, extra.Raw)
				return p.present(t, chain.String())
			},
			failed: []string{dsdjwt.CheckDelegateContent},
		},
		{
			name: "unreferenced credential disclosure and a KB-SD-JWT of another key",
			build: func(t *testing.T, p *parties) string {
				extra, err := dsdjwt.NewClaimDisclosure("extra", "not in _sd")
				if err != nil {
					t.Fatal(err)
				}
				p.disclosures = append(p.disclosures, extra.Raw)
				chain, _ := dsdjwt.Split(p.mandate)
				chain.Disclosures = p.disclosures
				chain.KBSDJWT = p.kbSDJWT(t, dsdtest.NewKey(), func(_, _ map[string]any) {})
				return p.present(t, chain.String())
			},
			failed: []string{dsdjwt.CheckDisclosures, dsdjwt.CheckHolderSignature},
		},
		{
			name: "unreferenced delegate disclosure and a delegate KB-JWT of another key",
			build: func(t *testing.T, p *parties) string {
				extra, err := dsdjwt.NewDisclosure(supplier)
				if err != nil {
					t.Fatal(err)
				}
				chain, _ := dsdjwt.Split(p.mandate)
				chain.DelegateDisclosures = append(chain.DelegateDisclosures, extra.Raw)
				token, err := dsdjwt.Present(chain.String(), dsdjwt.Presentation{
					Audience: supplier, Nonce: "verifier-nonce", IssuedAt: t0.Add(time.Minute), AgentKey: dsdtest.NewKey(),
				})
				if err != nil {
					t.Fatal(err)
				}
				return token
			},
			failed: []string{dsdjwt.CheckDelegateContent, dsdjwt.CheckAgentSignature},
		},
		{
			name: "past exp in _sd withheld by the holder",
			build: func(t *testing.T, p *parties) string {
				p.issue(t, map[string]any{"exp": t0.Add(-time.Hour).Unix()}, "exp")
				return p.present(t, p.mandate)
			},
			failed:    []string{dsdjwt.CheckCredentialValid},
			ownChoice: true,
		},
		{
			name: "exp in _sd",
			build: func(t *testing.T, p *parties) string {
				p.issue(t, map[string]any{"exp": t0.Add(time.Hour).Unix()})
				return p.present(t, p.mandate)
			},
			failed:    []string{dsdjwt.CheckDisclosures, dsdjwt.CheckCredentialValid},
			ownChoice: true,
		},
		{
			name: "cnf in _sd",
			build: func(t *testing.T, p *parties) string {
				p.issue(t, map[string]any{"cnf": map[string]any{"jwk": dsdtest.JWK(p.holder)}})
				return p.present(t, p.mandate)
			},
			failed:    []string{dsdjwt.CheckDisclosures, dsdjwt.CheckHolderKey},
			ownChoice: true,
		},
		{
			name:  "expired mandate",
			build: func(t *testing.T, p *parties) string { return p.present(t, p.mandate) },
			expect: func(_ *dsdjwt.PresentationExpectation, opts *dsdjwt.Options) {
				opts.Now = t0.Add(time.Hour + 2*time.Minute)
			},
			failed: []string{dsdjwt.CheckMandateValid, dsdjwt.CheckIssuedAt},
		},
		{
			name: "delegate payload without exp",
			build: func(t *testing.T, p *parties) string {
				return p.present(t, p.withPayload(t, func(payload map[string]any) { delete(payload, "exp") }))
			},
			failed:    []string{dsdjwt.CheckMandateValid},
			ownChoice: true,
		},
		{
			name: "delegate payload with exp after the year 9999",
			build: func(t *testing.T, p *parties) string {
				return p.present(t, p.withPayload(t, func(payload map[string]any) { payload["exp"] = 1e15 }))
			},
			failed: []string{dsdjwt.CheckMandateValid},
		},
		{
			name: "expired credential",
			build: func(t *testing.T, p *parties) string {
				token, err := dsdjwt.Present(p.mandate, dsdjwt.Presentation{
					Audience: supplier, Nonce: "verifier-nonce", IssuedAt: t0.Add(25 * time.Hour), AgentKey: p.agent,
				})
				if err != nil {
					t.Fatal(err)
				}
				return token
			},
			expect: func(_ *dsdjwt.PresentationExpectation, opts *dsdjwt.Options) {
				opts.Now = t0.Add(25 * time.Hour)
			},
			failed: []string{dsdjwt.CheckCredentialValid, dsdjwt.CheckMandateValid},
		},
		{
			name:  "wrong audience",
			build: func(t *testing.T, p *parties) string { return p.present(t, p.mandate) },
			expect: func(expected *dsdjwt.PresentationExpectation, _ *dsdjwt.Options) {
				expected.Audience = otherBuyer
			},
			failed: []string{dsdjwt.CheckAudience},
		},
		{
			name:  "wrong nonce",
			build: func(t *testing.T, p *parties) string { return p.present(t, p.mandate) },
			expect: func(expected *dsdjwt.PresentationExpectation, _ *dsdjwt.Options) {
				expected.Nonce = "another-nonce"
			},
			failed: []string{dsdjwt.CheckNonce},
		},
		{
			name: "delegate KB-JWT signed with another key",
			build: func(t *testing.T, p *parties) string {
				token, err := dsdjwt.Present(p.mandate, dsdjwt.Presentation{
					Audience: supplier, Nonce: "verifier-nonce", IssuedAt: t0.Add(time.Minute), AgentKey: dsdtest.NewKey(),
				})
				if err != nil {
					t.Fatal(err)
				}
				return token
			},
			failed: []string{dsdjwt.CheckAgentSignature},
		},
		{
			name: "audience disclosure removed after the agent signed",
			build: func(t *testing.T, p *parties) string {
				chain, _ := dsdjwt.Split(p.present(t, p.mandate))
				chain.DelegateDisclosures = chain.DelegateDisclosures[:1]
				return chain.String()
			},
			failed: []string{dsdjwt.CheckPresentationHash},
		},
		{
			name: "delegate payload without cnf",
			build: func(t *testing.T, p *parties) string {
				p.sent = p.transactionData(t, t0.Add(time.Hour), dsdjwt.JWK{})
				p.mandate = p.delegate(p.sent)
				return p.present(t, p.mandate)
			},
			failed: []string{dsdjwt.CheckAgentKey},
		},
		{
			name:  "issuer outside the trusted list",
			build: func(t *testing.T, p *parties) string { return p.present(t, p.mandate) },
			expect: func(_ *dsdjwt.PresentationExpectation, opts *dsdjwt.Options) {
				resolve := opts.ResolveIssuer
				opts.ResolveIssuer = func(header, claims map[string]any) (dsdjwt.Issuer, error) {
					issuer, err := resolve(header, claims)
					issuer.TrustError = errors.New("the certificate chain ends at no trusted list entry")
					return issuer, err
				}
			},
			failed: []string{dsdjwt.CheckIssuerTrusted},
		},
		{
			name:  "verifier without issuer keys",
			build: func(t *testing.T, p *parties) string { return p.present(t, p.mandate) },
			expect: func(_ *dsdjwt.PresentationExpectation, opts *dsdjwt.Options) {
				opts.ResolveIssuer = func(_, _ map[string]any) (dsdjwt.Issuer, error) {
					return dsdjwt.Issuer{}, errors.New("this verifier has no issuer keys")
				}
			},
			failed: []string{dsdjwt.CheckIssuerSignature},
		},
		{
			name:  "credential signed with another key",
			build: func(t *testing.T, p *parties) string { return p.present(t, p.mandate) },
			expect: func(_ *dsdjwt.PresentationExpectation, opts *dsdjwt.Options) {
				opts.ResolveIssuer = func(_, _ map[string]any) (dsdjwt.Issuer, error) {
					return dsdjwt.Issuer{Name: "Other issuer", Key: &dsdtest.NewKey().PublicKey}, nil
				}
			},
			failed: []string{dsdjwt.CheckIssuerSignature},
		},
		{
			name:  "no status check on a credential with an invalid signature",
			build: func(t *testing.T, p *parties) string { return p.present(t, p.mandate) },
			expect: func(_ *dsdjwt.PresentationExpectation, opts *dsdjwt.Options) {
				opts.ResolveIssuer = func(_, _ map[string]any) (dsdjwt.Issuer, error) {
					return dsdjwt.Issuer{Name: "Other issuer", Key: &dsdtest.NewKey().PublicKey}, nil
				}
				opts.CheckStatus = func(map[string]any) error { return errors.New("the status check ran") }
			},
			failed: []string{dsdjwt.CheckIssuerSignature},
		},
		{
			name:  "revoked credential",
			build: func(t *testing.T, p *parties) string { return p.present(t, p.mandate) },
			expect: func(_ *dsdjwt.PresentationExpectation, opts *dsdjwt.Options) {
				opts.CheckStatus = func(map[string]any) error { return errors.New("the status list marks the credential as invalid") }
			},
			failed: []string{dsdjwt.CheckStatus},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := newParties(t)
			token := tt.build(t, p)
			expected := dsdjwt.PresentationExpectation{Audience: supplier, Nonce: "verifier-nonce"}
			opts := p.options()
			if tt.expect != nil {
				tt.expect(&expected, &opts)
			}
			report, err := dsdjwt.VerifyPresentation(token, expected, opts)
			if err != nil {
				t.Fatal(err)
			}
			if failed := dsdtest.Failed(report); !slices.Equal(failed, tt.failed) {
				t.Fatalf("failed checks = %v, want %v", failed, tt.failed)
			}
			if report.Valid != (len(tt.failed) == 0) {
				t.Fatalf("valid = %v with failed checks %v", report.Valid, tt.failed)
			}
			assertEveryCheck(t, report, presentationChecks)
			issuer, err := opts.ResolveIssuer(nil, nil)
			if err != nil || tt.ownChoice {
				return
			}
			_, libraryErr := delegate.Verify(token, issuer.Key, delegate.Options{
				Now: opts.Now, Audience: expected.Audience, Nonce: expected.Nonce, MaxAge: 5 * time.Minute, RequireKeyBinding: true,
			})
			protocolFailed := slices.DeleteFunc(slices.Clone(tt.failed), func(check string) bool {
				return slices.Contains(productChecks, check)
			})
			if (libraryErr == nil) != (len(protocolFailed) == 0) {
				t.Fatalf("eudi-dev delegate.Verify = %v, failed protocol checks %v", libraryErr, protocolFailed)
			}
		})
	}
}

// productChecks are outside draft-ietf-oauth-delegate-sd-jwt-00 §6. The
// verifier of this product adds them.
var productChecks = []string{dsdjwt.CheckIssuerTrusted, dsdjwt.CheckStatus}

func TestVerifyPresentationReportsTheChain(t *testing.T) {
	p := newParties(t)
	report, err := dsdjwt.VerifyPresentation(p.present(t, p.mandate),
		dsdjwt.PresentationExpectation{Audience: supplier, Nonce: "verifier-nonce"}, p.options())
	if err != nil {
		t.Fatal(err)
	}
	wantKeys := map[string]string{
		dsdjwt.LinkCredential:   dsdtest.JWK(p.issuer).Thumbprint(),
		dsdjwt.LinkMandate:      dsdtest.JWK(p.holder).Thumbprint(),
		dsdjwt.LinkPresentation: dsdtest.JWK(p.agent).Thumbprint(),
	}
	for kind, want := range wantKeys {
		if got := report.Link(kind).KeyThumbprint; got != want {
			t.Errorf("%s key = %s, want %s", kind, got, want)
		}
	}
	if got := report.Mandate.Audiences; !slices.Equal(got, []string{supplier}) {
		t.Errorf("disclosed audiences = %v, want only the supplier", got)
	}
	if got := report.Mandate.Limit; got != (dsdjwt.Limit{Amount: "5000.00", Currency: "EUR"}) {
		t.Errorf("limit = %+v", got)
	}
	powers, _ := report.Credential["scope_of_representation_powers"].([]any)
	if len(powers) != 2 {
		t.Errorf("disclosed powers = %v, want 2 array elements", powers)
	}
	if status := report.Link(dsdjwt.LinkCredential).Check(dsdjwt.CheckStatus); status != dsdjwt.Skipped {
		t.Errorf("status check = %s, want skipped without a status checker", status)
	}
}

func TestVerifyPresentationStructure(t *testing.T) {
	p := newParties(t)
	presented := p.present(t, p.mandate)
	chain, _ := dsdjwt.Split(presented)
	plain := strings.Join(append([]string{chain.IssuerJWT}, chain.Disclosures...), "~") + "~" + chain.DelegateKBJWT

	tests := []struct {
		name, token string
		noChain     bool
	}{
		{name: "plain SD-JWT+KB", token: plain, noChain: true},
		{name: "2 empty components", token: strings.Replace(presented, "~~", "~~~", 1)},
		{name: "no KB-SD-JWT after the empty component", token: chain.IssuerJWT + "~~" + chain.DelegateKBJWT},
		{name: "mandate without a delegate KB-JWT", token: p.mandate},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			report, err := dsdjwt.VerifyPresentation(tt.token, dsdjwt.PresentationExpectation{Audience: supplier, Nonce: "verifier-nonce"}, p.options())
			if errors.Is(err, dsdjwt.ErrNoDelegation) != tt.noChain {
				t.Fatalf("error = %v, no delegation expected = %v", err, tt.noChain)
			}
			if report.Valid || report.Structure.Result != dsdjwt.Fail {
				t.Fatalf("structure check = %+v, valid = %v", report.Structure, report.Valid)
			}
		})
	}
}

func TestVerifyMandate(t *testing.T) {
	tests := []struct {
		name   string
		build  func(t *testing.T, p *parties) string
		expect func(p *parties, expected *dsdjwt.MandateExpectation)
		failed []string
	}{
		{
			name:  "valid mandate",
			build: func(_ *testing.T, p *parties) string { return p.mandate },
		},
		{
			name:  "mandate for another agent service",
			build: func(_ *testing.T, p *parties) string { return p.mandate },
			expect: func(_ *parties, expected *dsdjwt.MandateExpectation) {
				expected.Audience = "redirect_uri:https://another.example/response"
			},
			failed: []string{dsdjwt.CheckAudience},
		},
		{
			name:  "nonce of another request",
			build: func(_ *testing.T, p *parties) string { return p.mandate },
			expect: func(_ *parties, expected *dsdjwt.MandateExpectation) {
				expected.Nonce = "another-nonce"
			},
			failed: []string{dsdjwt.CheckNonce},
		},
		{
			name: "transaction data hash of another entry",
			build: func(t *testing.T, p *parties) string {
				return p.withKBSDJWT(t, p.kbSDJWT(t, p.holder, func(_, payload map[string]any) {
					payload["transaction_data_hashes"] = []any{dsdtest.Hash("another entry")}
				}))
			},
			failed: []string{dsdjwt.CheckTransactionData},
		},
		{
			name: "wallet signed another delegate payload",
			build: func(t *testing.T, p *parties) string {
				return p.delegate(p.transactionData(t, t0.Add(48*time.Hour), dsdtest.JWK(p.agent)))
			},
			failed: []string{dsdjwt.CheckTransactionData, dsdjwt.CheckRequestedPayload},
		},
		{
			name: "expired KB-SD-JWT",
			build: func(t *testing.T, p *parties) string {
				return p.withKBSDJWT(t, p.kbSDJWT(t, p.holder, func(_, payload map[string]any) {
					payload["exp"] = t0.Add(time.Minute).Unix()
				}))
			},
			failed: []string{dsdjwt.CheckMandateTime},
		},
		{
			name: "KB-SD-JWT not valid yet",
			build: func(t *testing.T, p *parties) string {
				return p.withKBSDJWT(t, p.kbSDJWT(t, p.holder, func(_, payload map[string]any) {
					payload["nbf"] = t0.Add(time.Hour).Unix()
				}))
			},
			failed: []string{dsdjwt.CheckMandateTime},
		},
		{
			name:   "token that already has a delegate KB-JWT",
			build:  func(t *testing.T, p *parties) string { return p.present(t, p.mandate) },
			failed: []string{dsdjwt.CheckStructure},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := newParties(t)
			token := tt.build(t, p)
			expected := dsdjwt.MandateExpectation{Audience: agentService, Nonce: "mandate-nonce", Sent: p.sent}
			if tt.expect != nil {
				tt.expect(p, &expected)
			}
			report, err := dsdjwt.VerifyMandate(token, expected, p.options())
			if err != nil {
				t.Fatal(err)
			}
			if failed := dsdtest.Failed(report); !slices.Equal(failed, tt.failed) {
				t.Fatalf("failed checks = %v, want %v", failed, tt.failed)
			}
			if report.Structure.Result == dsdjwt.Pass {
				assertEveryCheck(t, report, mandateChecks)
			}
		})
	}
}

var (
	credentialChecks = []string{
		dsdjwt.CheckIssuerSignature, dsdjwt.CheckIssuerTrusted, dsdjwt.CheckDisclosures,
		dsdjwt.CheckCredentialValid, dsdjwt.CheckStatus, dsdjwt.CheckHolderKey,
	}
	chainChecks = []string{
		dsdjwt.CheckMandateType, dsdjwt.CheckHolderSignature, dsdjwt.CheckMandateHash, dsdjwt.CheckMandateTime,
		dsdjwt.CheckOnePayload, dsdjwt.CheckDelegateContent, dsdjwt.CheckMandateValid, dsdjwt.CheckAgentKey,
	}
	presentationChecks = map[string][]string{
		dsdjwt.LinkCredential: credentialChecks,
		dsdjwt.LinkMandate:    chainChecks,
		dsdjwt.LinkPresentation: {
			dsdjwt.CheckPresentationType, dsdjwt.CheckAgentSignature, dsdjwt.CheckAudience,
			dsdjwt.CheckNonce, dsdjwt.CheckIssuedAt, dsdjwt.CheckPresentationHash,
		},
	}
	mandateChecks = map[string][]string{
		dsdjwt.LinkCredential: credentialChecks,
		dsdjwt.LinkMandate: append(slices.Clone(chainChecks),
			dsdjwt.CheckAudience, dsdjwt.CheckNonce, dsdjwt.CheckTransactionData, dsdjwt.CheckRequestedPayload),
	}
)

// assertEveryCheck requires each link to report every check once, as pass,
// fail or skipped.
func assertEveryCheck(t *testing.T, report *dsdjwt.Report, want map[string][]string) {
	t.Helper()
	if len(report.Links) != len(want) {
		t.Fatalf("%d links, want %d", len(report.Links), len(want))
	}
	for _, link := range report.Links {
		var names []string
		for _, check := range link.Checks {
			names = append(names, check.Name)
		}
		if !slices.Equal(names, want[link.Kind]) {
			t.Errorf("%s checks = %v, want %v", link.Kind, names, want[link.Kind])
		}
	}
}

func TestVerifyMandateRefusesPlainSDJWT(t *testing.T) {
	p := newParties(t)
	plain := strings.Join(append([]string{p.issuerJWT}, p.disclosures...), "~") + "~" + p.kbSDJWT(t, p.holder, func(header, _ map[string]any) {
		header["typ"] = "kb+jwt"
	})
	_, err := dsdjwt.VerifyMandate(plain, dsdjwt.MandateExpectation{}, p.options())
	if !errors.Is(err, dsdjwt.ErrNoDelegation) {
		t.Fatalf("error = %v, want ErrNoDelegation", err)
	}
}

func TestPresentKeepsOnlyTheVerifiersAudience(t *testing.T) {
	p := newParties(t)
	mandate, _ := dsdjwt.Split(p.mandate)
	presented, _ := dsdjwt.Split(p.present(t, p.mandate))
	if len(mandate.DelegateDisclosures) != 3 || len(presented.DelegateDisclosures) != 2 {
		t.Fatalf("delegate disclosures: mandate %d, presentation %d, want 3 and 2",
			len(mandate.DelegateDisclosures), len(presented.DelegateDisclosures))
	}
	if !slices.Equal(mandate.Disclosures, presented.Disclosures) || mandate.KBSDJWT != presented.KBSDJWT {
		t.Fatal("the SD-JWT part or the KB-SD-JWT changed")
	}
	if _, err := dsdjwt.Present(p.present(t, p.mandate), dsdjwt.Presentation{Audience: supplier, AgentKey: p.agent}); err == nil {
		t.Fatal("presenting a dSD-JWT+KB again must fail")
	}
}
