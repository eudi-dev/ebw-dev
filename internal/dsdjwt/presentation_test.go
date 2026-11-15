package dsdjwt_test

import (
	"crypto/ecdsa"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/eudi-dev/ebw-dev/internal/dsdjwt"
	"github.com/eudi-dev/ebw-dev/internal/dsdjwt/dsdtest"
)

const notary = "x509_hash:notary"

func (p *parties) presentPlain(change func(*dsdtest.Presentation)) string {
	presentation := dsdtest.Presentation{
		HolderKey: p.holder, IssuerJWT: p.issuerJWT, Disclosures: p.disclosures,
		Audience: notary, Nonce: "notary-nonce", IssuedAt: t0.Add(time.Minute),
	}
	if change != nil {
		change(&presentation)
	}
	return dsdtest.Present(presentation)
}

func TestVerifySDJWT(t *testing.T) {
	p := newParties(t)
	expected := dsdjwt.SDJWTExpectation{Audience: notary, Nonce: "notary-nonce"}

	t.Run("valid", func(t *testing.T) {
		report, err := dsdjwt.VerifySDJWT(p.presentPlain(nil), expected, p.options())
		if err != nil {
			t.Fatal(err)
		}
		if !report.Valid {
			t.Fatalf("failed checks: %v", dsdtest.Failed(report))
		}
		kinds := []string{}
		for _, link := range report.Links {
			kinds = append(kinds, link.Kind)
		}
		if !slices.Equal(kinds, []string{dsdjwt.LinkCredential, dsdjwt.LinkPresentation}) {
			t.Fatalf("links %v", kinds)
		}
		if report.Credential["company_statutory_full_name"] != "Acme Logistics GmbH" {
			t.Fatalf("credential claims %v", report.Credential)
		}
	})

	failures := []struct {
		name  string
		token func() string
		check string
	}{
		{"audience of another verifier", func() string {
			return p.presentPlain(func(pr *dsdtest.Presentation) { pr.Audience = "x509_hash:other" })
		}, dsdjwt.CheckAudience},
		{"nonce of another request", func() string {
			return p.presentPlain(func(pr *dsdtest.Presentation) { pr.Nonce = "old" })
		}, dsdjwt.CheckNonce},
		{"stale key binding", func() string {
			return p.presentPlain(func(pr *dsdtest.Presentation) { pr.IssuedAt = t0.Add(-time.Hour) })
		}, dsdjwt.CheckIssuedAt},
		{"signed by another key", func() string {
			return p.presentPlain(func(pr *dsdtest.Presentation) { pr.HolderKey = dsdtest.NewKey() })
		}, dsdjwt.CheckHolderSignature},
		{"disclosure left out after signing", func() string {
			token := p.presentPlain(nil)
			return strings.Replace(token, "~"+p.disclosures[0]+"~", "~", 1)
		}, dsdjwt.CheckKeyBindingSDHash},
		{"key binding of the wrong type", func() string {
			sdJWT := strings.Join(append([]string{p.issuerJWT}, p.disclosures...), "~") + "~"
			return sdJWT + sign(t, p.holder, map[string]any{"typ": "jwt", "alg": "ES256"}, map[string]any{
				"iat": t0.Unix(), "aud": notary, "nonce": "notary-nonce", "sd_hash": dsdtest.Hash(sdJWT),
			})
		}, dsdjwt.CheckPresentationType},
	}
	for _, failure := range failures {
		t.Run(failure.name, func(t *testing.T) {
			report, err := dsdjwt.VerifySDJWT(failure.token(), expected, p.options())
			if err != nil {
				t.Fatal(err)
			}
			if report.Valid || !slices.Equal(dsdtest.Failed(report), []string{failure.check}) {
				t.Fatalf("failed checks %v, expected only %s", dsdtest.Failed(report), failure.check)
			}
		})
	}

	t.Run("unreferenced disclosure and a key binding of another key", func(t *testing.T) {
		extra, err := dsdjwt.NewClaimDisclosure("extra", "not in _sd")
		if err != nil {
			t.Fatal(err)
		}
		token := p.presentPlain(func(pr *dsdtest.Presentation) {
			pr.Disclosures = append(slices.Clone(p.disclosures), extra.Raw)
			pr.HolderKey = dsdtest.NewKey()
		})
		report, err := dsdjwt.VerifySDJWT(token, expected, p.options())
		if err != nil {
			t.Fatal(err)
		}
		if want := []string{dsdjwt.CheckDisclosures, dsdjwt.CheckHolderSignature}; !slices.Equal(dsdtest.Failed(report), want) {
			t.Fatalf("failed checks %v, want %v", dsdtest.Failed(report), want)
		}
		assertEveryCheck(t, report, map[string][]string{
			dsdjwt.LinkCredential: credentialChecks,
			dsdjwt.LinkPresentation: {
				dsdjwt.CheckPresentationType, dsdjwt.CheckHolderSignature, dsdjwt.CheckAudience,
				dsdjwt.CheckNonce, dsdjwt.CheckIssuedAt, dsdjwt.CheckKeyBindingSDHash,
			},
		})
	})

	t.Run("expired credential", func(t *testing.T) {
		options := p.options()
		options.Now = t0.Add(48 * time.Hour)
		token := p.presentPlain(func(pr *dsdtest.Presentation) { pr.IssuedAt = options.Now })
		report, _ := dsdjwt.VerifySDJWT(token, expected, options)
		if !slices.Equal(dsdtest.Failed(report), []string{dsdjwt.CheckCredentialValid}) {
			t.Fatalf("failed checks %v", dsdtest.Failed(report))
		}
	})

	for name, token := range map[string]string{
		"delegation chain":   p.mandate,
		"no key binding":     strings.Join(append([]string{p.issuerJWT}, p.disclosures...), "~") + "~",
		"no separator":       p.issuerJWT,
		"key binding broken": strings.Join(append([]string{p.issuerJWT}, p.disclosures...), "~") + "~not-a-jwt",
	} {
		t.Run(name, func(t *testing.T) {
			report, err := dsdjwt.VerifySDJWT(token, expected, p.options())
			if err != nil {
				t.Fatal(err)
			}
			if report.Valid {
				t.Fatal("the report is valid")
			}
		})
	}
}

func sign(t *testing.T, key *ecdsa.PrivateKey, header, payload map[string]any) string {
	t.Helper()
	token, err := dsdjwt.SignES256(key, header, payload)
	if err != nil {
		t.Fatal(err)
	}
	return token
}
