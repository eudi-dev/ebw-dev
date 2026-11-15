package demo

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"
)

// walletCredential is an entry of the wallet's GET /api/credentials.
type walletCredential struct {
	ID        string        `json:"id"`
	Type      string        `json:"vct"`
	IssuedAt  time.Time     `json:"issued_at"`
	ValidFrom time.Time     `json:"valid_from,omitzero"`
	ExpiresAt time.Time     `json:"expires_at,omitzero"`
	Status    *walletStatus `json:"status"`
}

// walletStatus is the Token Status List entry of a wallet credential.
type walletStatus struct {
	URI    string `json:"uri"`
	Index  int    `json:"idx"`
	Status int    `json:"status"`
}

// valid reports whether the credential is neither revoked nor expired at now.
func (c walletCredential) valid(now time.Time) bool {
	if !c.ExpiresAt.IsZero() && !now.Before(c.ExpiresAt) {
		return false
	}
	return c.Status == nil || c.Status.Status == 0
}

type walletError struct {
	Status      int
	Description string `json:"error_description"`
}

func (e *walletError) Error() string {
	if e.Description != "" {
		return fmt.Sprintf("the wallet returned HTTP %d: %s", e.Status, e.Description)
	}
	return fmt.Sprintf("the wallet returned HTTP %d", e.Status)
}

// walletClient calls the HTTP API of the business wallet.
type walletClient struct {
	base string
	http *http.Client
}

func newWalletClient(base string) walletClient {
	return walletClient{base: base, http: &http.Client{Timeout: 15 * time.Second}}
}

func (c walletClient) call(ctx context.Context, method, path string, body, into any) error {
	var reader io.Reader
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			return err
		}
		reader = bytes.NewReader(encoded)
	}
	request, err := http.NewRequestWithContext(ctx, method, c.base+path, reader)
	if err != nil {
		return err
	}
	request.Header.Set("Accept", "application/json")
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	response, err := c.http.Do(request)
	if err != nil {
		return fmt.Errorf("the wallet is not reachable: %w", err)
	}
	defer response.Body.Close()
	data, err := io.ReadAll(io.LimitReader(response.Body, 4<<20))
	if err != nil {
		return err
	}
	if response.StatusCode >= 300 {
		problem := &walletError{Status: response.StatusCode}
		_ = json.Unmarshal(data, problem)
		return problem
	}
	if into == nil {
		return nil
	}
	return json.Unmarshal(data, into)
}

func (c walletClient) credentials(ctx context.Context) ([]walletCredential, error) {
	var credentials []walletCredential
	err := c.call(ctx, http.MethodGet, "/api/credentials", nil, &credentials)
	return credentials, err
}

// setStatus writes the Token Status List entry of a credential. The value 1 revokes it.
func (c walletClient) setStatus(ctx context.Context, id string, status int) error {
	return c.call(ctx, http.MethodPost, "/api/credentials/"+url.PathEscape(id)+"/status", map[string]int{"status": status}, nil)
}

func (c walletClient) issue(ctx context.Context, template string) error {
	return c.call(ctx, http.MethodPost, "/api/issue", map[string]string{"template": template}, nil)
}

type accessCertificate struct {
	Certificate string `json:"certificate"`
}

func (c walletClient) accessCertificate(ctx context.Context, identifier, service, csr string, dnsNames []string) (accessCertificate, error) {
	var issued accessCertificate
	err := c.call(ctx, http.MethodPost, "/api/registrar/access-certificates", map[string]any{
		"identifier":        identifier,
		"serviceIdentifier": service,
		"csr":               csr,
		"dnsNames":          dnsNames,
	}, &issued)
	return issued, err
}

// verifierInfo has the registrar issue a registration certificate for the
// intended use. It returns the verifier_info of a request (OpenID4VP 1.0
// §5.1).
func (c walletClient) verifierInfo(ctx context.Context, identifier, intendedUse string) (json.RawMessage, error) {
	var issued struct {
		VerifierInfo string `json:"verifierInfo"`
	}
	err := c.call(ctx, http.MethodPost, "/api/registrar/registration-certificates", map[string]string{
		"identifier":            identifier,
		"intendedUseIdentifier": intendedUse,
	}, &issued)
	if err != nil {
		return nil, err
	}
	if !json.Valid([]byte(issued.VerifierInfo)) {
		return nil, errors.New("the registrar returned no verifier_info")
	}
	return json.RawMessage(issued.VerifierInfo), nil
}

// credentialOffer is the answer of the wallet's issuer to POST
// /issuer/api/offers: a pre-authorized OpenID4VCI 1.0 offer by reference.
type credentialOffer struct {
	ID       string `json:"id"`
	OfferURI string `json:"offer_uri"`
	// SchemeURI is the offer in the openid-credential-offer scheme
	// (OpenID4VCI 1.0 §4.1).
	SchemeURI string `json:"scheme_uri"`
	Issuer    string `json:"issuer"`
	DCAPI     struct {
		Digital struct {
			Requests []struct {
				Data map[string]any `json:"data"`
			} `json:"requests"`
		} `json:"digital"`
	} `json:"dc_api"`
}

// createOffer has the wallet's issuer make an offer for one credential
// configuration. The credential carries a status list entry.
func (c walletClient) createOffer(ctx context.Context, configuration string) (credentialOffer, error) {
	var offer credentialOffer
	query := url.Values{"credential": {configuration}, "status": {"true"}}
	err := c.call(ctx, http.MethodPost, "/issuer/api/offers?"+query.Encode(), nil, &offer)
	return offer, err
}
