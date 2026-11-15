package demo

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/eudi-dev/ebw-dev/internal/dsdjwt"
)

// relyingParty is a service of a relying party in the registrar of the wallet.
// wallet-config/relying-parties.yaml registers each of them.
type relyingParty struct {
	ID      string
	Service string
	// Name is the common name in the access certificate request.
	Name string
}

var agentService = relyingParty{ID: "DETEST.00000471", Service: "agent-service", Name: "Acme agent service"}

// registration is the identity of a relying party service: the key and the
// access certificate for its requests, and the registration certificate of
// each intended use.
type registration struct {
	key          *ecdsa.PrivateKey
	certificate  []byte
	clientID     string
	verifierInfo map[string]json.RawMessage
}

// registered returns the registration of the service with the verifier_info
// of the intended use. The first call asks the registrar for the certificates.
func (s *Server) registered(ctx context.Context, party relyingParty, intendedUse string) (*registration, json.RawMessage, error) {
	s.registrationMu.Lock()
	defer s.registrationMu.Unlock()
	key := party.ID + "/" + party.Service
	current := s.registrations[key]
	if current == nil {
		created, err := s.register(ctx, party)
		if err != nil {
			return nil, nil, fmt.Errorf("getting the access certificate for %s of %s failed: %w", party.Service, party.ID, err)
		}
		current = created
		s.registrations[key] = current
	}
	if intendedUse == "" {
		return current, nil, nil
	}
	info, ok := current.verifierInfo[intendedUse]
	if !ok {
		var err error
		info, err = s.wallet.verifierInfo(ctx, party.ID, intendedUse)
		if err != nil {
			return nil, nil, fmt.Errorf("getting the registration certificate for %s of %s failed: %w", intendedUse, party.ID, err)
		}
		current.verifierInfo[intendedUse] = info
	}
	return current, info, nil
}

func (s *Server) register(ctx context.Context, party relyingParty) (*registration, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	request, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: party.Name},
	}, key)
	if err != nil {
		return nil, err
	}
	var dnsNames []string
	if host := s.public.Hostname(); net.ParseIP(host) == nil {
		dnsNames = []string{host}
	}
	csr := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: request})
	issued, err := s.wallet.accessCertificate(ctx, party.ID, party.Service, string(csr), dnsNames)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode([]byte(issued.Certificate))
	if block == nil {
		return nil, errors.New("the registrar returned no PEM certificate")
	}
	certificate, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, err
	}
	if public, ok := certificate.PublicKey.(*ecdsa.PublicKey); !ok || !public.Equal(&key.PublicKey) {
		return nil, errors.New("the access certificate is for another key")
	}
	// OpenID4VP 1.0 §5.9.3: the client identifier is the SHA-256 hash of the
	// DER encoded leaf certificate.
	hash := sha256.Sum256(certificate.Raw)
	return &registration{
		key:          key,
		certificate:  certificate.Raw,
		clientID:     "x509_hash:" + base64.RawURLEncoding.EncodeToString(hash[:]),
		verifierInfo: map[string]json.RawMessage{},
	}, nil
}

// forgetRegistration makes the next request ask the registrar again. A wallet
// with new keys refuses the certificates of the old ones.
func (s *Server) forgetRegistration() {
	s.registrationMu.Lock()
	defer s.registrationMu.Unlock()
	clear(s.registrations)
}

// requestObject signs the authorization request with the key of the access
// certificate (OpenID4VP 1.0 §5, RFC 9101). aud is the static value of
// OpenID4VP 1.0 §5.8. The header carries the leaf certificate without the CA.
func (r *registration) requestObject(claims map[string]any, now time.Time) (string, error) {
	signed := map[string]any{
		"iss":       r.clientID,
		"aud":       "https://self-issued.me/v2",
		"iat":       now.Unix(),
		"exp":       now.Add(10 * time.Minute).Unix(),
		"client_id": r.clientID,
	}
	for name, value := range claims {
		signed[name] = value
	}
	return dsdjwt.SignES256(r.key, map[string]any{
		"alg": "ES256",
		"typ": "oauth-authz-req+jwt",
		"x5c": []string{base64.StdEncoding.EncodeToString(r.certificate)},
	}, signed)
}
