// Package trust loads the trust anchors of the business wallet over HTTP and
// checks issuers and status list entries against them.
package trust

import (
	"context"
	"crypto/ecdsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/eudi-dev/ebw-dev/internal/dsdjwt"
)

const maxBody = 1 << 20

// List is a trusted list of the wallet (ETSI TS 119 602 V1.1.1).
type List struct {
	ID         string
	Type       string
	NextUpdate string
	Issuance   []*x509.Certificate
	// Revocation holds the certificates of the revocation service. They sign
	// the status list.
	Revocation []*x509.Certificate
}

type snapshot struct {
	loadedAt time.Time
	walletCA []*x509.Certificate
	lists    map[string]*List
	origins  []string
	// statusClient fetches status lists. It trusts the wallet CA for TLS.
	statusClient *http.Client
}

type Store struct {
	walletURL string
	client    *http.Client

	mu      sync.RWMutex
	current *snapshot
}

// NewStore returns a store for the wallet at the given base URL. Call Reload
// before use.
func NewStore(walletURL string) *Store {
	return &Store{
		walletURL: strings.TrimRight(walletURL, "/"),
		client:    &http.Client{Timeout: 10 * time.Second},
	}
}

func get(ctx context.Context, client *http.Client, target string) ([]byte, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return nil, err
	}
	response, err := client.Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s answered %s", target, response.Status)
	}
	return io.ReadAll(io.LimitReader(response.Body, maxBody))
}

func (s *Store) Reload(ctx context.Context) error {
	next := &snapshot{loadedAt: time.Now(), lists: map[string]*List{}}

	caPEM, err := get(ctx, s.client, s.walletURL+"/api/certificates/ca")
	if err != nil {
		return fmt.Errorf("loading the wallet CA: %w", err)
	}
	for block, rest := pem.Decode(caPEM); block != nil; block, rest = pem.Decode(rest) {
		certificate, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return fmt.Errorf("parsing the wallet CA: %w", err)
		}
		next.walletCA = append(next.walletCA, certificate)
	}
	if len(next.walletCA) == 0 {
		return errors.New("the wallet CA endpoint returned no certificate")
	}

	indexJSON, err := get(ctx, s.client, s.walletURL+"/api/trustlists")
	if err != nil {
		return fmt.Errorf("loading the list of trusted lists: %w", err)
	}
	var index struct {
		Lists []struct {
			ID                    string `json:"id"`
			Path                  string `json:"path"`
			URL                   string `json:"url"`
			IssuanceServiceType   string `json:"issuanceServiceType"`
			RevocationServiceType string `json:"revocationServiceType"`
		} `json:"trust_lists"`
	}
	if err := json.Unmarshal(indexJSON, &index); err != nil {
		return fmt.Errorf("reading the list of trusted lists: %w", err)
	}
	for _, entry := range index.Lists {
		token, err := get(ctx, s.client, s.walletURL+entry.Path)
		if err != nil {
			return fmt.Errorf("loading the trusted list %s: %w", entry.ID, err)
		}
		list, err := parseList(strings.TrimSpace(string(token)), next.walletCA, entry.IssuanceServiceType, entry.RevocationServiceType)
		if err != nil {
			return fmt.Errorf("trusted list %s: %w", entry.ID, err)
		}
		list.ID = entry.ID
		next.lists[entry.ID] = list
		if published, err := url.Parse(entry.URL); err == nil && published.Host != "" {
			if origin := published.Scheme + "://" + published.Host; !slices.Contains(next.origins, origin) {
				next.origins = append(next.origins, origin)
			}
		}
	}

	next.statusClient = statusClient(next.walletCA)

	s.mu.Lock()
	previous := s.current
	s.current = next
	s.mu.Unlock()
	if previous != nil {
		previous.statusClient.CloseIdleConnections()
	}
	return nil
}

type loteDocument struct {
	LoTE struct {
		Information struct {
			Type       string `json:"LoTEType"`
			NextUpdate string `json:"NextUpdate"`
		} `json:"ListAndSchemeInformation"`
		Entities []struct {
			Services []struct {
				Information struct {
					Type     string `json:"ServiceTypeIdentifier"`
					Identity struct {
						Certificates []struct {
							Value string `json:"val"`
						} `json:"X509Certificates"`
					} `json:"ServiceDigitalIdentity"`
				} `json:"ServiceInformation"`
			} `json:"TrustedEntityServices"`
		} `json:"TrustedEntitiesList"`
	} `json:"LoTE"`
}

func parseList(token string, walletCA []*x509.Certificate, issuanceType, revocationType string) (*List, error) {
	_, payload, err := verifyX5C(token, walletCA, time.Now())
	if err != nil {
		return nil, err
	}
	var document loteDocument
	if err := json.Unmarshal(payload, &document); err != nil {
		return nil, fmt.Errorf("reading the list: %w", err)
	}
	list := &List{Type: document.LoTE.Information.Type, NextUpdate: document.LoTE.Information.NextUpdate}
	for _, entity := range document.LoTE.Entities {
		for _, service := range entity.Services {
			for _, encoded := range service.Information.Identity.Certificates {
				der, err := base64.StdEncoding.DecodeString(encoded.Value)
				if err != nil {
					return nil, fmt.Errorf("decoding a service certificate: %w", err)
				}
				certificate, err := x509.ParseCertificate(der)
				if err != nil {
					return nil, fmt.Errorf("parsing a service certificate: %w", err)
				}
				switch service.Information.Type {
				case issuanceType:
					list.Issuance = append(list.Issuance, certificate)
				case revocationType:
					list.Revocation = append(list.Revocation, certificate)
				}
			}
		}
	}
	return list, nil
}

func verifyX5C(token string, anchors []*x509.Certificate, now time.Time) (map[string]any, []byte, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, nil, errors.New("a JWT must have 3 parts separated by dots")
	}
	headerJSON, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, nil, fmt.Errorf("header: %w", err)
	}
	var header map[string]any
	if err := json.Unmarshal(headerJSON, &header); err != nil {
		return nil, nil, fmt.Errorf("header: %w", err)
	}
	chain, err := certificatesFromHeader(header)
	if err != nil {
		return nil, nil, err
	}
	if err := chainsTo(chain, anchors, now); err != nil {
		return nil, nil, err
	}
	key, ok := chain[0].PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return nil, nil, errors.New("the signer certificate has no ECDSA key")
	}
	if err := dsdjwt.VerifyES256(token, header, key); err != nil {
		return nil, nil, err
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, nil, fmt.Errorf("payload: %w", err)
	}
	return header, payload, nil
}

func certificatesFromHeader(header map[string]any) ([]*x509.Certificate, error) {
	entries, _ := header["x5c"].([]any)
	if len(entries) == 0 {
		return nil, errors.New("the header has no x5c")
	}
	chain := make([]*x509.Certificate, 0, len(entries))
	for _, entry := range entries {
		text, _ := entry.(string)
		der, err := base64.StdEncoding.DecodeString(text)
		if err != nil {
			return nil, fmt.Errorf("decoding x5c: %w", err)
		}
		certificate, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, fmt.Errorf("parsing x5c: %w", err)
		}
		chain = append(chain, certificate)
	}
	return chain, nil
}

func chainsTo(chain, anchors []*x509.Certificate, now time.Time) error {
	if len(anchors) == 0 {
		return errors.New("the trusted list holds no certificate for this service")
	}
	roots, intermediates := x509.NewCertPool(), x509.NewCertPool()
	for _, anchor := range anchors {
		roots.AddCert(anchor)
	}
	for _, certificate := range chain[1:] {
		intermediates.AddCert(certificate)
	}
	_, err := chain[0].Verify(x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
		CurrentTime:   now,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	})
	return err
}

func (s *Store) snapshot() (*snapshot, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.current == nil {
		return nil, errors.New("the trusted lists of the wallet are not loaded")
	}
	return s.current, nil
}

func (snap *snapshot) anchors(lists []string, pick func(*List) []*x509.Certificate) []*x509.Certificate {
	var anchors []*x509.Certificate
	for _, id := range lists {
		if list := snap.lists[id]; list != nil {
			anchors = append(anchors, pick(list)...)
		}
	}
	return anchors
}

// ResolveIssuer returns a resolver for dsdjwt. A credential is trusted when
// its x5c chain ends at an issuance certificate of a named list.
func (s *Store) ResolveIssuer(lists []string, now time.Time) func(header, claims map[string]any) (dsdjwt.Issuer, error) {
	return func(header, _ map[string]any) (dsdjwt.Issuer, error) {
		chain, err := certificatesFromHeader(header)
		if err != nil {
			return dsdjwt.Issuer{}, err
		}
		key, ok := chain[0].PublicKey.(*ecdsa.PublicKey)
		if !ok {
			return dsdjwt.Issuer{}, errors.New("the issuer certificate has no ECDSA key")
		}
		issuer := dsdjwt.Issuer{Name: chain[0].Subject.CommonName, Key: key}
		snap, err := s.snapshot()
		if err != nil {
			issuer.TrustError = err
			return issuer, nil
		}
		if err := chainsTo(chain, snap.anchors(lists, func(l *List) []*x509.Certificate { return l.Issuance }), now); err != nil {
			issuer.TrustError = fmt.Errorf("no issuer in the trusted lists %s anchors the certificate chain: %w", strings.Join(lists, ", "), err)
		}
		return issuer, nil
	}
}

type Summary struct {
	LoadedAt time.Time     `json:"loaded_at"`
	Lists    []ListSummary `json:"lists"`
}

type ListSummary struct {
	ID         string   `json:"id"`
	Type       string   `json:"type"`
	NextUpdate string   `json:"next_update,omitempty"`
	Issuers    []string `json:"issuers"`
}

func (s *Store) Summary() (Summary, error) {
	snap, err := s.snapshot()
	if err != nil {
		return Summary{}, err
	}
	summary := Summary{LoadedAt: snap.loadedAt}
	for id, list := range snap.lists {
		item := ListSummary{ID: id, Type: list.Type, NextUpdate: list.NextUpdate, Issuers: []string{}}
		for _, certificate := range list.Issuance {
			item.Issuers = append(item.Issuers, certificate.Subject.CommonName)
		}
		summary.Lists = append(summary.Lists, item)
	}
	slices.SortFunc(summary.Lists, func(a, b ListSummary) int { return strings.Compare(a.ID, b.ID) })
	return summary, nil
}

func statusClient(walletCA []*x509.Certificate) *http.Client {
	pool, err := x509.SystemCertPool()
	if err != nil || pool == nil {
		pool = x509.NewCertPool()
	}
	for _, certificate := range walletCA {
		pool.AddCert(certificate)
	}
	return &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12},
			IdleConnTimeout: 90 * time.Second,
		},
		// A redirect could lead the fetch away from the origins that
		// CheckStatus allows.
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return errors.New("the status list server answered with a redirect")
		},
	}
}
